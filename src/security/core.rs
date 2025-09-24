use hyper::{Body, Request, Response};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use super::config::*;
use super::jwt::*;
use super::responses::*;
use super::utils::network::ip_match;

#[derive(Clone, Copy)]
struct RateState {
    tokens: f64,
    last: Instant,
}

#[derive(Clone)]
pub struct SecurityManager {
    cfg: SecurityConfig,
    rate_map: std::sync::Arc<tokio::sync::Mutex<HashMap<String, RateState>>>,
    jwt_cache: std::sync::Arc<tokio::sync::Mutex<HashMap<String, std::time::Instant>>>,
    #[cfg(feature = "jwt-rs256")]
    jwks_cache: std::sync::Arc<tokio::sync::Mutex<HashMap<String, super::jwt::JwkCacheEntry>>>,
}

impl SecurityManager {
    pub fn new(cfg: SecurityConfig) -> Self {
        Self {
            cfg,
            rate_map: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            jwt_cache: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            #[cfg(feature = "jwt-rs256")]
            jwks_cache: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn max_body_bytes(&self) -> Option<u64> {
        self.cfg.ddos.as_ref().and_then(|d| d.max_body_bytes)
    }

    pub async fn check_request(
        &self,
        req: &Request<Body>,
        client_ip: Option<IpAddr>,
    ) -> Option<Response<Body>> {
        if !self.cfg.enabled {
            return None;
        }

        // DDoS: basic header limits
        if let Some(dd) = &self.cfg.ddos {
            if let Some(max) = dd.max_headers {
                if req.headers().len() > max {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("headers_len"))]
                    )
                    .increment(1);
                    return resp_431();
                }
            }
            if let Some(maxb) = dd.max_header_bytes {
                if headers_size(req) > maxb {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("headers_size"))]
                    )
                    .increment(1);
                    return resp_431();
                }
            }
            if let Some(max_body) = dd.max_body_bytes {
                if let Some(len) = req
                    .headers()
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if len > max_body {
                        metrics::counter!(
                            "dispa_security_denied_total",
                            &[("kind", String::from("body_too_large"))]
                        )
                        .increment(1);
                        return resp_413();
                    }
                } else if dd.require_content_length.unwrap_or(false) {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("length_required"))]
                    )
                    .increment(1);
                    return resp_411();
                }
            }
        }

        // Rate limit by IP
        if let Some(rl) = &self.cfg.rate_limit {
            if rl.enabled {
                let key = client_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let now = Instant::now();
                let mut map = self.rate_map.lock().await;
                let mut st = *map.get(&key).unwrap_or(&RateState {
                    tokens: rl.burst,
                    last: now,
                });
                let dt = now.duration_since(st.last).as_secs_f64();
                st.tokens = (st.tokens + dt * rl.rate_per_sec).min(rl.burst);
                st.last = now;
                let allow = if st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    true
                } else {
                    false
                };
                map.insert(key.clone(), st);
                drop(map);
                if !allow {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("rate_limit"))]
                    )
                    .increment(1);
                    return resp_429();
                }
            }
        }

        // Access control allow/deny
        if let Some(ac) = &self.cfg.access_control {
            let ip = client_ip.or_else(|| {
                if ac.trust_proxy_headers {
                    // parse first entry in X-Forwarded-For
                    req.headers()
                        .get("x-forwarded-for")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.split(',').next())
                        .and_then(|s| s.trim().parse::<IpAddr>().ok())
                } else {
                    None
                }
            });
            if let Some(ip) = ip {
                if let Some(denied) = &ac.denied_ips {
                    if denied.iter().any(|p| ip_match(p, &ip)) {
                        metrics::counter!(
                            "dispa_security_denied_total",
                            &[("kind", String::from("denied_ip"))]
                        )
                        .increment(1);
                        return resp_403();
                    }
                }
                if let Some(allowed) = &ac.allowed_ips {
                    if !allowed.iter().any(|p| ip_match(p, &ip)) {
                        metrics::counter!(
                            "dispa_security_denied_total",
                            &[("kind", String::from("not_allowed_ip"))]
                        )
                        .increment(1);
                        return resp_403();
                    }
                }
            }
        }

        // JWT (Bearer) validation if configured
        if let Some(jwt) = &self.cfg.jwt {
            if jwt.enabled {
                let name = self
                    .cfg
                    .auth
                    .as_ref()
                    .and_then(|a| a.header_name.clone())
                    .unwrap_or_else(|| "authorization".into());
                if let Some(val) = req.headers().get(&name).and_then(|h| h.to_str().ok()) {
                    if let Some(token) = val
                        .strip_prefix("Bearer ")
                        .or_else(|| val.strip_prefix("bearer "))
                    {
                        if !self.verify_jwt(token, jwt).await {
                            metrics::counter!(
                                "dispa_security_denied_total",
                                &[("kind", String::from("jwt_invalid"))]
                            )
                            .increment(1);
                            return Some(resp_401("Invalid token"));
                        }
                    } else {
                        metrics::counter!(
                            "dispa_security_denied_total",
                            &[("kind", String::from("auth_missing"))]
                        )
                        .increment(1);
                        return Some(resp_401("Unauthorized"));
                    }
                } else {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("auth_missing"))]
                    )
                    .increment(1);
                    return Some(resp_401("Unauthorized"));
                }
            }
        }

        // Simple static auth (API Key / Bearer static list)
        if let Some(auth) = &self.cfg.auth {
            if auth.enabled {
                match auth.mode {
                    AuthMode::ApiKey => {
                        let name = auth
                            .header_name
                            .clone()
                            .unwrap_or_else(|| "x-api-key".into());
                        let v = req.headers().get(name).and_then(|h| h.to_str().ok());
                        if v.is_none()
                            || !auth
                                .keys
                                .iter()
                                .any(|k| v.map(|val| val == k).unwrap_or(false))
                        {
                            metrics::counter!(
                                "dispa_security_denied_total",
                                &[("kind", String::from("auth_apikey"))]
                            )
                            .increment(1);
                            return Some(resp_401("API key required"));
                        }
                    }
                    AuthMode::Bearer => {
                        // If JWT already configured, this static list can be used as allowlist fallback (optional)
                        let name = auth
                            .header_name
                            .clone()
                            .unwrap_or_else(|| "authorization".into());
                        let v = req.headers().get(name).and_then(|h| h.to_str().ok());
                        if let Some(val) = v {
                            let token = val
                                .strip_prefix("Bearer ")
                                .or_else(|| val.strip_prefix("bearer "))
                                .unwrap_or("");
                            if !auth.keys.iter().any(|k| token == k) {
                                metrics::counter!(
                                    "dispa_security_denied_total",
                                    &[("kind", String::from("auth_bearer"))]
                                )
                                .increment(1);
                                return Some(resp_401("Invalid token"));
                            }
                        } else {
                            metrics::counter!(
                                "dispa_security_denied_total",
                                &[("kind", String::from("auth_missing"))]
                            )
                            .increment(1);
                            return Some(resp_401("Unauthorized"));
                        }
                    }
                }
            }
        }

        None
    }

    async fn verify_jwt(&self, token: &str, cfg: &JwtConfig) -> bool {
        match cfg.algorithm.to_ascii_uppercase().as_str() {
            "HS256" => verify_hs256_jwt(token, cfg, &self.jwt_cache).await,
            "RS256" => {
                #[cfg(feature = "jwt-rs256")]
                {
                    verify_rs256_jwt(token, cfg, &self.jwt_cache, &self.jwks_cache).await
                }
                #[cfg(not(feature = "jwt-rs256"))]
                {
                    false
                }
            }
            _ => false,
        }
    }
}

fn headers_size(req: &Request<Body>) -> usize {
    let mut n = 0usize;
    for (k, v) in req.headers().iter() {
        n += k.as_str().len();
        if let Ok(s) = v.to_str() {
            n += s.len();
        }
    }
    n
}

pub type SharedSecurity = std::sync::Arc<tokio::sync::RwLock<Option<SecurityManager>>>;

#[cfg(test)]
mod tests {
    use super::super::utils::crypto::base64_encode;
    use super::*;
    use hyper::{Request, StatusCode};
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_ddos_header_limits() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let cfg = SecurityConfig {
                enabled: true,
                access_control: None,
                auth: None,
                rate_limit: None,
                ddos: Some(DdosConfig {
                    max_headers: Some(1),
                    max_header_bytes: None,
                    max_body_bytes: None,
                    require_content_length: None,
                }),
                jwt: None,
            };
            let mgr = SecurityManager::new(cfg);
            let mut req = Request::builder().uri("/").body(Body::empty()).unwrap(); // OK in tests - valid request
                                                                                    // two headers should be rejected when max_headers=1
            *req.headers_mut() = {
                let mut h = hyper::HeaderMap::new();
                h.insert("a", hyper::header::HeaderValue::from_static("1"));
                h.insert("b", hyper::header::HeaderValue::from_static("2"));
                h
            };
            let out = mgr.check_request(&req, None).await;
            assert!(out.is_some());
            assert_eq!(
                out.unwrap().status(), // OK in tests - response expected
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            );
        })
        .await
        .expect("test_ddos_header_limits timed out");
    }

    #[test]
    fn test_ip_match_cidr_ipv4_ipv6() {
        let ip4: IpAddr = "192.168.1.42".parse().unwrap(); // OK in tests - valid IP
        assert!(ip_match("192.168.1.0/24", &ip4));
        assert!(!ip_match("192.168.2.0/24", &ip4));
        assert!(ip_match("192.168.1.*", &ip4));

        let ip6: IpAddr = "2001:db8::1".parse().unwrap(); // OK in tests - valid IP
        assert!(ip_match("2001:db8::/32", &ip6));
        assert!(!ip_match("2001:dead::/32", &ip6));
    }

    #[tokio::test]
    async fn test_jwt_hs256_validation() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Build minimal HS256 JWT: header {alg:HS256,typ:JWT}, payload with exp far future
            let header = b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            let payload = format!(
                "{{\"iss\":\"me\",\"aud\":\"you\",\"exp\":{}}}",
                32503680000u64
            ); // year 3000
            fn b64url_enc(data: &[u8]) -> String {
                let enc = base64_encode(data);
                enc.replace('+', "-")
                    .replace('/', "_")
                    .trim_end_matches('=')
                    .to_string()
            }
            let signing_input =
                format!("{}.{}", b64url_enc(header), b64url_enc(payload.as_bytes()));
            let sig = hmac_sha256(b"secret", signing_input.as_bytes());
            let token = format!("{}.{}", signing_input, b64url_enc(&sig));

            let cfg = SecurityConfig {
                enabled: true,
                access_control: None,
                auth: None,
                rate_limit: None,
                ddos: None,
                jwt: Some(JwtConfig {
                    enabled: true,
                    algorithm: "HS256".into(),
                    secret: Some("secret".into()),
                    leeway_secs: Some(5),
                    issuer: Some("me".into()),
                    audience: Some("you".into()),
                    cache_enabled: Some(true),
                    rs256_keys: None,
                    jwks_url: None,
                    jwks_cache_secs: None,
                }),
            };
            let mgr = SecurityManager::new(cfg);
            let req = Request::builder()
                .uri("/")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(); // OK in tests - valid request
            let out = mgr.check_request(&req, None).await;
            assert!(out.is_none());
        })
        .await
        .expect("test_jwt_hs256_validation timed out");
    }

    #[tokio::test]
    async fn test_jwt_claims_issuer_audience_leeway() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Build HS256 token with iat in near future but within leeway
            let header = b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap() // OK in tests - time calculation expected to succeed
                .as_secs() as i64;
            let iat = now + 3; // 3s in the future
            let payload = format!(
                "{{\"iss\":\"me\",\"aud\":\"you\",\"exp\":{},\"iat\":{}}}",
                now + 60,
                iat
            );
            fn b64url_enc(data: &[u8]) -> String {
                base64_encode(data)
                    .replace('+', "-")
                    .replace('/', "_")
                    .trim_end_matches('=')
                    .to_string()
            }
            let signing_input =
                format!("{}.{}", b64url_enc(header), b64url_enc(payload.as_bytes()));
            let sig = hmac_sha256(b"secret", signing_input.as_bytes());
            let token = format!("{}.{}", signing_input, b64url_enc(&sig));

            let cfg = SecurityConfig {
                enabled: true,
                access_control: None,
                auth: None,
                rate_limit: None,
                ddos: None,
                jwt: Some(JwtConfig {
                    enabled: true,
                    algorithm: "HS256".into(),
                    secret: Some("secret".into()),
                    leeway_secs: Some(5),
                    issuer: Some("me".into()),
                    audience: Some("you".into()),
                    cache_enabled: Some(true),
                    rs256_keys: None,
                    jwks_url: None,
                    jwks_cache_secs: None,
                }),
            };
            let mgr = SecurityManager::new(cfg);
            let req = Request::builder()
                .uri("/")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(); // OK in tests - valid request
            assert!(mgr.check_request(&req, None).await.is_none());

            // Wrong audience
            let payload2 = format!("{{\"iss\":\"me\",\"aud\":\"other\",\"exp\":{}}}", now + 60);
            let signing_input2 =
                format!("{}.{}", b64url_enc(header), b64url_enc(payload2.as_bytes()));
            let sig2 = hmac_sha256(b"secret", signing_input2.as_bytes());
            let token2 = format!("{}.{}", signing_input2, b64url_enc(&sig2));
            let req2 = Request::builder()
                .uri("/")
                .header("authorization", format!("Bearer {}", token2))
                .body(Body::empty())
                .unwrap(); // OK in tests - valid request
            assert!(mgr.check_request(&req2, None).await.is_some());
        })
        .await
        .expect("test_jwt_claims_issuer_audience_leeway timed out");
    }
}
