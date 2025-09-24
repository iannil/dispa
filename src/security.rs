#![allow(dead_code)]
pub mod auth;
pub mod enhanced_auth;

use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub access_control: Option<AccessControlConfig>,
    pub auth: Option<AuthConfig>,
    pub rate_limit: Option<GlobalRateLimitConfig>,
    pub ddos: Option<DdosConfig>,
    pub jwt: Option<JwtConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessControlConfig {
    pub allowed_ips: Option<Vec<String>>, // exact ip or simple wildcard like 192.168.1.*
    pub denied_ips: Option<Vec<String>>,
    #[serde(default)]
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    ApiKey,
    Bearer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub mode: AuthMode,
    /// Header name: default x-api-key for ApiKey, authorization for Bearer
    pub header_name: Option<String>,
    /// Static keys/tokens list
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalRateLimitConfig {
    pub enabled: bool,
    pub rate_per_sec: f64,
    pub burst: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DdosConfig {
    pub max_headers: Option<usize>,
    pub max_header_bytes: Option<usize>,
    pub max_body_bytes: Option<u64>,
    pub require_content_length: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub enabled: bool,
    /// Algorithm: only "HS256" supported currently
    pub algorithm: String,
    /// Shared secret (HS256)
    pub secret: Option<String>,
    /// Acceptable clock skew in seconds when validating exp/nbf (default 0)
    pub leeway_secs: Option<u64>,
    /// Optional issuer to match ("iss")
    pub issuer: Option<String>,
    /// Optional audience to match ("aud")
    pub audience: Option<String>,
    /// Enable simple token cache keyed by token string to expiration instant
    pub cache_enabled: Option<bool>,
    /// RS256 JWK public keys (n,e base64url) with optional kid
    pub rs256_keys: Option<Vec<RsaJwk>>,
    /// JWKS URL to fetch keys (requires feature `jwt-rs256-net`)
    pub jwks_url: Option<String>,
    /// JWKS cache seconds (default 600)
    pub jwks_cache_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RsaJwk {
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
}

#[derive(Clone)]
pub struct SecurityManager {
    cfg: SecurityConfig,
    rate_map: std::sync::Arc<tokio::sync::Mutex<HashMap<String, RateState>>>,
    jwt_cache: std::sync::Arc<tokio::sync::Mutex<HashMap<String, std::time::Instant>>>,
    #[cfg(feature = "jwt-rs256")]
    jwks_cache: std::sync::Arc<tokio::sync::Mutex<HashMap<String, JwkCacheEntry>>>,
}

#[derive(Clone, Copy)]
struct RateState {
    tokens: f64,
    last: Instant,
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
                    return Some(resp_431());
                }
            }
            if let Some(maxb) = dd.max_header_bytes {
                if headers_size(req) > maxb {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("headers_size"))]
                    )
                    .increment(1);
                    return Some(resp_431());
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
                        return Some(resp_413());
                    }
                } else if dd.require_content_length.unwrap_or(false) {
                    metrics::counter!(
                        "dispa_security_denied_total",
                        &[("kind", String::from("length_required"))]
                    )
                    .increment(1);
                    return Some(resp_411());
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
                    return Some(resp_429());
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
                        return Some(resp_403());
                    }
                }
                if let Some(allowed) = &ac.allowed_ips {
                    if !allowed.iter().any(|p| ip_match(p, &ip)) {
                        metrics::counter!(
                            "dispa_security_denied_total",
                            &[("kind", String::from("not_allowed_ip"))]
                        )
                        .increment(1);
                        return Some(resp_403());
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
                        if v.is_none() || !auth.keys.iter().any(|k| v.unwrap() == k) {
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
            "HS256" => {
                // Cache fast-path
                if cfg.cache_enabled.unwrap_or(true) {
                    if let Some(exp) = self.jwt_cache.lock().await.get(token).cloned() {
                        if exp > std::time::Instant::now() {
                            return true;
                        }
                    }
                }
                // Split token
                let (h_b64, p_b64, _s_b64, header, payload, sig) = match decode_jwt_parts(token) {
                    Some(t) => t,
                    None => return false,
                };
                // Verify alg
                if header.get("alg").and_then(|v| v.as_str()).unwrap_or("") != "HS256" {
                    return false;
                }
                // Compute HMAC
                let secret = match cfg.secret.as_ref() {
                    Some(s) => s.as_bytes(),
                    None => return false,
                };
                let signing_input = format!("{}.{}", h_b64, p_b64);
                let mac = hmac_sha256(secret, signing_input.as_bytes());
                if mac != sig {
                    return false;
                }
                if !validate_claims(&payload, cfg).await {
                    return false;
                }
                // Cache expiration
                cache_token_exp(&self.jwt_cache, token, &payload, cfg).await;
                true
            }
            "RS256" => {
                #[cfg(feature = "jwt-rs256")]
                {
                    if cfg.cache_enabled.unwrap_or(true) {
                        if let Some(exp) = self.jwt_cache.lock().await.get(token).cloned() {
                            if exp > std::time::Instant::now() {
                                return true;
                            }
                        }
                    }
                    let (h_b64, p_b64, _s_b64, header, payload, sig) = match decode_jwt_parts(token)
                    {
                        Some(t) => t,
                        None => return false,
                    };
                    if header.get("alg").and_then(|v| v.as_str()).unwrap_or("") != "RS256" {
                        return false;
                    }
                    let kid = header
                        .get("kid")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    // Resolve RSA key
                    let key = match self.resolve_rs256_key(cfg, &kid).await {
                        Some(k) => k,
                        None => return false,
                    };
                    let signing_input = format!("{}.{}", h_b64, p_b64);
                    if !rsa_verify_sha256(&key.n, &key.e, signing_input.as_bytes(), &sig) {
                        return false;
                    }
                    if !validate_claims(&payload, cfg).await {
                        return false;
                    }
                    cache_token_exp(&self.jwt_cache, token, &payload, cfg).await;
                    true
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

fn decode_jwt_parts(
    token: &str,
) -> Option<(
    String,
    String,
    String,
    serde_json::Value,
    serde_json::Value,
    Vec<u8>,
)> {
    let mut parts = token.split('.');
    let (h_b64, p_b64, s_b64) = (
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.to_string(),
    );
    let header = b64url_decode(&h_b64)?;
    let payload = b64url_decode(&p_b64)?;
    let sig = b64url_decode(&s_b64)?;
    let header_json: serde_json::Value = serde_json::from_slice(&header).ok()?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    Some((h_b64, p_b64, s_b64, header_json, payload_json, sig))
}

async fn validate_claims(payload_json: &serde_json::Value, cfg: &JwtConfig) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let leeway = cfg.leeway_secs.unwrap_or(0) as i64;
    if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
        if now > exp + leeway {
            return false;
        }
    }
    if let Some(nbf) = payload_json.get("nbf").and_then(|v| v.as_i64()) {
        if now + leeway < nbf {
            return false;
        }
    }
    if let Some(iat) = payload_json.get("iat").and_then(|v| v.as_i64()) {
        if iat - leeway > now {
            return false;
        }
    }
    if let Some(iss) = cfg.issuer.as_ref() {
        if payload_json.get("iss").and_then(|v| v.as_str()) != Some(iss.as_str()) {
            return false;
        }
    }
    if let Some(aud) = cfg.audience.as_ref() {
        match payload_json.get("aud") {
            Some(serde_json::Value::String(s)) if s == aud => {}
            _ => return false,
        }
    }
    true
}

async fn cache_token_exp(
    cache: &std::sync::Arc<tokio::sync::Mutex<HashMap<String, std::time::Instant>>>,
    token: &str,
    payload_json: &serde_json::Value,
    cfg: &JwtConfig,
) {
    if cfg.cache_enabled.unwrap_or(true) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
            let ttl = if exp > now { (exp - now) as u64 } else { 0 };
            cache.lock().await.insert(
                token.to_string(),
                std::time::Instant::now() + std::time::Duration::from_secs(ttl),
            );
        }
    }
}

#[cfg(feature = "jwt-rs256")]
fn rsa_verify_sha256(n_b64url: &str, e_b64url: &str, msg: &[u8], sig: &[u8]) -> bool {
    let n = match b64url_decode(n_b64url) {
        Some(v) => v,
        None => return false,
    };
    let e = match b64url_decode(e_b64url) {
        Some(v) => v,
        None => return false,
    };
    let pk = ring::signature::RsaPublicKeyComponents { n: &n, e: &e };
    pk.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
        .is_ok()
}

#[cfg(feature = "jwt-rs256")]
struct JwkCacheEntry {
    key: RsaJwk,
    exp: std::time::Instant,
}

// Removed unused type alias to satisfy clippy when building all features

#[cfg(feature = "jwt-rs256")]
impl SecurityManager {
    async fn fetch_jwks(&self, url: &str, _ttl_secs: u64) -> HashMap<String, RsaJwk> {
        #[cfg(feature = "jwt-rs256-net")]
        {
            let mut map = HashMap::new();
            if let Ok(resp) = reqwest::get(url).await {
                if let Ok(text) = resp.text().await {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(keys) = json.get("keys").and_then(|k| k.as_array()) {
                            for k in keys {
                                if k.get("kty").and_then(|x| x.as_str()) == Some("RSA")
                                    && k.get("alg").and_then(|x| x.as_str()) == Some("RS256")
                                {
                                    if let (Some(n), Some(e)) = (
                                        k.get("n").and_then(|x| x.as_str()),
                                        k.get("e").and_then(|x| x.as_str()),
                                    ) {
                                        let kid = k
                                            .get("kid")
                                            .and_then(|x| x.as_str())
                                            .map(|s| s.to_string());
                                        let jwk = RsaJwk {
                                            kid: kid.clone(),
                                            n: n.to_string(),
                                            e: e.to_string(),
                                        };
                                        if let Some(kid) = kid {
                                            map.insert(kid, jwk);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            map
        }
        #[cfg(not(feature = "jwt-rs256-net"))]
        {
            HashMap::new()
        }
    }
}

#[cfg(feature = "jwt-rs256")]
impl SecurityManager {
    async fn resolve_rs256_key(&self, cfg: &JwtConfig, kid: &Option<String>) -> Option<RsaJwk> {
        // Prefer static keys if provided
        if let Some(keys) = &cfg.rs256_keys {
            if let Some(k) = kid {
                if let Some(j) = keys.iter().find(|j| j.kid.as_ref() == Some(k)) {
                    return Some(j.clone());
                }
            } else if let Some(j) = keys.first() {
                return Some(j.clone());
            }
        }
        // JWKS fetch/cache (feature-gated)
        #[cfg(feature = "jwt-rs256-net")]
        {
            if let Some(url) = &cfg.jwks_url {
                let ttl = cfg.jwks_cache_secs.unwrap_or(600);
                // 1) Check cache
                if let Some(k) = kid {
                    if let Some(entry) = self.jwks_cache.lock().await.get(k) {
                        if entry.exp > std::time::Instant::now() {
                            return Some(entry.key.clone());
                        }
                    }
                }
                // 2) Fetch JWKS and refresh cache
                let map = self.fetch_jwks(url, ttl).await;
                let mut cache = self.jwks_cache.lock().await;
                let exp = std::time::Instant::now() + std::time::Duration::from_secs(ttl);
                for (kid_s, jwk) in map.into_iter() {
                    cache.insert(kid_s.clone(), JwkCacheEntry { key: jwk, exp });
                }
                if let Some(k) = kid {
                    return cache.get(k).map(|e| e.key.clone());
                }
                // If kid is None, return None (cannot select)
            }
        }
        None
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

// Minimal base64 encoder (used by tests/JWT helpers). Keep before test module to satisfy clippy.
#[cfg(test)]
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len().div_ceil(3)) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn ip_match(pattern: &str, ip: &IpAddr) -> bool {
    // CIDR support: a.b.c.d/len or xxxx::/len
    if let Some((addr, len)) = parse_cidr(pattern) {
        return cidr_match(&addr, len, ip);
    }
    match ip {
        IpAddr::V4(v4) => {
            let s = v4.to_string();
            if let Some(pfx) = pattern.strip_suffix(".*") {
                s.starts_with(pfx)
            } else {
                s == pattern
            }
        }
        IpAddr::V6(v6) => v6.to_string() == pattern,
    }
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, len_str) = s.split_once('/')?;
    let addr: IpAddr = addr_str.parse().ok()?;
    let len: u8 = len_str.parse().ok()?;
    Some((addr, len))
}

fn cidr_match(net: &IpAddr, prefix: u8, ip: &IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let n = u32::from(*n);
            let i = u32::from(*i);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix as u32)
            };
            (n & mask) == (i & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let n = u128::from(*n);
            let i = u128::from(*i);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix as u32)
            };
            (n & mask) == (i & mask)
        }
        _ => false,
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };
    if k.len() < BLOCK {
        k.resize(BLOCK, 0);
    }
    let mut ipad = vec![0x36u8; BLOCK];
    let mut opad = vec![0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut ih = Sha256::new();
    ih.update(&ipad);
    ih.update(msg);
    let inner = ih.finalize();
    let mut oh = Sha256::new();
    oh.update(&opad);
    oh.update(inner);
    oh.finalize().to_vec()
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    // Convert URL-safe to standard base64
    let mut b = s.replace('-', "+").replace('_', "/");
    while !b.len().is_multiple_of(4) {
        b.push('=');
    }
    base64_decode(&b)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    // Minimal base64 decoder for standard alphabet with padding
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(64), // padding
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        i += 4;
        if a == 64 || b == 64 {
            return None;
        }
        let n = ((a as u32) << 18)
            | ((b as u32) << 12)
            | (if c == 64 { 0 } else { (c as u32) << 6 })
            | (if d == 64 { 0 } else { d as u32 });
        out.push(((n >> 16) & 0xFF) as u8);
        if c != 64 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if d != 64 {
            out.push((n & 0xFF) as u8);
        }
    }
    Some(out)
}

fn resp_429() -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "1")
        .body(Body::from("Rate limited"))
        .unwrap()
}
fn resp_431() -> Response<Body> {
    Response::builder()
        .status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
        .body(Body::from("Headers too large"))
        .unwrap()
}
fn resp_413() -> Response<Body> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(Body::from("Payload too large"))
        .unwrap()
}
fn resp_411() -> Response<Body> {
    Response::builder()
        .status(StatusCode::LENGTH_REQUIRED)
        .body(Body::from("Content-Length required"))
        .unwrap()
}
fn resp_403() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("Forbidden"))
        .unwrap()
}
fn resp_401(msg: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

pub type SharedSecurity = std::sync::Arc<RwLock<Option<SecurityManager>>>;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
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
            let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
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
                out.unwrap().status(),
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            );
        })
        .await
        .expect("test_ddos_header_limits timed out");
    }

    #[test]
    fn test_ip_match_cidr_ipv4_ipv6() {
        let ip4: IpAddr = "192.168.1.42".parse().unwrap();
        assert!(ip_match("192.168.1.0/24", &ip4));
        assert!(!ip_match("192.168.2.0/24", &ip4));
        assert!(ip_match("192.168.1.*", &ip4));

        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
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
                .unwrap();
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
                .unwrap()
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
                .unwrap();
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
                .unwrap();
            assert!(mgr.check_request(&req2, None).await.is_some());
        })
        .await
        .expect("test_jwt_claims_issuer_audience_leeway timed out");
    }
}

// (moved base64 helper above)
