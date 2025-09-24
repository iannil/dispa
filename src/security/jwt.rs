use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::config::JwtConfig;
#[cfg(feature = "jwt-rs256")]
use super::config::RsaJwk;
use super::utils::crypto::{b64url_decode, hmac_sha256};

#[cfg(feature = "jwt-rs256")]
pub struct JwkCacheEntry {
    pub key: RsaJwk,
    pub exp: std::time::Instant,
}

pub async fn verify_hs256_jwt(
    token: &str,
    cfg: &JwtConfig,
    jwt_cache: &Arc<Mutex<HashMap<String, std::time::Instant>>>,
) -> bool {
    // Cache fast-path
    if cfg.cache_enabled.unwrap_or(true) {
        if let Some(exp) = jwt_cache.lock().await.get(token).cloned() {
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
    cache_token_exp(jwt_cache, token, &payload, cfg).await;
    true
}

#[cfg(feature = "jwt-rs256")]
pub async fn verify_rs256_jwt(
    token: &str,
    cfg: &JwtConfig,
    jwt_cache: &Arc<Mutex<HashMap<String, std::time::Instant>>>,
    jwks_cache: &Arc<Mutex<HashMap<String, JwkCacheEntry>>>,
) -> bool {
    if cfg.cache_enabled.unwrap_or(true) {
        if let Some(exp) = jwt_cache.lock().await.get(token).cloned() {
            if exp > std::time::Instant::now() {
                return true;
            }
        }
    }

    let (h_b64, p_b64, _s_b64, header, payload, sig) = match decode_jwt_parts(token) {
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
    let key = match resolve_rs256_key(cfg, &kid, jwks_cache).await {
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

    cache_token_exp(jwt_cache, token, &payload, cfg).await;
    true
}

pub fn decode_jwt_parts(
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

pub async fn validate_claims(payload_json: &serde_json::Value, cfg: &JwtConfig) -> bool {
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

pub async fn cache_token_exp(
    cache: &Arc<Mutex<HashMap<String, std::time::Instant>>>,
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
async fn resolve_rs256_key(
    cfg: &JwtConfig,
    kid: &Option<String>,
    jwks_cache: &Arc<Mutex<HashMap<String, JwkCacheEntry>>>,
) -> Option<RsaJwk> {
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
                if let Some(entry) = jwks_cache.lock().await.get(k) {
                    if entry.exp > std::time::Instant::now() {
                        return Some(entry.key.clone());
                    }
                }
            }

            // 2) Fetch JWKS and refresh cache
            let map = fetch_jwks(url, ttl).await;
            let mut cache = jwks_cache.lock().await;
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

#[cfg(all(feature = "jwt-rs256", feature = "jwt-rs256-net"))]
async fn fetch_jwks(url: &str, _ttl_secs: u64) -> HashMap<String, RsaJwk> {
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
                                let kid =
                                    k.get("kid").and_then(|x| x.as_str()).map(|s| s.to_string());
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

#[cfg(all(feature = "jwt-rs256", not(feature = "jwt-rs256-net")))]
async fn fetch_jwks(_url: &str, _ttl_secs: u64) -> HashMap<String, RsaJwk> {
    HashMap::new()
}
