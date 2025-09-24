use serde::{Deserialize, Serialize};

/// Main security configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub access_control: Option<AccessControlConfig>,
    pub auth: Option<AuthConfig>,
    pub rate_limit: Option<GlobalRateLimitConfig>,
    pub ddos: Option<DdosConfig>,
    pub jwt: Option<JwtConfig>,
}

/// Access control configuration for IP allowlists and denylists
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessControlConfig {
    pub allowed_ips: Option<Vec<String>>, // exact ip or simple wildcard like 192.168.1.*
    pub denied_ips: Option<Vec<String>>,
    #[serde(default)]
    pub trust_proxy_headers: bool,
}

/// Authentication mode enumeration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    ApiKey,
    Bearer,
}

/// Authentication configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub mode: AuthMode,
    /// Header name: default x-api-key for ApiKey, authorization for Bearer
    pub header_name: Option<String>,
    /// Static keys/tokens list
    pub keys: Vec<String>,
}

/// Global rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalRateLimitConfig {
    pub enabled: bool,
    pub rate_per_sec: f64,
    pub burst: f64,
}

/// DDoS protection configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DdosConfig {
    pub max_headers: Option<usize>,
    pub max_header_bytes: Option<usize>,
    pub max_body_bytes: Option<u64>,
    pub require_content_length: Option<bool>,
}

/// JWT configuration for token validation
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

/// RSA JWK key structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RsaJwk {
    pub kid: Option<String>,
    pub n: String,
    pub e: String,
}
