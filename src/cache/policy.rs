use crate::cache::{CacheConfig, CachePolicy};
use hyper::{HeaderMap, StatusCode, Uri};
use std::time::Duration;
use tracing::debug;

/// Cache policy engine for determining caching behavior
#[derive(Clone)]
pub struct PolicyEngine {
    /// Cache configuration
    config: CacheConfig,
    /// Compiled policies for faster matching
    policies: Vec<CachePolicy>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(config: CacheConfig) -> Self {
        Self {
            policies: config.policies.clone(),
            config,
        }
    }

    /// Determine if a request/response should be cached
    pub fn should_cache(
        &self,
        uri: &Uri,
        request_headers: &HeaderMap,
        status: StatusCode,
        response_headers: &HeaderMap,
    ) -> CacheDecision {
        if !self.config.enabled {
            return CacheDecision::DoNotCache("Caching disabled".to_string());
        }

        // Check cache-control headers first
        if let Some(decision) = self.check_cache_control_headers(response_headers) {
            return decision;
        }

        // Check for authentication headers in request
        if self.has_auth_headers(request_headers) {
            return CacheDecision::DoNotCache("Request has authentication headers".to_string());
        }

        // Find matching policy
        let matching_policy = self.find_matching_policy(uri, response_headers);

        match matching_policy {
            Some(policy) => {
                debug!("Found matching cache policy: {}", policy.name);

                // Check if status code is cacheable
                if !policy.is_status_cacheable(status.as_u16()) {
                    return CacheDecision::DoNotCache(format!(
                        "Status code {} not cacheable for policy '{}'",
                        status.as_u16(),
                        policy.name
                    ));
                }

                // Check for no-cache headers
                if policy.has_no_cache_headers(request_headers) {
                    return CacheDecision::DoNotCache(format!(
                        "Request has no-cache headers for policy '{}'",
                        policy.name
                    ));
                }

                // Determine TTL
                let ttl = self.determine_ttl(policy, response_headers);

                CacheDecision::Cache {
                    ttl,
                    policy_name: policy.name.clone(),
                    vary_suffix: policy.get_vary_suffix(request_headers),
                }
            }
            None => {
                // No specific policy matches, check if it's generally cacheable
                if self.is_generally_cacheable(status, response_headers) {
                    let ttl = Duration::from_secs(self.config.default_ttl);
                    CacheDecision::Cache {
                        ttl,
                        policy_name: "default".to_string(),
                        vary_suffix: String::new(),
                    }
                } else {
                    CacheDecision::DoNotCache(
                        "No matching policy and not generally cacheable".to_string(),
                    )
                }
            }
        }
    }

    /// Generate cache key for a request
    pub fn generate_cache_key(
        &self,
        uri: &Uri,
        _request_headers: &HeaderMap,
        vary_suffix: &str,
    ) -> String {
        let base_key = match &self.config.key_prefix {
            Some(prefix) => format!(
                "{}:{}",
                prefix,
                uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
            ),
            None => uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
                .to_string(),
        };

        if vary_suffix.is_empty() {
            base_key
        } else {
            format!("{}{}", base_key, vary_suffix)
        }
    }

    /// Find the first matching policy for the request/response
    fn find_matching_policy(
        &self,
        uri: &Uri,
        response_headers: &HeaderMap,
    ) -> Option<&CachePolicy> {
        let path = uri.path();
        let content_type = response_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok());

        // Find first matching policy (policies are evaluated in order)
        self.policies
            .iter()
            .find(|&policy| policy.matches(path, content_type))
    }

    /// Check cache-control headers for explicit caching directives
    fn check_cache_control_headers(&self, headers: &HeaderMap) -> Option<CacheDecision> {
        if let Some(cache_control) = headers.get("cache-control") {
            if let Ok(cache_control_str) = cache_control.to_str() {
                let lowercase_directives: Vec<String> = cache_control_str
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect();

                let directives: Vec<&str> =
                    lowercase_directives.iter().map(|s| s.as_str()).collect();

                // Check for no-cache, no-store, private
                if directives.contains(&"no-cache")
                    || directives.contains(&"no-store")
                    || directives.contains(&"private")
                {
                    return Some(CacheDecision::DoNotCache(
                        "Cache-Control directive forbids caching".to_string(),
                    ));
                }

                // Check for max-age
                for directive in &directives {
                    if let Some(max_age_str) = directive.strip_prefix("max-age=") {
                        if let Ok(max_age) = max_age_str.parse::<u64>() {
                            if max_age > 0 {
                                return Some(CacheDecision::Cache {
                                    ttl: Duration::from_secs(max_age),
                                    policy_name: "cache-control".to_string(),
                                    vary_suffix: String::new(),
                                });
                            } else {
                                return Some(CacheDecision::DoNotCache(
                                    "max-age=0 in Cache-Control".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if request has authentication headers
    fn has_auth_headers(&self, headers: &HeaderMap) -> bool {
        headers.contains_key("authorization")
            || headers.contains_key("proxy-authorization")
            || headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_lowercase().contains("no-cache"))
                .unwrap_or(false)
    }

    /// Check if response is generally cacheable based on status and headers
    fn is_generally_cacheable(&self, status: StatusCode, headers: &HeaderMap) -> bool {
        // Only cache successful responses and some redirects by default
        let cacheable_statuses = [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501];

        if !cacheable_statuses.contains(&status.as_u16()) {
            return false;
        }

        // Check for Expires header
        if let Some(expires) = headers.get("expires") {
            if let Ok(expires_str) = expires.to_str() {
                // If Expires is in the past or invalid, don't cache
                if expires_str == "0" || expires_str.to_lowercase() == "no-cache" {
                    return false;
                }
            }
        }

        // Check for Set-Cookie (typically means response is personalized)
        if headers.contains_key("set-cookie") {
            return false;
        }

        true
    }

    /// Determine TTL for caching based on policy and headers
    fn determine_ttl(&self, policy: &CachePolicy, headers: &HeaderMap) -> Duration {
        // Check for Cache-Control max-age first
        if let Some(cache_control) = headers.get("cache-control") {
            if let Ok(cache_control_str) = cache_control.to_str() {
                for directive in cache_control_str.split(',') {
                    let directive = directive.trim().to_lowercase();
                    if let Some(max_age_str) = directive.strip_prefix("max-age=") {
                        if let Ok(max_age) = max_age_str.parse::<u64>() {
                            return Duration::from_secs(max_age);
                        }
                    }
                }
            }
        }

        // Use policy TTL if specified
        if let Some(policy_ttl) = policy.ttl {
            return Duration::from_secs(policy_ttl);
        }

        // Fall back to default TTL
        Duration::from_secs(self.config.default_ttl)
    }

    /// Update configuration (for hot-reload support)
    pub fn update_config(&mut self, new_config: CacheConfig) {
        self.config = new_config;
        self.policies = self.config.policies.clone();
        debug!("Cache policy engine configuration updated");
    }

    /// Get current configuration
    pub fn get_config(&self) -> &CacheConfig {
        &self.config
    }

    /// Get policy by name
    pub fn get_policy(&self, name: &str) -> Option<&CachePolicy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Decision about whether to cache a response
#[derive(Debug, Clone)]
pub enum CacheDecision {
    /// Cache the response with specified TTL
    Cache {
        ttl: Duration,
        policy_name: String,
        vary_suffix: String,
    },
    /// Do not cache the response
    DoNotCache(String),
}

impl CacheDecision {
    /// Check if this decision is to cache
    pub fn should_cache(&self) -> bool {
        matches!(self, CacheDecision::Cache { .. })
    }

    /// Get the reason for not caching (if applicable)
    pub fn no_cache_reason(&self) -> Option<&str> {
        match self {
            CacheDecision::DoNotCache(reason) => Some(reason),
            _ => None,
        }
    }

    /// Get TTL if caching
    pub fn ttl(&self) -> Option<Duration> {
        match self {
            CacheDecision::Cache { ttl, .. } => Some(*ttl),
            _ => None,
        }
    }

    /// Get policy name if caching
    pub fn policy_name(&self) -> Option<&str> {
        match self {
            CacheDecision::Cache { policy_name, .. } => Some(policy_name),
            _ => None,
        }
    }

    /// Get vary suffix if caching
    pub fn vary_suffix(&self) -> Option<&str> {
        match self {
            CacheDecision::Cache { vary_suffix, .. } => Some(vary_suffix),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::CachePolicyPattern;
    use crate::config::{CacheConfig, CachePolicy};
    use hyper::{HeaderMap, StatusCode, Uri};

    fn create_test_config() -> CacheConfig {
        CacheConfig {
            enabled: true,
            max_size: 1024 * 1024,
            default_ttl: 3600,
            policies: vec![
                CachePolicy {
                    name: "static-assets".to_string(),
                    pattern: CachePolicyPattern::PathPrefix("/static/".to_string()),
                    ttl: Some(86400),
                    cacheable_status_codes: vec![200, 404],
                    vary_headers: None,
                    no_cache_headers: vec!["authorization".to_string()],
                },
                CachePolicy {
                    name: "api-responses".to_string(),
                    pattern: CachePolicyPattern::ContentType("application/json".to_string()),
                    ttl: Some(300),
                    cacheable_status_codes: vec![200],
                    vary_headers: Some(vec!["accept".to_string()]),
                    no_cache_headers: vec!["authorization".to_string()],
                },
            ],
            etag_enabled: true,
            key_prefix: Some("dispa".to_string()),
            metrics_enabled: true,
        }
    }

    #[test]
    fn test_policy_engine_creation() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config.clone());

        assert!(engine.is_enabled());
        assert_eq!(engine.get_config().policies.len(), 2);
    }

    #[test]
    fn test_should_cache_with_matching_policy() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/static/css/style.css".parse().unwrap(); // OK in tests - valid URI
        let request_headers = HeaderMap::new();
        let status = StatusCode::OK;
        let response_headers = HeaderMap::new();

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(decision.should_cache());
        assert_eq!(decision.policy_name(), Some("static-assets"));
        assert_eq!(decision.ttl(), Some(Duration::from_secs(86400)));
    }

    #[test]
    fn test_should_not_cache_with_auth_headers() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/static/css/style.css".parse().unwrap(); // OK in tests - valid URI
        let mut request_headers = HeaderMap::new();
        request_headers.insert("authorization", "Bearer token".parse().unwrap()); // OK in tests - valid header
        let status = StatusCode::OK;
        let response_headers = HeaderMap::new();

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(!decision.should_cache());
        assert!(decision
            .no_cache_reason()
            .unwrap() // OK in tests - DoNotCache expected
            .contains("authentication"));
    }

    #[test]
    fn test_should_not_cache_with_cache_control_no_cache() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/static/css/style.css".parse().unwrap(); // OK in tests - valid URI
        let request_headers = HeaderMap::new();
        let status = StatusCode::OK;
        let mut response_headers = HeaderMap::new();
        response_headers.insert("cache-control", "no-cache".parse().unwrap()); // OK in tests - valid header

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(!decision.should_cache());
        assert!(decision
            .no_cache_reason()
            .unwrap() // OK in tests - DoNotCache expected
            .contains("Cache-Control"));
    }

    #[test]
    fn test_should_cache_with_cache_control_max_age() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/some/path".parse().unwrap(); // OK in tests - valid URI
        let request_headers = HeaderMap::new();
        let status = StatusCode::OK;
        let mut response_headers = HeaderMap::new();
        response_headers.insert("cache-control", "public, max-age=7200".parse().unwrap()); // OK in tests - valid header

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(decision.should_cache());
        assert_eq!(decision.policy_name(), Some("cache-control"));
        assert_eq!(decision.ttl(), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn test_should_not_cache_uncacheable_status() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/static/css/style.css".parse().unwrap(); // OK in tests - valid URI
        let request_headers = HeaderMap::new();
        let status = StatusCode::INTERNAL_SERVER_ERROR;
        let response_headers = HeaderMap::new();

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(!decision.should_cache());
        assert!(decision
            .no_cache_reason()
            .unwrap() // OK in tests - DoNotCache expected
            .contains("not cacheable"));
    }

    #[test]
    fn test_content_type_matching() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/api/users".parse().unwrap(); // OK in tests - valid URI
        let mut request_headers = HeaderMap::new();
        request_headers.insert("accept", "application/json".parse().unwrap()); // OK in tests - valid header
        let status = StatusCode::OK;
        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", "application/json".parse().unwrap()); // OK in tests - valid header

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(decision.should_cache());
        assert_eq!(decision.policy_name(), Some("api-responses"));
        assert_eq!(decision.ttl(), Some(Duration::from_secs(300)));
        assert!(decision
            .vary_suffix()
            .unwrap() // OK in tests - Cache decision expected
            .contains("accept:application/json"));
    }

    #[test]
    fn test_generate_cache_key() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/api/users?page=1".parse().unwrap(); // OK in tests - valid URI
        let headers = HeaderMap::new();

        let key = engine.generate_cache_key(&uri, &headers, "");
        assert_eq!(key, "dispa:/api/users?page=1");

        let key_with_vary = engine.generate_cache_key(&uri, &headers, ":accept:application/json");
        assert_eq!(
            key_with_vary,
            "dispa:/api/users?page=1:accept:application/json"
        );
    }

    #[test]
    fn test_generally_cacheable() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let mut headers = HeaderMap::new();

        // Cacheable status codes
        assert!(engine.is_generally_cacheable(StatusCode::OK, &headers));
        assert!(engine.is_generally_cacheable(StatusCode::NOT_FOUND, &headers));
        assert!(engine.is_generally_cacheable(StatusCode::MOVED_PERMANENTLY, &headers));

        // Non-cacheable status codes
        assert!(!engine.is_generally_cacheable(StatusCode::INTERNAL_SERVER_ERROR, &headers));
        assert!(!engine.is_generally_cacheable(StatusCode::BAD_REQUEST, &headers));

        // Set-Cookie makes it non-cacheable
        headers.insert("set-cookie", "session=abc123".parse().unwrap()); // OK in tests - valid header
        assert!(!engine.is_generally_cacheable(StatusCode::OK, &headers));

        // Expires=0 makes it non-cacheable
        headers.clear();
        headers.insert("expires", "0".parse().unwrap()); // OK in tests - valid header
        assert!(!engine.is_generally_cacheable(StatusCode::OK, &headers));
    }

    #[test]
    fn test_disabled_caching() {
        let mut config = create_test_config();
        config.enabled = false;
        let engine = PolicyEngine::new(config);

        let uri: Uri = "/static/css/style.css".parse().unwrap(); // OK in tests - valid URI
        let request_headers = HeaderMap::new();
        let status = StatusCode::OK;
        let response_headers = HeaderMap::new();

        let decision = engine.should_cache(&uri, &request_headers, status, &response_headers);

        assert!(!decision.should_cache());
        assert!(decision.no_cache_reason().unwrap().contains("disabled")); // OK in tests - DoNotCache expected
    }

    #[test]
    fn test_get_policy_by_name() {
        let config = create_test_config();
        let engine = PolicyEngine::new(config);

        let policy = engine.get_policy("static-assets");
        assert!(policy.is_some());
        assert_eq!(policy.unwrap().name, "static-assets"); // OK in tests - policy expected to exist

        let missing_policy = engine.get_policy("nonexistent");
        assert!(missing_policy.is_none());
    }

    #[test]
    fn test_update_config() {
        let config = create_test_config();
        let mut engine = PolicyEngine::new(config);

        assert_eq!(engine.get_config().policies.len(), 2);

        let mut new_config = create_test_config();
        new_config.policies.push(CachePolicy {
            name: "new-policy".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/new/".to_string()),
            ttl: Some(1800),
            cacheable_status_codes: vec![200],
            vary_headers: None,
            no_cache_headers: vec![],
        });

        engine.update_config(new_config);
        assert_eq!(engine.get_config().policies.len(), 3);
        assert!(engine.get_policy("new-policy").is_some());
    }
}
