use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Cache configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Enable/disable caching
    pub enabled: bool,
    /// Maximum cache size in bytes
    pub max_size: u64,
    /// Default TTL for cached responses in seconds
    pub default_ttl: u64,
    /// Cache policies for different content types
    pub policies: Vec<CachePolicy>,
    /// Enable ETag support
    pub etag_enabled: bool,
    /// Cache key prefix
    pub key_prefix: Option<String>,
    /// Enable cache metrics
    pub metrics_enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size: 100 * 1024 * 1024, // 100MB
            default_ttl: 3600,           // 1 hour
            policies: vec![
                // Default policies for common content types
                CachePolicy {
                    name: "static-assets".to_string(),
                    pattern: CachePolicyPattern::ContentType("image/*".to_string()),
                    ttl: Some(86400), // 24 hours
                    cacheable_status_codes: vec![200, 301, 302, 404],
                    vary_headers: None,
                    no_cache_headers: vec!["authorization".to_string(), "cookie".to_string()],
                },
                CachePolicy {
                    name: "api-responses".to_string(),
                    pattern: CachePolicyPattern::PathPrefix("/api/".to_string()),
                    ttl: Some(300), // 5 minutes
                    cacheable_status_codes: vec![200],
                    vary_headers: Some(vec!["accept".to_string(), "accept-encoding".to_string()]),
                    no_cache_headers: vec!["authorization".to_string()],
                },
            ],
            etag_enabled: true,
            key_prefix: None,
            metrics_enabled: true,
        }
    }
}

impl CacheConfig {
    /// Validate cache configuration
    pub fn validate(&self) -> Result<()> {
        if self.max_size == 0 {
            return Err(anyhow::anyhow!("Cache max_size must be greater than 0"));
        }

        if self.default_ttl == 0 {
            return Err(anyhow::anyhow!("Cache default_ttl must be greater than 0"));
        }

        // Validate policies
        for policy in &self.policies {
            policy.validate()?;
        }

        Ok(())
    }
}

/// Cache policy definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CachePolicy {
    /// Policy name for identification
    pub name: String,
    /// Pattern to match requests/responses
    pub pattern: CachePolicyPattern,
    /// TTL override for this policy (in seconds)
    pub ttl: Option<u64>,
    /// HTTP status codes that are cacheable
    pub cacheable_status_codes: Vec<u16>,
    /// Headers to include in cache key (Vary support)
    pub vary_headers: Option<Vec<String>>,
    /// Headers that prevent caching when present
    pub no_cache_headers: Vec<String>,
}

impl CachePolicy {
    /// Validate cache policy
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Cache policy name cannot be empty"));
        }

        if self.cacheable_status_codes.is_empty() {
            return Err(anyhow::anyhow!(
                "Cache policy must have at least one cacheable status code"
            ));
        }

        // Validate status codes are in valid range
        for &status in &self.cacheable_status_codes {
            if !(100..=599).contains(&status) {
                return Err(anyhow::anyhow!("Invalid HTTP status code: {}", status));
            }
        }

        Ok(())
    }

    /// Check if this policy matches the request/response
    #[allow(dead_code)]
    pub fn matches(&self, request_path: &str, content_type: Option<&str>) -> bool {
        match &self.pattern {
            CachePolicyPattern::PathPrefix(prefix) => request_path.starts_with(prefix),
            CachePolicyPattern::PathSuffix(suffix) => request_path.ends_with(suffix),
            CachePolicyPattern::PathRegex(regex) => {
                // For now, simple contains check - could be enhanced with actual regex
                request_path.contains(regex)
            }
            CachePolicyPattern::ContentType(pattern) => {
                if let Some(ct) = content_type {
                    if pattern.ends_with("*") {
                        let prefix = &pattern[..pattern.len() - 1];
                        ct.starts_with(prefix)
                    } else {
                        ct == pattern
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Check if status code is cacheable according to this policy
    #[allow(dead_code)]
    pub fn is_status_cacheable(&self, status: u16) -> bool {
        self.cacheable_status_codes.contains(&status)
    }

    /// Check if request has no-cache headers
    #[allow(dead_code)]
    pub fn has_no_cache_headers(&self, headers: &hyper::HeaderMap) -> bool {
        for header_name in &self.no_cache_headers {
            if headers.contains_key(header_name) {
                return true;
            }
        }
        false
    }

    /// Get cache key suffix based on vary headers
    #[allow(dead_code)]
    pub fn get_vary_suffix(&self, headers: &hyper::HeaderMap) -> String {
        if let Some(ref vary_headers) = self.vary_headers {
            let mut vary_values = Vec::new();
            for header_name in vary_headers {
                if let Some(value) = headers.get(header_name) {
                    if let Ok(value_str) = value.to_str() {
                        vary_values.push(format!("{}:{}", header_name, value_str));
                    }
                }
            }
            if !vary_values.is_empty() {
                return format!("|{}", vary_values.join("|"));
            }
        }
        String::new()
    }
}

/// Cache policy pattern types
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum CachePolicyPattern {
    /// Match requests by path prefix
    PathPrefix(String),
    /// Match requests by path suffix
    PathSuffix(String),
    /// Match requests by path regex pattern
    PathRegex(String),
    /// Match responses by content type
    ContentType(String),
}
