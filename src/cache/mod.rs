#![allow(dead_code)]
use hyper::{Body, HeaderMap, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

pub mod advanced_strategies;
pub mod etag;
pub mod policy;
pub mod storage; // 高级缓存策略和CDN集成

pub use etag::ETagManager;
pub use policy::PolicyEngine;
pub use storage::{CacheMetrics, InMemoryCache};

// Re-export config types for convenience
pub use crate::config::{CacheConfig, CachePolicy};

/// Cached response entry
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Response status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body
    pub body: Vec<u8>,
    /// Cache creation timestamp
    pub created_at: SystemTime,
    /// Time to live in seconds
    pub ttl: Duration,
    /// ETag value if present
    pub etag: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Size in bytes
    pub size: usize,
}

/// Serializable version of CacheEntry for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableCacheEntry {
    /// Response status code as u16
    pub status_code: u16,
    /// Response headers as key-value pairs
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
    /// Cache creation timestamp
    pub created_at: SystemTime,
    /// Time to live in seconds
    pub ttl: Duration,
    /// ETag value if present
    pub etag: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Size in bytes
    pub size: usize,
}

impl From<CacheEntry> for SerializableCacheEntry {
    fn from(entry: CacheEntry) -> Self {
        let headers = entry
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        Self {
            status_code: entry.status.as_u16(),
            headers,
            body: entry.body,
            created_at: entry.created_at,
            ttl: entry.ttl,
            etag: entry.etag,
            content_type: entry.content_type,
            size: entry.size,
        }
    }
}

impl From<SerializableCacheEntry> for CacheEntry {
    fn from(entry: SerializableCacheEntry) -> Self {
        let status = StatusCode::from_u16(entry.status_code).unwrap_or(StatusCode::OK);
        let mut headers = HeaderMap::new();

        for (key, value) in entry.headers {
            if let (Ok(key), Ok(value)) = (
                key.parse::<hyper::header::HeaderName>(),
                value.parse::<hyper::header::HeaderValue>(),
            ) {
                headers.insert(key, value);
            }
        }

        Self {
            status,
            headers,
            body: entry.body,
            created_at: entry.created_at,
            ttl: entry.ttl,
            etag: entry.etag,
            content_type: entry.content_type,
            size: entry.size,
        }
    }
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(status: StatusCode, headers: HeaderMap, body: Vec<u8>, ttl: Duration) -> Self {
        let size = body.len();
        let etag = headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Self {
            status,
            headers,
            body,
            created_at: SystemTime::now(),
            ttl,
            etag,
            content_type,
            size,
        }
    }

    /// Check if this cache entry is expired
    pub fn is_expired(&self) -> bool {
        match self.created_at.elapsed() {
            Ok(elapsed) => elapsed > self.ttl,
            Err(_) => true, // If we can't determine elapsed time, consider it expired
        }
    }

    /// Convert to HTTP response
    pub fn to_response(&self) -> Result<Response<Body>, hyper::http::Error> {
        let mut response = Response::builder().status(self.status);

        // Copy headers
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }

        // Add cache headers
        response = response.header("X-Cache", "HIT").header(
            "X-Cache-Created",
            self.created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        );

        Ok(response.body(Body::from(self.body.clone()))?)
    }

    /// Check if entry matches ETag for conditional request
    pub fn matches_etag(&self, if_none_match: &str) -> bool {
        if let Some(ref etag) = self.etag {
            if_none_match == "*" || if_none_match == etag
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::cache::CachePolicyPattern;
    use hyper::header::{CONTENT_TYPE, ETAG};

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.max_size, 100 * 1024 * 1024);
        assert_eq!(config.default_ttl, 3600);
        assert_eq!(config.policies.len(), 2);
        assert!(config.enable_etag);
        assert!(config.enable_metrics);
    }

    #[test]
    fn test_cache_config_validation() {
        let mut config = CacheConfig::default();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Zero max_size should fail
        config.max_size = 0;
        assert!(config.validate().is_err());

        // Zero default_ttl should fail
        config.max_size = 1024;
        config.default_ttl = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_cache_policy_validation() {
        let policy = CachePolicy {
            name: "test".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/test".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200, 404],
            vary_headers: None,
            no_cache_headers: vec![],
        };

        assert!(policy.validate().is_ok());

        // Empty name should fail
        let mut invalid_policy = policy.clone();
        invalid_policy.name = String::new();
        assert!(invalid_policy.validate().is_err());

        // Empty cacheable status codes should fail
        let mut invalid_policy = policy.clone();
        invalid_policy.cacheable_status_codes = vec![];
        assert!(invalid_policy.validate().is_err());

        // Invalid status code should fail
        let mut invalid_policy = policy.clone();
        invalid_policy.cacheable_status_codes = vec![999];
        assert!(invalid_policy.validate().is_err());
    }

    #[test]
    fn test_cache_policy_matches() {
        let policy = CachePolicy {
            name: "test".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/api".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200],
            vary_headers: None,
            no_cache_headers: vec![],
        };

        assert!(policy.matches("/api/users", None));
        assert!(policy.matches("/api/data", None));
        assert!(!policy.matches("/web/page", None));

        // Test content type matching
        let content_policy = CachePolicy {
            name: "content".to_string(),
            pattern: CachePolicyPattern::ContentType("image/*".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200],
            vary_headers: None,
            no_cache_headers: vec![],
        };

        assert!(content_policy.matches("/any/path", Some("image/png")));
        assert!(content_policy.matches("/any/path", Some("image/jpeg")));
        assert!(!content_policy.matches("/any/path", Some("text/html")));
        assert!(!content_policy.matches("/any/path", None));
    }

    #[test]
    fn test_cache_policy_status_cacheable() {
        let policy = CachePolicy {
            name: "test".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/test".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200, 404],
            vary_headers: None,
            no_cache_headers: vec![],
        };

        assert!(policy.is_status_cacheable(200));
        assert!(policy.is_status_cacheable(404));
        assert!(!policy.is_status_cacheable(500));
        assert!(!policy.is_status_cacheable(301));
    }

    #[test]
    fn test_cache_policy_no_cache_headers() {
        let policy = CachePolicy {
            name: "test".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/test".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200],
            vary_headers: None,
            no_cache_headers: vec!["authorization".to_string(), "cookie".to_string()],
        };

        let mut headers = HeaderMap::new();
        assert!(!policy.has_no_cache_headers(&headers));

        headers.insert("authorization", "Bearer token".parse().unwrap()); // OK in tests - valid header value
        assert!(policy.has_no_cache_headers(&headers));

        headers.clear();
        headers.insert("cookie", "session=abc".parse().unwrap()); // OK in tests - valid header value
        assert!(policy.has_no_cache_headers(&headers));

        headers.clear();
        headers.insert("accept", "application/json".parse().unwrap()); // OK in tests - valid header value
        assert!(!policy.has_no_cache_headers(&headers));
    }

    #[test]
    fn test_cache_policy_vary_suffix() {
        let policy = CachePolicy {
            name: "test".to_string(),
            pattern: CachePolicyPattern::PathPrefix("/test".to_string()),
            ttl: Some(300),
            cacheable_status_codes: vec![200],
            vary_headers: Some(vec!["accept".to_string(), "accept-encoding".to_string()]),
            no_cache_headers: vec![],
        };

        let mut headers = HeaderMap::new();
        assert_eq!(policy.get_vary_suffix(&headers), "");

        headers.insert("accept", "application/json".parse().unwrap()); // OK in tests - valid header value
        headers.insert("accept-encoding", "gzip".parse().unwrap()); // OK in tests - valid header value

        let suffix = policy.get_vary_suffix(&headers);
        assert!(suffix.contains("accept:application/json"));
        assert!(suffix.contains("accept-encoding:gzip"));
    }

    #[test]
    fn test_cache_entry_creation() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap()); // OK in tests - valid header value
        headers.insert(ETAG, "\"123456\"".parse().unwrap()); // OK in tests - valid header value

        let body = b"{'data': 'test'}".to_vec();
        let entry = CacheEntry::new(
            StatusCode::OK,
            headers,
            body.clone(),
            Duration::from_secs(300),
        );

        assert_eq!(entry.status, StatusCode::OK);
        assert_eq!(entry.body, body);
        assert_eq!(entry.size, body.len());
        assert_eq!(entry.etag, Some("\"123456\"".to_string()));
        assert_eq!(entry.content_type, Some("application/json".to_string()));
        assert_eq!(entry.ttl, Duration::from_secs(300));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_etag_matching() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, "\"123456\"".parse().unwrap()); // OK in tests - valid header value

        let entry = CacheEntry::new(
            StatusCode::OK,
            headers,
            b"test".to_vec(),
            Duration::from_secs(300),
        );

        assert!(entry.matches_etag("\"123456\""));
        assert!(entry.matches_etag("*"));
        assert!(!entry.matches_etag("\"654321\""));
    }

    #[test]
    fn test_cache_metrics() {
        let mut metrics = CacheMetrics::default();

        assert_eq!(metrics.hit_ratio(), 0.0);
        assert_eq!(metrics.total_requests(), 0);

        metrics.hits = 7;
        metrics.misses = 3;

        assert_eq!(metrics.hit_ratio(), 70.0);
        assert_eq!(metrics.total_requests(), 10);
    }
}
