use crate::cache::CacheEntry;
use hyper::{header::HeaderValue, Body, HeaderMap, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use tracing::debug;

/// ETag generator and validator for HTTP caching
#[derive(Clone)]
pub struct ETagManager {
    /// Whether ETag support is enabled
    enabled: bool,
}

impl ETagManager {
    /// Create a new ETag manager
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Generate an ETag for response content
    pub fn generate_etag(&self, content: &[u8]) -> Option<String> {
        if !self.enabled {
            return None;
        }

        // Generate SHA-256 hash of content
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hasher.finalize();

        // Convert to hex string and wrap in quotes
        let mut etag = String::with_capacity(66); // "0x" + 64 hex chars + quotes
        etag.push('"');
        for byte in hash {
            write!(&mut etag, "{:02x}", byte).expect("Writing to string should not fail");
        }
        etag.push('"');

        Some(etag)
    }

    /// Generate a weak ETag (for dynamic content that's semantically equivalent)
    pub fn generate_weak_etag(&self, content: &[u8]) -> Option<String> {
        if !self.enabled {
            return None;
        }

        self.generate_etag(content)
            .map(|strong_etag| format!("W/{}", strong_etag))
    }

    /// Check if a request has conditional headers
    pub fn has_conditional_headers(&self, headers: &HeaderMap) -> bool {
        if !self.enabled {
            return false;
        }

        headers.contains_key("if-none-match")
            || headers.contains_key("if-match")
            || headers.contains_key("if-modified-since")
            || headers.contains_key("if-unmodified-since")
    }

    /// Validate If-None-Match header against ETag
    pub fn validate_if_none_match(&self, headers: &HeaderMap, etag: &str) -> ConditionalResult {
        if !self.enabled {
            return ConditionalResult::Continue;
        }

        if let Some(if_none_match) = headers.get("if-none-match") {
            if let Ok(if_none_match_str) = if_none_match.to_str() {
                debug!(
                    "Validating If-None-Match: {} against ETag: {}",
                    if_none_match_str, etag
                );

                // Handle wildcard
                if if_none_match_str.trim() == "*" {
                    return ConditionalResult::NotModified;
                }

                // Parse multiple ETags (comma-separated)
                for etag_value in if_none_match_str.split(',') {
                    let etag_value = etag_value.trim();
                    if self.etags_match(etag_value, etag) {
                        return ConditionalResult::NotModified;
                    }
                }
            }
        }

        ConditionalResult::Continue
    }

    /// Validate If-Match header against ETag
    pub fn validate_if_match(&self, headers: &HeaderMap, etag: &str) -> ConditionalResult {
        if !self.enabled {
            return ConditionalResult::Continue;
        }

        if let Some(if_match) = headers.get("if-match") {
            if let Ok(if_match_str) = if_match.to_str() {
                debug!(
                    "Validating If-Match: {} against ETag: {}",
                    if_match_str, etag
                );

                // Handle wildcard
                if if_match_str.trim() == "*" {
                    return ConditionalResult::Continue;
                }

                // Parse multiple ETags (comma-separated)
                for etag_value in if_match_str.split(',') {
                    let etag_value = etag_value.trim();
                    if self.etags_match(etag_value, etag) {
                        return ConditionalResult::Continue;
                    }
                }

                // If no ETags matched, return precondition failed
                return ConditionalResult::PreconditionFailed;
            }
        }

        ConditionalResult::Continue
    }

    /// Check if two ETags match (handling weak/strong comparison)
    fn etags_match(&self, etag1: &str, etag2: &str) -> bool {
        // Remove W/ prefix for weak ETags for comparison
        let etag1_strong = if let Some(stripped) = etag1.strip_prefix("W/") {
            stripped
        } else {
            etag1
        };

        let etag2_strong = if let Some(stripped) = etag2.strip_prefix("W/") {
            stripped
        } else {
            etag2
        };

        etag1_strong == etag2_strong
    }

    /// Add ETag header to response
    pub fn add_etag_header(&self, response: &mut Response<Body>, etag: &str) {
        if !self.enabled {
            return;
        }

        if let Ok(header_value) = HeaderValue::from_str(etag) {
            response.headers_mut().insert("etag", header_value);
            debug!("Added ETag header: {}", etag);
        }
    }

    /// Create a 304 Not Modified response
    pub fn create_not_modified_response(&self, original_headers: &HeaderMap) -> Response<Body> {
        let mut response = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .expect("Creating NOT_MODIFIED response with valid values should not fail");

        // Copy cacheable headers to 304 response
        self.copy_cacheable_headers(original_headers, response.headers_mut());

        response
    }

    /// Create a 412 Precondition Failed response
    pub fn create_precondition_failed_response(&self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::PRECONDITION_FAILED)
            .body(Body::from("Precondition Failed"))
            .expect("Creating PRECONDITION_FAILED response with valid values should not fail")
    }

    /// Copy cacheable headers to 304 response
    fn copy_cacheable_headers(&self, from: &HeaderMap, to: &mut HeaderMap) {
        // Headers that should be included in 304 responses
        let cacheable_headers = [
            "cache-control",
            "date",
            "etag",
            "expires",
            "last-modified",
            "server",
            "vary",
        ];

        for header_name in &cacheable_headers {
            if let Some(value) = from.get(*header_name) {
                to.insert(*header_name, value.clone());
            }
        }
    }

    /// Process conditional request and return appropriate response
    pub fn process_conditional_request(
        &self,
        request_headers: &HeaderMap,
        cache_entry: &CacheEntry,
    ) -> ConditionalResult {
        if !self.enabled {
            return ConditionalResult::Continue;
        }

        // Get ETag from cache entry
        let etag = match &cache_entry.etag {
            Some(etag) => etag,
            None => return ConditionalResult::Continue,
        };

        // Check If-Match first (for write operations)
        if self.validate_if_match(request_headers, etag) == ConditionalResult::PreconditionFailed {
            return ConditionalResult::PreconditionFailed;
        }

        // Check If-None-Match (for caching)
        self.validate_if_none_match(request_headers, etag)
    }

    /// Extract ETag from response headers
    pub fn extract_etag_from_response(&self, response: &Response<Body>) -> Option<String> {
        if !self.enabled {
            return None;
        }

        response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Generate ETag from cache entry
    pub fn generate_etag_for_entry(&self, entry: &CacheEntry) -> Option<String> {
        if !self.enabled {
            return None;
        }

        // If entry already has an ETag, use it
        if let Some(ref etag) = entry.etag {
            return Some(etag.clone());
        }

        // Otherwise generate one from content
        self.generate_etag(&entry.body)
    }
}

/// Result of conditional request validation
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionalResult {
    /// Continue with normal processing
    Continue,
    /// Return 304 Not Modified
    NotModified,
    /// Return 412 Precondition Failed
    PreconditionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheEntry;
    use hyper::{HeaderMap, StatusCode};
    use std::time::Duration;

    #[test]
    fn test_etag_generation() {
        let etag_manager = ETagManager::new(true);

        let content = b"Hello, World!";
        let etag = etag_manager.generate_etag(content).unwrap(); // OK in tests - expected to succeed // OK in tests - expected to succeed

        // Should be a quoted hex string
        assert!(etag.starts_with('"'));
        assert!(etag.ends_with('"'));
        assert_eq!(etag.len(), 66); // quotes + 64 hex chars

        // Same content should generate same ETag
        let etag2 = etag_manager.generate_etag(content).unwrap(); // OK in tests - expected to succeed // OK in tests - expected to succeed
        assert_eq!(etag, etag2);

        // Different content should generate different ETag
        let etag3 = etag_manager.generate_etag(b"Different content").unwrap(); // OK in tests - expected to succeed // OK in tests - expected to succeed
        assert_ne!(etag, etag3);
    }

    #[test]
    fn test_weak_etag_generation() {
        let etag_manager = ETagManager::new(true);

        let content = b"Hello, World!";
        let weak_etag = etag_manager.generate_weak_etag(content).unwrap(); // OK in tests - expected to succeed

        assert!(weak_etag.starts_with("W/"));

        let strong_etag = etag_manager.generate_etag(content).unwrap(); // OK in tests - expected to succeed
        assert_eq!(weak_etag, format!("W/{}", strong_etag));
    }

    #[test]
    fn test_etag_disabled() {
        let etag_manager = ETagManager::new(false);

        let content = b"Hello, World!";
        assert!(etag_manager.generate_etag(content).is_none());
        assert!(etag_manager.generate_weak_etag(content).is_none());
    }

    #[test]
    fn test_conditional_headers_detection() {
        let etag_manager = ETagManager::new(true);

        let mut headers = HeaderMap::new();
        assert!(!etag_manager.has_conditional_headers(&headers));

        headers.insert("if-none-match", "\"123456\"".parse().unwrap());
        assert!(etag_manager.has_conditional_headers(&headers));

        headers.clear();
        headers.insert("if-match", "\"123456\"".parse().unwrap());
        assert!(etag_manager.has_conditional_headers(&headers));

        headers.clear();
        headers.insert(
            "if-modified-since",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert!(etag_manager.has_conditional_headers(&headers));
    }

    #[test]
    fn test_if_none_match_validation() {
        let etag_manager = ETagManager::new(true);
        let etag = "\"123456789abcdef\"";

        let mut headers = HeaderMap::new();

        // No If-None-Match header
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, etag),
            ConditionalResult::Continue
        );

        // Matching ETag
        headers.insert("if-none-match", etag.parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, etag),
            ConditionalResult::NotModified
        );

        // Non-matching ETag
        headers.insert("if-none-match", "\"different\"".parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, etag),
            ConditionalResult::Continue
        );

        // Wildcard
        headers.insert("if-none-match", "*".parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, etag),
            ConditionalResult::NotModified
        );

        // Multiple ETags with match
        headers.insert(
            "if-none-match",
            "\"other\", \"123456789abcdef\", \"another\""
                .parse()
                .unwrap(), // OK in tests - expected to succeed
        );
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, etag),
            ConditionalResult::NotModified
        );
    }

    #[test]
    fn test_if_match_validation() {
        let etag_manager = ETagManager::new(true);
        let etag = "\"123456789abcdef\"";

        let mut headers = HeaderMap::new();

        // No If-Match header
        assert_eq!(
            etag_manager.validate_if_match(&headers, etag),
            ConditionalResult::Continue
        );

        // Matching ETag
        headers.insert("if-match", etag.parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_match(&headers, etag),
            ConditionalResult::Continue
        );

        // Non-matching ETag
        headers.insert("if-match", "\"different\"".parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_match(&headers, etag),
            ConditionalResult::PreconditionFailed
        );

        // Wildcard
        headers.insert("if-match", "*".parse().unwrap());
        assert_eq!(
            etag_manager.validate_if_match(&headers, etag),
            ConditionalResult::Continue
        );
    }

    #[test]
    fn test_etag_matching() {
        let etag_manager = ETagManager::new(true);

        // Strong ETags
        assert!(etag_manager.etags_match("\"123456\"", "\"123456\""));
        assert!(!etag_manager.etags_match("\"123456\"", "\"654321\""));

        // Weak ETags
        assert!(etag_manager.etags_match("W/\"123456\"", "\"123456\""));
        assert!(etag_manager.etags_match("\"123456\"", "W/\"123456\""));
        assert!(etag_manager.etags_match("W/\"123456\"", "W/\"123456\""));

        // Mixed
        assert!(!etag_manager.etags_match("W/\"123456\"", "\"654321\""));
    }

    #[test]
    fn test_not_modified_response() {
        let etag_manager = ETagManager::new(true);

        let mut original_headers = HeaderMap::new();
        original_headers.insert("etag", "\"123456\"".parse().unwrap());
        original_headers.insert("cache-control", "max-age=3600".parse().unwrap());
        original_headers.insert("custom-header", "should-not-copy".parse().unwrap());

        let response = etag_manager.create_not_modified_response(&original_headers);

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(response.headers().contains_key("etag"));
        assert!(response.headers().contains_key("cache-control"));
        assert!(!response.headers().contains_key("custom-header"));
    }

    #[test]
    fn test_process_conditional_request() {
        let etag_manager = ETagManager::new(true);

        let entry = CacheEntry::new(
            StatusCode::OK,
            {
                let mut headers = HeaderMap::new();
                headers.insert("etag", "\"123456\"".parse().unwrap());
                headers
            },
            b"test content".to_vec(),
            Duration::from_secs(3600),
        );

        let mut request_headers = HeaderMap::new();

        // No conditional headers
        assert_eq!(
            etag_manager.process_conditional_request(&request_headers, &entry),
            ConditionalResult::Continue
        );

        // Matching If-None-Match
        request_headers.insert("if-none-match", "\"123456\"".parse().unwrap());
        assert_eq!(
            etag_manager.process_conditional_request(&request_headers, &entry),
            ConditionalResult::NotModified
        );

        // Non-matching If-Match
        request_headers.clear();
        request_headers.insert("if-match", "\"different\"".parse().unwrap());
        assert_eq!(
            etag_manager.process_conditional_request(&request_headers, &entry),
            ConditionalResult::PreconditionFailed
        );
    }

    #[test]
    fn test_disabled_etag_manager() {
        let etag_manager = ETagManager::new(false);

        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", "\"123456\"".parse().unwrap());

        assert!(!etag_manager.has_conditional_headers(&headers));
        assert_eq!(
            etag_manager.validate_if_none_match(&headers, "\"123456\""),
            ConditionalResult::Continue
        );
        assert_eq!(
            etag_manager.validate_if_match(&headers, "\"123456\""),
            ConditionalResult::Continue
        );
    }
}
