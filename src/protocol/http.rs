//! HTTP protocol implementations

#![allow(unused_variables)] // For context parameters in protocol implementations

use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
// TCP types available when needed

use super::traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolStats,
    ProtocolType,
};

/// HTTP/1.1 protocol handler
pub struct HttpProtocolHandler {
    stats: Arc<HttpStats>,
}

/// HTTP/2 protocol handler
pub struct Http2ProtocolHandler {
    stats: Arc<HttpStats>,
}

#[derive(Debug)]
struct HttpStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    total_requests: AtomicU64,
    bytes_transferred: AtomicU64,
    error_count: AtomicU64,
}

impl HttpStats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    fn to_protocol_stats(&self) -> ProtocolStats {
        ProtocolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            avg_response_time_ms: 0.0, // TODO: Implement moving average
            last_activity: Some(std::time::SystemTime::now()),
        }
    }
}

impl HttpProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(HttpStats::new()),
        }
    }
}

impl Protocol for HttpProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Http
    }

    fn name(&self) -> &str {
        "HTTP/1.1"
    }

    fn supports_connection(&self, _context: &ConnectionContext) -> bool {
        true
    }
}

#[async_trait]
impl ProtocolHandler for HttpProtocolHandler {
    async fn handle_request(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Basic HTTP/1.1 request handling
        match request.method() {
            &hyper::Method::GET
            | &hyper::Method::POST
            | &hyper::Method::PUT
            | &hyper::Method::DELETE => {
                // Handle standard HTTP methods
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Server", "Dispa-Proxy/1.0")
                    .header("Connection", "keep-alive")
                    .body(Body::from("HTTP/1.1 request processed"))
                    .map_err(|e| ProtocolError::HandlerError {
                        message: format!("Failed to build response: {}", e),
                    })?;

                Ok(response)
            }
            _ => {
                self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                Err(ProtocolError::HandlerError {
                    message: format!("Unsupported HTTP method: {}", request.method()),
                })
            }
        }
    }

    async fn detect_protocol(
        &self,
        request: &Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // HTTP/1.1 detection based on version and headers
        Ok(request.version() == hyper::Version::HTTP_11)
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        // HTTP handler is healthy if error rate is below threshold
        let total_requests = self.stats.total_requests.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);

        if total_requests == 0 {
            return true; // No requests yet, consider healthy
        }

        let error_rate = (errors as f64 / total_requests as f64) * 100.0;
        error_rate < 10.0 // Less than 10% error rate is considered healthy
    }
}

impl Http2ProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(HttpStats::new()),
        }
    }
}

impl Protocol for Http2ProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Http2
    }

    fn name(&self) -> &str {
        "HTTP/2"
    }

    fn supports_connection(&self, context: &ConnectionContext) -> bool {
        // Check for HTTP/2 indicators in metadata
        context
            .get_metadata("alpn")
            .map(|alpn| alpn == "h2")
            .unwrap_or(false)
            || context
                .get_metadata("upgrade")
                .map(|upgrade| upgrade.contains("h2c"))
                .unwrap_or(false)
    }

    fn config(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "max_concurrent_streams": 100,
            "initial_window_size": 65536,
            "max_frame_size": 16384,
            "enable_push": false
        }))
    }
}

#[async_trait]
impl ProtocolHandler for Http2ProtocolHandler {
    async fn handle_request(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // HTTP/2 specific handling
        match request.method() {
            &hyper::Method::GET
            | &hyper::Method::POST
            | &hyper::Method::PUT
            | &hyper::Method::DELETE => {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("Server", "Dispa-Proxy/1.0")
                    .body(Body::from("HTTP/2 request processed"))
                    .map_err(|e| ProtocolError::HandlerError {
                        message: format!("Failed to build HTTP/2 response: {}", e),
                    })?;

                Ok(response)
            }
            _ => {
                self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                Err(ProtocolError::HandlerError {
                    message: format!("Unsupported HTTP/2 method: {}", request.method()),
                })
            }
        }
    }

    async fn handle_upgrade(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        // Handle HTTP/1.1 to HTTP/2 upgrade
        if request
            .headers()
            .get("upgrade")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.contains("h2c"))
            .unwrap_or(false)
        {
            let response = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("Connection", "Upgrade")
                .header("Upgrade", "h2c")
                .body(Body::empty())
                .map_err(|e| ProtocolError::UpgradeFailed {
                    reason: format!("Failed to build upgrade response: {}", e),
                })?;

            Ok(response)
        } else {
            Err(ProtocolError::UpgradeFailed {
                reason: "Invalid HTTP/2 upgrade request".to_string(),
            })
        }
    }

    async fn detect_protocol(
        &self,
        request: &Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // HTTP/2 detection based on version, ALPN, or upgrade headers
        Ok(request.version() == hyper::Version::HTTP_2
            || context
                .get_metadata("alpn")
                .map(|alpn| alpn == "h2" || alpn == "h2c")
                .unwrap_or(false)
            || request
                .headers()
                .get("upgrade")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.contains("h2c"))
                .unwrap_or(false))
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        let total_requests = self.stats.total_requests.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);

        if total_requests == 0 {
            return true;
        }

        let error_rate = (errors as f64 / total_requests as f64) * 100.0;
        error_rate < 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn create_test_context() -> ConnectionContext {
        ConnectionContext::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
        )
    }

    #[tokio::test]
    async fn test_http_protocol_handler() {
        let handler = HttpProtocolHandler::new();
        let context = create_test_context();

        assert_eq!(handler.protocol_type(), ProtocolType::Http);
        assert_eq!(handler.name(), "HTTP/1.1");
        assert!(handler.supports_connection(&context));

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .version(hyper::Version::HTTP_11)
            .body(Body::empty())
            .unwrap();

        let detected = handler.detect_protocol(&request, &context).await.unwrap();
        assert!(detected);

        let response = handler.handle_request(request, &context).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_http2_protocol_handler() {
        let handler = Http2ProtocolHandler::new();
        let mut context = create_test_context();
        context.add_metadata("alpn".to_string(), "h2".to_string());

        assert_eq!(handler.protocol_type(), ProtocolType::Http2);
        assert_eq!(handler.name(), "HTTP/2");
        assert!(handler.supports_connection(&context));

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .version(hyper::Version::HTTP_2)
            .body(Body::empty())
            .unwrap();

        let detected = handler.detect_protocol(&request, &context).await.unwrap();
        assert!(detected);

        let response = handler.handle_request(request, &context).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_http2_upgrade() {
        let handler = Http2ProtocolHandler::new();
        let context = create_test_context();

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Connection", "Upgrade, HTTP2-Settings")
            .header("Upgrade", "h2c")
            .header("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_upgrade(request, &context).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers().get("upgrade").unwrap(), "h2c");
    }

    #[tokio::test]
    async fn test_protocol_stats() {
        let handler = HttpProtocolHandler::new();
        let context = create_test_context();

        // Initial stats should be zero
        let stats = handler.get_stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.error_count, 0);

        // Process a request
        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        handler.handle_request(request, &context).await.unwrap();

        // Stats should be updated
        let stats = handler.get_stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.error_count, 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let handler = HttpProtocolHandler::new();

        // Should be healthy with no requests
        assert!(handler.health_check().await);

        // Should still be healthy after successful requests
        let context = create_test_context();
        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        handler.handle_request(request, &context).await.unwrap();
        assert!(handler.health_check().await);
    }
}
