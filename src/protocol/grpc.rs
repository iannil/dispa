//! gRPC protocol implementation

#![allow(unused_variables)] // For context parameters in protocol implementations

use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;

use super::traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolStats,
    ProtocolType,
};

/// gRPC protocol handler
pub struct GrpcProtocolHandler {
    stats: Arc<GrpcStats>,
}

#[derive(Debug)]
struct GrpcStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    total_requests: AtomicU64,
    bytes_transferred: AtomicU64,
    error_count: AtomicU64,
    streaming_calls: AtomicU64,
}

impl GrpcStats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            streaming_calls: AtomicU64::new(0),
        }
    }

    fn to_protocol_stats(&self) -> ProtocolStats {
        ProtocolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            avg_response_time_ms: 0.0, // TODO: Implement gRPC-specific metrics
            last_activity: Some(std::time::SystemTime::now()),
        }
    }
}

impl GrpcProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(GrpcStats::new()),
        }
    }
}

impl Default for GrpcProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcProtocolHandler {
    /// Check if request is a gRPC request
    fn is_grpc_request(request: &Request<Body>) -> bool {
        // gRPC uses HTTP/2 with specific content-type
        request
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|ct| ct.starts_with("application/grpc"))
            .unwrap_or(false)
    }

    /// Extract gRPC method from path
    fn extract_grpc_method(path: &str) -> Option<(String, String)> {
        // gRPC path format: /{package.service}/{method}
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Generate gRPC error response
    fn grpc_error_response(code: u32, message: &str) -> ProtocolResult<Response<Body>> {
        Response::builder()
            .status(StatusCode::OK) // gRPC always uses 200 OK for application-level errors
            .header("content-type", "application/grpc")
            .header("grpc-status", code.to_string())
            .header("grpc-message", message)
            .body(Body::empty())
            .map_err(|e| ProtocolError::HandlerError {
                message: format!("Failed to build gRPC error response: {}", e),
            })
    }
}

impl Protocol for GrpcProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Grpc
    }

    fn name(&self) -> &str {
        "gRPC"
    }

    fn supports_connection(&self, context: &ConnectionContext) -> bool {
        // gRPC requires HTTP/2
        context.protocol_version.contains("HTTP/2")
            || context
                .get_metadata("alpn")
                .map(|alpn| alpn == "h2")
                .unwrap_or(false)
    }

    fn config(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "max_receive_message_size": 4194304, // 4MB
            "max_send_message_size": 4194304,    // 4MB
            "keepalive_time": 7200,              // 2 hours
            "keepalive_timeout": 20,             // 20 seconds
            "keepalive_permit_without_calls": false,
            "max_connection_idle": 300,          // 5 minutes
            "max_connection_age": 2147483647,    // Max i32
            "compression": "gzip"
        }))
    }
}

#[async_trait]
impl ProtocolHandler for GrpcProtocolHandler {
    async fn handle_request(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Validate gRPC request
        if !Self::is_grpc_request(&request) {
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return Self::grpc_error_response(3, "Invalid gRPC request"); // INVALID_ARGUMENT
        }

        // Extract service and method
        let path = request.uri().path();
        let (service, method) = Self::extract_grpc_method(path).ok_or_else(|| {
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
            ProtocolError::HandlerError {
                message: format!("Invalid gRPC path: {}", path),
            }
        })?;

        // Check if it's a streaming call
        let is_streaming = request.headers().get("grpc-encoding").is_some()
            || request.headers().get("content-length").is_none(); // Streaming calls don't have content-length

        if is_streaming {
            self.stats.streaming_calls.fetch_add(1, Ordering::Relaxed);
        }

        // Process the gRPC call
        match request.method() {
            &hyper::Method::POST => {
                // Standard gRPC call
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "0") // OK
                    .header("grpc-message", "")
                    .body(Body::from(format!(
                        "gRPC call to {}.{} processed",
                        service, method
                    )))
                    .map_err(|e| ProtocolError::HandlerError {
                        message: format!("Failed to build gRPC response: {}", e),
                    })?;

                self.stats
                    .bytes_transferred
                    .fetch_add(1024, Ordering::Relaxed);
                Ok(response)
            }
            _ => {
                self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                Self::grpc_error_response(12, "Unimplemented method") // UNIMPLEMENTED
            }
        }
    }

    async fn handle_stream(
        &self,
        _stream: TcpStream,
        context: &ConnectionContext,
    ) -> ProtocolResult<()> {
        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        // Handle gRPC streaming connection
        // This would implement bidirectional streaming support

        // Simulate stream processing
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        self.stats
            .bytes_transferred
            .fetch_add(2048, Ordering::Relaxed);
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);

        Ok(())
    }

    async fn detect_protocol(
        &self,
        request: &Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // Detect gRPC based on content-type and HTTP/2
        let is_grpc_content = Self::is_grpc_request(request);
        let is_http2 = request.version() == hyper::Version::HTTP_2
            || context
                .get_metadata("alpn")
                .map(|alpn| alpn == "h2")
                .unwrap_or(false);

        Ok(is_grpc_content && is_http2)
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        // gRPC handler is healthy based on error rate and streaming performance
        let total_requests = self.stats.total_requests.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);

        if total_requests == 0 {
            return true; // No requests yet, consider healthy
        }

        let error_rate = (errors as f64 / total_requests as f64) * 100.0;
        let active_connections = self.stats.active_connections.load(Ordering::Relaxed);

        // Healthy if error rate is low and not too many active connections
        error_rate < 5.0 && active_connections < 1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn create_test_context() -> ConnectionContext {
        let mut context = ConnectionContext::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
        );
        context.protocol_version = "HTTP/2".to_string();
        context.add_metadata("alpn".to_string(), "h2".to_string());
        context
    }

    #[tokio::test]
    async fn test_grpc_protocol_handler() {
        let handler = GrpcProtocolHandler::new();
        let context = create_test_context();

        assert_eq!(handler.protocol_type(), ProtocolType::Grpc);
        assert_eq!(handler.name(), "gRPC");
        assert!(handler.supports_connection(&context));

        // Test configuration
        let config = handler.config().unwrap();
        assert_eq!(config["max_receive_message_size"], 4194304);
    }

    #[tokio::test]
    async fn test_grpc_request_detection() {
        let handler = GrpcProtocolHandler::new();
        let context = create_test_context();

        // Valid gRPC request
        let grpc_request = Request::builder()
            .method("POST")
            .uri("/helloworld.Greeter/SayHello")
            .version(hyper::Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(Body::empty())
            .unwrap();

        assert!(GrpcProtocolHandler::is_grpc_request(&grpc_request));

        let detected = handler
            .detect_protocol(&grpc_request, &context)
            .await
            .unwrap();
        assert!(detected);

        // Non-gRPC request
        let http_request = Request::builder()
            .method("GET")
            .uri("/api/users")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        assert!(!GrpcProtocolHandler::is_grpc_request(&http_request));
    }

    #[tokio::test]
    async fn test_grpc_method_extraction() {
        assert_eq!(
            GrpcProtocolHandler::extract_grpc_method("/helloworld.Greeter/SayHello"),
            Some(("helloworld.Greeter".to_string(), "SayHello".to_string()))
        );

        assert_eq!(
            GrpcProtocolHandler::extract_grpc_method("/package.Service/Method"),
            Some(("package.Service".to_string(), "Method".to_string()))
        );

        assert_eq!(
            GrpcProtocolHandler::extract_grpc_method("/invalid-path"),
            None
        );
    }

    #[tokio::test]
    async fn test_grpc_request_handling() {
        let handler = GrpcProtocolHandler::new();
        let context = create_test_context();

        let grpc_request = Request::builder()
            .method("POST")
            .uri("/helloworld.Greeter/SayHello")
            .version(hyper::Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("content-length", "100")
            .body(Body::from("grpc request data"))
            .unwrap();

        let response = handler
            .handle_request(grpc_request, &context)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert_eq!(content_type, "application/grpc");

        let grpc_status = response.headers().get("grpc-status").unwrap();
        assert_eq!(grpc_status, "0"); // OK status
    }

    #[tokio::test]
    async fn test_grpc_error_response() {
        let response = GrpcProtocolHandler::grpc_error_response(3, "Invalid argument").unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("grpc-status").unwrap(), "3");
        assert_eq!(
            response.headers().get("grpc-message").unwrap(),
            "Invalid argument"
        );
    }

    #[tokio::test]
    async fn test_grpc_invalid_request() {
        let handler = GrpcProtocolHandler::new();
        let context = create_test_context();

        // Request without proper gRPC content-type
        let invalid_request = Request::builder()
            .method("POST")
            .uri("/helloworld.Greeter/SayHello")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = handler
            .handle_request(invalid_request, &context)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("grpc-status").unwrap(), "3"); // INVALID_ARGUMENT
    }

    #[tokio::test]
    async fn test_grpc_stats() {
        let handler = GrpcProtocolHandler::new();
        let context = create_test_context();

        // Initial stats
        let stats = handler.get_stats();
        assert_eq!(stats.total_requests, 0);

        // Process a request
        let grpc_request = Request::builder()
            .method("POST")
            .uri("/test.Service/Method")
            .header("content-type", "application/grpc")
            .body(Body::empty())
            .unwrap();

        handler
            .handle_request(grpc_request, &context)
            .await
            .unwrap();

        // Check updated stats
        let stats = handler.get_stats();
        assert_eq!(stats.total_requests, 1);
        assert!(stats.bytes_transferred > 0);
    }
}
