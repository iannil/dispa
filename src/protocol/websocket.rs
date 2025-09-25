//! WebSocket protocol implementation

#![allow(unused_variables)] // For request parameter in WebSocket implementation

use async_trait::async_trait;
use hyper::{Body, Request, Response, StatusCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;

use super::traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolStats,
    ProtocolType,
};

/// WebSocket protocol handler
pub struct WebSocketProtocolHandler {
    stats: Arc<WebSocketStats>,
}

#[derive(Debug)]
struct WebSocketStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    total_messages: AtomicU64,
    bytes_transferred: AtomicU64,
    error_count: AtomicU64,
    upgrade_count: AtomicU64,
}

impl WebSocketStats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_messages: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            upgrade_count: AtomicU64::new(0),
        }
    }

    fn to_protocol_stats(&self) -> ProtocolStats {
        ProtocolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.total_messages.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            avg_response_time_ms: 0.0, // WebSocket doesn't have traditional response times
            last_activity: Some(std::time::SystemTime::now()),
        }
    }
}

impl Default for WebSocketProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(WebSocketStats::new()),
        }
    }

    /// Generate WebSocket accept key from client key
    fn generate_accept_key(client_key: &str) -> String {
        use sha1::{Digest, Sha1};
        const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        let mut hasher = Sha1::new();
        hasher.update(client_key.as_bytes());
        hasher.update(WEBSOCKET_MAGIC_STRING.as_bytes());
        let result = hasher.finalize();

        use base64::engine::general_purpose;
        use base64::Engine;

        general_purpose::STANDARD.encode(result)
    }

    /// Validate WebSocket upgrade request
    fn validate_upgrade_request(request: &Request<Body>) -> bool {
        // Check for required WebSocket upgrade headers
        let headers = request.headers();

        headers
            .get("connection")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
            && headers
                .get("upgrade")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_lowercase() == "websocket")
                .unwrap_or(false)
            && headers.get("sec-websocket-key").is_some()
            && headers
                .get("sec-websocket-version")
                .and_then(|h| h.to_str().ok())
                .map(|s| s == "13")
                .unwrap_or(false)
    }
}

impl Protocol for WebSocketProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::WebSocket
    }

    fn name(&self) -> &str {
        "WebSocket"
    }

    fn supports_connection(&self, context: &ConnectionContext) -> bool {
        // WebSocket requires HTTP upgrade
        context
            .get_metadata("upgrade")
            .map(|upgrade| upgrade.to_lowercase() == "websocket")
            .unwrap_or(false)
    }

    fn config(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "max_frame_size": 1048576, // 1MB
            "max_message_size": 16777216, // 16MB
            "ping_interval": 30,
            "pong_timeout": 10,
            "compression": false
        }))
    }
}

#[async_trait]
impl ProtocolHandler for WebSocketProtocolHandler {
    async fn handle_request(
        &self,
        request: Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        // WebSocket doesn't handle regular HTTP requests
        // This would be called after upgrade
        self.stats.error_count.fetch_add(1, Ordering::Relaxed);
        Err(ProtocolError::HandlerError {
            message: "WebSocket handler called for non-upgrade request".to_string(),
        })
    }

    async fn handle_stream(
        &self,
        _stream: TcpStream,
        _context: &ConnectionContext,
    ) -> ProtocolResult<()> {
        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        // WebSocket stream handling would go here
        // This is a placeholder - actual implementation would handle WebSocket frames

        // Simulate message processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        self.stats.total_messages.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_transferred
            .fetch_add(1024, Ordering::Relaxed);

        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    async fn handle_upgrade(
        &self,
        request: Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        // Validate WebSocket upgrade request
        if !Self::validate_upgrade_request(&request) {
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
            return Err(ProtocolError::UpgradeFailed {
                reason: "Invalid WebSocket upgrade request".to_string(),
            });
        }

        // Get client key and generate accept key
        let client_key = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| ProtocolError::UpgradeFailed {
                reason: "Missing Sec-WebSocket-Key header".to_string(),
            })?;

        let accept_key = Self::generate_accept_key(client_key);

        // Build upgrade response
        let mut response_builder = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", accept_key);

        // Handle optional subprotocol
        if let Some(protocols) = request.headers().get("sec-websocket-protocol") {
            if let Ok(protocols_str) = protocols.to_str() {
                // For simplicity, accept the first requested protocol
                if let Some(first_protocol) = protocols_str.split(',').next() {
                    response_builder =
                        response_builder.header("Sec-WebSocket-Protocol", first_protocol.trim());
                }
            }
        }

        let response =
            response_builder
                .body(Body::empty())
                .map_err(|e| ProtocolError::UpgradeFailed {
                    reason: format!("Failed to build WebSocket upgrade response: {}", e),
                })?;

        self.stats.upgrade_count.fetch_add(1, Ordering::Relaxed);
        Ok(response)
    }

    async fn detect_protocol(
        &self,
        request: &Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // Detect WebSocket upgrade request
        Ok(Self::validate_upgrade_request(request))
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        // WebSocket handler is healthy if upgrade success rate is good
        let total_upgrades = self.stats.upgrade_count.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);

        if total_upgrades == 0 {
            return true; // No upgrades yet, consider healthy
        }

        let error_rate = (errors as f64 / total_upgrades as f64) * 100.0;
        error_rate < 15.0 // Less than 15% error rate is acceptable for WebSocket
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
        context.add_metadata("upgrade".to_string(), "websocket".to_string());
        context
    }

    #[tokio::test]
    async fn test_websocket_protocol_handler() {
        let handler = WebSocketProtocolHandler::new();
        let context = create_test_context();

        assert_eq!(handler.protocol_type(), ProtocolType::WebSocket);
        assert_eq!(handler.name(), "WebSocket");
        assert!(handler.supports_connection(&context));

        // Test configuration
        let config = handler.config().unwrap();
        assert!(config["max_frame_size"].is_number());
    }

    #[tokio::test]
    async fn test_websocket_upgrade_request_validation() {
        let handler = WebSocketProtocolHandler::new();

        // Valid WebSocket upgrade request
        let valid_request = Request::builder()
            .method("GET")
            .uri("/ws")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(Body::empty())
            .unwrap();

        assert!(WebSocketProtocolHandler::validate_upgrade_request(
            &valid_request
        ));

        let context = create_test_context();
        let detected = handler
            .detect_protocol(&valid_request, &context)
            .await
            .unwrap();
        assert!(detected);

        // Test upgrade handling
        let response = handler
            .handle_upgrade(valid_request, &context)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(response.headers().get("upgrade").unwrap(), "websocket");
        assert!(response.headers().get("sec-websocket-accept").is_some());
    }

    #[tokio::test]
    async fn test_websocket_invalid_upgrade() {
        let handler = WebSocketProtocolHandler::new();
        let context = create_test_context();

        // Invalid WebSocket upgrade request (missing key)
        let invalid_request = Request::builder()
            .method("GET")
            .uri("/ws")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .body(Body::empty())
            .unwrap();

        assert!(!WebSocketProtocolHandler::validate_upgrade_request(
            &invalid_request
        ));

        let result = handler.handle_upgrade(invalid_request, &context).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProtocolError::UpgradeFailed { .. }
        ));
    }

    #[test]
    fn test_generate_accept_key() {
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        let accept_key = WebSocketProtocolHandler::generate_accept_key(client_key);
        assert_eq!(accept_key, expected_accept);
    }

    #[tokio::test]
    async fn test_websocket_with_subprotocol() {
        let handler = WebSocketProtocolHandler::new();
        let context = create_test_context();

        let request = Request::builder()
            .method("GET")
            .uri("/ws")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", "chat, superchat")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_upgrade(request, &context).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

        // Should select first protocol
        assert_eq!(
            response.headers().get("sec-websocket-protocol").unwrap(),
            "chat"
        );
    }
}
