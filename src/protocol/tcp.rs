//! TCP protocol implementation

use async_trait::async_trait;
use hyper::{Body, Request, Response};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolStats,
    ProtocolType,
};

/// TCP protocol handler
pub struct TcpProtocolHandler {
    stats: Arc<TcpStats>,
}

#[derive(Debug)]
struct TcpStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    bytes_transferred: AtomicU64,
    error_count: AtomicU64,
    connection_duration_ms: AtomicU64,
}

impl TcpStats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            connection_duration_ms: AtomicU64::new(0),
        }
    }

    fn to_protocol_stats(&self) -> ProtocolStats {
        let total_connections = self.total_connections.load(Ordering::Relaxed);
        let duration_sum = self.connection_duration_ms.load(Ordering::Relaxed);

        ProtocolStats {
            total_connections,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: total_connections, // For TCP, connections are like requests
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            avg_response_time_ms: if total_connections > 0 {
                duration_sum as f64 / total_connections as f64
            } else {
                0.0
            },
            last_activity: Some(std::time::SystemTime::now()),
        }
    }
}

impl TcpProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(TcpStats::new()),
        }
    }
}

impl Default for TcpProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpProtocolHandler {
    /// Handle TCP stream proxying
    async fn proxy_tcp_stream(
        &self,
        client_stream: TcpStream,
        target_addr: &str,
    ) -> ProtocolResult<()> {
        // Connect to target server
        let target_stream = TcpStream::connect(target_addr)
            .await
            .map_err(|e| ProtocolError::ConnectionError { source: e })?;

        // Split streams for bidirectional copying
        let (client_read, client_write) = client_stream.into_split();
        let (target_read, target_write) = target_stream.into_split();

        // Spawn tasks for bidirectional data copying
        let client_to_target = {
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                let mut client_read = client_read;
                let mut target_write = target_write;
                let mut buffer = vec![0u8; 8192];
                let mut total_bytes = 0u64;

                while let Ok(bytes_read) = client_read.read(&mut buffer).await {
                    if bytes_read == 0 {
                        break; // EOF
                    }

                    if (target_write.write_all(&buffer[..bytes_read]).await).is_err() {
                        break;
                    }

                    total_bytes += bytes_read as u64;
                }

                stats
                    .bytes_transferred
                    .fetch_add(total_bytes, Ordering::Relaxed);
                total_bytes
            })
        };

        let target_to_client = {
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                let mut target_read = target_read;
                let mut client_write = client_write;
                let mut buffer = vec![0u8; 8192];
                let mut total_bytes = 0u64;

                while let Ok(bytes_read) = target_read.read(&mut buffer).await {
                    if bytes_read == 0 {
                        break; // EOF
                    }

                    if (client_write.write_all(&buffer[..bytes_read]).await).is_err() {
                        break;
                    }

                    total_bytes += bytes_read as u64;
                }

                stats
                    .bytes_transferred
                    .fetch_add(total_bytes, Ordering::Relaxed);
                total_bytes
            })
        };

        // Wait for either direction to complete
        let _ = tokio::select! {
            result1 = client_to_target => result1,
            result2 = target_to_client => result2,
        };

        Ok(())
    }
}

impl Protocol for TcpProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Tcp
    }

    fn name(&self) -> &str {
        "TCP"
    }

    fn supports_connection(&self, _context: &ConnectionContext) -> bool {
        // TCP handler supports any connection
        true
    }

    fn config(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "buffer_size": 8192,
            "connect_timeout": 30,
            "read_timeout": 300,
            "write_timeout": 30,
            "keepalive": true,
            "nodelay": true
        }))
    }
}

#[async_trait]
impl ProtocolHandler for TcpProtocolHandler {
    async fn handle_request(
        &self,
        _request: Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        // TCP doesn't handle HTTP requests
        self.stats.error_count.fetch_add(1, Ordering::Relaxed);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: self.protocol_type().to_string(),
        })
    }

    async fn handle_stream(
        &self,
        stream: TcpStream,
        context: &ConnectionContext,
    ) -> ProtocolResult<()> {
        let start_time = std::time::Instant::now();

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        let target_addr = format!(
            "{}:{}",
            context.target_addr.ip(),
            context.target_addr.port()
        );

        // Handle the TCP stream
        let result = self.proxy_tcp_stream(stream, &target_addr).await;

        // Update connection statistics
        let duration = start_time.elapsed();
        self.stats
            .connection_duration_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);

        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);

        if result.is_err() {
            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    async fn detect_protocol(
        &self,
        _request: &Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // TCP protocol detection would be based on port or connection context
        // For now, return false since TCP is typically a fallback protocol
        Ok(false)
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        // TCP handler is healthy if not too many errors and reasonable connection count
        let total_connections = self.stats.total_connections.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);
        let active_connections = self.stats.active_connections.load(Ordering::Relaxed);

        if total_connections == 0 {
            return true; // No connections yet, consider healthy
        }

        let error_rate = (errors as f64 / total_connections as f64) * 100.0;

        // Healthy if error rate is low and not too many active connections
        error_rate < 20.0 && active_connections < 500
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn create_test_context(target_port: u16) -> ConnectionContext {
        ConnectionContext::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            format!("127.0.0.1:{}", target_port)
                .parse::<SocketAddr>()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_tcp_protocol_handler() {
        let handler = TcpProtocolHandler::new();
        let context = create_test_context(3000);

        assert_eq!(handler.protocol_type(), ProtocolType::Tcp);
        assert_eq!(handler.name(), "TCP");
        assert!(handler.supports_connection(&context));

        // Test configuration
        let config = handler.config().unwrap();
        assert_eq!(config["buffer_size"], 8192);
        assert_eq!(config["connect_timeout"], 30);
    }

    #[tokio::test]
    async fn test_tcp_request_handling() {
        let handler = TcpProtocolHandler::new();
        let context = create_test_context(3000);

        // TCP handler should not handle HTTP requests
        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let result = handler.handle_request(request, &context).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProtocolError::UnsupportedProtocol { .. }
        ));
    }

    #[tokio::test]
    async fn test_tcp_protocol_detection() {
        let handler = TcpProtocolHandler::new();
        let context = create_test_context(3000);

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let detected = handler.detect_protocol(&request, &context).await.unwrap();
        assert!(!detected); // TCP typically doesn't detect from HTTP requests
    }

    #[tokio::test]
    async fn test_tcp_stats() {
        let handler = TcpProtocolHandler::new();

        // Initial stats should be zero
        let stats = handler.get_stats();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.bytes_transferred, 0);
    }

    #[tokio::test]
    async fn test_tcp_health_check() {
        let handler = TcpProtocolHandler::new();

        // Should be healthy with no connections
        assert!(handler.health_check().await);

        // Simulate some successful connections
        handler
            .stats
            .total_connections
            .store(100, Ordering::Relaxed);
        handler.stats.error_count.store(5, Ordering::Relaxed); // 5% error rate
        handler
            .stats
            .active_connections
            .store(10, Ordering::Relaxed);

        assert!(handler.health_check().await);

        // Simulate high error rate
        handler.stats.error_count.store(25, Ordering::Relaxed); // 25% error rate
        assert!(!handler.health_check().await);
    }

    #[tokio::test]
    async fn test_tcp_stream_proxy_connection_failure() {
        let handler = TcpProtocolHandler::new();

        // Create a dummy client stream (this will fail to connect to non-existent server)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create a client connection to the listener
        let client_stream = TcpStream::connect(addr).await.unwrap();

        // Try to proxy to a non-existent server
        let result = handler
            .proxy_tcp_stream(client_stream, "127.0.0.1:65535")
            .await;
        assert!(result.is_err());
    }
}
