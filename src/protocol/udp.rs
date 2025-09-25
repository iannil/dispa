//! UDP protocol implementation

use async_trait::async_trait;
use hyper::{Body, Request, Response};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

use super::traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolStats,
    ProtocolType,
};

/// UDP protocol handler
pub struct UdpProtocolHandler {
    stats: Arc<UdpStats>,
}

#[derive(Debug)]
struct UdpStats {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_transferred: AtomicU64,
    error_count: AtomicU64,
}

impl UdpStats {
    fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    fn to_protocol_stats(&self) -> ProtocolStats {
        ProtocolStats {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.packets_sent.load(Ordering::Relaxed)
                + self.packets_received.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            avg_response_time_ms: 0.0, // UDP is connectionless, no meaningful response time
            last_activity: Some(std::time::SystemTime::now()),
        }
    }
}

impl UdpProtocolHandler {
    pub fn new() -> Self {
        Self {
            stats: Arc::new(UdpStats::new()),
        }
    }

    /// Handle UDP packet forwarding
    async fn proxy_udp_packets(
        &self,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
        initial_data: Vec<u8>,
    ) -> ProtocolResult<()> {
        // Create UDP socket for proxying
        let proxy_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ProtocolError::ConnectionError { source: e })?;

        // Forward the initial packet to target
        proxy_socket
            .send_to(&initial_data, target_addr)
            .await
            .map_err(|e| ProtocolError::ConnectionError { source: e })?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_transferred
            .fetch_add(initial_data.len() as u64, Ordering::Relaxed);

        // Set up bidirectional packet forwarding
        let mut buffer = vec![0u8; 65536]; // Maximum UDP packet size
        let timeout_duration = tokio::time::Duration::from_secs(30);

        loop {
            match tokio::time::timeout(timeout_duration, proxy_socket.recv_from(&mut buffer)).await
            {
                Ok(Ok((bytes_received, sender_addr))) => {
                    if sender_addr == target_addr {
                        // Packet from target server, forward to client
                        if let Err(_) = proxy_socket
                            .send_to(&buffer[..bytes_received], client_addr)
                            .await
                        {
                            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    } else if sender_addr == client_addr {
                        // Packet from client, forward to target
                        if (proxy_socket
                            .send_to(&buffer[..bytes_received], target_addr)
                            .await)
                            .is_err()
                        {
                            self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
                    }

                    self.stats
                        .bytes_transferred
                        .fetch_add(bytes_received as u64, Ordering::Relaxed);
                }
                Ok(Err(_)) => {
                    // Socket error
                    self.stats.error_count.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    // Timeout - no more packets
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Protocol for UdpProtocolHandler {
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Udp
    }

    fn name(&self) -> &str {
        "UDP"
    }

    fn supports_connection(&self, context: &ConnectionContext) -> bool {
        // UDP support could be determined by port or context metadata
        context
            .get_metadata("protocol")
            .map(|proto| proto.to_lowercase() == "udp")
            .unwrap_or(false)
    }

    fn config(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "max_packet_size": 65536,
            "timeout": 30,
            "buffer_size": 65536,
            "session_timeout": 300,
            "max_sessions": 1000
        }))
    }
}

#[async_trait]
impl ProtocolHandler for UdpProtocolHandler {
    async fn handle_request(
        &self,
        _request: Request<Body>,
        _context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        // UDP doesn't handle HTTP requests
        self.stats.error_count.fetch_add(1, Ordering::Relaxed);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: self.protocol_type().to_string(),
        })
    }

    async fn handle_stream(
        &self,
        _stream: TcpStream,
        _context: &ConnectionContext,
    ) -> ProtocolResult<()> {
        // UDP doesn't use TCP streams
        self.stats.error_count.fetch_add(1, Ordering::Relaxed);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: "UDP doesn't support TCP streams".to_string(),
        })
    }

    async fn detect_protocol(
        &self,
        _request: &Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        // UDP protocol detection based on context metadata
        Ok(context
            .get_metadata("protocol")
            .map(|proto| proto.to_lowercase() == "udp")
            .unwrap_or(false))
    }

    fn get_stats(&self) -> ProtocolStats {
        self.stats.to_protocol_stats()
    }

    async fn health_check(&self) -> bool {
        // UDP handler is healthy based on error rate and active sessions
        let total_packets = self.stats.packets_sent.load(Ordering::Relaxed)
            + self.stats.packets_received.load(Ordering::Relaxed);
        let errors = self.stats.error_count.load(Ordering::Relaxed);
        let active_connections = self.stats.active_connections.load(Ordering::Relaxed);

        if total_packets == 0 {
            return true; // No packets yet, consider healthy
        }

        let error_rate = (errors as f64 / total_packets as f64) * 100.0;

        // Healthy if error rate is reasonable and not too many active sessions
        error_rate < 10.0 && active_connections < 1000
    }
}

/// UDP session manager for handling stateful UDP connections
pub struct UdpSessionManager {
    handler: Arc<UdpProtocolHandler>,
}

impl UdpSessionManager {
    pub fn new(handler: Arc<UdpProtocolHandler>) -> Self {
        Self { handler }
    }

    /// Handle a new UDP packet and manage session
    pub async fn handle_packet(
        &self,
        data: Vec<u8>,
        client_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> ProtocolResult<()> {
        self.handler
            .stats
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
        self.handler
            .stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        let result = self
            .handler
            .proxy_udp_packets(client_addr, target_addr, data)
            .await;

        self.handler
            .stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> ConnectionContext {
        let mut context = ConnectionContext::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
        );
        context.add_metadata("protocol".to_string(), "udp".to_string());
        context
    }

    #[tokio::test]
    async fn test_udp_protocol_handler() {
        let handler = UdpProtocolHandler::new();
        let context = create_test_context();

        assert_eq!(handler.protocol_type(), ProtocolType::Udp);
        assert_eq!(handler.name(), "UDP");
        assert!(handler.supports_connection(&context));

        // Test configuration
        let config = handler.config().unwrap();
        assert_eq!(config["max_packet_size"], 65536);
        assert_eq!(config["timeout"], 30);
    }

    #[tokio::test]
    async fn test_udp_request_handling() {
        let handler = UdpProtocolHandler::new();
        let context = create_test_context();

        // UDP handler should not handle HTTP requests
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
    async fn test_udp_stream_handling() {
        let handler = UdpProtocolHandler::new();
        let context = create_test_context();

        // Create a dummy TCP stream
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).await.unwrap();

        // UDP handler should not handle TCP streams
        let result = handler.handle_stream(stream, &context).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_protocol_detection() {
        let handler = UdpProtocolHandler::new();
        let context = create_test_context();

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let detected = handler.detect_protocol(&request, &context).await.unwrap();
        assert!(detected); // Should detect based on metadata

        // Test without UDP metadata
        let context_no_udp = ConnectionContext::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
        );

        let detected = handler
            .detect_protocol(&request, &context_no_udp)
            .await
            .unwrap();
        assert!(!detected);
    }

    #[tokio::test]
    async fn test_udp_stats() {
        let handler = UdpProtocolHandler::new();

        // Initial stats should be zero
        let stats = handler.get_stats();
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.bytes_transferred, 0);

        // Simulate some packet activity
        handler.stats.packets_sent.store(100, Ordering::Relaxed);
        handler.stats.packets_received.store(95, Ordering::Relaxed);
        handler
            .stats
            .bytes_transferred
            .store(10240, Ordering::Relaxed);

        let stats = handler.get_stats();
        assert_eq!(stats.total_requests, 195); // sent + received
        assert_eq!(stats.bytes_transferred, 10240);
    }

    #[tokio::test]
    async fn test_udp_health_check() {
        let handler = UdpProtocolHandler::new();

        // Should be healthy with no packets
        assert!(handler.health_check().await);

        // Simulate successful packet handling
        handler.stats.packets_sent.store(100, Ordering::Relaxed);
        handler.stats.packets_received.store(100, Ordering::Relaxed);
        handler.stats.error_count.store(10, Ordering::Relaxed); // 5% error rate
        handler
            .stats
            .active_connections
            .store(50, Ordering::Relaxed);

        assert!(handler.health_check().await);

        // Simulate high error rate
        handler.stats.error_count.store(25, Ordering::Relaxed); // 12.5% error rate
        assert!(!handler.health_check().await);
    }

    #[tokio::test]
    async fn test_udp_session_manager() {
        let handler = Arc::new(UdpProtocolHandler::new());
        let session_manager = UdpSessionManager::new(handler);

        let client_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let target_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let test_data = b"Hello UDP".to_vec();

        // This would normally handle the packet, but will fail due to no actual target server
        // We're just testing the session management structure
        let result = session_manager
            .handle_packet(test_data, client_addr, target_addr)
            .await;

        // Result depends on whether target is reachable, but the session handling code ran
        match result {
            Ok(_) => println!("UDP packet handling succeeded"),
            Err(_) => println!("UDP packet handling failed (expected without target server)"),
        }
    }
}
