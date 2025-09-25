//! Protocol traits and types

use async_trait::async_trait;
use hyper::{Body, Request, Response};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_stream::Stream;

/// Protocol type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolType {
    /// HTTP/1.1 protocol
    Http,
    /// HTTP/2 protocol
    Http2,
    /// WebSocket protocol
    WebSocket,
    /// gRPC protocol (HTTP/2 based)
    Grpc,
    /// TCP layer 4 protocol
    Tcp,
    /// UDP layer 4 protocol
    Udp,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "http"),
            ProtocolType::Http2 => write!(f, "http2"),
            ProtocolType::WebSocket => write!(f, "websocket"),
            ProtocolType::Grpc => write!(f, "grpc"),
            ProtocolType::Tcp => write!(f, "tcp"),
            ProtocolType::Udp => write!(f, "udp"),
        }
    }
}

impl Default for ProtocolType {
    fn default() -> Self {
        ProtocolType::Http
    }
}

/// Protocol-specific errors
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Unsupported protocol: {protocol}")]
    UnsupportedProtocol { protocol: String },

    #[error("Protocol upgrade failed: {reason}")]
    UpgradeFailed { reason: String },

    #[error("Connection error: {source}")]
    ConnectionError {
        #[from]
        source: std::io::Error,
    },

    #[error("Protocol parsing error: {message}")]
    ParseError { message: String },

    #[error("Protocol configuration error: {message}")]
    ConfigError { message: String },

    #[error("Protocol timeout")]
    Timeout,

    #[error("Protocol handler error: {message}")]
    HandlerError { message: String },
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Connection context information
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Client address
    pub client_addr: SocketAddr,
    /// Target server address
    pub target_addr: SocketAddr,
    /// Protocol version
    pub protocol_version: String,
    /// Connection metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Connection start time
    pub start_time: std::time::Instant,
    /// Connection ID
    pub connection_id: String,
}

impl ConnectionContext {
    /// Create a new connection context
    pub fn new(client_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            client_addr,
            target_addr,
            protocol_version: String::new(),
            metadata: std::collections::HashMap::new(),
            start_time: std::time::Instant::now(),
            connection_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Get connection duration
    pub fn duration(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Protocol trait for different communication protocols
pub trait Protocol {
    /// Get the protocol type
    fn protocol_type(&self) -> ProtocolType;

    /// Get the protocol name
    fn name(&self) -> &str;

    /// Check if the protocol supports the given connection
    fn supports_connection(&self, context: &ConnectionContext) -> bool;

    /// Get protocol-specific configuration
    fn config(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Protocol handler trait for processing connections
#[async_trait]
pub trait ProtocolHandler: Protocol + Send + Sync {
    /// Handle HTTP request (for HTTP-based protocols)
    async fn handle_request(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        let _ = (request, context);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: self.protocol_type().to_string(),
        })
    }

    /// Handle TCP stream (for stream-based protocols)
    async fn handle_stream(
        &self,
        stream: TcpStream,
        context: &ConnectionContext,
    ) -> ProtocolResult<()> {
        let _ = (stream, context);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: self.protocol_type().to_string(),
        })
    }

    /// Handle protocol upgrade (for protocols that require upgrade)
    async fn handle_upgrade(
        &self,
        request: Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<Response<Body>> {
        let _ = (request, context);
        Err(ProtocolError::UnsupportedProtocol {
            protocol: self.protocol_type().to_string(),
        })
    }

    /// Detect protocol from request/stream
    async fn detect_protocol(
        &self,
        request: &Request<Body>,
        context: &ConnectionContext,
    ) -> ProtocolResult<bool> {
        let _ = (request, context);
        Ok(false)
    }

    /// Get protocol statistics
    fn get_stats(&self) -> ProtocolStats {
        ProtocolStats::default()
    }

    /// Check if protocol is healthy
    async fn health_check(&self) -> bool {
        true
    }
}

/// Protocol statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    /// Total connections handled
    pub total_connections: u64,
    /// Active connections
    pub active_connections: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Total requests handled (for request-response protocols)
    pub total_requests: u64,
    /// Average response time (milliseconds)
    pub avg_response_time_ms: f64,
    /// Error count
    pub error_count: u64,
    /// Last activity timestamp
    pub last_activity: Option<std::time::SystemTime>,
}

impl ProtocolStats {
    /// Update connection stats
    pub fn update_connection(&mut self, active_change: i32) {
        if active_change > 0 {
            self.total_connections += active_change as u64;
            self.active_connections += active_change as u64;
        } else {
            self.active_connections = self
                .active_connections
                .saturating_sub((-active_change) as u64);
        }
        self.last_activity = Some(std::time::SystemTime::now());
    }

    /// Update request stats
    pub fn update_request(&mut self, response_time_ms: f64) {
        self.total_requests += 1;
        // Simple moving average
        if self.avg_response_time_ms == 0.0 {
            self.avg_response_time_ms = response_time_ms;
        } else {
            self.avg_response_time_ms =
                (self.avg_response_time_ms * 0.9) + (response_time_ms * 0.1);
        }
        self.last_activity = Some(std::time::SystemTime::now());
    }

    /// Update transfer stats
    pub fn update_transfer(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
        self.last_activity = Some(std::time::SystemTime::now());
    }

    /// Update error stats
    pub fn update_error(&mut self) {
        self.error_count += 1;
        self.last_activity = Some(std::time::SystemTime::now());
    }
}

/// Protocol stream type
pub type ProtocolStream = Pin<Box<dyn Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_type_display() {
        assert_eq!(ProtocolType::Http.to_string(), "http");
        assert_eq!(ProtocolType::Http2.to_string(), "http2");
        assert_eq!(ProtocolType::WebSocket.to_string(), "websocket");
        assert_eq!(ProtocolType::Grpc.to_string(), "grpc");
        assert_eq!(ProtocolType::Tcp.to_string(), "tcp");
        assert_eq!(ProtocolType::Udp.to_string(), "udp");
    }

    #[test]
    fn test_protocol_type_default() {
        assert_eq!(ProtocolType::default(), ProtocolType::Http);
    }

    #[test]
    fn test_connection_context() {
        let client = "127.0.0.1:8080".parse().unwrap();
        let target = "127.0.0.1:3000".parse().unwrap();
        let mut ctx = ConnectionContext::new(client, target);

        ctx.add_metadata("test".to_string(), "value".to_string());
        assert_eq!(ctx.get_metadata("test"), Some(&"value".to_string()));

        assert!(ctx.duration().as_nanos() > 0);
        assert!(!ctx.connection_id.is_empty());
    }

    #[test]
    fn test_protocol_stats() {
        let mut stats = ProtocolStats::default();

        stats.update_connection(1);
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.active_connections, 1);

        stats.update_request(100.0);
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.avg_response_time_ms, 100.0);

        stats.update_request(200.0);
        assert_eq!(stats.total_requests, 2);
        // Moving average: 100 * 0.9 + 200 * 0.1 = 90 + 20 = 110
        assert!((stats.avg_response_time_ms - 110.0).abs() < 0.1);

        stats.update_transfer(1024);
        assert_eq!(stats.bytes_transferred, 1024);

        stats.update_error();
        assert_eq!(stats.error_count, 1);

        stats.update_connection(-1);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.total_connections, 1);
    }
}
