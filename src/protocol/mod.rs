//! Protocol support module
//!
//! This module provides protocol abstraction and implementations for various protocols:
//! - HTTP/1.1 and HTTP/2
//! - WebSocket
//! - gRPC
//! - TCP/UDP (Layer 4)

pub mod grpc;
pub mod http;
pub mod tcp;
pub mod traits;
pub mod udp;
pub mod websocket;

// Re-export public types
pub use traits::{
    ConnectionContext, Protocol, ProtocolError, ProtocolHandler, ProtocolResult, ProtocolType,
};

pub use grpc::GrpcProtocolHandler;
pub use http::{Http2ProtocolHandler, HttpProtocolHandler};
pub use tcp::TcpProtocolHandler;
pub use udp::UdpProtocolHandler;
pub use websocket::WebSocketProtocolHandler;

use std::collections::HashMap;
use std::sync::Arc;

/// Protocol registry for managing different protocol handlers
pub struct ProtocolRegistry {
    handlers: HashMap<ProtocolType, Arc<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
    /// Create a new protocol registry
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a protocol handler
    pub fn register(&mut self, protocol: ProtocolType, handler: Arc<dyn ProtocolHandler>) {
        self.handlers.insert(protocol, handler);
    }

    /// Get a protocol handler
    pub fn get_handler(&self, protocol: &ProtocolType) -> Option<&Arc<dyn ProtocolHandler>> {
        self.handlers.get(protocol)
    }

    /// Get all registered protocols
    pub fn protocols(&self) -> Vec<ProtocolType> {
        self.handlers.keys().cloned().collect()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        let mut registry = Self::new();

        // Register default protocol handlers
        registry.register(ProtocolType::Http, Arc::new(HttpProtocolHandler::new()));
        registry.register(ProtocolType::Http2, Arc::new(Http2ProtocolHandler::new()));
        registry.register(
            ProtocolType::WebSocket,
            Arc::new(WebSocketProtocolHandler::new()),
        );
        registry.register(ProtocolType::Grpc, Arc::new(GrpcProtocolHandler::new()));
        registry.register(ProtocolType::Tcp, Arc::new(TcpProtocolHandler::new()));
        registry.register(ProtocolType::Udp, Arc::new(UdpProtocolHandler::new()));

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_registry() {
        let registry = ProtocolRegistry::default();

        assert!(registry.get_handler(&ProtocolType::Http).is_some());
        assert!(registry.get_handler(&ProtocolType::Http2).is_some());
        assert!(registry.get_handler(&ProtocolType::WebSocket).is_some());
        assert!(registry.get_handler(&ProtocolType::Grpc).is_some());
        assert!(registry.get_handler(&ProtocolType::Tcp).is_some());
        assert!(registry.get_handler(&ProtocolType::Udp).is_some());

        let protocols = registry.protocols();
        assert!(protocols.len() >= 6);
    }
}
