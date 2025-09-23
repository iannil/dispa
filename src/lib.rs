//! # Dispa - 高性能流量拦截和转发代理
//!
//! Dispa是一个用Rust编写的高性能HTTP代理服务器，专注于流量拦截、记录和转发。
//! 它提供了灵活的负载均衡、健康检查、插件系统和监控功能。
//!
//! ## 核心功能
//!
//! - **流量拦截**: 基于域名的智能流量拦截和路由
//! - **负载均衡**: 支持多种算法（轮询、加权、最少连接等）
//! - **健康检查**: 自动的后端服务健康监控
//! - **插件系统**: 可扩展的请求/响应处理插件
//! - **监控指标**: Prometheus兼容的指标导出
//! - **配置热重载**: 无需重启的配置更新
//! - **优雅关闭**: 零停机的服务关闭
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use dispa::{config::Config, proxy::ProxyServer, logger::TrafficLogger};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::from_file_with_env("config.toml").await?;
//!     let bind_addr: SocketAddr = "0.0.0.0:8080".parse()?;
//!     let traffic_logger = TrafficLogger::new(config.logging.clone());
//!     let server = ProxyServer::new(config, bind_addr, traffic_logger);
//!     server.run().await?;
//!     Ok(())
//! }
//! ```

pub mod balancer;
pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod graceful_shutdown;
pub mod logger;
pub mod monitoring;
pub mod plugins;
pub mod proxy;
pub mod retry;
pub mod routing;
pub mod security;
pub mod state;
pub mod tls;

// Re-export commonly used types
pub use cache::{
    CacheConfig, CacheEntry, CacheMetrics, CachePolicy, ETagManager, InMemoryCache, PolicyEngine,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, CircuitBreakerStats,
};
pub use error::{DispaError, DispaResult, ErrorSeverity};
pub use graceful_shutdown::{ResourceCleanup, ShutdownManager, ShutdownSignal, TaskHandle};
pub use retry::{BackoffStrategy, ErrorRecovery, ExponentialBackoff, RetryConfig, RetryExecutor};
pub use routing::{RoutingConfig, RoutingDecision, RoutingEngine};
pub use tls::{CertificateConfig, TlsConfig, TlsManager, TlsVersion};
