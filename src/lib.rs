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

pub mod balancer; // 负载均衡器模块，提供多种负载均衡算法和健康检查
pub mod cache; // 缓存模块，提供HTTP响应缓存和ETag管理
pub mod circuit_breaker; // 断路器模块，提供服务故障保护
pub mod config; // 配置管理模块，支持TOML配置和热重载
pub mod error; // 错误处理模块，定义统一的错误类型和处理
pub mod graceful_shutdown; // 优雅关闭模块，确保零停机关闭
pub mod logger; // 日志记录模块，支持文件和数据库双重存储
pub mod monitoring; // 监控模块，提供指标收集和健康检查端点
pub mod plugins; // 插件系统模块，支持请求和响应处理插件
pub mod proxy; // 代理服务器模块，核心HTTP代理功能
pub mod retry; // 重试机制模块，提供智能重试策略
pub mod routing; // 路由引擎模块，支持高级路由规则
pub mod security; // 安全模块，提供认证和授权功能
pub mod state; // 统一状态管理模块，提供类型安全的状态访问
pub mod tls; // TLS模块，提供SSL/TLS证书管理

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
