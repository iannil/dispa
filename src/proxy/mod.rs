//! # 代理服务器模块
//!
//! 本模块实现了Dispa的核心HTTP代理功能，包括：
//!
//! - HTTP请求处理和转发
//! - 域名匹配和路由决策
//! - 负载均衡和故障转移
//! - 请求/响应缓存支持
//! - 插件系统集成
//!
//! ## 主要组件
//!
//! - `ProxyServer`: 主代理服务器，处理HTTP连接
//! - `RequestProcessor`: 请求处理流水线
//! - `RequestForwarder`: 请求转发引擎
//! - `HttpClient`: HTTP客户端连接池
//! - `CachedHandler`: 缓存增强的请求处理器
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use dispa::proxy::ProxyServer;
//! use dispa::config::Config;
//! use dispa::logger::TrafficLogger;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::from_file_with_env("config.toml").await?;
//! let bind_addr: SocketAddr = "0.0.0.0:8080".parse()?;
//! let traffic_logger = TrafficLogger::new(config.logging.clone());
//! let server = ProxyServer::new(config, bind_addr, traffic_logger);
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

pub mod cached_handler; // 缓存增强的请求处理器
pub mod handler; // 核心HTTP请求处理器
pub mod http_client; // HTTP客户端连接池管理
pub mod http_server; // HTTP/HTTPS服务器管理器
pub mod request_forwarder; // 请求转发引擎
pub mod request_processor; // 请求处理流水线
pub mod server; // 主代理服务器实现
pub mod server_core; // 代理服务器核心组件

pub use server::ProxyServer;
