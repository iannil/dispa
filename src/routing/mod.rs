//! # 路由引擎模块
//!
//! 本模块提供高级路由功能，包括：
//!
//! - 基于复杂条件的请求路由
//! - 请求和响应的动态修改
//! - 路径重写和头部操作
//! - 自定义响应生成
//! - 插件系统集成
//!
//! ## 主要组件
//!
//! - `RoutingEngine`: 主要的路由决策引擎
//! - `RoutingConfig`: 路由配置和规则定义
//! - `RoutingConditions`: 路由匹配条件
//! - `RoutingActions`: 路由动作和转换
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use dispa::routing::{RoutingEngine, RoutingConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RoutingConfig::default();
//! let engine = RoutingEngine::new(config)?;
//!
//! // 在请求处理中使用路由引擎
//! // let decision = engine.route_request(&request).await;
//! # Ok(())
//! # }
//! ```

pub mod actions;
pub mod conditions;
pub mod config;
pub mod engine;

// 重新导出主要类型以保持API兼容性
pub use config::RoutingConfig;
pub use engine::{RoutingDecision, RoutingEngine};
