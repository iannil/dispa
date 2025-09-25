//! # 负载均衡器模块
//!
//! 本模块提供了完整的负载均衡和健康检查功能，支持多种负载均衡算法
//! 和自动故障检测。
//!
//! ## 负载均衡算法
//!
//! - **轮询 (Round Robin)**: 依次分配请求到各个后端服务器
//! - **加权轮询 (Weighted Round Robin)**: 根据服务器权重分配请求
//! - **最少连接 (Least Connections)**: 选择当前连接数最少的服务器
//! - **随机 (Random)**: 随机选择后端服务器
//! - **IP哈希 (IP Hash)**: 根据客户端IP选择固定的后端服务器
//!
//! ## 健康检查功能
//!
//! - 并发健康检查，支持多个检查端点
//! - 可配置的检查间隔和超时设置
//! - 基于阈值的健康状态切换
//! - 自动故障转移和服务恢复检测
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use dispa::balancer::LoadBalancer;
//! use dispa::config::TargetConfig;
//!
//! # async fn example() {
//! let target_config = TargetConfig::default();
//! let load_balancer = LoadBalancer::new(target_config);
//!
//! // 选择下一个健康的目标服务器
//! if let Some(target) = load_balancer.get_target().await {
//!     println!("选择的目标: {}", target.url);
//! }
//! # }
//! ```

pub mod health_check; // 健康检查模块，提供并发健康监控
pub mod load_balancer; // 负载均衡器实现，支持多种算法

// New modular components
pub mod algorithms; // 负载均衡算法实现
pub mod enhanced_algorithms; // 增强负载均衡算法 (一致性哈希、地理路由、会话粘性等)
pub mod metrics; // 指标收集和统计
pub mod state; // 负载均衡器状态管理

pub use load_balancer::LoadBalancer;
