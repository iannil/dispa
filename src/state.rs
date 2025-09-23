//! # 统一状态管理模块
//!
//! 本模块提供了Dispa应用程序的统一状态管理模式，包括：
//!
//! - 统一的异步锁类型定义
//! - 类型安全的状态句柄
//! - 一致的状态访问模式
//! - 状态更新的最佳实践
//!
//! ## 设计原则
//!
//! 1. **异步优先**: 统一使用tokio::sync::RwLock以避免阻塞
//! 2. **类型安全**: 为不同状态创建专门的句柄类型
//! 3. **最小化锁争用**: 提供细粒度的状态访问
//! 4. **一致性**: 统一的状态更新和访问模式

use std::sync::Arc;
use tokio::sync::RwLock;

/// 统一的异步读写锁类型别名
#[allow(dead_code)]
pub type SharedState<T> = Arc<RwLock<T>>;

/// 创建新的共享状态
#[allow(dead_code)]
pub fn new_shared_state<T>(value: T) -> SharedState<T> {
    Arc::new(RwLock::new(value))
}

/// 域名配置状态句柄
#[allow(dead_code)]
pub type DomainConfigHandle = SharedState<crate::config::DomainConfig>;

/// 负载均衡器状态句柄
#[allow(dead_code)]
pub type LoadBalancerHandle = SharedState<crate::balancer::LoadBalancer>;

/// 路由引擎状态句柄
#[allow(dead_code)]
pub type RoutingEngineHandle = SharedState<Option<crate::routing::RoutingEngine>>;

/// 插件引擎状态句柄
#[allow(dead_code)]
pub type PluginEngineHandle = SharedState<Option<crate::plugins::PluginEngine>>;

/// 安全管理器状态句柄
#[allow(dead_code)]
pub type SecurityManagerHandle = SharedState<Option<crate::security::SecurityManager>>;

/// 指标任务状态句柄
#[allow(dead_code)]
pub type MetricsTaskHandle = SharedState<Option<tokio::task::JoinHandle<()>>>;

/// 状态管理器 - 提供统一的状态访问接口
#[allow(dead_code)]
#[derive(Clone)]
pub struct StateManager {
    pub domain_config: DomainConfigHandle,
    pub load_balancer: LoadBalancerHandle,
    pub routing_engine: RoutingEngineHandle,
    pub plugin_engine: PluginEngineHandle,
    pub security_manager: SecurityManagerHandle,
    pub metrics_task: MetricsTaskHandle,
}

#[allow(dead_code)]
impl StateManager {
    /// 创建新的状态管理器
    pub fn new(
        domain_config: crate::config::DomainConfig,
        load_balancer: crate::balancer::LoadBalancer,
    ) -> Self {
        Self {
            domain_config: new_shared_state(domain_config),
            load_balancer: new_shared_state(load_balancer),
            routing_engine: new_shared_state(None),
            plugin_engine: new_shared_state(None),
            security_manager: new_shared_state(None),
            metrics_task: new_shared_state(None),
        }
    }

    /// 安全地读取域名配置
    pub async fn read_domain_config<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&crate::config::DomainConfig) -> R,
    {
        let guard = self.domain_config.read().await;
        f(&guard)
    }

    /// 安全地更新域名配置
    pub async fn update_domain_config<F>(&self, f: F)
    where
        F: FnOnce(&mut crate::config::DomainConfig),
    {
        let mut guard = self.domain_config.write().await;
        f(&mut guard);
    }

    /// 安全地读取负载均衡器状态
    pub async fn read_load_balancer<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&crate::balancer::LoadBalancer) -> R,
    {
        let guard = self.load_balancer.read().await;
        f(&guard)
    }

    /// 安全地更新负载均衡器
    pub async fn update_load_balancer<F>(&self, f: F)
    where
        F: FnOnce(&mut crate::balancer::LoadBalancer),
    {
        let mut guard = self.load_balancer.write().await;
        f(&mut guard);
    }

    /// 检查路由引擎是否可用
    pub async fn has_routing_engine(&self) -> bool {
        let guard = self.routing_engine.read().await;
        guard.is_some()
    }

    /// 安全地使用路由引擎
    pub async fn with_routing_engine<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&crate::routing::RoutingEngine) -> R,
    {
        let guard = self.routing_engine.read().await;
        guard.as_ref().map(f)
    }

    /// 设置路由引擎
    pub async fn set_routing_engine(&self, engine: Option<crate::routing::RoutingEngine>) {
        let mut guard = self.routing_engine.write().await;
        *guard = engine;
    }

    /// 检查插件引擎是否可用
    pub async fn has_plugin_engine(&self) -> bool {
        let guard = self.plugin_engine.read().await;
        guard.is_some()
    }

    /// 安全地使用插件引擎
    pub async fn with_plugin_engine<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&crate::plugins::PluginEngine) -> R,
    {
        let guard = self.plugin_engine.read().await;
        guard.as_ref().map(f)
    }

    /// 设置插件引擎
    pub async fn set_plugin_engine(&self, engine: Option<crate::plugins::PluginEngine>) {
        let mut guard = self.plugin_engine.write().await;
        *guard = engine;
    }

    /// 检查安全管理器是否可用
    pub async fn has_security_manager(&self) -> bool {
        let guard = self.security_manager.read().await;
        guard.is_some()
    }

    /// 安全地使用安全管理器
    pub async fn with_security_manager<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&crate::security::SecurityManager) -> R,
    {
        let guard = self.security_manager.read().await;
        guard.as_ref().map(f)
    }

    /// 设置安全管理器
    pub async fn set_security_manager(&self, manager: Option<crate::security::SecurityManager>) {
        let mut guard = self.security_manager.write().await;
        *guard = manager;
    }
}
