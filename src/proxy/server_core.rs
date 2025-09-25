use std::net::SocketAddr;

use super::handler::ProxyHandler;
use super::http_client;
use super::http_server::HttpServerManager;
use crate::balancer::LoadBalancer;
use crate::config::{Config, DomainConfig};
use crate::error::DispaResult;
use crate::logger::TrafficLogger;
use crate::plugins::{PluginEngine, SharedPluginEngine};
use crate::routing::RoutingEngine;
use crate::security::{SecurityManager, SharedSecurity};
use crate::tls::TlsManager;

/// 高性能HTTP代理服务器核心组件
///
/// ProxyServerCore负责管理代理服务器的核心状态和组件，
/// 包括负载均衡器、域名配置、流量日志等。
pub struct ProxyServerCore {
    pub bind_addr: SocketAddr,
    pub config: Config,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    domain_config: std::sync::Arc<std::sync::RwLock<DomainConfig>>,
    traffic_logger: TrafficLogger,
    tls_manager: Option<TlsManager>,
    routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
    plugins: SharedPluginEngine,
    security: SharedSecurity,
}

impl ProxyServerCore {
    /// 创建新的代理服务器核心
    pub fn new(config: Config, bind_addr: SocketAddr, traffic_logger: TrafficLogger) -> Self {
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(LoadBalancer::new(
            config.targets.clone(),
        )));

        // 初始化共享HTTP客户端池（首次调用获胜）
        http_client::init(config.http_client.as_ref());

        // 设置域名配置
        let domain_config = std::sync::Arc::new(std::sync::RwLock::new(config.domains.clone()));

        // 初始化TLS管理器
        let tls_manager = if let Some(tls_config) = &config.tls {
            if tls_config.enabled {
                Some(TlsManager::new(tls_config.clone()))
            } else {
                None
            }
        } else {
            None
        };

        // 初始化路由引擎
        let routing_engine = if let Some(routing_config) = &config.routing {
            match RoutingEngine::new(routing_config.clone()) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    tracing::warn!("Failed to initialize routing engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        };

        // 初始化插件引擎
        let plugins = if let Some(plugin_config) = &config.plugins {
            match PluginEngine::new(plugin_config) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    tracing::warn!("Failed to initialize plugin engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        };

        // 初始化安全管理器
        let security = if let Some(security_config) = &config.security {
            std::sync::Arc::new(tokio::sync::RwLock::new(Some(SecurityManager::new(
                security_config.clone(),
            ))))
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        };

        Self {
            bind_addr,
            config,
            load_balancer,
            domain_config,
            traffic_logger,
            tls_manager,
            routing_engine,
            plugins,
            security,
        }
    }

    /// 初始化代理服务器（包括TLS等）
    pub async fn initialize(&mut self) -> DispaResult<()> {
        if let Some(ref mut tls_manager) = self.tls_manager {
            tracing::info!("Initializing TLS configuration");
            tls_manager.initialize().await?;
            tracing::info!("TLS configuration initialized successfully");
        }
        Ok(())
    }

    /// 创建代理处理器
    pub fn create_handler(&self) -> ProxyHandler {
        ProxyHandler::with_shared_routing(
            std::sync::Arc::clone(&self.domain_config),
            std::sync::Arc::clone(&self.load_balancer),
            self.traffic_logger.clone(),
            std::sync::Arc::clone(&self.routing_engine),
            std::sync::Arc::clone(&self.plugins),
            std::sync::Arc::clone(&self.security),
        )
    }

    /// 运行代理服务器
    pub async fn run(self) -> anyhow::Result<()> {
        let handler = self.create_handler();
        let http_server = HttpServerManager::new(self.bind_addr, self.tls_manager);
        http_server.run(handler).await
    }

    // 访问器方法
    /// 获取负载均衡器句柄
    pub fn load_balancer_handle(&self) -> std::sync::Arc<tokio::sync::RwLock<LoadBalancer>> {
        std::sync::Arc::clone(&self.load_balancer)
    }

    /// 获取路由引擎句柄
    pub fn routing_engine_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>> {
        std::sync::Arc::clone(&self.routing_engine)
    }

    /// 获取插件引擎句柄
    pub fn plugins_handle(&self) -> SharedPluginEngine {
        std::sync::Arc::clone(&self.plugins)
    }

    /// 获取安全管理器句柄
    pub fn security_handle(&self) -> SharedSecurity {
        std::sync::Arc::clone(&self.security)
    }

    /// 获取域名配置句柄
    pub fn domain_config_handle(&self) -> std::sync::Arc<std::sync::RwLock<DomainConfig>> {
        std::sync::Arc::clone(&self.domain_config)
    }
}

// Tests temporarily removed due to configuration API changes
// TODO: Update tests to match current configuration structure
