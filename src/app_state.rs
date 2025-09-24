use crate::balancer::LoadBalancer;
use crate::config::DomainConfig;
use crate::logger::TrafficLogger;
use crate::plugins::PluginEngine;
use crate::routing::RoutingEngine;
use crate::security::SecurityManager;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Centralized application state management
///
/// This struct contains all shared state that needs to be accessed
/// across different parts of the application. It reduces Arc::clone
/// calls and provides a single source of truth for state management.
#[derive(Clone)]
pub struct AppState {
    pub domain_handle: Arc<std::sync::RwLock<DomainConfig>>,
    pub lb_handle: Arc<RwLock<LoadBalancer>>,
    pub routing_handle: Arc<RwLock<Option<RoutingEngine>>>,
    pub plugins_handle: Arc<RwLock<Option<PluginEngine>>>,
    pub security_handle: Arc<RwLock<Option<SecurityManager>>>,
    pub metrics_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    pub traffic_logger: TrafficLogger,
}

impl AppState {
    /// Create new application state from proxy server and metrics handle
    pub fn new(
        domain_handle: Arc<std::sync::RwLock<DomainConfig>>,
        lb_handle: Arc<RwLock<LoadBalancer>>,
        routing_handle: Arc<RwLock<Option<RoutingEngine>>>,
        plugins_handle: Arc<RwLock<Option<PluginEngine>>>,
        security_handle: Arc<RwLock<Option<SecurityManager>>>,
        metrics_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
        traffic_logger: TrafficLogger,
    ) -> Self {
        Self {
            domain_handle,
            lb_handle,
            routing_handle,
            plugins_handle,
            security_handle,
            metrics_handle,
            traffic_logger,
        }
    }
}

/// Configuration reload logic
///
/// This module handles hot-reloading of configuration, updating all
/// relevant components when configuration changes are detected.
pub mod config_reload {
    use super::*;
    use crate::monitoring;
    use crate::proxy::http_client;

    /// Set up configuration reload hook
    ///
    /// This function creates a closure that handles configuration changes
    /// by updating all relevant components with new configuration values.
    pub fn setup_reload_hook(
        app_state: AppState,
    ) -> impl Fn(&crate::config::Config) + Send + Sync + 'static {
        move |cfg: &crate::config::Config| {
            // Re-init HTTP client pool
            http_client::init(cfg.http_client.as_ref());
            tracing::info!("HTTP client pool re-initialized from reloaded config");

            // Update load balancer
            update_load_balancer(&app_state.lb_handle, cfg.targets.clone());

            // Update routing engine
            update_routing_engine(&app_state.routing_handle, cfg.routing.clone());

            // Update domain configuration
            update_domain_config(&app_state.domain_handle, cfg.domains.clone());

            // Reconfigure traffic logger
            reconfigure_traffic_logger(&app_state.traffic_logger, cfg.logging.clone());

            // Update plugin engine
            update_plugin_engine(&app_state.plugins_handle, cfg.plugins.clone());

            // Update security manager
            update_security_manager(&app_state.security_handle, cfg.security.clone());

            // Restart monitoring server
            restart_monitoring_server(&app_state.metrics_handle, cfg.monitoring.clone());
        }
    }

    /// Update load balancer with new configuration
    fn update_load_balancer(
        lb_handle: &Arc<RwLock<LoadBalancer>>,
        targets: crate::config::TargetConfig,
    ) {
        let lb_handle = lb_handle.clone();
        tokio::spawn(async move {
            let new_lb = crate::balancer::LoadBalancer::new(targets);
            let mut guard = lb_handle.write().await;
            *guard = new_lb;
            tracing::info!("Load balancer reloaded from new config");
        });
    }

    /// Update routing engine with new configuration
    fn update_routing_engine(
        routing_handle: &Arc<RwLock<Option<RoutingEngine>>>,
        routing_cfg: Option<crate::routing::RoutingConfig>,
    ) {
        let routing_handle = routing_handle.clone();
        tokio::spawn(async move {
            let mut guard = routing_handle.write().await;
            match routing_cfg {
                Some(rc) => match crate::routing::RoutingEngine::new(rc) {
                    Ok(engine) => {
                        *guard = Some(engine);
                        tracing::info!("Routing engine reloaded from new config");
                    }
                    Err(e) => {
                        *guard = None;
                        tracing::warn!("Failed to rebuild routing engine: {}", e);
                    }
                },
                None => {
                    *guard = None;
                    tracing::info!("Routing engine disabled via config reload");
                }
            }
        });
    }

    /// Update domain configuration
    fn update_domain_config(
        domain_handle: &Arc<std::sync::RwLock<DomainConfig>>,
        domain_cfg: DomainConfig,
    ) {
        let domain_handle = domain_handle.clone();
        tokio::spawn(async move {
            if let Ok(mut guard) = domain_handle.write() {
                *guard = domain_cfg;
                tracing::info!("Domain configuration reloaded from new config");
            }
        });
    }

    /// Reconfigure traffic logger
    fn reconfigure_traffic_logger(logger: &TrafficLogger, log_cfg: crate::config::LoggingConfig) {
        let logger = logger.clone();
        tokio::spawn(async move {
            if let Err(e) = logger.reconfigure(log_cfg).await {
                tracing::warn!("Failed to reconfigure traffic logger: {}", e);
            } else {
                tracing::info!("Traffic logger reconfigured successfully");
            }
        });
    }

    /// Update plugin engine
    fn update_plugin_engine(
        plugins_handle: &Arc<RwLock<Option<PluginEngine>>>,
        plugins_cfg: Option<crate::config::PluginsConfig>,
    ) {
        let plugins_handle = plugins_handle.clone();
        tokio::spawn(async move {
            let engine = match plugins_cfg {
                Some(pc) => PluginEngine::new(&pc).ok(),
                None => None,
            };
            *plugins_handle.write().await = engine;
            tracing::info!("Plugin engine reloaded from new config");
        });
    }

    /// Update security manager
    fn update_security_manager(
        security_handle: &Arc<RwLock<Option<SecurityManager>>>,
        security_cfg: Option<crate::security::SecurityConfig>,
    ) {
        let security_handle = security_handle.clone();
        tokio::spawn(async move {
            let mgr = security_cfg.map(crate::security::SecurityManager::new);
            *security_handle.write().await = mgr;
            tracing::info!("Security manager reloaded from new config");
        });
    }

    /// Restart monitoring server with new configuration
    fn restart_monitoring_server(
        metrics_handle: &Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
        monitoring_cfg: crate::config::MonitoringConfig,
    ) {
        let metrics_handle = metrics_handle.clone();
        tokio::spawn(async move {
            // Abort previous server if running
            if let Some(handle) = metrics_handle.write().await.take() {
                handle.abort();
            }
            match monitoring::start_metrics_server(monitoring_cfg).await {
                Ok(new_handle) => {
                    *metrics_handle.write().await = Some(new_handle);
                    tracing::info!("Monitoring server restarted with new config");
                }
                Err(e) => {
                    tracing::error!("Failed to restart monitoring server: {}", e);
                }
            }
        });
    }
}

/// Application initialization logic
pub mod app_init {
    use super::*;
    use crate::config::ConfigManager;
    use crate::logger::TrafficLogger;
    use crate::monitoring;
    use crate::monitoring::admin::{self, AdminState};
    use crate::proxy::{http_client, ProxyServer};
    use anyhow::Result;

    /// Initialize the complete application
    pub async fn initialize_app(
        config_path: &str,
        bind_addr: SocketAddr,
    ) -> Result<(ConfigManager, AppState, ProxyServer)> {
        // Load configuration with manager to support hot-reload
        let cfg_manager = ConfigManager::new(config_path).await?;
        let config = cfg_manager.get_config();
        tracing::info!("Loaded configuration from {}", config_path);

        // Initialize HTTP client pool from initial config
        http_client::init(config.http_client.as_ref());

        // Start monitoring server
        let metrics_handle = Arc::new(RwLock::new(Some(
            monitoring::start_metrics_server(config.monitoring.clone()).await?,
        )));

        // Create and start proxy server
        let mut traffic_logger = TrafficLogger::new(config.logging.clone());
        traffic_logger.initialize().await?;

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Create centralized app state
        let app_state = AppState::new(
            proxy_server.domain_config_handle(),
            proxy_server.load_balancer_handle(),
            proxy_server.routing_engine_handle(),
            proxy_server.plugins_handle(),
            proxy_server.security_handle(),
            metrics_handle,
            traffic_logger,
        );

        // Initialize admin state
        admin::init_admin(AdminState {
            config_path: std::path::PathBuf::from(config_path),
            domain_config: app_state.domain_handle.clone(),
            load_balancer: app_state.lb_handle.clone(),
            routing_engine: app_state.routing_handle.clone(),
            plugins: app_state.plugins_handle.clone(),
            security: app_state.security_handle.clone(),
        });

        Ok((cfg_manager, app_state, proxy_server))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::LoadBalancer;
    use crate::config::{DomainConfig, LoggingConfig, TargetConfig};

    #[tokio::test]
    async fn test_app_state_creation() {
        let domain_config = DomainConfig {
            intercept_domains: vec!["test.com".to_string()],
            exclude_domains: Some(vec![]),
            enable_wildcard: true,
        };

        let targets_config = TargetConfig::default();
        let logging_config = LoggingConfig::default();

        let domain_handle = Arc::new(std::sync::RwLock::new(domain_config));
        let lb_handle = Arc::new(RwLock::new(LoadBalancer::new(targets_config)));
        let routing_handle = Arc::new(RwLock::new(None));
        let plugins_handle = Arc::new(RwLock::new(None));
        let security_handle = Arc::new(RwLock::new(None));
        let metrics_handle = Arc::new(RwLock::new(None));
        let traffic_logger = TrafficLogger::new(logging_config);

        let app_state = AppState::new(
            domain_handle,
            lb_handle,
            routing_handle,
            plugins_handle,
            security_handle,
            metrics_handle,
            traffic_logger,
        );

        // Test that app_state can be cloned (required for sharing across tasks)
        let _cloned_state = app_state.clone();
    }

    #[tokio::test]
    async fn test_config_reload_hook_creation() {
        let domain_config = DomainConfig {
            intercept_domains: vec!["test.com".to_string()],
            exclude_domains: Some(vec![]),
            enable_wildcard: true,
        };

        let targets_config = TargetConfig::default();
        let logging_config = LoggingConfig::default();

        let domain_handle = Arc::new(std::sync::RwLock::new(domain_config));
        let lb_handle = Arc::new(RwLock::new(LoadBalancer::new(targets_config)));
        let routing_handle = Arc::new(RwLock::new(None));
        let plugins_handle = Arc::new(RwLock::new(None));
        let security_handle = Arc::new(RwLock::new(None));
        let metrics_handle = Arc::new(RwLock::new(None));
        let traffic_logger = TrafficLogger::new(logging_config);

        let app_state = AppState::new(
            domain_handle,
            lb_handle,
            routing_handle,
            plugins_handle,
            security_handle,
            metrics_handle,
            traffic_logger,
        );

        // Test that we can create a reload hook
        let _reload_hook = config_reload::setup_reload_hook(app_state);
    }
}
