use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};

mod balancer;
mod cache;
mod circuit_breaker;
mod config;
mod error;
mod graceful_shutdown;
mod logger;
mod monitoring;
mod proxy;
mod plugins;
mod retry;
mod routing;
mod tls;
mod security;

use config::{Config, ConfigManager};
use crate::plugins::PluginEngine;
use crate::proxy::http_client;
use proxy::ProxyServer;
use crate::monitoring::admin::{self, AdminState};

/// Shared application state to reduce Arc cloning
#[derive(Clone)]
struct AppState {
    pub domain_handle: Arc<std::sync::RwLock<config::DomainConfig>>,
    pub lb_handle: Arc<tokio::sync::RwLock<balancer::LoadBalancer>>,
    pub routing_handle: Arc<tokio::sync::RwLock<Option<routing::RoutingEngine>>>,
    pub plugins_handle: Arc<tokio::sync::RwLock<Option<plugins::PluginEngine>>>,
    pub security_handle: Arc<tokio::sync::RwLock<Option<security::SecurityManager>>>,
    pub metrics_handle: Arc<tokio::sync::RwLock<Option<tokio::task::JoinHandle<()>>>>,
    pub traffic_logger: logger::TrafficLogger,
}

#[derive(Parser)]
#[command(name = "dispa")]
#[command(about = "A high-performance traffic interception and forwarding proxy")]
struct Args {
    #[arg(short, long, default_value = "config/config.toml")]
    config: String,

    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("dispa={},tower_http=debug", level))
        .init();

    info!("Starting dispa traffic interceptor");

    // Load configuration with manager to support hot-reload
    let mut cfg_manager = ConfigManager::new(&args.config).await?;
    let config = cfg_manager.get_config();
    info!("Loaded configuration from {}", args.config);
    // Initialize HTTP client pool from initial config
    http_client::init(config.http_client.as_ref());

    // Start monitoring server (track handle for hot-reload restart)
    let metrics_handle = Arc::new(tokio::sync::RwLock::new(Some(
        monitoring::start_metrics_server(config.monitoring.clone()).await?,
    )));

    // Create and start proxy server
    let mut traffic_logger = logger::TrafficLogger::new(config.logging.clone());
    traffic_logger.initialize().await?;

    let proxy_server = ProxyServer::new(config, args.bind, traffic_logger.clone());

    // Create app state to centralize shared handles
    let app_state = AppState {
        domain_handle: proxy_server.domain_config_handle(),
        lb_handle: proxy_server.load_balancer_handle(),
        routing_handle: proxy_server.routing_engine_handle(),
        plugins_handle: proxy_server.plugins_handle(),
        security_handle: proxy_server.security_handle(),
        metrics_handle,
        traffic_logger,
    };

    // Initialize admin state with references from app_state
    admin::init_admin(AdminState{
        config_path: std::path::PathBuf::from(&args.config),
        domain_config: app_state.domain_handle.clone(),
        load_balancer: app_state.lb_handle.clone(),
        routing_engine: app_state.routing_handle.clone(),
        plugins: app_state.plugins_handle.clone(),
        security: app_state.security_handle.clone(),
    });

    // Cluster support removed

    // Set reload hook now that we have handles
    let state_for_reload = app_state.clone();
    cfg_manager.set_reload_hook(move |cfg: &Config| {
        // Re-init HTTP client pool
        http_client::init(cfg.http_client.as_ref());
        tracing::info!("HTTP client pool re-initialized from reloaded config");

        // Rebuild load balancer
        let lb_handle = state_for_reload.lb_handle.clone();
        let targets = cfg.targets.clone();
        tokio::spawn(async move {
            let new_lb = crate::balancer::LoadBalancer::new(targets);
            let mut guard = lb_handle.write().await;
            *guard = new_lb;
            tracing::info!("Load balancer reloaded from new config");
        });

        // Update routing engine from new config
        let routing_handle = state_for_reload.routing_handle.clone();
        let routing_cfg = cfg.routing.clone();
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

        // Update domain intercept config
        let domain_cfg = cfg.domains.clone();
        let domain_handle = state_for_reload.domain_handle.clone();
        tokio::spawn(async move {
            if let Ok(mut guard) = domain_handle.write() {
                *guard = domain_cfg;
                tracing::info!("Domain configuration reloaded from new config");
            }
        });

        // Reconfigure traffic logger
        let logger = state_for_reload.traffic_logger.clone();
        let log_cfg = cfg.logging.clone();
        tokio::spawn(async move {
            if let Err(e) = logger.reconfigure(log_cfg).await {
                tracing::warn!("Failed to reconfigure traffic logger: {}", e);
            } else {
                tracing::info!("Traffic logger reconfigured successfully");
            }
        });

        // Rebuild plugin engine
        let plugins_cfg = cfg.plugins.clone();
        let plugins_handle = state_for_reload.plugins_handle.clone();
        tokio::spawn(async move {
            let engine = match plugins_cfg {
                Some(pc) => PluginEngine::new(&pc).ok(),
                None => None,
            };
            *plugins_handle.write().await = engine;
            tracing::info!("Plugin engine reloaded from new config");
        });

        // Rebuild security manager
        let security_cfg = cfg.security.clone();
        let security_handle = state_for_reload.security_handle.clone();
        tokio::spawn(async move {
            let mgr = match security_cfg {
                Some(sc) => Some(crate::security::SecurityManager::new(sc)),
                None => None,
            };
            *security_handle.write().await = mgr;
            tracing::info!("Security manager reloaded from new config");
        });

        // Restart monitoring server with new ports (best-effort)
        let monitoring_cfg = cfg.monitoring.clone();
        let metrics_handle = state_for_reload.metrics_handle.clone();
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

        // Cluster support removed
    });

    // Start watching for config changes (best-effort)
    if let Err(e) = cfg_manager.start_hot_reload().await {
        tracing::warn!("Failed to start config hot-reload: {}", e);
    }

    // Setup graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        warn!("Received CTRL+C, shutting down gracefully...");
    };

    // Run the proxy server with graceful shutdown
    tokio::select! {
        result = proxy_server.run() => {
            if let Err(e) = result {
                tracing::error!("Proxy server error: {}", e);
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received");
        }
    }

    info!("Dispa shutdown complete");
    Ok(())
}
