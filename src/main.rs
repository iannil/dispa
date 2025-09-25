#![allow(dead_code)]
use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tokio::signal;
use tracing::{info, warn};
mod app_state;
mod balancer;
mod cache;
mod circuit_breaker;
mod config;
mod error;
mod graceful_shutdown;
mod logger;
mod monitoring;
mod plugins;
mod proxy;
mod retry;
mod routing;
mod security;
mod state;
mod tls;

use app_state::{app_init, config_reload};

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

    // Initialize application components
    let (mut cfg_manager, app_state, proxy_server) =
        app_init::initialize_app(&args.config, args.bind).await?;

    // Set up configuration reload hook
    let reload_hook = config_reload::setup_reload_hook(app_state.clone());
    cfg_manager.set_reload_hook(reload_hook);

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
