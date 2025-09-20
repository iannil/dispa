use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tokio::signal;
use tracing::{info, warn};

mod balancer;
mod circuit_breaker;
mod config;
mod error;
mod graceful_shutdown;
mod logger;
mod monitoring;
mod proxy;
mod retry;
mod routing;
mod tls;

use config::Config;
use proxy::ProxyServer;

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

    // Load configuration
    let config = Config::from_file(&args.config).await?;
    info!("Loaded configuration from {}", args.config);

    // Start monitoring server
    let _monitoring_handle = monitoring::start_metrics_server(config.monitoring.clone()).await?;

    // Create and start proxy server
    let mut traffic_logger = logger::TrafficLogger::new(config.logging.clone());
    traffic_logger.initialize().await?;

    let proxy_server = ProxyServer::new(config, args.bind, traffic_logger);

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
