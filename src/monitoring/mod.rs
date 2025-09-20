pub mod metrics;
pub mod health;

use anyhow::Result;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

use crate::config::MonitoringConfig;

pub async fn start_metrics_server(config: MonitoringConfig) -> Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        if let Err(e) = metrics::run_metrics_server(config).await {
            tracing::error!("Metrics server error: {}", e);
        }
    });

    Ok(handle)
}