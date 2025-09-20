use anyhow::Result;
use std::time::Duration;
use reqwest::Client;
use tracing::{debug, error};

use crate::config::Target;

pub struct HealthChecker {
    client: Client,
}

impl HealthChecker {
    pub fn new(timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        Self { client }
    }

    pub async fn check_target(&self, target: &Target) -> bool {
        let health_url = format!("{}/health", target.url);

        match self.client.get(&health_url).send().await {
            Ok(response) => {
                let is_healthy = response.status().is_success();
                debug!("Health check for {}: {}", target.name,
                      if is_healthy { "healthy" } else { "unhealthy" });
                is_healthy
            }
            Err(e) => {
                debug!("Health check failed for {}: {}", target.name, e);
                false
            }
        }
    }

    pub async fn check_target_with_custom_path(&self, target: &Target, path: &str) -> bool {
        let health_url = format!("{}{}", target.url, path);

        match self.client.get(&health_url).send().await {
            Ok(response) => {
                response.status().is_success() || response.status().is_redirection()
            }
            Err(e) => {
                error!("Custom health check failed for {} at {}: {}", target.name, path, e);
                false
            }
        }
    }
}