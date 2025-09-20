use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::{Target, TargetConfig, LoadBalancingType};

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}

#[derive(Clone)]
pub struct LoadBalancer {
    targets: Vec<Target>,
    health_status: Arc<RwLock<Vec<HealthStatus>>>,
    config: TargetConfig,
    current_index: Arc<RwLock<usize>>,
}

impl LoadBalancer {
    pub fn new(config: TargetConfig) -> Self {
        let target_count = config.targets.len();
        let health_status = vec![HealthStatus::default(); target_count];

        let lb = Self {
            targets: config.targets.clone(),
            health_status: Arc::new(RwLock::new(health_status)),
            config,
            current_index: Arc::new(RwLock::new(0)),
        };

        // Start health checker if enabled
        if lb.config.health_check.enabled {
            let health_checker = lb.clone();
            tokio::spawn(async move {
                health_checker.run_health_checks().await;
            });
        }

        lb
    }

    pub async fn get_target(&self) -> Option<Target> {
        let health_status = self.health_status.read().await;
        let healthy_targets: Vec<(usize, &Target)> = self.targets
            .iter()
            .enumerate()
            .filter(|(i, _)| health_status[*i].is_healthy)
            .collect();

        if healthy_targets.is_empty() {
            warn!("No healthy targets available");
            return None;
        }

        let selected = match self.config.load_balancing.lb_type {
            LoadBalancingType::RoundRobin => {
                self.round_robin_select(&healthy_targets).await
            }
            LoadBalancingType::Weighted => {
                self.weighted_select(&healthy_targets).await
            }
            LoadBalancingType::Random => {
                self.random_select(&healthy_targets).await
            }
            LoadBalancingType::LeastConnections => {
                // For simplicity, fallback to round robin
                // In production, you'd track active connections per target
                self.round_robin_select(&healthy_targets).await
            }
        };

        selected.map(|target| target.clone())
    }

    async fn round_robin_select<'a>(&self, healthy_targets: &'a [(usize, &Target)]) -> Option<&'a Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        let mut current_index = self.current_index.write().await;
        *current_index = (*current_index + 1) % healthy_targets.len();
        Some(healthy_targets[*current_index].1)
    }

    async fn weighted_select<'a>(&self, healthy_targets: &'a [(usize, &Target)]) -> Option<&'a Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        let total_weight: u32 = healthy_targets
            .iter()
            .map(|(_, target)| target.weight.unwrap_or(1))
            .sum();

        if total_weight == 0 {
            return self.round_robin_select(healthy_targets).await;
        }

        // Simple weighted selection - in production you might use a more sophisticated algorithm
        let random_weight = (Instant::now().elapsed().as_nanos() % total_weight as u128) as u32;
        let mut cumulative_weight = 0;

        for (_, target) in healthy_targets {
            cumulative_weight += target.weight.unwrap_or(1);
            if random_weight < cumulative_weight {
                return Some(target);
            }
        }

        // Fallback to first target
        Some(healthy_targets[0].1)
    }

    async fn random_select<'a>(&self, healthy_targets: &'a [(usize, &Target)]) -> Option<&'a Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        let index = (Instant::now().elapsed().as_nanos() % healthy_targets.len() as u128) as usize;
        Some(healthy_targets[index].1)
    }

    async fn run_health_checks(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(
            self.config.health_check.interval
        ));

        loop {
            interval.tick().await;
            self.check_all_targets().await;
        }
    }

    async fn check_all_targets(&self) {
        let mut health_status = self.health_status.write().await;

        for (i, target) in self.targets.iter().enumerate() {
            let is_healthy = self.check_target_health(target).await;
            let status = &mut health_status[i];

            if is_healthy {
                status.consecutive_failures = 0;
                status.consecutive_successes += 1;

                if !status.is_healthy &&
                   status.consecutive_successes >= self.config.health_check.healthy_threshold {
                    status.is_healthy = true;
                    debug!("Target {} is now healthy", target.name);
                }
            } else {
                status.consecutive_successes = 0;
                status.consecutive_failures += 1;

                if status.is_healthy &&
                   status.consecutive_failures >= self.config.health_check.unhealthy_threshold {
                    status.is_healthy = false;
                    warn!("Target {} is now unhealthy", target.name);
                }
            }

            status.last_check = Instant::now();
        }
    }

    async fn check_target_health(&self, target: &Target) -> bool {
        let timeout = Duration::from_secs(self.config.health_check.timeout);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();

        // Simple HTTP GET to root path for health check
        let health_url = format!("{}/", target.url);

        match client.get(&health_url).send().await {
            Ok(response) => {
                let status = response.status();
                status.is_success() || status.is_redirection()
            }
            Err(e) => {
                debug!("Health check failed for target {}: {}", target.name, e);
                false
            }
        }
    }

    pub async fn get_health_status(&self) -> Vec<(String, bool)> {
        let health_status = self.health_status.read().await;
        self.targets
            .iter()
            .zip(health_status.iter())
            .map(|(target, status)| (target.name.clone(), status.is_healthy))
            .collect()
    }
}