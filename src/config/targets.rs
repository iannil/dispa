#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Target servers configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TargetConfig {
    pub targets: Vec<Target>,
    pub load_balancing: LoadBalancingConfig,
    pub health_check: HealthCheckConfig,
}

/// Individual target server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Target {
    pub address: String,
    pub weight: Option<f64>,
    pub timeout: Option<u64>, // seconds
    pub name: String,         // Target identifier
    pub url: String,          // Effective URL for health checks and forwarding
}

/// Load balancing configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoadBalancingConfig {
    pub algorithm: LoadBalancingType,
    pub lb_type: LoadBalancingType, // Alias for algorithm
    pub sticky_sessions: Option<bool>,
}

/// Load balancing algorithms
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub enum LoadBalancingType {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    Weighted, // Alias for WeightedRoundRobin
    LeastConnections,
    Random,
}

/// Health check configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval: u64,            // seconds
    pub timeout: u64,             // seconds
    pub threshold: usize,         // consecutive failures before marking unhealthy
    pub healthy_threshold: u32,   // consecutive successes before marking healthy
    pub unhealthy_threshold: u32, // consecutive failures before marking unhealthy
}

impl Default for LoadBalancingConfig {
    fn default() -> Self {
        Self {
            algorithm: LoadBalancingType::default(),
            lb_type: LoadBalancingType::default(),
            sticky_sessions: Some(false),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: 30,
            timeout: 5,
            threshold: 3,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        }
    }
}

impl TargetConfig {
    /// Validate target configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.targets.is_empty() {
            return Err(anyhow::anyhow!("At least one target must be configured"));
        }

        for target in &self.targets {
            target.validate()?;
        }

        self.health_check.validate()?;

        Ok(())
    }
}

impl Target {
    /// Validate target configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.address.is_empty() {
            return Err(anyhow::anyhow!("Target address cannot be empty"));
        }

        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Target name cannot be empty"));
        }

        // Basic URL validation
        if !self.address.starts_with("http://") && !self.address.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "Target address must be a valid HTTP/HTTPS URL: {}",
                self.address
            ));
        }

        if let Some(weight) = self.weight {
            if weight <= 0.0 {
                return Err(anyhow::anyhow!(
                    "Target weight must be positive: {}",
                    weight
                ));
            }
        }

        if let Some(timeout) = self.timeout {
            if timeout == 0 {
                return Err(anyhow::anyhow!("Target timeout must be greater than 0"));
            }
        }

        Ok(())
    }

    /// Get the weight for this target (default: 1.0)
    pub fn get_weight(&self) -> f64 {
        self.weight.unwrap_or(1.0)
    }

    /// Get the timeout for this target
    pub fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout.unwrap_or(30))
    }
}

impl HealthCheckConfig {
    /// Validate health check configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.interval == 0 {
            return Err(anyhow::anyhow!(
                "Health check interval must be greater than 0"
            ));
        }

        if self.timeout == 0 {
            return Err(anyhow::anyhow!(
                "Health check timeout must be greater than 0"
            ));
        }

        if self.timeout >= self.interval {
            return Err(anyhow::anyhow!(
                "Health check timeout ({}) must be less than interval ({})",
                self.timeout,
                self.interval
            ));
        }

        if self.threshold == 0 {
            return Err(anyhow::anyhow!(
                "Health check threshold must be greater than 0"
            ));
        }

        if self.healthy_threshold == 0 {
            return Err(anyhow::anyhow!(
                "Health check healthy_threshold must be greater than 0"
            ));
        }

        if self.unhealthy_threshold == 0 {
            return Err(anyhow::anyhow!(
                "Health check unhealthy_threshold must be greater than 0"
            ));
        }

        Ok(())
    }

    /// Get the interval as Duration
    pub fn get_interval(&self) -> Duration {
        Duration::from_secs(self.interval)
    }

    /// Get the timeout as Duration
    pub fn get_timeout(&self) -> Duration {
        Duration::from_secs(self.timeout)
    }
}
