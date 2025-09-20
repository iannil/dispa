use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub domains: DomainConfig,
    pub targets: TargetConfig,
    pub logging: LoggingConfig,
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind_address: SocketAddr,
    pub workers: Option<usize>,
    pub keep_alive_timeout: Option<u64>,
    pub request_timeout: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
    pub intercept_domains: Vec<String>,
    pub exclude_domains: Option<Vec<String>>,
    pub wildcard_support: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TargetConfig {
    pub targets: Vec<Target>,
    pub load_balancing: LoadBalancingConfig,
    pub health_check: HealthCheckConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Target {
    pub name: String,
    pub url: String,
    pub weight: Option<u32>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoadBalancingConfig {
    #[serde(rename = "type")]
    pub lb_type: LoadBalancingType,
    pub sticky_sessions: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoadBalancingType {
    RoundRobin,
    Weighted,
    LeastConnections,
    Random,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval: u64,
    pub timeout: u64,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    #[serde(rename = "type")]
    pub log_type: LoggingType,
    pub database: Option<DatabaseConfig>,
    pub file: Option<FileConfig>,
    pub retention_days: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingType {
    Database,
    File,
    Both,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileConfig {
    pub directory: String,
    pub max_file_size: Option<u64>,
    pub rotation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub metrics_port: u16,
    pub health_check_port: u16,
}

impl Config {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.domains.intercept_domains.is_empty() {
            return Err(anyhow::anyhow!("At least one intercept domain must be specified"));
        }

        if self.targets.targets.is_empty() {
            return Err(anyhow::anyhow!("At least one target must be specified"));
        }

        for target in &self.targets.targets {
            if target.url.is_empty() {
                return Err(anyhow::anyhow!("Target URL cannot be empty"));
            }
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        Config {
            server: ServerConfig {
                bind_address: "0.0.0.0:8080".parse().unwrap(),
                workers: Some(4),
                keep_alive_timeout: Some(60),
                request_timeout: Some(30),
            },
            domains: DomainConfig {
                intercept_domains: vec!["example.com".to_string()],
                exclude_domains: None,
                wildcard_support: true,
            },
            targets: TargetConfig {
                targets: vec![Target {
                    name: "default".to_string(),
                    url: "http://localhost:3000".to_string(),
                    weight: Some(1),
                    timeout: Some(30),
                }],
                load_balancing: LoadBalancingConfig {
                    lb_type: LoadBalancingType::RoundRobin,
                    sticky_sessions: false,
                },
                health_check: HealthCheckConfig {
                    enabled: true,
                    interval: 30,
                    timeout: 10,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                },
            },
            logging: LoggingConfig {
                enabled: true,
                log_type: LoggingType::File,
                database: None,
                file: Some(FileConfig {
                    directory: "./logs".to_string(),
                    max_file_size: Some(100_000_000), // 100MB
                    rotation: true,
                }),
                retention_days: Some(30),
            },
            monitoring: MonitoringConfig {
                enabled: true,
                metrics_port: 9090,
                health_check_port: 8081,
            },
        }
    }
}