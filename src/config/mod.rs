//! # 配置管理模块
//!
//! 本模块提供了Dispa代理服务器的完整配置管理功能，包括：
//!
//! - TOML配置文件解析和验证
//! - 环境变量替换和扩展
//! - 配置热重载支持
//! - 类型安全的配置结构定义
//!
//! ## 配置结构
//!
//! 主配置包含以下子模块：
//! - `server`: 服务器基础配置（端口、工作线程等）
//! - `domains`: 域名拦截规则配置
//! - `targets`: 后端目标服务器配置
//! - `logging`: 日志记录配置
//! - `monitoring`: 监控和指标配置
//! - `cache`: 缓存配置（可选）
//! - `security`: 安全功能配置（可选）
//! - `plugins`: 插件系统配置（可选）
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use dispa::config::Config;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::from_file_with_env("config.toml").await?;
//! println!("服务器监听地址: {}", config.server.bind);
//! # Ok(())
//! # }
//! ```

pub mod cache; // 缓存配置模块
pub mod http_client; // HTTP客户端配置模块
pub mod logging; // 日志记录配置模块
pub mod manager; // 配置管理器和热重载模块
pub mod monitoring; // 监控配置模块
pub mod num_cpus; // CPU数量检测模块
pub mod plugins; // 插件配置模块
pub mod server; // 服务器配置模块
pub mod targets; // 目标服务器配置模块

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use tracing::{info, warn};

// Re-export all public types
pub use cache::{CacheConfig, CachePolicy};
pub use http_client::HttpClientConfig;
pub use logging::{DatabaseConfig, FileConfig, LoggingConfig, LoggingType};
pub use manager::ConfigManager;
pub use monitoring::MonitoringConfig;
pub use plugins::{PluginErrorStrategy, PluginStage, PluginType, PluginsConfig};
pub use server::{DomainConfig, ServerConfig};
pub use targets::{
    HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, Target, TargetConfig,
};

// Re-export external dependencies that are part of the config API
pub use crate::routing::RoutingConfig;
pub use crate::security::SecurityConfig;
pub use crate::tls::TlsConfig;

/// Dispa代理服务器主配置结构
///
/// 包含所有子系统的配置选项，支持TOML格式序列化和反序列化。
/// 可选配置项允许按需启用功能模块。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// 服务器基础配置（监听地址、工作线程等）
    pub server: ServerConfig,
    /// 域名拦截和路由规则配置
    pub domains: DomainConfig,
    /// 后端目标服务器配置和负载均衡设置
    pub targets: TargetConfig,
    /// 日志记录配置（文件/数据库存储）
    pub logging: LoggingConfig,
    /// 监控指标和健康检查配置
    pub monitoring: MonitoringConfig,
    /// TLS/SSL证书配置（可选）
    pub tls: Option<TlsConfig>,
    /// 高级路由规则配置（可选）
    pub routing: Option<RoutingConfig>,
    /// HTTP响应缓存配置（可选）
    pub cache: Option<CacheConfig>,
    /// 上游HTTP客户端连接池配置（可选）
    pub http_client: Option<HttpClientConfig>,
    /// 插件系统配置（可选）
    pub plugins: Option<PluginsConfig>,
    /// 安全认证和授权配置（可选）
    pub security: Option<SecurityConfig>,
}

impl Config {
    /// Load configuration from file with environment variable expansion
    pub async fn from_file_with_env<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path.as_ref()).await?;

        // Expand environment variables in the content
        let expanded_content = expand_env_vars(&content);

        let mut config: Config = toml::from_str(&expanded_content)?;

        // Post-process configuration
        config.apply_defaults();
        config.validate()?;

        info!("Configuration loaded from {:?}", path.as_ref());
        Ok(config)
    }

    /// Apply default values where needed
    fn apply_defaults(&mut self) {
        // Apply server defaults
        if self.server.workers.is_none() {
            self.server.workers = Some(num_cpus::get());
        }

        // Apply cache defaults if enabled
        if let Some(cache) = &mut self.cache {
            if !cache.enabled {
                // Disable metrics if cache is disabled
                cache.metrics_enabled = false;
            }
        }

        // Apply monitoring defaults
        if !self.monitoring.enabled {
            // Disable capacity monitoring if monitoring is disabled
            if let Some(capacity) = &mut self.monitoring.capacity {
                capacity.enabled = false;
            }
        }

        // Apply logging defaults based on log_type
        match self.logging.log_type {
            LoggingType::File => {
                if self.logging.file.is_none() {
                    self.logging.file = Some(FileConfig {
                        directory: "logs".to_string(),
                        rotation: true,
                        max_file_size: Some(1_000_000),
                    });
                }
            }
            LoggingType::Database => {
                if self.logging.database.is_none() {
                    self.logging.database = Some(DatabaseConfig {
                        url: "sqlite:data/traffic.db".to_string(),
                        max_connections: Some(10),
                        connection_timeout: Some(30),
                    });
                }
            }
            LoggingType::Both => {
                if self.logging.file.is_none() {
                    self.logging.file = Some(FileConfig {
                        directory: "logs".to_string(),
                        rotation: true,
                        max_file_size: Some(1_000_000),
                    });
                }
                if self.logging.database.is_none() {
                    self.logging.database = Some(DatabaseConfig {
                        url: "sqlite:data/traffic.db".to_string(),
                        max_connections: Some(10),
                        connection_timeout: Some(30),
                    });
                }
            }
        }
    }

    /// Validate the entire configuration
    pub fn validate(&self) -> Result<()> {
        // Validate individual sections
        self.targets.validate()?;
        self.logging.validate()?;
        self.monitoring.validate()?;

        if let Some(cache) = &self.cache {
            cache.validate()?;
        }

        if let Some(http_client) = &self.http_client {
            http_client.validate()?;
        }

        if let Some(plugins) = &self.plugins {
            plugins.validate()?;
        }

        // Validate domain configuration
        if self.domains.intercept_domains.is_empty()
            && self
                .domains
                .exclude_domains
                .as_ref()
                .is_none_or(|v| v.is_empty())
        {
            warn!("No domains configured for interception - proxy will handle all traffic");
        }

        // Validate server configuration
        if let Some(workers) = self.server.workers {
            if workers == 0 {
                return Err(anyhow::anyhow!("Server workers must be greater than 0"));
            }
        }

        if let Some(max_connections) = self.server.max_connections {
            if max_connections == 0 {
                return Err(anyhow::anyhow!(
                    "Server max_connections must be greater than 0"
                ));
            }
        }

        if let Some(timeout) = self.server.connection_timeout {
            if timeout == 0 {
                return Err(anyhow::anyhow!(
                    "Server connection_timeout must be greater than 0"
                ));
            }
        }

        // Cross-validation between configurations
        self.validate_cross_dependencies()?;

        Ok(())
    }

    /// Validate cross-dependencies between different configuration sections
    fn validate_cross_dependencies(&self) -> Result<()> {
        // If plugins are enabled and apply before domain match,
        // ensure this doesn't conflict with security settings
        if let Some(plugins) = &self.plugins {
            if plugins.enabled && plugins.apply_before_domain_match {
                if let Some(security) = &self.security {
                    if security.enabled {
                        warn!(
                            "Plugins run before domain matching while security is enabled. \
                            Ensure security rules are compatible with all traffic, not just intercepted domains."
                        );
                    }
                }
            }
        }

        // Validate monitoring and cache metrics consistency
        if let Some(cache) = &self.cache {
            if cache.enabled && cache.metrics_enabled && !self.monitoring.enabled {
                warn!(
                    "Cache metrics are enabled but monitoring is disabled. \
                    Cache metrics will not be available."
                );
            }
        }

        // Validate TLS and security compatibility
        if let Some(tls) = &self.tls {
            if let Some(security) = &self.security {
                if security.enabled && tls.cert_path.is_some() {
                    info!("Both TLS and security are enabled - ensure security rules account for HTTPS traffic");
                }
            }
        }

        Ok(())
    }

    /// Get effective number of workers
    #[allow(dead_code)]
    pub fn get_workers(&self) -> usize {
        self.server.workers.unwrap_or_else(num_cpus::get)
    }

    /// Check if caching is enabled
    #[allow(dead_code)]
    pub fn is_cache_enabled(&self) -> bool {
        self.cache.as_ref().is_some_and(|c| c.enabled)
    }

    /// Check if plugins are enabled
    #[allow(dead_code)]
    pub fn is_plugins_enabled(&self) -> bool {
        self.plugins.as_ref().is_some_and(|p| p.enabled)
    }

    /// Check if security is enabled
    #[allow(dead_code)]
    pub fn is_security_enabled(&self) -> bool {
        self.security.as_ref().is_some_and(|s| s.enabled)
    }

    /// Check if TLS is enabled
    #[allow(dead_code)]
    pub fn is_tls_enabled(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.cert_path.is_some())
    }
}

/// Expand environment variables in configuration content
/// Supports ${VAR} and ${VAR:-default} syntax
fn expand_env_vars(content: &str) -> String {
    let mut result = content.to_string();

    // Simple regex-like replacement for ${VAR} and ${VAR:-default}
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_expr = &result[start + 2..start + end];
            let replacement = if let Some(default_pos) = var_expr.find(":-") {
                let var_name = &var_expr[..default_pos];
                let default_value = &var_expr[default_pos + 2..];
                env::var(var_name).unwrap_or_else(|_| default_value.to_string())
            } else {
                env::var(var_expr).unwrap_or_else(|_| {
                    warn!(
                        "Environment variable '{}' not found, using empty string",
                        var_expr
                    );
                    String::new()
                })
            };

            result.replace_range(start..start + end + 1, &replacement);
        } else {
            break; // Malformed ${VAR expression
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper function to create a temporary config file
    fn create_temp_config_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();
        temp_file
    }

    #[tokio::test]
    async fn test_basic_config_loading() {
        let config_content = r#"
[server]
bind = "127.0.0.1:8080"

[domains]
intercept_domains = ["example.com"]
exclude_domains = []
wildcard_support = true

[[targets.targets]]
address = "http://localhost:3000"
weight = 1.0
name = "target1"
url = "http://localhost:3000"

[targets.load_balancing]
algorithm = "RoundRobin"
lb_type = "RoundRobin"

[targets.health_check]
enabled = true
interval = 30
timeout = 5
threshold = 3
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
level = "info"
format = "json"
output = "File"
log_type = "File"

[logging.file]
directory = "logs"
rotation = true
max_file_size = 1000000

[monitoring]
enabled = true
bind = "127.0.0.1:8081"
health_endpoint = "/health"
metrics_endpoint = "/metrics"
prometheus_enabled = true
metrics_port = 9090
health_check_port = 8081
"#;

        let temp_file = create_temp_config_file(config_content);
        let config = Config::from_file_with_env(temp_file.path()).await.unwrap();

        assert_eq!(config.domains.intercept_domains, vec!["example.com"]);
        assert_eq!(config.targets.targets.len(), 1);
        assert_eq!(config.targets.targets[0].address, "http://localhost:3000");
        assert!(config.logging.enabled);
        assert!(config.monitoring.enabled);
    }

    #[tokio::test]
    async fn test_env_var_expansion() {
        env::set_var("TEST_HOST", "127.0.0.1");
        env::set_var("TEST_PORT", "8080");

        let config_content = r#"
[server]
bind = "${TEST_HOST:-localhost}:${TEST_PORT:-8080}"

[domains]
intercept_domains = ["${TEST_HOST}"]
exclude_domains = []
wildcard_support = true

[[targets.targets]]
address = "http://${TEST_HOST:-localhost}:3000"
name = "target1"
url = "http://${TEST_HOST:-localhost}:3000"

[targets.load_balancing]
algorithm = "RoundRobin"
lb_type = "RoundRobin"

[targets.health_check]
enabled = true
interval = 30
timeout = 5
threshold = 3
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
level = "info"
format = "json"
output = "File"
log_type = "File"

[logging.file]
directory = "logs"
rotation = true
max_file_size = 1000000

[monitoring]
enabled = true
bind = "127.0.0.1:8081"
health_endpoint = "/health"
metrics_endpoint = "/metrics"
prometheus_enabled = true
metrics_port = 9090
health_check_port = 8081
"#;

        let temp_file = create_temp_config_file(config_content);
        let config = Config::from_file_with_env(temp_file.path()).await.unwrap();

        assert_eq!(config.server.bind.to_string(), "127.0.0.1:8080");
        assert_eq!(config.domains.intercept_domains, vec!["127.0.0.1"]);
        assert_eq!(config.targets.targets[0].address, "http://127.0.0.1:3000");

        // Clean up
        env::remove_var("TEST_HOST");
        env::remove_var("TEST_PORT");
    }

    #[tokio::test]
    async fn test_config_defaults() {
        let config_content = r#"
[server]
bind = "127.0.0.1:8080"

[domains]
intercept_domains = ["example.com"]
exclude_domains = []
wildcard_support = true

[[targets.targets]]
address = "http://localhost:3000"
name = "target1"
url = "http://localhost:3000"

[targets.load_balancing]
algorithm = "RoundRobin"
lb_type = "RoundRobin"

[targets.health_check]
enabled = true
interval = 30
timeout = 5
threshold = 3
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
level = "info"
format = "json"
output = "File"
log_type = "File"

[monitoring]
enabled = true
bind = "127.0.0.1:8081"
health_endpoint = "/health"
metrics_endpoint = "/metrics"
prometheus_enabled = true
metrics_port = 9090
health_check_port = 8081
"#;

        let temp_file = create_temp_config_file(config_content);
        let config = Config::from_file_with_env(temp_file.path()).await.unwrap();

        // Check defaults are applied
        assert!(config.server.workers.is_some());
        assert!(config.server.workers.unwrap() > 0);
        assert!(config.logging.file.is_some());
        assert_eq!(config.targets.targets[0].get_weight(), 1.0);
    }

    #[test]
    fn test_expand_env_vars() {
        env::set_var("TEST_VAR", "test_value");

        let content = "host = \"${TEST_VAR}\"";
        let result = expand_env_vars(content);
        assert_eq!(result, "host = \"test_value\"");

        let content_with_default = "host = \"${MISSING_VAR:-default_value}\"";
        let result = expand_env_vars(content_with_default);
        assert_eq!(result, "host = \"default_value\"");

        // Clean up
        env::remove_var("TEST_VAR");
    }

    #[tokio::test]
    async fn test_config_validation() {
        let invalid_config = r#"
[server]
bind = "127.0.0.1:8080"
workers = 0

[domains]
intercept_domains = []
exclude_domains = []
wildcard_support = true

[targets]
targets = []

[targets.load_balancing]
algorithm = "RoundRobin"
lb_type = "RoundRobin"

[targets.health_check]
enabled = true
interval = 30
timeout = 5
threshold = 3
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
level = "info"
format = "json"
output = "File"
log_type = "File"

[monitoring]
enabled = true
bind = "127.0.0.1:8081"
health_endpoint = "/health"
metrics_endpoint = "/metrics"
prometheus_enabled = true
metrics_port = 9090
health_check_port = 8081
"#;

        let temp_file = create_temp_config_file(invalid_config);
        let result = Config::from_file_with_env(temp_file.path()).await;

        // Should fail validation due to workers = 0 and empty targets
        assert!(result.is_err());
    }
}
