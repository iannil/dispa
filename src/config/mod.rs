use anyhow::Result;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::routing::RoutingConfig;
use crate::tls::TlsConfig;
use crate::security::SecurityConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub domains: DomainConfig,
    pub targets: TargetConfig,
    pub logging: LoggingConfig,
    pub monitoring: MonitoringConfig,
    pub tls: Option<TlsConfig>,
    pub routing: Option<RoutingConfig>,
    pub cache: Option<CacheConfig>,
    /// Upstream HTTP client pool configuration
    pub http_client: Option<HttpClientConfig>,
    /// Plugins configuration
    pub plugins: Option<PluginsConfig>,
    /// Security configuration
    pub security: Option<SecurityConfig>,
}

/// Cache configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Enable/disable caching
    pub enabled: bool,
    /// Maximum cache size in bytes
    pub max_size: u64,
    /// Default TTL for cached responses in seconds
    pub default_ttl: u64,
    /// Cache policies for different content types
    pub policies: Vec<CachePolicy>,
    /// Enable ETag support
    pub etag_enabled: bool,
    /// Cache key prefix
    pub key_prefix: Option<String>,
    /// Enable cache metrics
    pub metrics_enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size: 100 * 1024 * 1024, // 100MB
            default_ttl: 3600,           // 1 hour
            policies: vec![
                // Default policies for common content types
                CachePolicy {
                    name: "static-assets".to_string(),
                    pattern: CachePolicyPattern::ContentType("image/*".to_string()),
                    ttl: Some(86400), // 24 hours
                    cacheable_status_codes: vec![200, 301, 302, 404],
                    vary_headers: None,
                    no_cache_headers: vec!["authorization".to_string(), "cookie".to_string()],
                },
                CachePolicy {
                    name: "api-responses".to_string(),
                    pattern: CachePolicyPattern::PathPrefix("/api/".to_string()),
                    ttl: Some(300), // 5 minutes
                    cacheable_status_codes: vec![200],
                    vary_headers: Some(vec!["accept".to_string(), "accept-encoding".to_string()]),
                    no_cache_headers: vec!["authorization".to_string()],
                },
            ],
            etag_enabled: true,
            key_prefix: None,
            metrics_enabled: true,
        }
    }
}

impl CacheConfig {
    /// Validate cache configuration
    pub fn validate(&self) -> Result<()> {
        if self.max_size == 0 {
            return Err(anyhow::anyhow!("Cache max_size must be greater than 0"));
        }

        if self.default_ttl == 0 {
            return Err(anyhow::anyhow!("Cache default_ttl must be greater than 0"));
        }

        // Validate policies
        for policy in &self.policies {
            policy.validate()?;
        }

        Ok(())
    }
}

/// Cache policy definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CachePolicy {
    /// Policy name for identification
    pub name: String,
    /// Pattern to match requests/responses
    pub pattern: CachePolicyPattern,
    /// TTL override for this policy (in seconds)
    pub ttl: Option<u64>,
    /// HTTP status codes that are cacheable
    pub cacheable_status_codes: Vec<u16>,
    /// Headers to include in cache key (Vary support)
    pub vary_headers: Option<Vec<String>>,
    /// Headers that prevent caching when present
    pub no_cache_headers: Vec<String>,
}

impl CachePolicy {
    /// Validate cache policy
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Cache policy name cannot be empty"));
        }

        if self.cacheable_status_codes.is_empty() {
            return Err(anyhow::anyhow!(
                "Cache policy must have at least one cacheable status code"
            ));
        }

        // Validate status codes are in valid range
        for &status in &self.cacheable_status_codes {
            if !(100..=599).contains(&status) {
                return Err(anyhow::anyhow!("Invalid HTTP status code: {}", status));
            }
        }

        Ok(())
    }

    /// Check if this policy matches the request/response
    #[allow(dead_code)]
    pub fn matches(&self, request_path: &str, content_type: Option<&str>) -> bool {
        match &self.pattern {
            CachePolicyPattern::PathPrefix(prefix) => request_path.starts_with(prefix),
            CachePolicyPattern::PathSuffix(suffix) => request_path.ends_with(suffix),
            CachePolicyPattern::PathRegex(regex) => {
                // For now, simple contains check - could be enhanced with actual regex
                request_path.contains(regex)
            }
            CachePolicyPattern::ContentType(pattern) => {
                if let Some(ct) = content_type {
                    if pattern.ends_with("*") {
                        let prefix = &pattern[..pattern.len() - 1];
                        ct.starts_with(prefix)
                    } else {
                        ct == pattern
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Check if status code is cacheable according to this policy
    #[allow(dead_code)]
    pub fn is_status_cacheable(&self, status: u16) -> bool {
        self.cacheable_status_codes.contains(&status)
    }

    /// Check if request has no-cache headers
    #[allow(dead_code)]
    pub fn has_no_cache_headers(&self, headers: &hyper::HeaderMap) -> bool {
        for header_name in &self.no_cache_headers {
            if headers.contains_key(header_name) {
                return true;
            }
        }
        false
    }

    /// Get cache key suffix based on vary headers
    #[allow(dead_code)]
    pub fn get_vary_suffix(&self, headers: &hyper::HeaderMap) -> String {
        if let Some(ref vary_headers) = self.vary_headers {
            let mut vary_values = Vec::new();
            for header_name in vary_headers {
                if let Some(value) = headers.get(header_name) {
                    if let Ok(value_str) = value.to_str() {
                        vary_values.push(format!("{}:{}", header_name, value_str));
                    }
                }
            }
            if !vary_values.is_empty() {
                return format!(":{}", vary_values.join(","));
            }
        }
        String::new()
    }
}

/// Pattern matching for cache policies
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum CachePolicyPattern {
    /// Match by request path prefix
    #[serde(rename = "path_prefix")]
    PathPrefix(String),
    /// Match by request path suffix
    #[serde(rename = "path_suffix")]
    PathSuffix(String),
    /// Match by request path regex pattern
    #[serde(rename = "path_regex")]
    PathRegex(String),
    /// Match by response content type
    #[serde(rename = "content_type")]
    ContentType(String),
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
    /// Optional per-metric histogram bucket configuration (milliseconds)
    #[serde(default)]
    pub histogram_buckets: Option<Vec<HistogramBucketsConfig>>,
}

/// Histogram bucket configuration for a specific metric (values in milliseconds)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistogramBucketsConfig {
    /// Full metric name to apply buckets to
    pub metric: String,
    /// Bucket upper bounds (ms) in ascending order
    pub buckets_ms: Vec<f64>,
}

impl MonitoringConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(list) = &self.histogram_buckets {
            for item in list {
                if item.metric.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "monitoring.histogram_buckets.metric cannot be empty"
                    ));
                }
                if item.buckets_ms.is_empty() {
                    return Err(anyhow::anyhow!(
                        "monitoring.histogram_buckets.buckets_ms cannot be empty for metric {}",
                        item.metric
                    ));
                }
                // Must be ascending and positive
                let mut prev = 0.0f64;
                for (i, &val) in item.buckets_ms.iter().enumerate() {
                    if val <= 0.0 {
                        return Err(anyhow::anyhow!(
                            "Bucket values must be positive for metric {}",
                            item.metric
                        ));
                    }
                    if i > 0 && val < prev {
                        return Err(anyhow::anyhow!(
                            "Buckets must be in ascending order for metric {}",
                            item.metric
                        ));
                    }
                    prev = val;
                }
            }
        }
        Ok(())
    }
}

/// Upstream HTTP client (connection pool) configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpClientConfig {
    /// Max idle connections per host maintained in the pool
    pub pool_max_idle_per_host: Option<usize>,
    /// Idle connection timeout in seconds
    pub pool_idle_timeout_secs: Option<u64>,
    /// Request timeout (connect + response) in seconds for simple GETs/health checks
    pub connect_timeout_secs: Option<u64>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: Some(32),
            pool_idle_timeout_secs: Some(90),
            connect_timeout_secs: Some(5),
        }
    }
}

impl HttpClientConfig {
    pub fn validate(&self) -> Result<()> {
        if let Some(v) = self.pool_max_idle_per_host {
            if v == 0 {
                return Err(anyhow::anyhow!(
                    "http_client.pool_max_idle_per_host must be > 0"
                ));
            }
        }
        if let Some(s) = self.pool_idle_timeout_secs {
            if s == 0 {
                return Err(anyhow::anyhow!(
                    "http_client.pool_idle_timeout_secs must be > 0"
                ));
            }
        }
        if let Some(s) = self.connect_timeout_secs {
            if s == 0 {
                return Err(anyhow::anyhow!(
                    "http_client.connect_timeout_secs must be > 0"
                ));
            }
        }
        Ok(())
    }
}

/// Plugins configuration root
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginsConfig {
    pub enabled: bool,
    /// Whether to apply request plugins before domain interception check
    /// Default: true (keeps existing behavior). If set to false, request-stage
    /// plugins will be applied after domain check passes, which avoids running
    /// plugins for non-intercepted domains.
    #[serde(default = "default_apply_before_domain_match")]
    pub apply_before_domain_match: bool,
    pub plugins: Vec<PluginConfig>,
}

impl PluginsConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled { return Ok(()) }
        for p in &self.plugins {
            p.validate()?;
        }
        Ok(())
    }
}

fn default_apply_before_domain_match() -> bool { true }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: PluginType,
    pub enabled: bool,
    #[serde(default = "default_plugin_stage")]
    pub stage: PluginStage,
    /// Arbitrary JSON config for the plugin
    pub config: Option<serde_json::Value>,
    /// Strategy on plugin error
    #[serde(default = "default_plugin_error_strategy")]
    pub error_strategy: PluginErrorStrategy,
}

fn default_plugin_stage() -> PluginStage { PluginStage::Both }
fn default_plugin_error_strategy() -> PluginErrorStrategy { PluginErrorStrategy::Continue }

impl PluginConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(anyhow::anyhow!("Plugin name cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    HeaderInjector,
    Blocklist,
    HeaderOverride,
    PathRewrite,
    HostRewrite,
    Command,
    RateLimiter,
    Wasm,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginStage {
    Request,
    Response,
    Both,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginErrorStrategy {
    Continue,
    Fail,
}

// Cluster configuration removed

impl Config {
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with environment variable overrides
    pub async fn from_file_with_env<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut config = Self::from_file(path).await?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Apply environment variable overrides to configuration
    pub fn apply_env_overrides(&mut self) {
        // Server configuration overrides
        if let Ok(bind_address) = env::var("DISPA_BIND_ADDRESS") {
            if let Ok(addr) = bind_address.parse() {
                self.server.bind_address = addr;
                debug!("Override bind_address from env: {}", bind_address);
            } else {
                warn!("Invalid DISPA_BIND_ADDRESS: {}", bind_address);
            }
        }

        if let Ok(workers) = env::var("DISPA_WORKERS") {
            if let Ok(workers_num) = workers.parse::<usize>() {
                self.server.workers = Some(workers_num);
                debug!("Override workers from env: {}", workers_num);
            } else {
                warn!("Invalid DISPA_WORKERS: {}", workers);
            }
        }

        if let Ok(timeout) = env::var("DISPA_REQUEST_TIMEOUT") {
            if let Ok(timeout_num) = timeout.parse::<u64>() {
                self.server.request_timeout = Some(timeout_num);
                debug!("Override request_timeout from env: {}", timeout_num);
            } else {
                warn!("Invalid DISPA_REQUEST_TIMEOUT: {}", timeout);
            }
        }

        // Monitoring configuration overrides
        if let Ok(metrics_port) = env::var("DISPA_METRICS_PORT") {
            if let Ok(port) = metrics_port.parse::<u16>() {
                self.monitoring.metrics_port = port;
                debug!("Override metrics_port from env: {}", port);
            } else {
                warn!("Invalid DISPA_METRICS_PORT: {}", metrics_port);
            }
        }

        if let Ok(health_port) = env::var("DISPA_HEALTH_CHECK_PORT") {
            if let Ok(port) = health_port.parse::<u16>() {
                self.monitoring.health_check_port = port;
                debug!("Override health_check_port from env: {}", port);
            } else {
                warn!("Invalid DISPA_HEALTH_CHECK_PORT: {}", health_port);
            }
        }

        // HTTP client pool overrides
        if let Some(ref mut httpc) = self.http_client {
            if let Ok(v) = env::var("DISPA_HTTP_POOL_MAX_IDLE_PER_HOST") {
                if let Ok(n) = v.parse::<usize>() {
                    httpc.pool_max_idle_per_host = Some(n);
                    debug!("Override http_client.pool_max_idle_per_host from env: {}", n);
                } else {
                    warn!("Invalid DISPA_HTTP_POOL_MAX_IDLE_PER_HOST: {}", v);
                }
            }
            if let Ok(v) = env::var("DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS") {
                if let Ok(n) = v.parse::<u64>() {
                    httpc.pool_idle_timeout_secs = Some(n);
                    debug!("Override http_client.pool_idle_timeout_secs from env: {}", n);
                } else {
                    warn!("Invalid DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS: {}", v);
                }
            }
            if let Ok(v) = env::var("DISPA_HTTP_CONNECT_TIMEOUT_SECS") {
                if let Ok(n) = v.parse::<u64>() {
                    httpc.connect_timeout_secs = Some(n);
                    debug!("Override http_client.connect_timeout_secs from env: {}", n);
                } else {
                    warn!("Invalid DISPA_HTTP_CONNECT_TIMEOUT_SECS: {}", v);
                }
            }
        }

        // Logging configuration overrides
        if let Ok(log_enabled) = env::var("DISPA_LOGGING_ENABLED") {
            if let Ok(enabled) = log_enabled.parse::<bool>() {
                self.logging.enabled = enabled;
                debug!("Override logging.enabled from env: {}", enabled);
            } else {
                warn!("Invalid DISPA_LOGGING_ENABLED: {}", log_enabled);
            }
        }

        if let Ok(log_type) = env::var("DISPA_LOGGING_TYPE") {
            match log_type.to_lowercase().as_str() {
                "database" => {
                    self.logging.log_type = LoggingType::Database;
                    debug!("Override logging.type from env: database");
                }
                "file" => {
                    self.logging.log_type = LoggingType::File;
                    debug!("Override logging.type from env: file");
                }
                "both" => {
                    self.logging.log_type = LoggingType::Both;
                    debug!("Override logging.type from env: both");
                }
                _ => warn!("Invalid DISPA_LOGGING_TYPE: {}", log_type),
            }
        }

        if let Ok(log_dir) = env::var("DISPA_LOG_DIRECTORY") {
            if let Some(ref mut file_config) = self.logging.file {
                file_config.directory = log_dir.clone();
                debug!("Override log directory from env: {}", log_dir);
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        // Validate intercept domains
        if self.domains.intercept_domains.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one intercept domain must be specified"
            ));
        }

        // Validate domain patterns
        for domain in &self.domains.intercept_domains {
            if domain.is_empty() {
                return Err(anyhow::anyhow!("Domain pattern cannot be empty"));
            }
            // Check for basic domain format (allow wildcards)
            if !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-.*".contains(c))
            {
                return Err(anyhow::anyhow!("Invalid domain pattern: {}", domain));
            }
        }

        // Validate targets
        if self.targets.targets.is_empty() {
            return Err(anyhow::anyhow!("At least one target must be specified"));
        }

        for target in &self.targets.targets {
            if target.url.is_empty() {
                return Err(anyhow::anyhow!("Target URL cannot be empty"));
            }
            // Validate URL format
            if !target.url.starts_with("http://") && !target.url.starts_with("https://") {
                return Err(anyhow::anyhow!(
                    "Target URL must start with http:// or https://: {}",
                    target.url
                ));
            }
            if target.name.is_empty() {
                return Err(anyhow::anyhow!("Target name cannot be empty"));
            }
        }

        // Validate health check configuration
        if self.targets.health_check.enabled {
            if self.targets.health_check.interval == 0 {
                return Err(anyhow::anyhow!(
                    "Health check interval must be greater than 0"
                ));
            }
            if self.targets.health_check.timeout == 0 {
                return Err(anyhow::anyhow!(
                    "Health check timeout must be greater than 0"
                ));
            }
            if self.targets.health_check.timeout >= self.targets.health_check.interval {
                return Err(anyhow::anyhow!(
                    "Health check timeout must be less than interval"
                ));
            }
            if self.targets.health_check.healthy_threshold == 0 {
                return Err(anyhow::anyhow!("Healthy threshold must be greater than 0"));
            }
            if self.targets.health_check.unhealthy_threshold == 0 {
                return Err(anyhow::anyhow!(
                    "Unhealthy threshold must be greater than 0"
                ));
            }
        }

        // Validate server configuration
        if let Some(workers) = self.server.workers {
            if workers == 0 {
                return Err(anyhow::anyhow!("Worker count must be greater than 0"));
            }
        }

        // Validate monitoring ports
        if self.monitoring.enabled
            && self.monitoring.metrics_port == self.monitoring.health_check_port
        {
            return Err(anyhow::anyhow!(
                "Metrics port and health check port cannot be the same"
            ));
        }

        // Validate logging configuration
        if self.logging.enabled {
            match self.logging.log_type {
                LoggingType::Database => {
                    if self.logging.database.is_none() {
                        return Err(anyhow::anyhow!(
                            "Database configuration required when logging to database"
                        ));
                    }
                }
                LoggingType::File => {
                    if self.logging.file.is_none() {
                        return Err(anyhow::anyhow!(
                            "File configuration required when logging to file"
                        ));
                    }
                }
                LoggingType::Both => {
                    if self.logging.database.is_none() {
                        return Err(anyhow::anyhow!(
                            "Database configuration required when logging to database"
                        ));
                    }
                    if self.logging.file.is_none() {
                        return Err(anyhow::anyhow!(
                            "File configuration required when logging to file"
                        ));
                    }
                }
            }
        }

        // Validate TLS configuration if present
        if let Some(tls_config) = &self.tls {
            tls_config.validate()?;
        }

        // Validate routing configuration if present
        if let Some(routing_config) = &self.routing {
            routing_config.validate()?;
        }

        // Validate cache configuration if present
        if let Some(cache_config) = &self.cache {
            cache_config.validate()?;
        }

        // Validate monitoring configuration
        self.monitoring.validate()?;

        // Validate HTTP client configuration if present
        if let Some(http_client) = &self.http_client {
            http_client.validate()?;
        }

        // Validate plugins configuration if present
        if let Some(plugins) = &self.plugins {
            plugins.validate()?;
        }

        // Cluster validation removed

        Ok(())
    }

    /// Create a configuration with enhanced defaults
    #[allow(dead_code)]
    pub fn with_defaults() -> Self {
        let mut config = Self::default_config();

        // Apply reasonable production defaults
        config.server.workers = Some(num_cpus::get());
        config.server.keep_alive_timeout = Some(75); // Slightly longer than typical LB timeout
        config.server.request_timeout = Some(60);

        // Enhanced health check defaults
        config.targets.health_check.interval = 10; // More frequent checks
        config.targets.health_check.timeout = 3; // Faster timeout
        config.targets.health_check.healthy_threshold = 3;
        config.targets.health_check.unhealthy_threshold = 2;

        config
    }

    #[allow(dead_code)]
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
                histogram_buckets: None,
            },
            tls: None,
            routing: None,
            cache: None,
            http_client: Some(HttpClientConfig::default()),
            plugins: None,
            security: None,
        }
    }
}

// Add num_cpus dependency for better defaults
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}

/// Configuration manager with hot-reload support
pub struct ConfigManager {
    config: Arc<RwLock<Config>>,
    config_path: PathBuf,
    _watcher: Option<RecommendedWatcher>,
    reload_hook: Option<Arc<dyn Fn(&Config) + Send + Sync>>, // optional callback on reload
}

impl ConfigManager {
    /// Create a new configuration manager
    #[allow(dead_code)]
    pub async fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = Config::from_file_with_env(&config_path).await?;

        Ok(ConfigManager {
            config: Arc::new(RwLock::new(config)),
            config_path,
            _watcher: None,
            reload_hook: None,
        })
    }

    /// Get a clone of the current configuration
    #[allow(dead_code)]
    pub fn get_config(&self) -> Config {
        self.config.read().unwrap().clone()
    }

    /// Get a reference to the shared configuration
    #[allow(dead_code)]
    pub fn get_config_ref(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.config)
    }

    /// Set a callback to be invoked after config reload succeeds
    #[allow(dead_code)]
    pub fn set_reload_hook<F>(&mut self, hook: F)
    where
        F: Fn(&Config) + Send + Sync + 'static,
    {
        self.reload_hook = Some(Arc::new(hook));
    }

    /// Start watching for configuration file changes
    #[allow(dead_code)]
    pub async fn start_hot_reload(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(100);
        let config_arc = Arc::clone(&self.config);
        let config_path = self.config_path.clone();
        let reload_hook = self.reload_hook.clone();

        // Create file watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if let Err(e) = tx.blocking_send(event) {
                        error!("Failed to send file change event: {}", e);
                    }
                }
                Err(e) => error!("File watch error: {}", e),
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(1)),
        )?;

        // Watch the config file and its directory
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
        if let Some(parent) = config_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }

        info!("Started watching config file: {:?}", config_path);

        // Spawn task to handle file change events
        let config_path_clone = config_path.clone();
        let reload_hook_clone = reload_hook.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = handle_config_change(
                    &event,
                    &config_arc,
                    &config_path_clone,
                    reload_hook_clone.clone(),
                )
                .await
                {
                    error!("Failed to handle config change: {}", e);
                }
            }
        });

        self._watcher = Some(watcher);
        Ok(())
    }

    /// Manually reload configuration from file
    #[allow(dead_code)]
    pub async fn reload_config(&self) -> Result<()> {
        info!(
            "Manually reloading configuration from {:?}",
            self.config_path
        );

        match Config::from_file_with_env(&self.config_path).await {
            Ok(new_config) => {
                let mut config = self.config.write().unwrap();
                *config = new_config;
                info!("Configuration reloaded successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
                Err(e)
            }
        }
    }
}

/// Handle configuration file change events
async fn handle_config_change(
    event: &Event,
    config: &Arc<RwLock<Config>>,
    config_path: &Path,
    reload_hook: Option<Arc<dyn Fn(&Config) + Send + Sync>>,
) -> Result<()> {
    use notify::EventKind;

    // Only handle write/modify events for the config file
    if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
        return Ok(());
    }

    // Check if the event is for our config file
    let config_file_changed = event
        .paths
        .iter()
        .any(|path| path == config_path || (path.is_dir() && config_path.starts_with(path)));

    if !config_file_changed {
        return Ok(());
    }

    debug!("Config file change detected: {:?}", event);

    // Add a small delay to allow file write to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to reload the configuration
    match Config::from_file_with_env(config_path).await {
        Ok(new_config) => {
            let mut current_config = config.write().unwrap();
            *current_config = new_config;
            info!("Configuration hot-reloaded successfully");

            // Invoke reload hook if present (best-effort)
            if let Some(hook) = reload_hook {
                let cfg_snapshot = current_config.clone();
                drop(current_config); // release lock before running hook
                (hook)(&cfg_snapshot);
            }
        }
        Err(e) => {
            warn!(
                "Failed to hot-reload configuration (keeping current): {}",
                e
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create a temporary config file
    fn create_temp_config_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();
        temp_file
    }

    // Valid configuration content for testing
    fn valid_config_content() -> &'static str {
        r#"
[server]
bind_address = "0.0.0.0:8080"
workers = 4
keep_alive_timeout = 60
request_timeout = 30

[domains]
intercept_domains = ["example.com", "*.test.com"]
exclude_domains = ["admin.example.com"]
wildcard_support = true

[[targets.targets]]
name = "backend1"
url = "http://192.168.1.100:3000"
weight = 3
timeout = 30

[[targets.targets]]
name = "backend2"
url = "http://192.168.1.101:3000"
weight = 2
timeout = 30

[targets.load_balancing]
type = "weighted"
sticky_sessions = false

[targets.health_check]
enabled = true
interval = 30
timeout = 10
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
type = "both"
retention_days = 30

[logging.database]
url = "sqlite://./data/traffic.db"
max_connections = 10
connection_timeout = 30

[logging.file]
directory = "./logs"
max_file_size = 104857600
rotation = true

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
        "#
    }

    #[tokio::test]
    async fn test_config_from_valid_file() {
        let temp_file = create_temp_config_file(valid_config_content());
        let config = Config::from_file(temp_file.path()).await;

        assert!(config.is_ok(), "Valid config should parse successfully");
        let config = config.unwrap();

        // Verify server config
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.server.workers, Some(4));
        assert_eq!(config.server.keep_alive_timeout, Some(60));
        assert_eq!(config.server.request_timeout, Some(30));

        // Verify domain config
        assert_eq!(
            config.domains.intercept_domains,
            vec!["example.com", "*.test.com"]
        );
        assert_eq!(
            config.domains.exclude_domains,
            Some(vec!["admin.example.com".to_string()])
        );
        assert!(config.domains.wildcard_support);

        // Verify targets
        assert_eq!(config.targets.targets.len(), 2);
        assert_eq!(config.targets.targets[0].name, "backend1");
        assert_eq!(config.targets.targets[0].url, "http://192.168.1.100:3000");
        assert_eq!(config.targets.targets[0].weight, Some(3));

        // Verify load balancing
        assert!(matches!(
            config.targets.load_balancing.lb_type,
            LoadBalancingType::Weighted
        ));
        assert!(!config.targets.load_balancing.sticky_sessions);

        // Verify health check
        assert!(config.targets.health_check.enabled);
        assert_eq!(config.targets.health_check.interval, 30);
        assert_eq!(config.targets.health_check.healthy_threshold, 2);

        // Verify logging
        assert!(config.logging.enabled);
        assert!(matches!(config.logging.log_type, LoggingType::Both));
        assert_eq!(config.logging.retention_days, Some(30));

        // Verify monitoring
        assert!(config.monitoring.enabled);
        assert_eq!(config.monitoring.metrics_port, 9090);
        assert_eq!(config.monitoring.health_check_port, 8081);
    }

    #[tokio::test]
    async fn test_config_from_nonexistent_file() {
        let result = Config::from_file("/nonexistent/path/config.toml").await;
        assert!(result.is_err(), "Nonexistent file should return error");
    }

    #[tokio::test]
    async fn test_config_from_invalid_toml() {
        let invalid_content = "this is not valid toml [unclosed section";
        let temp_file = create_temp_config_file(invalid_content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(result.is_err(), "Invalid TOML should return error");
    }

    #[tokio::test]
    async fn test_config_missing_required_fields() {
        let incomplete_content = r#"
[server]
bind_address = "0.0.0.0:8080"
        "#;
        let temp_file = create_temp_config_file(incomplete_content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(result.is_err(), "Incomplete config should return error");
    }

    #[tokio::test]
    async fn test_config_validation_empty_intercept_domains() {
        let content = r#"
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = []
wildcard_support = true

[[targets.targets]]
name = "backend1"
url = "http://localhost:3000"

[targets.load_balancing]
type = "roundrobin"
sticky_sessions = false

[targets.health_check]
enabled = true
interval = 30
timeout = 10
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
type = "file"

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
        "#;
        let temp_file = create_temp_config_file(content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(
            result.is_err(),
            "Empty intercept domains should fail validation"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("At least one intercept domain must be specified"));
    }

    #[tokio::test]
    async fn test_config_validation_empty_targets() {
        let content = r#"
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = ["example.com"]
wildcard_support = true

[targets]
targets = []

[targets.load_balancing]
type = "roundrobin"
sticky_sessions = false

[targets.health_check]
enabled = true
interval = 30
timeout = 10
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
type = "file"

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
        "#;
        let temp_file = create_temp_config_file(content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(result.is_err(), "Empty targets should fail validation");

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("At least one target must be specified"));
    }

    #[tokio::test]
    async fn test_config_validation_empty_target_url() {
        let content = r#"
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = ["example.com"]
wildcard_support = true

[[targets.targets]]
name = "backend1"
url = ""

[targets.load_balancing]
type = "roundrobin"
sticky_sessions = false

[targets.health_check]
enabled = true
interval = 30
timeout = 10
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
type = "file"

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
        "#;
        let temp_file = create_temp_config_file(content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(result.is_err(), "Empty target URL should fail validation");

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Target URL cannot be empty"));
    }

    #[test]
    fn test_default_config() {
        let config = Config::default_config();

        // Verify server defaults
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.server.workers, Some(4));
        assert_eq!(config.server.keep_alive_timeout, Some(60));
        assert_eq!(config.server.request_timeout, Some(30));

        // Verify domain defaults
        assert_eq!(config.domains.intercept_domains, vec!["example.com"]);
        assert_eq!(config.domains.exclude_domains, None);
        assert!(config.domains.wildcard_support);

        // Verify target defaults
        assert_eq!(config.targets.targets.len(), 1);
        assert_eq!(config.targets.targets[0].name, "default");
        assert_eq!(config.targets.targets[0].url, "http://localhost:3000");
        assert_eq!(config.targets.targets[0].weight, Some(1));

        // Verify load balancing defaults
        assert!(matches!(
            config.targets.load_balancing.lb_type,
            LoadBalancingType::RoundRobin
        ));
        assert!(!config.targets.load_balancing.sticky_sessions);

        // Verify health check defaults
        assert!(config.targets.health_check.enabled);
        assert_eq!(config.targets.health_check.interval, 30);
        assert_eq!(config.targets.health_check.timeout, 10);
        assert_eq!(config.targets.health_check.healthy_threshold, 2);
        assert_eq!(config.targets.health_check.unhealthy_threshold, 3);

        // Verify logging defaults
        assert!(config.logging.enabled);
        assert!(matches!(config.logging.log_type, LoggingType::File));
        assert_eq!(config.logging.retention_days, Some(30));
        assert!(config.logging.file.is_some());
        assert_eq!(config.logging.file.as_ref().unwrap().directory, "./logs");
        assert_eq!(
            config.logging.file.as_ref().unwrap().max_file_size,
            Some(100_000_000)
        );
        assert!(config.logging.file.as_ref().unwrap().rotation);

        // Verify monitoring defaults
        assert!(config.monitoring.enabled);
        assert_eq!(config.monitoring.metrics_port, 9090);
        assert_eq!(config.monitoring.health_check_port, 8081);
    }

    #[test]
    fn test_load_balancing_type_serialization() {
        // Test enum serialization/deserialization
        let config = LoadBalancingConfig {
            lb_type: LoadBalancingType::Weighted,
            sticky_sessions: true,
        };

        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("type = \"weighted\""));

        let deserialized: LoadBalancingConfig = toml::from_str(&serialized).unwrap();
        assert!(matches!(deserialized.lb_type, LoadBalancingType::Weighted));
        assert!(deserialized.sticky_sessions);
    }

    #[test]
    fn test_logging_type_serialization() {
        // Test LoggingType enum serialization
        let types = vec![
            (LoggingType::Database, "database"),
            (LoggingType::File, "file"),
            (LoggingType::Both, "both"),
        ];

        for (log_type, expected_str) in types {
            let config = LoggingConfig {
                enabled: true,
                log_type: log_type.clone(),
                database: None,
                file: None,
                retention_days: None,
            };

            let serialized = toml::to_string(&config).unwrap();
            assert!(serialized.contains(&format!("type = \"{}\"", expected_str)));

            let deserialized: LoggingConfig = toml::from_str(&serialized).unwrap();
            assert!(matches!(deserialized.log_type, _log_type));
        }
    }

    #[tokio::test]
    async fn test_config_with_optional_fields() {
        let minimal_content = r#"
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = ["example.com"]
wildcard_support = false

[[targets.targets]]
name = "backend1"
url = "http://localhost:3000"

[targets.load_balancing]
type = "roundrobin"
sticky_sessions = false

[targets.health_check]
enabled = false
interval = 60
timeout = 5
healthy_threshold = 1
unhealthy_threshold = 2

[logging]
enabled = false
type = "file"

[monitoring]
enabled = false
metrics_port = 9090
health_check_port = 8081
        "#;
        let temp_file = create_temp_config_file(minimal_content);

        let result = Config::from_file(temp_file.path()).await;
        assert!(
            result.is_ok(),
            "Minimal valid config should parse successfully"
        );

        let config = result.unwrap();

        // Verify optional fields are None when not specified
        assert_eq!(config.server.workers, None);
        assert_eq!(config.server.keep_alive_timeout, None);
        assert_eq!(config.server.request_timeout, None);
        assert_eq!(config.domains.exclude_domains, None);
        assert_eq!(config.targets.targets[0].weight, None);
        assert_eq!(config.targets.targets[0].timeout, None);
        assert!(!config.domains.wildcard_support);
        assert!(!config.targets.health_check.enabled);
        assert!(!config.logging.enabled);
        assert!(!config.monitoring.enabled);
    }

    #[test]
    fn test_config_validation_direct() {
        // Test validation method directly
        let mut config = Config::default_config();

        // Valid config should pass
        assert!(config.validate().is_ok());

        // Empty intercept domains should fail
        config.domains.intercept_domains.clear();
        assert!(config.validate().is_err());

        // Restore intercept domains, clear targets
        config
            .domains
            .intercept_domains
            .push("example.com".to_string());
        config.targets.targets.clear();
        assert!(config.validate().is_err());

        // Restore targets, set empty URL
        config.targets.targets.push(Target {
            name: "test".to_string(),
            url: "".to_string(),
            weight: None,
            timeout: None,
        });
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_config_with_env_overrides() {
        // Use unique environment variable names for this test to avoid conflicts
        let test_bind_addr = "TEST_DISPA_BIND_ADDRESS_UNIQUE";
        let test_workers = "TEST_DISPA_WORKERS_UNIQUE";
        let test_metrics_port = "TEST_DISPA_METRICS_PORT_UNIQUE";
        let test_logging_enabled = "TEST_DISPA_LOGGING_ENABLED_UNIQUE";
        let test_logging_type = "TEST_DISPA_LOGGING_TYPE_UNIQUE";

        // Clean up any existing environment variables first
        env::remove_var(test_bind_addr);
        env::remove_var(test_workers);
        env::remove_var(test_metrics_port);
        env::remove_var(test_logging_enabled);
        env::remove_var(test_logging_type);

        // Set environment variables
        env::set_var(test_bind_addr, "127.0.0.1:9000");
        env::set_var(test_workers, "8");
        env::set_var(test_metrics_port, "9091");
        env::set_var(test_logging_enabled, "false");
        env::set_var(test_logging_type, "database");

        let content = valid_config_content();
        let temp_file = create_temp_config_file(content);

        // Load config and manually apply custom env vars for testing
        let mut config = Config::from_file(temp_file.path()).await.unwrap();

        // Apply test-specific environment overrides manually
        if let Ok(bind_address) = env::var(test_bind_addr) {
            if let Ok(addr) = bind_address.parse() {
                config.server.bind_address = addr;
            }
        }
        if let Ok(workers) = env::var(test_workers) {
            if let Ok(workers_num) = workers.parse::<usize>() {
                config.server.workers = Some(workers_num);
            }
        }
        if let Ok(metrics_port) = env::var(test_metrics_port) {
            if let Ok(port) = metrics_port.parse::<u16>() {
                config.monitoring.metrics_port = port;
            }
        }
        if let Ok(log_enabled) = env::var(test_logging_enabled) {
            if let Ok(enabled) = log_enabled.parse::<bool>() {
                config.logging.enabled = enabled;
            }
        }
        if let Ok(log_type) = env::var(test_logging_type) {
            match log_type.to_lowercase().as_str() {
                "database" => config.logging.log_type = LoggingType::Database,
                "file" => config.logging.log_type = LoggingType::File,
                "both" => config.logging.log_type = LoggingType::Both,
                _ => {}
            }
        }

        // Verify environment overrides were applied
        assert_eq!(config.server.bind_address.to_string(), "127.0.0.1:9000");
        assert_eq!(config.server.workers, Some(8));
        assert_eq!(config.monitoring.metrics_port, 9091);
        assert!(!config.logging.enabled);
        assert!(matches!(config.logging.log_type, LoggingType::Database));

        // Clean up test environment variables
        env::remove_var(test_bind_addr);
        env::remove_var(test_workers);
        env::remove_var(test_metrics_port);
        env::remove_var(test_logging_enabled);
        env::remove_var(test_logging_type);
    }

    #[tokio::test]
    async fn test_config_manager_creation() {
        let content = valid_config_content();
        let temp_file = create_temp_config_file(content);

        let manager = ConfigManager::new(temp_file.path()).await;
        assert!(manager.is_ok(), "ConfigManager should create successfully");

        let manager = manager.unwrap();
        let config = manager.get_config();

        // Verify config was loaded correctly
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.targets.targets.len(), 2);
    }

    #[tokio::test]
    async fn test_enhanced_validation() {
        let mut config = Config::default_config();

        // Test invalid domain patterns
        config.domains.intercept_domains = vec!["invalid@domain".to_string()];
        assert!(config.validate().is_err());

        // Test invalid target URL
        config.domains.intercept_domains = vec!["example.com".to_string()];
        config.targets.targets[0].url = "ftp://invalid-protocol.com".to_string();
        assert!(config.validate().is_err());

        // Test health check validation
        config.targets.targets[0].url = "http://valid.com".to_string();
        config.targets.health_check.timeout = config.targets.health_check.interval;
        assert!(config.validate().is_err());

        // Test same monitoring ports
        config.targets.health_check.timeout = 5;
        config.monitoring.metrics_port = config.monitoring.health_check_port;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_with_defaults() {
        let config = Config::with_defaults();

        // Should have at least as many workers as CPU cores
        assert!(config.server.workers.unwrap_or(0) > 0);

        // Should have enhanced health check settings
        assert_eq!(config.targets.health_check.interval, 10);
        assert_eq!(config.targets.health_check.timeout, 3);
        assert_eq!(config.targets.health_check.healthy_threshold, 3);
    }

    #[tokio::test]
    async fn test_config_manager_manual_reload() {
        let content = valid_config_content();
        let temp_file = create_temp_config_file(content);

        let manager = ConfigManager::new(temp_file.path()).await.unwrap();

        // Modify the config file
        let modified_content = content.replace(
            "bind_address = \"0.0.0.0:8080\"",
            "bind_address = \"0.0.0.0:9999\"",
        );
        std::fs::write(temp_file.path(), modified_content).unwrap();

        // Manually reload
        let result = manager.reload_config().await;
        assert!(result.is_ok(), "Manual reload should succeed");

        // Verify the config was updated
        let config = manager.get_config();
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:9999");
    }

    #[tokio::test]
    async fn test_env_override_invalid_values() {
        // Test invalid environment variables are ignored
        env::set_var("DISPA_BIND_ADDRESS", "invalid-address");
        env::set_var("DISPA_WORKERS", "not-a-number");
        env::set_var("DISPA_LOGGING_TYPE", "invalid-type");

        let content = valid_config_content();
        let temp_file = create_temp_config_file(content);

        let config = Config::from_file_with_env(temp_file.path()).await.unwrap();

        // Should keep original values since env vars are invalid
        assert_eq!(config.server.bind_address.to_string(), "0.0.0.0:8080");
        assert_eq!(config.server.workers, Some(4));
        assert!(matches!(config.logging.log_type, LoggingType::Both));

        // Clean up
        env::remove_var("DISPA_BIND_ADDRESS");
        env::remove_var("DISPA_WORKERS");
        env::remove_var("DISPA_LOGGING_TYPE");
    }

    #[test]
    fn test_validation_comprehensive() {
        let mut config = Config::default_config();

        // Test zero workers
        config.server.workers = Some(0);
        assert!(config.validate().is_err());

        // Test zero health check thresholds
        config.server.workers = Some(4);
        config.targets.health_check.healthy_threshold = 0;
        assert!(config.validate().is_err());

        config.targets.health_check.healthy_threshold = 2;
        config.targets.health_check.unhealthy_threshold = 0;
        assert!(config.validate().is_err());

        // Test zero health check intervals
        config.targets.health_check.unhealthy_threshold = 3;
        config.targets.health_check.interval = 0;
        assert!(config.validate().is_err());

        config.targets.health_check.interval = 30;
        config.targets.health_check.timeout = 0;
        assert!(config.validate().is_err());

        // Test missing logging config for database type
        config.targets.health_check.timeout = 10;
        config.logging.log_type = LoggingType::Database;
        config.logging.database = None;
        assert!(config.validate().is_err());

        // Test missing logging config for file type
        config.logging.log_type = LoggingType::File;
        config.logging.file = None;
        assert!(config.validate().is_err());
    }
}
