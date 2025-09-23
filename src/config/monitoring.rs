use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Monitoring and metrics configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub health_endpoint: String,
    pub metrics_endpoint: String,
    pub prometheus_enabled: bool,
    pub histogram_buckets: Option<HistogramBucketsConfig>,
    /// Resource capacity monitoring
    pub capacity: Option<CapacityConfig>,
    /// Prometheus pushgateway configuration
    pub pushgateway: Option<PushgatewayConfig>,
    /// Metrics port (for compatibility)
    pub metrics_port: u16,
    /// Health check port (for compatibility)
    pub health_check_port: u16,
}

/// Histogram bucket configuration for latency metrics
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistogramBucketsConfig {
    /// Latency buckets in milliseconds
    pub latency_ms: Vec<f64>,
    /// Size buckets in bytes
    pub size_bytes: Vec<f64>,
}

/// Resource capacity monitoring configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapacityConfig {
    /// Enable capacity monitoring
    pub enabled: bool,
    /// Memory capacity monitoring
    pub memory: Option<MemoryCapacityConfig>,
    /// Connection capacity monitoring
    pub connections: Option<ConnectionCapacityConfig>,
    /// Request rate capacity monitoring
    pub request_rate: Option<RequestRateCapacityConfig>,
    /// Alert thresholds for capacity warnings
    pub alert_thresholds: Option<AlertThresholds>,
}

/// Memory capacity monitoring configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemoryCapacityConfig {
    /// Enable memory monitoring
    pub enabled: bool,
    /// Warning threshold as percentage (0.0-1.0)
    pub warning_threshold: f64,
    /// Critical threshold as percentage (0.0-1.0)
    pub critical_threshold: f64,
    /// Check interval in seconds
    pub check_interval: u64,
}

/// Connection capacity monitoring configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectionCapacityConfig {
    /// Enable connection monitoring
    pub enabled: bool,
    /// Maximum expected concurrent connections
    pub max_connections: usize,
    /// Warning threshold as percentage (0.0-1.0)
    pub warning_threshold: f64,
    /// Critical threshold as percentage (0.0-1.0)
    pub critical_threshold: f64,
}

/// Request rate capacity monitoring configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestRateCapacityConfig {
    /// Enable request rate monitoring
    pub enabled: bool,
    /// Maximum expected requests per second
    pub max_rps: f64,
    /// Warning threshold as percentage (0.0-1.0)
    pub warning_threshold: f64,
    /// Critical threshold as percentage (0.0-1.0)
    pub critical_threshold: f64,
    /// Window size for rate calculation in seconds
    pub window_size: u64,
}

/// Alert threshold configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertThresholds {
    /// Memory usage threshold for alerts
    pub memory_percent: f64,
    /// Connection usage threshold for alerts
    pub connection_percent: f64,
    /// Request rate threshold for alerts
    pub request_rate_percent: f64,
    /// CPU usage threshold for alerts
    pub cpu_percent: f64,
}

/// Prometheus pushgateway configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PushgatewayConfig {
    /// Pushgateway URL
    pub url: String,
    /// Job name for metrics
    pub job: String,
    /// Push interval in seconds
    pub interval: u64,
    /// Additional labels to include
    pub labels: Option<std::collections::HashMap<String, String>>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:8081".parse().unwrap(),
            health_endpoint: "/health".to_string(),
            metrics_endpoint: "/metrics".to_string(),
            prometheus_enabled: true,
            histogram_buckets: Some(HistogramBucketsConfig::default()),
            capacity: Some(CapacityConfig::default()),
            pushgateway: None,
            metrics_port: 9090,
            health_check_port: 8081,
        }
    }
}

impl Default for HistogramBucketsConfig {
    fn default() -> Self {
        Self {
            latency_ms: vec![
                0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
            ],
            size_bytes: vec![
                128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0,
            ],
        }
    }
}

impl Default for CapacityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            memory: Some(MemoryCapacityConfig::default()),
            connections: Some(ConnectionCapacityConfig::default()),
            request_rate: Some(RequestRateCapacityConfig::default()),
            alert_thresholds: Some(AlertThresholds::default()),
        }
    }
}

impl Default for MemoryCapacityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            warning_threshold: 0.8,   // 80%
            critical_threshold: 0.95, // 95%
            check_interval: 30,       // 30 seconds
        }
    }
}

impl Default for ConnectionCapacityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_connections: 10000,
            warning_threshold: 0.8,   // 80%
            critical_threshold: 0.95, // 95%
        }
    }
}

impl Default for RequestRateCapacityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_rps: 1000.0,
            warning_threshold: 0.8,   // 80%
            critical_threshold: 0.95, // 95%
            window_size: 60,          // 1 minute window
        }
    }
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            memory_percent: 85.0,
            connection_percent: 85.0,
            request_rate_percent: 85.0,
            cpu_percent: 80.0,
        }
    }
}

impl MonitoringConfig {
    /// Validate monitoring configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.health_endpoint.starts_with('/') {
            return Err(anyhow::anyhow!(
                "Health endpoint must start with '/': {}",
                self.health_endpoint
            ));
        }

        if !self.metrics_endpoint.starts_with('/') {
            return Err(anyhow::anyhow!(
                "Metrics endpoint must start with '/': {}",
                self.metrics_endpoint
            ));
        }

        if let Some(capacity) = &self.capacity {
            capacity.validate()?;
        }

        if let Some(pushgateway) = &self.pushgateway {
            pushgateway.validate()?;
        }

        Ok(())
    }
}

impl CapacityConfig {
    /// Validate capacity configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(memory) = &self.memory {
            memory.validate()?;
        }

        if let Some(connections) = &self.connections {
            connections.validate()?;
        }

        if let Some(request_rate) = &self.request_rate {
            request_rate.validate()?;
        }

        if let Some(thresholds) = &self.alert_thresholds {
            thresholds.validate()?;
        }

        Ok(())
    }
}

impl MemoryCapacityConfig {
    /// Validate memory capacity configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(0.0..=1.0).contains(&self.warning_threshold) {
            return Err(anyhow::anyhow!(
                "Memory warning threshold must be between 0.0 and 1.0: {}",
                self.warning_threshold
            ));
        }

        if !(0.0..=1.0).contains(&self.critical_threshold) {
            return Err(anyhow::anyhow!(
                "Memory critical threshold must be between 0.0 and 1.0: {}",
                self.critical_threshold
            ));
        }

        if self.warning_threshold >= self.critical_threshold {
            return Err(anyhow::anyhow!(
                "Memory warning threshold ({}) must be less than critical threshold ({})",
                self.warning_threshold,
                self.critical_threshold
            ));
        }

        if self.check_interval == 0 {
            return Err(anyhow::anyhow!(
                "Memory check interval must be greater than 0"
            ));
        }

        Ok(())
    }
}

impl ConnectionCapacityConfig {
    /// Validate connection capacity configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_connections == 0 {
            return Err(anyhow::anyhow!("Max connections must be greater than 0"));
        }

        if !(0.0..=1.0).contains(&self.warning_threshold) {
            return Err(anyhow::anyhow!(
                "Connection warning threshold must be between 0.0 and 1.0: {}",
                self.warning_threshold
            ));
        }

        if !(0.0..=1.0).contains(&self.critical_threshold) {
            return Err(anyhow::anyhow!(
                "Connection critical threshold must be between 0.0 and 1.0: {}",
                self.critical_threshold
            ));
        }

        if self.warning_threshold >= self.critical_threshold {
            return Err(anyhow::anyhow!(
                "Connection warning threshold ({}) must be less than critical threshold ({})",
                self.warning_threshold,
                self.critical_threshold
            ));
        }

        Ok(())
    }
}

impl RequestRateCapacityConfig {
    /// Validate request rate capacity configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_rps <= 0.0 {
            return Err(anyhow::anyhow!("Max RPS must be greater than 0"));
        }

        if !(0.0..=1.0).contains(&self.warning_threshold) {
            return Err(anyhow::anyhow!(
                "Request rate warning threshold must be between 0.0 and 1.0: {}",
                self.warning_threshold
            ));
        }

        if !(0.0..=1.0).contains(&self.critical_threshold) {
            return Err(anyhow::anyhow!(
                "Request rate critical threshold must be between 0.0 and 1.0: {}",
                self.critical_threshold
            ));
        }

        if self.warning_threshold >= self.critical_threshold {
            return Err(anyhow::anyhow!(
                "Request rate warning threshold ({}) must be less than critical threshold ({})",
                self.warning_threshold,
                self.critical_threshold
            ));
        }

        if self.window_size == 0 {
            return Err(anyhow::anyhow!(
                "Request rate window size must be greater than 0"
            ));
        }

        Ok(())
    }
}

impl AlertThresholds {
    /// Validate alert thresholds
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(0.0..=100.0).contains(&self.memory_percent) {
            return Err(anyhow::anyhow!(
                "Memory alert threshold must be between 0.0 and 100.0: {}",
                self.memory_percent
            ));
        }

        if !(0.0..=100.0).contains(&self.connection_percent) {
            return Err(anyhow::anyhow!(
                "Connection alert threshold must be between 0.0 and 100.0: {}",
                self.connection_percent
            ));
        }

        if !(0.0..=100.0).contains(&self.request_rate_percent) {
            return Err(anyhow::anyhow!(
                "Request rate alert threshold must be between 0.0 and 100.0: {}",
                self.request_rate_percent
            ));
        }

        if !(0.0..=100.0).contains(&self.cpu_percent) {
            return Err(anyhow::anyhow!(
                "CPU alert threshold must be between 0.0 and 100.0: {}",
                self.cpu_percent
            ));
        }

        Ok(())
    }
}

impl PushgatewayConfig {
    /// Validate pushgateway configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.url.is_empty() {
            return Err(anyhow::anyhow!("Pushgateway URL cannot be empty"));
        }

        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(anyhow::anyhow!(
                "Pushgateway URL must be a valid HTTP/HTTPS URL: {}",
                self.url
            ));
        }

        if self.job.is_empty() {
            return Err(anyhow::anyhow!("Pushgateway job name cannot be empty"));
        }

        if self.interval == 0 {
            return Err(anyhow::anyhow!(
                "Pushgateway interval must be greater than 0"
            ));
        }

        Ok(())
    }
}
