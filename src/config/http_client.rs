#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTTP client configuration for upstream requests
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpClientConfig {
    pub pool_max_idle_per_host: Option<usize>,
    pub pool_idle_timeout: Option<u64>,      // seconds
    pub pool_idle_timeout_secs: Option<u64>, // seconds (alias for compatibility)
    pub connect_timeout: Option<u64>,        // seconds
    pub connect_timeout_secs: Option<u64>,   // seconds (alias for compatibility)
    pub request_timeout: Option<u64>,        // seconds
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: Some(32),
            pool_idle_timeout: Some(300),      // 5 minutes
            pool_idle_timeout_secs: Some(300), // 5 minutes
            connect_timeout: Some(10),         // 10 seconds
            connect_timeout_secs: Some(10),    // 10 seconds
            request_timeout: Some(60),         // 60 seconds
        }
    }
}

impl HttpClientConfig {
    /// Validate HTTP client configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(max_idle) = self.pool_max_idle_per_host {
            if max_idle == 0 {
                return Err(anyhow::anyhow!(
                    "HTTP client pool_max_idle_per_host must be greater than 0"
                ));
            }
        }

        if let Some(idle_timeout) = self.pool_idle_timeout {
            if idle_timeout == 0 {
                return Err(anyhow::anyhow!(
                    "HTTP client pool_idle_timeout must be greater than 0"
                ));
            }
        }

        if let Some(connect_timeout) = self.connect_timeout {
            if connect_timeout == 0 {
                return Err(anyhow::anyhow!(
                    "HTTP client connect_timeout must be greater than 0"
                ));
            }
        }

        if let Some(request_timeout) = self.request_timeout {
            if request_timeout == 0 {
                return Err(anyhow::anyhow!(
                    "HTTP client request_timeout must be greater than 0"
                ));
            }
        }

        Ok(())
    }

    /// Get pool max idle connections per host
    pub fn get_pool_max_idle_per_host(&self) -> usize {
        self.pool_max_idle_per_host.unwrap_or(32)
    }

    /// Get pool idle timeout (try both field names for compatibility)
    pub fn get_pool_idle_timeout(&self) -> Duration {
        let timeout = self
            .pool_idle_timeout
            .or(self.pool_idle_timeout_secs)
            .unwrap_or(300);
        Duration::from_secs(timeout)
    }

    /// Get connect timeout (try both field names for compatibility)
    pub fn get_connect_timeout(&self) -> Duration {
        let timeout = self
            .connect_timeout
            .or(self.connect_timeout_secs)
            .unwrap_or(10);
        Duration::from_secs(timeout)
    }

    /// Get request timeout
    pub fn get_request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout.unwrap_or(60))
    }
}
