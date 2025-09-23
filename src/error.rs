#![allow(dead_code)]
use std::fmt;
use thiserror::Error;
use tokio::time::Duration;

/// Main error type for the Dispa proxy server
#[derive(Error, Debug, Clone)]
pub enum DispaError {
    /// Configuration related errors
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Network related errors
    #[error("Network error: {message}")]
    Network { message: String },

    /// Load balancer errors
    #[allow(dead_code)]
    #[error("Load balancer error: {message}")]
    LoadBalancer { message: String },

    /// Health check errors
    #[allow(dead_code)]
    #[error("Health check error: {message}")]
    HealthCheck { message: String },

    /// Proxy request errors
    #[error("Proxy error: {message}")]
    Proxy { message: String },

    /// Database errors
    #[error("Database error: {message}")]
    Database { message: String },

    /// File system errors
    #[error("File system error: {message}")]
    FileSystem { message: String },

    /// Target server errors
    #[allow(dead_code)]
    #[error("Target server error: {target}: {message}")]
    TargetServer { target: String, message: String },

    /// Circuit breaker errors
    #[error("Circuit breaker open for {target}")]
    CircuitBreakerOpen { target: String },

    /// Timeout errors
    #[error("Operation timed out after {duration:?}: {operation}")]
    Timeout {
        duration: Duration,
        operation: String,
    },

    /// Service unavailable (all targets down)
    #[allow(dead_code)]
    #[error("Service unavailable: {message}")]
    ServiceUnavailable { message: String },

    /// TLS/SSL related errors
    #[error("TLS error: {message}")]
    Tls { message: String },

    /// IO related errors
    #[error("IO error: {message}")]
    Io { message: String },

    /// Rate limiting errors
    #[allow(dead_code)]
    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    /// Payload too large
    #[error("Payload too large: {message}")]
    PayloadTooLarge { message: String },

    /// Internal server errors
    #[error("Internal server error: {message}")]
    Internal { message: String },
}

impl DispaError {
    /// Create a configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Create a network error
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    /// Create a load balancer error
    #[allow(dead_code)]
    pub fn load_balancer<S: Into<String>>(message: S) -> Self {
        Self::LoadBalancer {
            message: message.into(),
        }
    }

    /// Create a health check error
    #[allow(dead_code)]
    pub fn health_check<S: Into<String>>(message: S) -> Self {
        Self::HealthCheck {
            message: message.into(),
        }
    }

    /// Create a proxy error
    pub fn proxy<S: Into<String>>(message: S) -> Self {
        Self::Proxy {
            message: message.into(),
        }
    }

    /// Create a database error
    pub fn database<S: Into<String>>(message: S) -> Self {
        Self::Database {
            message: message.into(),
        }
    }

    /// Create a file system error
    pub fn file_system<S: Into<String>>(message: S) -> Self {
        Self::FileSystem {
            message: message.into(),
        }
    }

    /// Create a target server error
    #[allow(dead_code)]
    pub fn target_server<S: Into<String>, T: Into<String>>(target: T, message: S) -> Self {
        Self::TargetServer {
            target: target.into(),
            message: message.into(),
        }
    }

    /// Create a circuit breaker error
    pub fn circuit_breaker_open<S: Into<String>>(target: S) -> Self {
        Self::CircuitBreakerOpen {
            target: target.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout<S: Into<String>>(duration: Duration, operation: S) -> Self {
        Self::Timeout {
            duration,
            operation: operation.into(),
        }
    }

    /// Create a service unavailable error
    #[allow(dead_code)]
    pub fn service_unavailable<S: Into<String>>(message: S) -> Self {
        Self::ServiceUnavailable {
            message: message.into(),
        }
    }

    /// Create a TLS error
    pub fn tls<S: Into<String>>(message: S) -> Self {
        Self::Tls {
            message: message.into(),
        }
    }

    /// Create an IO error
    pub fn io<S: Into<String>>(message: S) -> Self {
        Self::Io {
            message: message.into(),
        }
    }

    /// Create a rate limit error
    #[allow(dead_code)]
    pub fn rate_limit<S: Into<String>>(message: S) -> Self {
        Self::RateLimit {
            message: message.into(),
        }
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            DispaError::Network { .. }
                | DispaError::TargetServer { .. }
                | DispaError::Timeout { .. }
                | DispaError::ServiceUnavailable { .. }
        )
    }

    /// Check if the error should trigger circuit breaker
    pub fn should_trigger_circuit_breaker(&self) -> bool {
        matches!(
            self,
            DispaError::TargetServer { .. }
                | DispaError::Timeout { .. }
                | DispaError::Network { .. }
        )
    }

    /// Get error severity level
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            DispaError::Config { .. } => ErrorSeverity::Critical,
            DispaError::Database { .. } => ErrorSeverity::High,
            DispaError::FileSystem { .. } => ErrorSeverity::High,
            DispaError::LoadBalancer { .. } => ErrorSeverity::High,
            DispaError::ServiceUnavailable { .. } => ErrorSeverity::High,
            DispaError::CircuitBreakerOpen { .. } => ErrorSeverity::Medium,
            DispaError::HealthCheck { .. } => ErrorSeverity::Medium,
            DispaError::TargetServer { .. } => ErrorSeverity::Medium,
            DispaError::Network { .. } => ErrorSeverity::Medium,
            DispaError::Timeout { .. } => ErrorSeverity::Medium,
            DispaError::Proxy { .. } => ErrorSeverity::Low,
            DispaError::RateLimit { .. } => ErrorSeverity::Low,
            DispaError::PayloadTooLarge { .. } => ErrorSeverity::Low,
            DispaError::Internal { .. } => ErrorSeverity::High,
            DispaError::Tls { .. } => ErrorSeverity::High,
            DispaError::Io { .. } => ErrorSeverity::Medium,
        }
    }
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Result type alias for Dispa operations
pub type DispaResult<T> = Result<T, DispaError>;

/// Convert from anyhow::Error to DispaError
impl From<anyhow::Error> for DispaError {
    fn from(err: anyhow::Error) -> Self {
        // Try to downcast to known error types first
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return DispaError::file_system(format!("IO error: {}", io_err));
        }

        if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
            return DispaError::network(format!("HTTP error: {}", hyper_err));
        }

        // reqwest no longer used in the forwarding path; keep generic mapping

        // Default to internal error
        DispaError::internal(err.to_string())
    }
}

/// Convert from std::io::Error to DispaError
impl From<std::io::Error> for DispaError {
    fn from(err: std::io::Error) -> Self {
        DispaError::file_system(format!("IO error: {}", err))
    }
}

/// Convert from hyper::Error to DispaError
impl From<hyper::Error> for DispaError {
    fn from(err: hyper::Error) -> Self {
        if err.is_timeout() {
            DispaError::timeout(Duration::from_secs(30), "HTTP request")
        } else if err.is_connect() {
            DispaError::network(format!("Connection error: {}", err))
        } else {
            DispaError::network(format!("HTTP error: {}", err))
        }
    }
}

// Note: reqwest::Error mapping removed after migration to hyper for forwarding and health checks

/// Convert from sqlx::Error to DispaError
impl From<sqlx::Error> for DispaError {
    fn from(err: sqlx::Error) -> Self {
        DispaError::database(format!("Database error: {}", err))
    }
}

/// Convert from toml::de::Error to DispaError
impl From<toml::de::Error> for DispaError {
    fn from(err: toml::de::Error) -> Self {
        DispaError::config(format!("TOML parsing error: {}", err))
    }
}

/// Convert from notify::Error to DispaError
impl From<notify::Error> for DispaError {
    fn from(err: notify::Error) -> Self {
        DispaError::file_system(format!("File watching error: {}", err))
    }
}

/// Convert from serde_json::Error to DispaError
impl From<serde_json::Error> for DispaError {
    fn from(err: serde_json::Error) -> Self {
        DispaError::internal(format!("JSON serialization error: {}", err))
    }
}

/// Convert from hyper::http::uri::InvalidUri to DispaError
impl From<hyper::http::uri::InvalidUri> for DispaError {
    fn from(err: hyper::http::uri::InvalidUri) -> Self {
        DispaError::config(format!("Invalid URI: {}", err))
    }
}

/// Convert from hyper::http::Error to DispaError
impl From<hyper::http::Error> for DispaError {
    fn from(err: hyper::http::Error) -> Self {
        DispaError::network(format!("HTTP error: {}", err))
    }
}

/// Convert from tokio::time::Elapsed to DispaError
impl From<tokio::time::error::Elapsed> for DispaError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        DispaError::timeout(Duration::from_secs(30), "operation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let config_err = DispaError::config("Invalid bind address");
        assert!(matches!(config_err, DispaError::Config { .. }));
        assert_eq!(
            config_err.to_string(),
            "Configuration error: Invalid bind address"
        );

        let network_err = DispaError::network("Connection refused");
        assert!(matches!(network_err, DispaError::Network { .. }));
        assert_eq!(network_err.to_string(), "Network error: Connection refused");

        let timeout_err = DispaError::timeout(Duration::from_secs(30), "health check");
        assert!(matches!(timeout_err, DispaError::Timeout { .. }));
        assert_eq!(
            timeout_err.to_string(),
            "Operation timed out after 30s: health check"
        );
    }

    #[test]
    fn test_error_properties() {
        let network_err = DispaError::network("Connection error");
        assert!(network_err.is_retryable());
        assert!(network_err.should_trigger_circuit_breaker());
        assert_eq!(network_err.severity(), ErrorSeverity::Medium);

        let config_err = DispaError::config("Invalid config");
        assert!(!config_err.is_retryable());
        assert!(!config_err.should_trigger_circuit_breaker());
        assert_eq!(config_err.severity(), ErrorSeverity::Critical);

        let circuit_breaker_err = DispaError::circuit_breaker_open("backend1");
        assert!(!circuit_breaker_err.is_retryable());
        assert!(!circuit_breaker_err.should_trigger_circuit_breaker());
        assert_eq!(circuit_breaker_err.severity(), ErrorSeverity::Medium);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ErrorSeverity::Critical > ErrorSeverity::High);
        assert!(ErrorSeverity::High > ErrorSeverity::Medium);
        assert!(ErrorSeverity::Medium > ErrorSeverity::Low);
    }

    #[test]
    fn test_error_conversions() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let dispa_error: DispaError = io_error.into();
        assert!(matches!(dispa_error, DispaError::FileSystem { .. }));

        let anyhow_error = anyhow::anyhow!("Generic error");
        let dispa_error: DispaError = anyhow_error.into();
        assert!(matches!(dispa_error, DispaError::Internal { .. }));
    }
}
