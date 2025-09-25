//! Core traits and types for service discovery
//!
//! This module defines the common interface that all service discovery implementations
//! must follow, along with shared data types and error handling.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tokio_stream::Stream;

/// Service discovery error types
#[derive(Debug, thiserror::Error)]
pub enum ServiceDiscoveryError {
    #[error("Service registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Service not found: {service_name}")]
    ServiceNotFound { service_name: String },

    #[error("Connection failed: {0}")]
    ConnectionFailed(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    #[error("Service discovery backend error: {0}")]
    BackendError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Result type for service discovery operations
pub type ServiceDiscoveryResult<T> = Result<T, ServiceDiscoveryError>;

/// Health status of a service instance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
    Critical,
    Warning,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
            HealthStatus::Critical => write!(f, "critical"),
            HealthStatus::Warning => write!(f, "warning"),
        }
    }
}

/// Health check configuration for a service instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check endpoint path
    pub endpoint: String,
    /// Check interval in seconds
    pub interval: Duration,
    /// Request timeout in seconds
    pub timeout: Duration,
    /// HTTP method for health check
    #[serde(default = "default_http_method")]
    pub method: String,
    /// Expected HTTP status codes for healthy state
    #[serde(default = "default_healthy_status")]
    pub healthy_status: Vec<u16>,
    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking healthy
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_healthy_status() -> Vec<u16> {
    vec![200]
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_success_threshold() -> u32 {
    2
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            endpoint: "/health".to_string(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            method: default_http_method(),
            healthy_status: default_healthy_status(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

/// A service instance discovered by the service discovery system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    /// Unique identifier for this service instance
    pub id: String,
    /// Service name (multiple instances can have the same name)
    pub name: String,
    /// IP address or hostname
    pub address: String,
    /// Port number
    pub port: u16,
    /// Service tags for filtering and routing
    #[serde(default)]
    pub tags: Vec<String>,
    /// Custom metadata key-value pairs
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Health check configuration
    pub health_check: Option<HealthCheckConfig>,
    /// Current health status
    #[serde(default = "default_health_status")]
    pub health_status: HealthStatus,
    /// Weight for load balancing (higher values get more traffic)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Service version for rolling deployments
    pub version: Option<String>,
    /// Geographic region/zone for geo-aware routing
    pub zone: Option<String>,
}

fn default_health_status() -> HealthStatus {
    HealthStatus::Unknown
}

fn default_weight() -> u32 {
    100
}

impl ServiceInstance {
    /// Create a new service instance
    pub fn new(id: String, name: String, address: String, port: u16) -> Self {
        Self {
            id,
            name,
            address,
            port,
            tags: Vec::new(),
            metadata: HashMap::new(),
            health_check: None,
            health_status: HealthStatus::Unknown,
            weight: 100,
            version: None,
            zone: None,
        }
    }

    /// Add a tag to this service instance
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    /// Add metadata to this service instance
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set health check configuration
    pub fn with_health_check(mut self, health_check: HealthCheckConfig) -> Self {
        self.health_check = Some(health_check);
        self
    }

    /// Set service weight for load balancing
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Get the service endpoint URL
    pub fn endpoint_url(&self, scheme: &str) -> String {
        format!("{}://{}:{}", scheme, self.address, self.port)
    }

    /// Check if this instance has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_string())
    }

    /// Get metadata value by key
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Type of service change event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceChangeEventType {
    /// Service instance was added
    Added,
    /// Service instance was updated
    Updated,
    /// Service instance was removed
    Removed,
    /// Health status changed
    HealthChanged,
}

/// Event representing a change in service discovery state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChangeEvent {
    /// Type of change
    pub event_type: ServiceChangeEventType,
    /// Service name affected
    pub service_name: String,
    /// Service instance (if applicable)
    pub instance: Option<ServiceInstance>,
    /// Previous instance state (for update events)
    pub previous_instance: Option<ServiceInstance>,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Additional event metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl ServiceChangeEvent {
    /// Create a new service added event
    pub fn added(service_name: String, instance: ServiceInstance) -> Self {
        Self {
            event_type: ServiceChangeEventType::Added,
            service_name,
            instance: Some(instance),
            previous_instance: None,
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create a new service removed event
    pub fn removed(service_name: String, instance: ServiceInstance) -> Self {
        Self {
            event_type: ServiceChangeEventType::Removed,
            service_name,
            instance: Some(instance),
            previous_instance: None,
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create a new service updated event
    pub fn updated(
        service_name: String,
        instance: ServiceInstance,
        previous: ServiceInstance,
    ) -> Self {
        Self {
            event_type: ServiceChangeEventType::Updated,
            service_name,
            instance: Some(instance),
            previous_instance: Some(previous),
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Create a new health status changed event
    pub fn health_changed(
        service_name: String,
        instance: ServiceInstance,
        previous: ServiceInstance,
    ) -> Self {
        Self {
            event_type: ServiceChangeEventType::HealthChanged,
            service_name,
            instance: Some(instance),
            previous_instance: Some(previous),
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }
}

/// Stream of service change events
pub type ServiceChangeStream = Box<dyn Stream<Item = ServiceChangeEvent> + Send + Unpin>;

/// Core service discovery trait
///
/// This trait defines the interface that all service discovery implementations must provide.
/// It supports service registration, discovery, health checking, and change notifications.
#[async_trait]
pub trait ServiceDiscovery: Send + Sync {
    /// Discover all instances of a service by name
    ///
    /// Returns a list of healthy service instances for the given service name.
    /// The implementation should filter out unhealthy instances unless specifically requested.
    ///
    /// # Arguments
    /// * `service_name` - Name of the service to discover
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<Vec<ServiceInstance>>` - List of service instances
    async fn discover_services(
        &self,
        service_name: &str,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>>;

    /// Discover services with additional filtering options
    ///
    /// # Arguments
    /// * `service_name` - Name of the service to discover
    /// * `tags` - Optional tags to filter by
    /// * `include_unhealthy` - Whether to include unhealthy instances
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<Vec<ServiceInstance>>` - Filtered list of service instances
    async fn discover_services_with_filter(
        &self,
        service_name: &str,
        tags: Option<&[String]>,
        include_unhealthy: bool,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>> {
        // Default implementation applies basic filtering
        let mut instances = self.discover_services(service_name).await?;

        // Filter by tags if specified
        if let Some(filter_tags) = tags {
            instances.retain(|instance| filter_tags.iter().all(|tag| instance.has_tag(tag)));
        }

        // Filter by health status if requested
        if !include_unhealthy {
            instances.retain(|instance| instance.health_status == HealthStatus::Healthy);
        }

        Ok(instances)
    }

    /// Watch for changes in service instances
    ///
    /// Returns a stream of service change events. The stream will emit events
    /// when services are added, removed, updated, or change health status.
    ///
    /// # Arguments
    /// * `service_name` - Name of the service to watch (empty string for all services)
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<ServiceChangeStream>` - Stream of change events
    async fn watch_changes(
        &self,
        service_name: &str,
    ) -> ServiceDiscoveryResult<ServiceChangeStream>;

    /// Register a service instance
    ///
    /// Registers a new service instance with the discovery backend. The instance
    /// will become available for discovery once registration is successful.
    ///
    /// # Arguments
    /// * `service` - Service instance to register
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<()>` - Success or error result
    async fn register_service(&self, service: &ServiceInstance) -> ServiceDiscoveryResult<()>;

    /// Deregister a service instance
    ///
    /// Removes a service instance from the discovery backend. The instance
    /// will no longer be returned by discovery queries.
    ///
    /// # Arguments
    /// * `service_id` - Unique ID of the service instance to remove
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<()>` - Success or error result
    async fn deregister_service(&self, service_id: &str) -> ServiceDiscoveryResult<()>;

    /// Perform a health check on a service instance
    ///
    /// Checks the health of a specific service instance and returns its status.
    /// This is typically used for on-demand health checks or validation.
    ///
    /// # Arguments
    /// * `service_id` - Unique ID of the service instance to check
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<HealthStatus>` - Current health status
    async fn health_check(&self, service_id: &str) -> ServiceDiscoveryResult<HealthStatus>;

    /// Update service instance metadata
    ///
    /// Updates the metadata for an existing service instance without re-registering it.
    /// This is useful for updating configuration or status information.
    ///
    /// # Arguments
    /// * `service_id` - Unique ID of the service instance
    /// * `metadata` - New metadata to set
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<()>` - Success or error result
    async fn update_service_metadata(
        &self,
        _service_id: &str,
        _metadata: HashMap<String, String>,
    ) -> ServiceDiscoveryResult<()> {
        // Default implementation returns not implemented error
        Err(ServiceDiscoveryError::BackendError(
            "update_service_metadata not implemented by this backend".to_string(),
        ))
    }

    /// Get all service names
    ///
    /// Returns a list of all known service names in the discovery backend.
    /// This is useful for service enumeration and debugging.
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<Vec<String>>` - List of service names
    async fn list_services(&self) -> ServiceDiscoveryResult<Vec<String>>;

    /// Get statistics about the service discovery backend
    ///
    /// Returns operational statistics like number of services, health check status, etc.
    /// This is useful for monitoring and debugging.
    ///
    /// # Returns
    /// * `ServiceDiscoveryResult<HashMap<String, String>>` - Statistics key-value pairs
    async fn get_stats(&self) -> ServiceDiscoveryResult<HashMap<String, String>> {
        // Default implementation returns basic stats
        let mut stats = HashMap::new();
        stats.insert("backend".to_string(), "unknown".to_string());
        stats.insert("status".to_string(), "active".to_string());
        Ok(stats)
    }
}
