//! Consul service discovery implementation
//!
//! This module provides service discovery functionality using HashiCorp Consul as the backend.
//! It supports service registration, discovery, health checks, and change notifications.

use async_trait::async_trait;

#[cfg(feature = "consul-discovery")]
use reqwest;

use crate::config::service_discovery::ConsulConfig;
use crate::service_discovery::{
    HealthStatus, ServiceChangeStream, ServiceDiscovery, ServiceDiscoveryError,
    ServiceDiscoveryResult, ServiceInstance,
};

/// Consul service discovery implementation
pub struct ConsulServiceDiscovery {
    config: ConsulConfig,
    #[cfg(feature = "consul-discovery")]
    client: reqwest::Client,
    // TODO: Add Consul client implementation
}

impl std::fmt::Debug for ConsulServiceDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsulServiceDiscovery")
            .field("config", &self.config)
            .field("client", &"<reqwest::Client>")
            .finish()
    }
}

impl ConsulServiceDiscovery {
    /// Create a new Consul service discovery instance
    pub async fn new(_config: ConsulConfig) -> ServiceDiscoveryResult<Self> {
        #[cfg(feature = "consul-discovery")]
        {
            let client = reqwest::ClientBuilder::new()
                .timeout(_config.request_timeout)
                .connect_timeout(_config.connect_timeout)
                .build()
                .map_err(|e| ServiceDiscoveryError::ConnectionFailed(std::io::Error::other(e)))?;

            let instance = Self {
                config: _config,
                client,
            };

            // Test connection to Consul
            instance.test_connection().await?;

            Ok(instance)
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled. Enable the 'consul-discovery' feature to use Consul"
                    .to_string(),
            ))
        }
    }

    /// Test connection to Consul
    #[cfg(feature = "consul-discovery")]
    async fn test_connection(&self) -> ServiceDiscoveryResult<()> {
        let url = format!("{}/v1/status/leader", self.config.address);
        let mut request = self.client.get(&url);

        if let Some(token) = &self.config.token {
            request = request.header("X-Consul-Token", token);
        }

        let response = request.send().await.map_err(|e| {
            ServiceDiscoveryError::ConnectionFailed(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                e,
            ))
        })?;

        if !response.status().is_success() {
            return Err(ServiceDiscoveryError::ConnectionFailed(
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("Consul connection test failed: HTTP {}", response.status()),
                ),
            ));
        }

        Ok(())
    }

    /// Convert ServiceInstance to Consul service registration format
    #[cfg(feature = "consul-discovery")]
    fn to_consul_service(&self, service: &ServiceInstance) -> serde_json::Value {
        let mut consul_service = serde_json::json!({
            "ID": service.id,
            "Name": service.name,
            "Address": service.address,
            "Port": service.port,
            "Tags": service.tags,
            "Meta": service.metadata
        });

        // Add health check if configured
        if let Some(health_check) = &service.health_check {
            let check = serde_json::json!({
                "HTTP": format!("{}:{}{}", service.address, service.port, health_check.endpoint),
                "Method": health_check.method,
                "Interval": format!("{}s", health_check.interval.as_secs()),
                "Timeout": format!("{}s", health_check.timeout.as_secs()),
                "DeregisterCriticalServiceAfter": format!("{}s", health_check.interval.as_secs() * health_check.failure_threshold as u64 * 2)
            });
            consul_service["Check"] = check;
        }

        consul_service
    }

    /// Convert Consul service response to ServiceInstance
    #[cfg(feature = "consul-discovery")]
    #[allow(clippy::wrong_self_convention)]
    fn from_consul_service(
        &self,
        consul_service: &serde_json::Value,
    ) -> ServiceDiscoveryResult<ServiceInstance> {
        let id = consul_service["ServiceID"].as_str().ok_or_else(|| {
            ServiceDiscoveryError::BackendError("Missing ServiceID in Consul response".to_string())
        })?;

        let name = consul_service["ServiceName"].as_str().ok_or_else(|| {
            ServiceDiscoveryError::BackendError(
                "Missing ServiceName in Consul response".to_string(),
            )
        })?;

        let address = consul_service["ServiceAddress"]
            .as_str()
            .unwrap_or_else(|| consul_service["Address"].as_str().unwrap_or(""))
            .to_string();

        let port = consul_service["ServicePort"].as_u64().ok_or_else(|| {
            ServiceDiscoveryError::BackendError(
                "Missing or invalid ServicePort in Consul response".to_string(),
            )
        })? as u16;

        let tags: Vec<String> = consul_service["ServiceTags"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let metadata: std::collections::HashMap<String, String> = consul_service["ServiceMeta"]
            .as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        // Determine health status from Consul checks
        let health_status = match consul_service["Checks"].as_array() {
            Some(checks) => {
                let has_critical = checks
                    .iter()
                    .any(|check| check["Status"].as_str() == Some("critical"));
                let has_warning = checks
                    .iter()
                    .any(|check| check["Status"].as_str() == Some("warning"));

                if has_critical {
                    HealthStatus::Critical
                } else if has_warning {
                    HealthStatus::Warning
                } else if checks
                    .iter()
                    .all(|check| check["Status"].as_str() == Some("passing"))
                {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unknown
                }
            }
            None => HealthStatus::Unknown,
        };

        Ok(ServiceInstance {
            id: id.to_string(),
            name: name.to_string(),
            address,
            port,
            tags,
            metadata,
            health_check: None, // We don't reconstruct the health check config from Consul
            health_status,
            weight: 100, // Default weight, Consul doesn't have built-in weights
            version: None,
            zone: None,
        })
    }
}

#[async_trait]
impl ServiceDiscovery for ConsulServiceDiscovery {
    async fn discover_services(
        &self,
        _service_name: &str,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>> {
        #[cfg(feature = "consul-discovery")]
        {
            let url = format!(
                "{}/v1/health/service/{}",
                self.config.address, _service_name
            );
            let mut request = self.client.get(&url).query(&[("passing", "true")]);

            if let Some(token) = &self.config.token {
                request = request.header("X-Consul-Token", token);
            }

            if let Some(dc) = &self.config.datacenter {
                request = request.query(&[("dc", dc)]);
            }

            let response = request.send().await.map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("Failed to query Consul: {}", e))
            })?;

            if !response.status().is_success() {
                return Err(ServiceDiscoveryError::BackendError(format!(
                    "Consul API error: HTTP {}",
                    response.status()
                )));
            }

            let consul_services: Vec<serde_json::Value> = response.json().await.map_err(|e| {
                ServiceDiscoveryError::BackendError(format!(
                    "Failed to parse Consul response: {}",
                    e
                ))
            })?;

            let mut instances = Vec::new();
            for consul_service in consul_services {
                if let Some(service) = consul_service.get("Service") {
                    match self.from_consul_service(service) {
                        Ok(instance) => instances.push(instance),
                        Err(e) => {
                            tracing::warn!("Failed to parse Consul service: {}", e);
                            continue;
                        }
                    }
                }
            }

            Ok(instances)
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled".to_string(),
            ))
        }
    }

    async fn watch_changes(
        &self,
        _service_name: &str,
    ) -> ServiceDiscoveryResult<ServiceChangeStream> {
        // TODO: Implement Consul watch functionality using blocking queries
        Err(ServiceDiscoveryError::BackendError(
            "Consul watch changes not yet implemented".to_string(),
        ))
    }

    async fn register_service(&self, _service: &ServiceInstance) -> ServiceDiscoveryResult<()> {
        #[cfg(feature = "consul-discovery")]
        {
            let consul_service = self.to_consul_service(_service);
            let url = format!("{}/v1/agent/service/register", self.config.address);
            let mut request = self.client.put(&url).json(&consul_service);

            if let Some(token) = &self.config.token {
                request = request.header("X-Consul-Token", token);
            }

            let response = request.send().await.map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("Failed to register service: {}", e))
            })?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(ServiceDiscoveryError::RegistrationFailed(format!(
                    "Consul registration failed: HTTP {} - {}",
                    status, error_text
                )));
            }

            tracing::info!(
                "Successfully registered service {} with Consul",
                _service.id
            );
            Ok(())
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled".to_string(),
            ))
        }
    }

    async fn deregister_service(&self, _service_id: &str) -> ServiceDiscoveryResult<()> {
        #[cfg(feature = "consul-discovery")]
        {
            let url = format!(
                "{}/v1/agent/service/deregister/{}",
                self.config.address, _service_id
            );
            let mut request = self.client.put(&url);

            if let Some(token) = &self.config.token {
                request = request.header("X-Consul-Token", token);
            }

            let response = request.send().await.map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("Failed to deregister service: {}", e))
            })?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                return Err(ServiceDiscoveryError::BackendError(format!(
                    "Consul deregistration failed: HTTP {} - {}",
                    status, error_text
                )));
            }

            tracing::info!(
                "Successfully deregistered service {} from Consul",
                _service_id
            );
            Ok(())
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled".to_string(),
            ))
        }
    }

    async fn health_check(&self, _service_id: &str) -> ServiceDiscoveryResult<HealthStatus> {
        #[cfg(feature = "consul-discovery")]
        {
            let url = format!("{}/v1/health/service/{}", self.config.address, _service_id);
            let mut request = self.client.get(&url);

            if let Some(token) = &self.config.token {
                request = request.header("X-Consul-Token", token);
            }

            let response = request.send().await.map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("Failed to check health: {}", e))
            })?;

            if !response.status().is_success() {
                return Err(ServiceDiscoveryError::HealthCheckFailed(format!(
                    "Health check failed: HTTP {}",
                    response.status()
                )));
            }

            let consul_services: Vec<serde_json::Value> = response.json().await.map_err(|e| {
                ServiceDiscoveryError::BackendError(format!(
                    "Failed to parse health response: {}",
                    e
                ))
            })?;

            // Find the specific service instance and return its health status
            for consul_service in consul_services {
                if let Some(service) = consul_service.get("Service") {
                    if service["ID"].as_str() == Some(service_id) {
                        let instance = self.from_consul_service(service)?;
                        return Ok(instance.health_status);
                    }
                }
            }

            Ok(HealthStatus::Unknown)
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled".to_string(),
            ))
        }
    }

    async fn list_services(&self) -> ServiceDiscoveryResult<Vec<String>> {
        #[cfg(feature = "consul-discovery")]
        {
            let url = format!("{}/v1/catalog/services", self.config.address);
            let mut request = self.client.get(&url);

            if let Some(token) = &self.config.token {
                request = request.header("X-Consul-Token", token);
            }

            if let Some(dc) = &self.config.datacenter {
                request = request.query(&[("dc", dc)]);
            }

            let response = request.send().await.map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("Failed to list services: {}", e))
            })?;

            if !response.status().is_success() {
                return Err(ServiceDiscoveryError::BackendError(format!(
                    "Failed to list services: HTTP {}",
                    response.status()
                )));
            }

            let services: std::collections::HashMap<String, Vec<String>> =
                response.json().await.map_err(|e| {
                    ServiceDiscoveryError::BackendError(format!(
                        "Failed to parse services response: {}",
                        e
                    ))
                })?;

            Ok(services.keys().cloned().collect())
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            Err(ServiceDiscoveryError::BackendError(
                "Consul discovery not enabled".to_string(),
            ))
        }
    }

    async fn get_stats(&self) -> ServiceDiscoveryResult<std::collections::HashMap<String, String>> {
        let mut stats = std::collections::HashMap::new();
        stats.insert("backend".to_string(), "consul".to_string());
        stats.insert("address".to_string(), self.config.address.clone());
        stats.insert(
            "tls_enabled".to_string(),
            self.config.tls_enabled.to_string(),
        );

        #[cfg(feature = "consul-discovery")]
        {
            // Try to get Consul status information
            if let Ok(()) = self.test_connection().await {
                stats.insert("status".to_string(), "connected".to_string());
            } else {
                stats.insert("status".to_string(), "disconnected".to_string());
            }
        }

        #[cfg(not(feature = "consul-discovery"))]
        {
            stats.insert("status".to_string(), "disabled".to_string());
        }

        if let Some(dc) = &self.config.datacenter {
            stats.insert("datacenter".to_string(), dc.clone());
        }

        Ok(stats)
    }
}
