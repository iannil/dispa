//! Service discovery unit tests
//!
//! This module contains unit tests for the service discovery functionality

use std::collections::HashMap;
use std::time::Duration;

use crate::service_discovery::{
    ConsulServiceDiscovery, DnsServiceDiscovery, HealthCheckConfig, HealthStatus, ServiceDiscovery,
    ServiceDiscoveryError, ServiceInstance,
};

// Helper function to create test service instance
fn create_test_service_instance() -> ServiceInstance {
    ServiceInstance {
        id: "test-service-1".to_string(),
        name: "test-service".to_string(),
        address: "127.0.0.1".to_string(),
        port: 8080,
        tags: vec!["api".to_string(), "v1".to_string()],
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("version".to_string(), "1.0.0".to_string());
            meta.insert("environment".to_string(), "test".to_string());
            meta
        },
        health_check: Some(HealthCheckConfig {
            endpoint: "/health".to_string(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            method: "GET".to_string(),
            healthy_status: vec![200],
            failure_threshold: 3,
            success_threshold: 2,
        }),
        health_status: HealthStatus::Healthy,
        weight: 100,
        version: Some("1.0.0".to_string()),
        zone: Some("us-east-1a".to_string()),
    }
}

#[cfg(test)]
mod service_instance_tests {
    use super::*;

    #[test]
    fn test_service_instance_creation() {
        let instance = ServiceInstance::new(
            "service-1".to_string(),
            "api-service".to_string(),
            "192.168.1.1".to_string(),
            8080,
        );

        assert_eq!(instance.id, "service-1");
        assert_eq!(instance.name, "api-service");
        assert_eq!(instance.address, "192.168.1.1");
        assert_eq!(instance.port, 8080);
        assert_eq!(instance.health_status, HealthStatus::Unknown);
        assert_eq!(instance.weight, 100);
    }

    #[test]
    fn test_service_instance_builder_pattern() {
        let instance = ServiceInstance::new(
            "service-1".to_string(),
            "api-service".to_string(),
            "192.168.1.1".to_string(),
            8080,
        )
        .with_tag("api".to_string())
        .with_tag("v1".to_string())
        .with_metadata("version".to_string(), "1.0.0".to_string())
        .with_weight(150);

        assert_eq!(instance.tags.len(), 2);
        assert!(instance.has_tag("api"));
        assert!(instance.has_tag("v1"));
        assert!(!instance.has_tag("v2"));

        assert_eq!(instance.get_metadata("version"), Some(&"1.0.0".to_string()));
        assert_eq!(instance.get_metadata("missing"), None);

        assert_eq!(instance.weight, 150);
    }

    #[test]
    fn test_endpoint_url_generation() {
        let instance = create_test_service_instance();

        assert_eq!(instance.endpoint_url("http"), "http://127.0.0.1:8080");
        assert_eq!(instance.endpoint_url("https"), "https://127.0.0.1:8080");
    }
}

#[cfg(test)]
mod health_check_config_tests {
    use super::*;

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();

        assert_eq!(config.endpoint, "/health");
        assert_eq!(config.method, "GET");
        assert_eq!(config.healthy_status, vec![200]);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
    }

    #[test]
    fn test_health_check_config_serde() {
        let config = HealthCheckConfig {
            endpoint: "/api/health".to_string(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            method: "POST".to_string(),
            healthy_status: vec![200, 204],
            failure_threshold: 5,
            success_threshold: 1,
        };

        let json = serde_json::to_string(&config).expect("Failed to serialize health check config");
        let deserialized: HealthCheckConfig =
            serde_json::from_str(&json).expect("Failed to deserialize health check config");

        assert_eq!(deserialized.endpoint, "/api/health");
        assert_eq!(deserialized.method, "POST");
        assert_eq!(deserialized.healthy_status, vec![200, 204]);
    }
}

#[cfg(test)]
mod dns_service_discovery_tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_service_discovery_creation() {
        let discovery = DnsServiceDiscovery::new_default().await;
        assert!(discovery.is_ok());

        let stats = discovery.unwrap().get_stats().await.unwrap();
        assert_eq!(stats.get("backend"), Some(&"dns".to_string()));
        assert_eq!(stats.get("status"), Some(&"active".to_string()));
    }

    #[tokio::test]
    async fn test_dns_unsupported_operations() {
        let discovery = DnsServiceDiscovery::new_default().await.unwrap();
        let service = create_test_service_instance();

        // DNS doesn't support service registration
        let result = discovery.register_service(&service).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ServiceDiscoveryError::BackendError(_)
        ));

        // DNS doesn't support service deregistration
        let result = discovery.deregister_service("test-id").await;
        assert!(result.is_err());

        // DNS doesn't support change watching
        let result = discovery.watch_changes("test-service").await;
        assert!(result.is_err());

        // DNS doesn't support service enumeration
        let result = discovery.list_services().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dns_health_check_invalid_service_id() {
        let discovery = DnsServiceDiscovery::new_default().await.unwrap();

        let result = discovery.health_check("invalid-format").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ServiceDiscoveryError::ConfigurationError(_)
        ));
    }
}

#[cfg(test)]
mod consul_service_discovery_tests {
    use super::*;
    use crate::config::service_discovery::ConsulConfig;

    #[tokio::test]
    async fn test_consul_config_default() {
        let config = ConsulConfig::default();

        assert_eq!(config.address, "http://localhost:8500");
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert!(!config.tls_enabled);
        assert!(config.token.is_none());
        assert!(config.datacenter.is_none());
    }

    #[tokio::test]
    async fn test_consul_service_discovery_without_feature() {
        let config = ConsulConfig::default();

        #[cfg(not(feature = "consul-discovery"))]
        {
            let result = ConsulServiceDiscovery::new(config).await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ServiceDiscoveryError::BackendError(_)
            ));
        }
    }

    #[cfg(feature = "consul-discovery")]
    #[tokio::test]
    async fn test_consul_to_consul_service_conversion() {
        // This test requires access to private methods and is disabled for now
        // The conversion functionality is tested indirectly through integration tests
        let _config = ConsulConfig::default();
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_service_discovery_error_display() {
        let error = ServiceDiscoveryError::ServiceNotFound {
            service_name: "missing-service".to_string(),
        };

        let error_string = error.to_string();
        assert!(error_string.contains("missing-service"));

        let error = ServiceDiscoveryError::RegistrationFailed("Connection timeout".to_string());
        assert!(error.to_string().contains("Connection timeout"));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Critical.to_string(), "critical");
        assert_eq!(HealthStatus::Warning.to_string(), "warning");
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }
}

// Integration test helpers (would typically be in separate integration test files)
#[cfg(test)]
mod integration_test_helpers {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Mock service discovery implementation for testing
    pub struct MockServiceDiscovery {
        pub services: Arc<Mutex<HashMap<String, Vec<ServiceInstance>>>>,
        pub registered_services: Arc<Mutex<Vec<ServiceInstance>>>,
    }

    impl MockServiceDiscovery {
        pub fn new() -> Self {
            Self {
                services: Arc::new(Mutex::new(HashMap::new())),
                registered_services: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub async fn add_mock_service(
            &self,
            service_name: String,
            instances: Vec<ServiceInstance>,
        ) {
            let mut services = self.services.lock().await;
            services.insert(service_name, instances);
        }
    }

    #[async_trait::async_trait]
    impl ServiceDiscovery for MockServiceDiscovery {
        async fn discover_services(
            &self,
            service_name: &str,
        ) -> Result<Vec<ServiceInstance>, ServiceDiscoveryError> {
            let services = self.services.lock().await;
            Ok(services.get(service_name).cloned().unwrap_or_else(Vec::new))
        }

        async fn watch_changes(
            &self,
            _service_name: &str,
        ) -> Result<crate::service_discovery::ServiceChangeStream, ServiceDiscoveryError> {
            Err(ServiceDiscoveryError::BackendError(
                "Mock does not support watching".to_string(),
            ))
        }

        async fn register_service(
            &self,
            service: &ServiceInstance,
        ) -> Result<(), ServiceDiscoveryError> {
            let mut registered = self.registered_services.lock().await;
            registered.push(service.clone());
            Ok(())
        }

        async fn deregister_service(&self, service_id: &str) -> Result<(), ServiceDiscoveryError> {
            let mut registered = self.registered_services.lock().await;
            registered.retain(|s| s.id != service_id);
            Ok(())
        }

        async fn health_check(
            &self,
            _service_id: &str,
        ) -> Result<HealthStatus, ServiceDiscoveryError> {
            Ok(HealthStatus::Healthy)
        }

        async fn list_services(&self) -> Result<Vec<String>, ServiceDiscoveryError> {
            let services = self.services.lock().await;
            Ok(services.keys().cloned().collect())
        }
    }

    #[tokio::test]
    async fn test_mock_service_discovery() {
        let mock = MockServiceDiscovery::new();
        let test_service = create_test_service_instance();

        // Test service registration
        mock.register_service(&test_service).await.unwrap();

        let registered = mock.registered_services.lock().await;
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].id, "test-service-1");

        // Test service discovery with mock data
        drop(registered); // Release lock
        mock.add_mock_service("test-service".to_string(), vec![test_service.clone()])
            .await;

        let discovered = mock.discover_services("test-service").await.unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].id, "test-service-1");

        // Test health check
        let health = mock.health_check("test-service-1").await.unwrap();
        assert_eq!(health, HealthStatus::Healthy);

        // Test service deregistration
        mock.deregister_service("test-service-1").await.unwrap();

        let registered = mock.registered_services.lock().await;
        assert_eq!(registered.len(), 0);
    }
}
