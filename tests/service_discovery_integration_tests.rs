//! Service discovery integration tests
//!
//! These tests require actual service discovery backends to be running.
//! They can be skipped in CI environments by setting SKIP_INTEGRATION_TESTS=1.

use std::collections::HashMap;
use std::time::Duration;

use dispa::service_discovery::{
    ConsulServiceDiscovery, DnsServiceDiscovery, HealthCheckConfig, HealthStatus, ServiceDiscovery,
    ServiceInstance,
};

use dispa::config::service_discovery::ConsulConfig;

fn should_skip_integration_tests() -> bool {
    std::env::var("SKIP_INTEGRATION_TESTS").is_ok()
}

// Helper function to create test service instance
fn create_test_service_instance() -> ServiceInstance {
    ServiceInstance {
        id: "integration-test-service-1".to_string(),
        name: "integration-test-service".to_string(),
        address: "127.0.0.1".to_string(),
        port: 8080,
        tags: vec!["api".to_string(), "test".to_string()],
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("test_run".to_string(), "integration".to_string());
            meta.insert(
                "timestamp".to_string(),
                chrono::Utc::now().timestamp().to_string(),
            );
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
        version: Some("integration-test".to_string()),
        zone: None,
    }
}

#[cfg(feature = "consul-discovery")]
#[tokio::test]
async fn test_consul_service_discovery_integration() {
    if should_skip_integration_tests() {
        println!("Skipping Consul integration test (SKIP_INTEGRATION_TESTS is set)");
        return;
    }

    // Test with default Consul configuration (assumes Consul running on localhost:8500)
    let config = ConsulConfig::default();

    let discovery = match ConsulServiceDiscovery::new(config).await {
        Ok(d) => d,
        Err(e) => {
            println!(
                "Skipping Consul integration test - Consul not available: {}",
                e
            );
            return;
        }
    };

    // Create test service
    let service = create_test_service_instance();

    // Test service registration
    discovery
        .register_service(&service)
        .await
        .expect("Failed to register test service with Consul");

    // Small delay to allow Consul to propagate the change
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test service discovery
    let discovered_services = discovery
        .discover_services("integration-test-service")
        .await
        .expect("Failed to discover services from Consul");

    assert!(
        !discovered_services.is_empty(),
        "No services discovered from Consul"
    );

    // Find our test service
    let test_service = discovered_services
        .iter()
        .find(|s| s.id == "integration-test-service-1")
        .expect("Test service not found in Consul discovery results");

    assert_eq!(test_service.name, "integration-test-service");
    assert_eq!(test_service.address, "127.0.0.1");
    assert_eq!(test_service.port, 8080);
    assert!(test_service.tags.contains(&"api".to_string()));
    assert!(test_service.tags.contains(&"test".to_string()));

    // Test health check
    let health_status = discovery
        .health_check("integration-test-service-1")
        .await
        .expect("Failed to check service health");

    println!("Service health status: {:?}", health_status);
    // Note: Health status might be Unknown initially if health check hasn't run yet

    // Test service listing
    let services = discovery
        .list_services()
        .await
        .expect("Failed to list services");

    assert!(
        services.contains(&"integration-test-service".to_string()),
        "integration-test-service not found in service list"
    );

    // Test service deregistration
    discovery
        .deregister_service("integration-test-service-1")
        .await
        .expect("Failed to deregister test service");

    // Verify service is removed (with small delay)
    tokio::time::sleep(Duration::from_millis(100)).await;

    let services_after_removal = discovery
        .discover_services("integration-test-service")
        .await
        .expect("Failed to discover services after removal");

    // Should be empty or not contain our specific instance
    let found_service = services_after_removal
        .iter()
        .find(|s| s.id == "integration-test-service-1");

    assert!(
        found_service.is_none(),
        "Test service should have been removed but was still found"
    );
}

#[tokio::test]
async fn test_dns_service_discovery_integration() {
    if should_skip_integration_tests() {
        println!("Skipping DNS integration test (SKIP_INTEGRATION_TESTS is set)");
        return;
    }

    let discovery = DnsServiceDiscovery::new_default()
        .await
        .expect("Failed to create DNS service discovery");

    // Test with a well-known service that should resolve
    // Using 'localhost' as it should be resolvable on most systems
    let services = discovery.discover_services("localhost").await;

    match services {
        Ok(instances) => {
            println!("DNS resolved {} instances for localhost", instances.len());
            for instance in instances {
                println!("  - {}:{}", instance.address, instance.port);
                assert!(!instance.address.is_empty());
                assert!(instance.port > 0);
            }
        }
        Err(e) => {
            println!("DNS lookup failed (expected in some environments): {}", e);
            // This is not necessarily a failure as DNS configuration varies
        }
    }

    // Test health check with a valid address:port format
    let health_status = discovery.health_check("127.0.0.1:80").await;

    match health_status {
        Ok(status) => {
            println!("Health check result: {:?}", status);
            // DNS health check should return Unknown since it can only check resolution
            assert!(matches!(
                status,
                HealthStatus::Unknown | HealthStatus::Unhealthy
            ));
        }
        Err(e) => {
            println!("Health check failed: {}", e);
        }
    }

    // Test invalid service ID format
    let invalid_health = discovery.health_check("invalid-format").await;
    assert!(invalid_health.is_err());

    // Test unsupported operations
    let service = create_test_service_instance();

    let register_result = discovery.register_service(&service).await;
    assert!(register_result.is_err());

    let deregister_result = discovery.deregister_service("test").await;
    assert!(deregister_result.is_err());

    let watch_result = discovery.watch_changes("test").await;
    assert!(watch_result.is_err());

    let list_result = discovery.list_services().await;
    assert!(list_result.is_err());

    // Test stats
    let stats = discovery
        .get_stats()
        .await
        .expect("Failed to get DNS discovery stats");

    assert_eq!(stats.get("backend"), Some(&"dns".to_string()));
    assert_eq!(stats.get("status"), Some(&"active".to_string()));
}

#[tokio::test]
async fn test_service_discovery_error_handling() {
    // Test with invalid Consul configuration
    #[cfg(feature = "consul-discovery")]
    {
        let mut bad_config = ConsulConfig::default();
        bad_config.address = "http://invalid-consul-host:9999".to_string();
        bad_config.connect_timeout = Duration::from_millis(100); // Very short timeout

        let result = ConsulServiceDiscovery::new(bad_config).await;
        assert!(result.is_err());
        println!("Expected Consul connection error: {}", result.unwrap_err());
    }

    // Test DNS with invalid configuration
    let discovery = DnsServiceDiscovery::new_default()
        .await
        .expect("Failed to create DNS discovery");

    // Test with non-existent service
    let result = discovery
        .discover_services("definitely-does-not-exist-service-12345")
        .await;

    match result {
        Ok(instances) => {
            assert!(
                instances.is_empty(),
                "Should not find instances for non-existent service"
            );
        }
        Err(e) => {
            println!("Expected error for non-existent service: {}", e);
        }
    }
}

#[tokio::test]
async fn test_service_instance_comprehensive() {
    let service = create_test_service_instance();

    // Test all the utility methods
    assert_eq!(service.endpoint_url("http"), "http://127.0.0.1:8080");
    assert_eq!(service.endpoint_url("https"), "https://127.0.0.1:8080");

    assert!(service.has_tag("api"));
    assert!(service.has_tag("test"));
    assert!(!service.has_tag("production"));

    assert_eq!(
        service.get_metadata("test_run"),
        Some(&"integration".to_string())
    );
    assert!(service.get_metadata("nonexistent").is_none());

    // Test health check configuration
    let health_check = service.health_check.as_ref().unwrap();
    assert_eq!(health_check.endpoint, "/health");
    assert_eq!(health_check.method, "GET");
    assert_eq!(health_check.healthy_status, vec![200]);
    assert_eq!(health_check.failure_threshold, 3);
    assert_eq!(health_check.success_threshold, 2);

    // Test serialization/deserialization
    let json = serde_json::to_string(&service).expect("Failed to serialize ServiceInstance");

    let deserialized: ServiceInstance =
        serde_json::from_str(&json).expect("Failed to deserialize ServiceInstance");

    assert_eq!(deserialized.id, service.id);
    assert_eq!(deserialized.name, service.name);
    assert_eq!(deserialized.address, service.address);
    assert_eq!(deserialized.port, service.port);
    assert_eq!(deserialized.tags, service.tags);
    assert_eq!(deserialized.metadata, service.metadata);
}

#[tokio::test]
async fn test_multiple_service_backends() {
    // This test verifies that we can use multiple service discovery backends
    // in the same application without conflicts

    let dns_discovery = DnsServiceDiscovery::new_default()
        .await
        .expect("Failed to create DNS discovery");

    #[cfg(feature = "consul-discovery")]
    let consul_discovery = {
        let config = ConsulConfig::default();
        ConsulServiceDiscovery::new(config).await.ok()
    };

    // Both should be able to provide stats
    let dns_stats = dns_discovery
        .get_stats()
        .await
        .expect("Failed to get DNS stats");

    assert_eq!(dns_stats.get("backend"), Some(&"dns".to_string()));

    #[cfg(feature = "consul-discovery")]
    if let Some(consul) = consul_discovery {
        let consul_stats = consul
            .get_stats()
            .await
            .expect("Failed to get Consul stats");

        assert_eq!(consul_stats.get("backend"), Some(&"consul".to_string()));

        // Verify they are different instances
        assert_ne!(dns_stats.get("backend"), consul_stats.get("backend"));
    }

    println!("Multiple backend test completed successfully");
}
