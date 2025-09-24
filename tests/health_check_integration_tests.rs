use dispa::balancer::health_check::{HealthChecker, HealthStatus};
use dispa::config::{HealthCheckConfig, Target};
use std::collections::HashMap;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use tokio::time::sleep;

/// Test health check system integration and edge cases
mod health_check_integration_tests {
    use super::*;

    /// Create a test target with given address
    fn create_test_target(name: &str, address: &str) -> Target {
        Target {
            name: name.to_string(),
            address: address.to_string(),
            weight: Some(1.0),
            timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Test health checker with unreachable targets
    #[tokio::test]
    async fn test_health_check_unreachable_targets() {
        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(500),
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 2,
        };

        let health_checker = HealthChecker::new(config);

        // Create targets with unreachable addresses
        let targets = vec![
            create_test_target("unreachable-1", "http://unreachable-host-1:8080"),
            create_test_target("unreachable-2", "http://unreachable-host-2:8080"),
        ];

        // Start monitoring (this should not panic or crash)
        let result = health_checker.start_monitoring(targets.clone()).await;
        assert!(result.is_ok(), "Health checker should start even with unreachable targets");

        // Wait a bit for health checks to run
        sleep(Duration::from_millis(300)).await;

        // All targets should be unhealthy
        for target in &targets {
            let is_healthy = health_checker.is_target_healthy(&target.name).await;
            assert!(!is_healthy, "Unreachable target {} should be unhealthy", target.name);
        }

        // Status should indicate failures
        let status = health_checker.get_all_health_status().await;
        for target in &targets {
            let target_status = status.get(&target.name);
            assert!(target_status.is_some(), "Should have status for {}", target.name);

            let target_status = target_status.unwrap();
            assert!(!target_status.is_healthy, "Target {} should be unhealthy", target.name);
            assert!(target_status.consecutive_failures > 0, "Should record failures for {}", target.name);
        }

        // Cleanup
        health_checker.stop();
    }

    /// Test health checker with mix of healthy and unhealthy targets
    #[tokio::test]
    async fn test_health_check_mixed_target_health() {
        // Start mock servers
        let healthy_server = MockServer::start().await;
        let unhealthy_server = MockServer::start().await;

        // Configure healthy server to respond with 200
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&healthy_server)
            .await;

        // Configure unhealthy server to respond with 500
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&unhealthy_server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(1000),
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);

        let targets = vec![
            create_test_target("healthy-target", &healthy_server.uri()),
            create_test_target("unhealthy-target", &unhealthy_server.uri()),
        ];

        health_checker.start_monitoring(targets.clone()).await.unwrap();

        // Wait for health checks to complete
        sleep(Duration::from_millis(500)).await;

        // Check results
        assert!(health_checker.is_target_healthy("healthy-target").await,
            "Healthy target should be reported as healthy");

        assert!(!health_checker.is_target_healthy("unhealthy-target").await,
            "Unhealthy target should be reported as unhealthy");

        let status = health_checker.get_all_health_status().await;

        let healthy_status = status.get("healthy-target").unwrap();
        assert!(healthy_status.is_healthy);
        assert!(healthy_status.consecutive_successes > 0);

        let unhealthy_status = status.get("unhealthy-target").unwrap();
        assert!(!unhealthy_status.is_healthy);
        assert!(unhealthy_status.consecutive_failures > 0);

        health_checker.stop();
    }

    /// Test health checker with custom health check path
    #[tokio::test]
    async fn test_custom_health_check_path() {
        let server = MockServer::start().await;

        // Mock custom health endpoint
        Mock::given(method("GET"))
            .and(path("/custom/status"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Service is running"))
            .mount(&server)
            .await;

        // Default path should not be mocked (will return 404)
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(1000),
            path: "/custom/status".to_string(), // Custom path
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("custom-path-target", &server.uri());

        health_checker.start_monitoring(vec![target]).await.unwrap();

        // Wait for health check
        sleep(Duration::from_millis(300)).await;

        // Should be healthy with custom path
        assert!(health_checker.is_target_healthy("custom-path-target").await,
            "Target should be healthy with custom health check path");

        health_checker.stop();
    }

    /// Test health checker threshold behavior
    #[tokio::test]
    async fn test_health_check_threshold_behavior() {
        let server = MockServer::start().await;

        // Initially respond with errors
        let error_mock = Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(3) // Fail 3 times
            .mount(&server)
            .await;

        // Then respond successfully
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(1000),
            path: "/health".to_string(),
            healthy_threshold: 2, // Need 2 consecutive successes to be healthy
            unhealthy_threshold: 3, // Need 3 consecutive failures to be unhealthy
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("threshold-target", &server.uri());

        health_checker.start_monitoring(vec![target]).await.unwrap();

        // Initially should be healthy (default state)
        assert!(health_checker.is_target_healthy("threshold-target").await,
            "Target should start as healthy");

        // Wait for failures to accumulate (3 failures needed)
        sleep(Duration::from_millis(400)).await;

        // Should now be unhealthy after 3 failures
        assert!(!health_checker.is_target_healthy("threshold-target").await,
            "Target should be unhealthy after threshold failures");

        // Wait for successful responses (2 successes needed to recover)
        sleep(Duration::from_millis(300)).await;

        // Should be healthy again after threshold successes
        assert!(health_checker.is_target_healthy("threshold-target").await,
            "Target should recover to healthy after threshold successes");

        health_checker.stop();
    }

    /// Test health checker with very short intervals
    #[tokio::test]
    async fn test_health_check_rapid_intervals() {
        let server = MockServer::start().await;
        let request_counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = request_counter.clone();

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with_fn(move |_| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(10), // Very short interval
            timeout: Duration::from_millis(100),
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("rapid-check-target", &server.uri());

        health_checker.start_monitoring(vec![target]).await.unwrap();

        // Wait for multiple checks
        sleep(Duration::from_millis(200)).await;

        // Should have made multiple requests
        let request_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert!(request_count >= 5, "Should have made multiple rapid health checks, got {}", request_count);

        assert!(health_checker.is_target_healthy("rapid-check-target").await,
            "Target should be healthy");

        health_checker.stop();
    }

    /// Test health checker timeout handling
    #[tokio::test]
    async fn test_health_check_timeout() {
        let server = MockServer::start().await;

        // Configure server to respond slowly
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200)) // Slower than timeout
            )
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(50), // Short timeout
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("timeout-target", &server.uri());

        health_checker.start_monitoring(vec![target]).await.unwrap();

        // Wait for health check attempts
        sleep(Duration::from_millis(300)).await;

        // Should be unhealthy due to timeouts
        assert!(!health_checker.is_target_healthy("timeout-target").await,
            "Target should be unhealthy due to timeouts");

        let status = health_checker.get_target_status("timeout-target").await;
        assert!(status.is_some());
        let status = status.unwrap();
        assert!(!status.is_healthy);
        assert!(status.consecutive_failures > 0);

        health_checker.stop();
    }

    /// Test health checker cleanup of removed targets
    #[tokio::test]
    async fn test_health_check_target_cleanup() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_millis(100),
            timeout: Duration::from_millis(1000),
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);

        // Start with multiple targets
        let initial_targets = vec![
            create_test_target("target-1", &server.uri()),
            create_test_target("target-2", &server.uri()),
            create_test_target("target-3", &server.uri()),
        ];

        health_checker.start_monitoring(initial_targets).await.unwrap();

        // Wait for initial health checks
        sleep(Duration::from_millis(200)).await;

        // All should be healthy
        assert_eq!(health_checker.get_all_health_status().await.len(), 3);

        // Cleanup with subset of targets
        let current_targets: std::collections::HashSet<String> =
            ["target-1".to_string(), "target-3".to_string()].into_iter().collect();

        health_checker.cleanup_expired_data(&current_targets).await;

        // After cleanup, only target-1 and target-3 should remain
        let remaining_status = health_checker.get_all_health_status().await;
        assert_eq!(remaining_status.len(), 2);
        assert!(remaining_status.contains_key("target-1"));
        assert!(remaining_status.contains_key("target-3"));
        assert!(!remaining_status.contains_key("target-2"));

        health_checker.stop();
    }

    /// Test force health check functionality
    #[tokio::test]
    async fn test_force_health_check() {
        let server = MockServer::start().await;
        let request_counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = request_counter.clone();

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with_fn(move |_| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: Duration::from_secs(3600), // Very long interval
            timeout: Duration::from_millis(1000),
            path: "/health".to_string(),
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let targets = vec![create_test_target("force-check-target", &server.uri())];

        health_checker.start_monitoring(targets.clone()).await.unwrap();

        // Wait a moment, should have minimal requests due to long interval
        sleep(Duration::from_millis(100)).await;
        let initial_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);

        // Force a health check
        health_checker.force_health_check(&targets).await;

        // Wait for forced check to complete
        sleep(Duration::from_millis(200)).await;

        let final_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert!(final_count > initial_count,
            "Force health check should trigger additional requests: {} -> {}",
            initial_count, final_count);

        health_checker.stop();
    }
}