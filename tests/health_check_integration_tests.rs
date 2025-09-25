use dispa::balancer::health_check::HealthChecker;
use dispa::config::{HealthCheckConfig, Target};
use tokio::time::{sleep, Duration};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test health check system integration and edge cases
mod health_check_integration_tests {
    use super::*;

    /// Create a test target with given address
    fn create_test_target(name: &str, url: &str) -> Target {
        Target {
            name: name.to_string(),
            address: url.replace("http://", "").replace("https://", ""),
            url: url.to_string(),
            weight: Some(1.0),
            timeout: Some(30), // seconds
        }
    }

    /// Test health checker with unreachable targets
    #[tokio::test]
    async fn test_health_check_unreachable_targets() {
        let config = HealthCheckConfig {
            enabled: true,
            interval: 1, // seconds
            timeout: 1,  // seconds
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 2,
        };

        let health_checker = HealthChecker::new(config);

        // Create targets with unreachable addresses
        let targets = vec![
            create_test_target("unreachable-1", "http://unreachable-host-1:8080"),
            create_test_target("unreachable-2", "http://unreachable-host-2:8080"),
        ];

        // Start monitoring in background (this should not panic or crash)
        let health_checker_clone = health_checker.clone();
        let targets_clone = targets.clone();
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(targets_clone).await });

        // Wait a bit for health checks to run (interval is seconds-based)
        sleep(Duration::from_millis(1500)).await;

        // All targets should be unhealthy
        for target in &targets {
            let is_healthy = health_checker.is_target_healthy(&target.name).await;
            assert!(
                !is_healthy,
                "Unreachable target {} should be unhealthy",
                target.name
            );
        }

        // Status should indicate failures
        let status = health_checker.get_all_health_status().await;
        for target in &targets {
            let target_status = status.get(&target.name);
            assert!(
                target_status.is_some(),
                "Should have status for {}",
                target.name
            );

            let target_status = target_status.unwrap();
            assert!(
                !target_status.is_healthy,
                "Target {} should be unhealthy",
                target.name
            );
            assert!(
                target_status.consecutive_failures > 0,
                "Should record failures for {}",
                target.name
            );
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
            interval: 1,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);

        let targets = vec![
            create_test_target("healthy-target", &healthy_server.uri()),
            create_test_target("unhealthy-target", &unhealthy_server.uri()),
        ];

        let health_checker_clone = health_checker.clone();
        let targets_clone = targets.clone();
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(targets_clone).await });

        // Wait for health checks to complete (interval is seconds-based)
        sleep(Duration::from_millis(1500)).await;

        // Check results
        assert!(
            health_checker.is_target_healthy("healthy-target").await,
            "Healthy target should be reported as healthy"
        );

        assert!(
            !health_checker.is_target_healthy("unhealthy-target").await,
            "Unhealthy target should be reported as unhealthy"
        );

        let status = health_checker.get_all_health_status().await;

        let healthy_status = status.get("healthy-target").unwrap();
        assert!(healthy_status.is_healthy);
        assert!(healthy_status.consecutive_successes > 0);

        let unhealthy_status = status.get("unhealthy-target").unwrap();
        assert!(!unhealthy_status.is_healthy);
        assert!(unhealthy_status.consecutive_failures > 0);

        health_checker.stop();
    }

    /// Test health checker with custom health check path (use explicit check API)
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
            interval: 1,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("custom-path-target", &server.uri());

        // Directly invoke custom path check
        let is_healthy = health_checker
            .check_target_with_custom_path(&target, "/custom/status")
            .await;
        assert!(is_healthy, "Custom path health check should succeed");
    }

    /// Test health checker threshold behavior
    #[tokio::test]
    async fn test_health_check_threshold_behavior() {
        let server = MockServer::start().await;

        // Initially respond with errors
        let _error_mock = Mock::given(method("GET"))
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
            interval: 1,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 2,   // Need 2 consecutive successes to be healthy
            unhealthy_threshold: 3, // Need 3 consecutive failures to be unhealthy
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("threshold-target", &server.uri());

        let health_checker_clone = health_checker.clone();
        let target_clone = vec![target.clone()];
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(target_clone).await });

        // Wait a moment for monitoring to initialize
        sleep(Duration::from_millis(100)).await;

        // Initially should be healthy (default state)
        assert!(
            health_checker.is_target_healthy("threshold-target").await,
            "Target should start as healthy"
        );

        // Wait for failures to accumulate (3 failures needed, seconds-based)
        sleep(Duration::from_millis(3500)).await;

        // Should now be unhealthy after 3 failures
        assert!(
            !health_checker.is_target_healthy("threshold-target").await,
            "Target should be unhealthy after threshold failures"
        );

        // Wait for successful responses (2 successes needed to recover)
        sleep(Duration::from_millis(2500)).await;

        // Should be healthy again after threshold successes
        assert!(
            health_checker.is_target_healthy("threshold-target").await,
            "Target should recover to healthy after threshold successes"
        );

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
            .respond_with(move |_: &wiremock::Request| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: 1,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("rapid-check-target", &server.uri());

        let health_checker_clone = health_checker.clone();
        let target_clone = vec![target.clone()];
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(target_clone).await });

        // Manually trigger multiple health checks to simulate rapid checks
        let target_clone = create_test_target("rapid-check-target", &server.uri());
        for _ in 0..8 {
            let _ = health_checker.check_target(&target_clone).await;
        }
        let request_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            request_count >= 8,
            "Expected at least 8 checks, got {}",
            request_count
        );

        assert!(
            health_checker.is_target_healthy("rapid-check-target").await,
            "Target should be healthy"
        );

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
                ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)), // Slower than timeout
            )
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: 1,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let target = create_test_target("timeout-target", &server.uri());

        let health_checker_clone = health_checker.clone();
        let target_clone = vec![target.clone()];
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(target_clone).await });

        // Wait for health check attempts (need at least 1 failure to become unhealthy)
        sleep(Duration::from_millis(1500)).await;

        // Should be unhealthy due to timeouts
        assert!(
            !health_checker.is_target_healthy("timeout-target").await,
            "Target should be unhealthy due to timeouts"
        );

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
            interval: 1,
            timeout: 1,
            threshold: 1,
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

        let health_checker_clone = health_checker.clone();
        let initial_targets_clone = initial_targets.clone();
        let _monitoring_handle = tokio::spawn(async move {
            health_checker_clone
                .start_monitoring(initial_targets_clone)
                .await
        });

        // Wait for initial health checks
        sleep(Duration::from_millis(200)).await;

        // All should be healthy
        assert_eq!(health_checker.get_all_health_status().await.len(), 3);

        // Cleanup with subset of targets
        let current_targets: std::collections::HashSet<String> =
            ["target-1".to_string(), "target-3".to_string()]
                .into_iter()
                .collect();

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
            .respond_with(move |_: &wiremock::Request| {
                counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;

        let config = HealthCheckConfig {
            enabled: true,
            interval: 3600,
            timeout: 1,
            threshold: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        };

        let health_checker = HealthChecker::new(config);
        let targets = vec![create_test_target("force-check-target", &server.uri())];

        let health_checker_clone = health_checker.clone();
        let targets_clone = targets.clone();
        let _monitoring_handle =
            tokio::spawn(async move { health_checker_clone.start_monitoring(targets_clone).await });

        // Wait a moment, should have minimal requests due to long interval
        sleep(Duration::from_millis(100)).await;
        let initial_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);

        // Force a health check
        health_checker.force_health_check(&targets).await;

        // Wait for forced check to complete
        sleep(Duration::from_millis(200)).await;

        let final_count = request_counter.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            final_count > initial_count,
            "Force health check should trigger additional requests: {} -> {}",
            initial_count,
            final_count
        );

        health_checker.stop();
    }
}
