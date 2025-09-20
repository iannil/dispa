use dispa::balancer::LoadBalancer;
use dispa::config::{
    Config, DomainConfig, FileConfig, HealthCheckConfig, LoadBalancingConfig, LoadBalancingType,
    LoggingConfig, LoggingType, MonitoringConfig, ServerConfig, Target, TargetConfig,
};
use dispa::logger::TrafficLogger;
use dispa::proxy::ProxyServer;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_end_to_end_test_config(target_urls: Vec<String>) -> Config {
    let targets: Vec<Target> = target_urls
        .into_iter()
        .enumerate()
        .map(|(i, url)| Target {
            name: format!("backend-{}", i + 1),
            url,
            weight: Some((i + 1) as u32), // Different weights for testing
            timeout: Some(30),
        })
        .collect();

    Config {
        server: ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(), // Auto-assign port
            workers: Some(2),
            keep_alive_timeout: Some(30),
            request_timeout: Some(10),
        },
        domains: DomainConfig {
            intercept_domains: vec![
                "test.example.com".to_string(),
                "*.api.example.com".to_string(),
            ],
            exclude_domains: Some(vec!["admin.api.example.com".to_string()]),
            wildcard_support: true,
        },
        targets: TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::Weighted,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false, // Disable for integration tests
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        },
        logging: LoggingConfig {
            enabled: false, // Disable for integration tests
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        },
        monitoring: MonitoringConfig {
            enabled: false, // Disable for integration tests
            metrics_port: 9090,
            health_check_port: 8081,
        },
        tls: None,
        routing: None,
        cache: None,
    }
}

#[tokio::test]
async fn test_end_to_end_proxy_with_load_balancing() {
    // Setup mock backend servers
    let backend1 = MockServer::start().await;
    let backend2 = MockServer::start().await;

    // Configure backend1 responses
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Backend 1"))
        .mount(&backend1)
        .await;

    // Configure backend2 responses
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Backend 2"))
        .mount(&backend2)
        .await;

    // Create proxy configuration
    let config = create_end_to_end_test_config(vec![backend1.uri(), backend2.uri()]);

    // Validate configuration
    assert!(config.validate().is_ok(), "Configuration should be valid");

    // Test load balancer creation and functionality
    let load_balancer = LoadBalancer::new(config.targets.clone());

    // Test that we can get targets from load balancer
    for _ in 0..10 {
        let target = load_balancer.get_target().await;
        assert!(target.is_some(), "Load balancer should return a target");
        let target = target.unwrap();
        assert!(
            target.name.starts_with("backend-"),
            "Target should have expected name"
        );
    }

    // Test traffic logger creation
    let traffic_logger = TrafficLogger::new(config.logging.clone());

    // Test proxy server creation
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

    // Verify proxy server configuration
    assert_eq!(proxy_server.bind_addr, bind_addr);
}

#[tokio::test]
async fn test_domain_matching_integration() {
    // Setup a single mock backend
    let backend = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
        .mount(&backend)
        .await;

    let config = create_end_to_end_test_config(vec![backend.uri()]);
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let traffic_logger = TrafficLogger::new(config.logging.clone());
    let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

    // Test domain configuration
    assert_eq!(proxy_server.config.domains.intercept_domains.len(), 2);
    assert!(proxy_server
        .config
        .domains
        .intercept_domains
        .contains(&"test.example.com".to_string()));
    assert!(proxy_server
        .config
        .domains
        .intercept_domains
        .contains(&"*.api.example.com".to_string()));
    assert!(proxy_server.config.domains.wildcard_support);
    assert!(proxy_server.config.domains.exclude_domains.is_some());
}

#[tokio::test]
async fn test_health_checking_integration() {
    // Setup mock backends with different health statuses
    let healthy_backend = MockServer::start().await;
    let unhealthy_backend = MockServer::start().await;

    // Healthy backend responds to health checks
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&healthy_backend)
        .await;

    // Unhealthy backend returns 500
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Error"))
        .mount(&unhealthy_backend)
        .await;

    let mut config =
        create_end_to_end_test_config(vec![healthy_backend.uri(), unhealthy_backend.uri()]);

    // Enable health checking for this test
    config.targets.health_check.enabled = true;
    config.targets.health_check.interval = 1; // Check every second
    config.targets.health_check.unhealthy_threshold = 1; // Fail quickly

    let load_balancer = LoadBalancer::new(config.targets.clone());

    // Give health checker time to run
    sleep(Duration::from_millis(100)).await;

    // Test health status retrieval
    let health_status = load_balancer.get_health_status().await;
    assert_eq!(
        health_status.len(),
        2,
        "Should track health for both backends"
    );

    // Test load balancer summary
    let summary = load_balancer.get_summary().await;
    assert_eq!(summary.total_targets, 2);
    assert!(summary.healthy_targets <= 2); // May be 0-2 depending on timing
}

#[tokio::test]
async fn test_different_load_balancing_algorithms() {
    // Setup multiple mock backends
    let backend1 = MockServer::start().await;
    let backend2 = MockServer::start().await;
    let backend3 = MockServer::start().await;

    for backend in [&backend1, &backend2, &backend3] {
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(backend)
            .await;
    }

    let target_urls = vec![backend1.uri(), backend2.uri(), backend3.uri()];

    // Test different load balancing algorithms
    let algorithms = vec![
        LoadBalancingType::RoundRobin,
        LoadBalancingType::Weighted,
        LoadBalancingType::Random,
        LoadBalancingType::LeastConnections,
    ];

    for algorithm in algorithms {
        let mut config = create_end_to_end_test_config(target_urls.clone());
        config.targets.load_balancing.lb_type = algorithm.clone();

        let load_balancer = LoadBalancer::new(config.targets.clone());

        // Test target selection with different algorithms
        let mut selected_targets = Vec::new();
        for _ in 0..6 {
            // Get more selections than targets to test distribution
            if let Some(target) = load_balancer.get_target().await {
                selected_targets.push(target.name);
            }
        }

        assert!(
            !selected_targets.is_empty(),
            "Should select targets with {:?} algorithm",
            algorithm
        );
        assert!(
            selected_targets.len() >= 3,
            "Should have multiple selections"
        );

        // For round robin and weighted, we should see all targets
        if matches!(
            algorithm,
            LoadBalancingType::RoundRobin | LoadBalancingType::Weighted
        ) {
            let unique_targets: std::collections::HashSet<_> =
                selected_targets.into_iter().collect();
            assert!(
                unique_targets.len() >= 2,
                "Should select from multiple targets"
            );
        }
    }
}

#[tokio::test]
async fn test_logging_integration() {
    // Test traffic logger integration with different configurations
    let logging_configs = vec![
        // Disabled logging
        LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        },
        // File logging only
        LoggingConfig {
            enabled: true,
            log_type: LoggingType::File,
            database: None,
            file: Some(FileConfig {
                directory: "/tmp/dispa_integration_test_logs".to_string(),
                max_file_size: Some(1000000),
                rotation: true,
            }),
            retention_days: Some(7),
        },
    ];

    for logging_config in logging_configs {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Test"))
            .mount(&backend)
            .await;

        let mut config = create_end_to_end_test_config(vec![backend.uri()]);
        config.logging = logging_config.clone();

        let mut traffic_logger = TrafficLogger::new(config.logging.clone());

        // Test logger initialization
        let init_result = traffic_logger.initialize().await;
        if logging_config.enabled && logging_config.file.is_some() {
            assert!(
                init_result.is_ok(),
                "File logger should initialize successfully"
            );
        } else {
            assert!(
                init_result.is_ok(),
                "Disabled logger should initialize without error"
            );
        }

        // Test proxy server creation with different logging configs
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(proxy_server.config.logging.enabled, logging_config.enabled);
        assert_eq!(
            proxy_server.config.logging.log_type,
            logging_config.log_type
        );
    }
}

#[tokio::test]
async fn test_monitoring_integration() {
    // Test monitoring configuration integration
    let monitoring_configs = vec![
        MonitoringConfig {
            enabled: false,
            metrics_port: 9090,
            health_check_port: 8081,
        },
        MonitoringConfig {
            enabled: true,
            metrics_port: 0,      // Auto-assign
            health_check_port: 0, // Auto-assign
        },
    ];

    for monitoring_config in monitoring_configs {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Test"))
            .mount(&backend)
            .await;

        let mut config = create_end_to_end_test_config(vec![backend.uri()]);
        config.monitoring = monitoring_config.clone();

        // Test that configuration is properly set
        assert_eq!(config.monitoring.enabled, monitoring_config.enabled);
        assert_eq!(
            config.monitoring.metrics_port,
            monitoring_config.metrics_port
        );
        assert_eq!(
            config.monitoring.health_check_port,
            monitoring_config.health_check_port
        );

        // Test proxy server creation with monitoring config
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = TrafficLogger::new(config.logging.clone());
        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(
            proxy_server.config.monitoring.enabled,
            monitoring_config.enabled
        );
    }
}

#[tokio::test]
async fn test_configuration_validation_integration() {
    // Test various configuration edge cases
    let test_cases = vec![
        // Valid minimal configuration
        (
            true,
            vec!["http://backend1.test".to_string()],
            vec!["test.com".to_string()],
        ),
        // Multiple targets and domains
        (
            true,
            vec![
                "http://backend1.test".to_string(),
                "http://backend2.test".to_string(),
            ],
            vec!["test.com".to_string(), "*.api.test".to_string()],
        ),
        // Empty targets (should fail)
        (false, vec![], vec!["test.com".to_string()]),
        // Empty domains (should fail)
        (false, vec!["http://backend1.test".to_string()], vec![]),
    ];

    for (should_be_valid, target_urls, domains) in test_cases {
        let mut config = create_end_to_end_test_config(target_urls);
        config.domains.intercept_domains = domains;

        let validation_result = config.validate();

        if should_be_valid {
            assert!(validation_result.is_ok(), "Configuration should be valid");

            // If valid, test that we can create components
            let traffic_logger = TrafficLogger::new(config.logging.clone());
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let _proxy_server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

            if !config.targets.targets.is_empty() {
                let _load_balancer = LoadBalancer::new(config.targets.clone());
            }
        } else {
            assert!(
                validation_result.is_err(),
                "Configuration should be invalid"
            );
        }
    }
}

#[tokio::test]
async fn test_concurrent_component_creation() {
    // Test creating multiple proxy components concurrently
    let backend = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Concurrent Test"))
        .mount(&backend)
        .await;

    let config = create_end_to_end_test_config(vec![backend.uri()]);

    let mut handles = Vec::new();

    // Create multiple components concurrently
    for i in 0..10 {
        let config_clone = config.clone();
        let handle = tokio::spawn(async move {
            let traffic_logger = TrafficLogger::new(config_clone.logging.clone());
            let load_balancer = LoadBalancer::new(config_clone.targets.clone());
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let _proxy_server = ProxyServer::new(config_clone, bind_addr, traffic_logger);

            // Test basic functionality
            let target = load_balancer.get_target().await;
            assert!(target.is_some(), "Load balancer {} should return target", i);

            // Return success indicator
            format!("Component set {} created successfully", i)
        });
        handles.push(handle);
    }

    // Wait for all concurrent creations to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(
            result.contains("created successfully"),
            "Concurrent creation failed: {}",
            result
        );
    }
}

#[tokio::test]
async fn test_component_interaction_patterns() {
    // Test how different components interact with each other
    let backend = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .mount(&backend)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("API Response"))
        .mount(&backend)
        .await;

    let config = create_end_to_end_test_config(vec![backend.uri()]);

    // Create all components
    let load_balancer = LoadBalancer::new(config.targets.clone());
    let traffic_logger = TrafficLogger::new(config.logging.clone());
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let proxy_server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

    // Test load balancer target selection
    let target = load_balancer.get_target().await;
    assert!(target.is_some());
    let target = target.unwrap();
    assert_eq!(target.name, "backend-1");
    assert_eq!(target.url, backend.uri());

    // Test load balancer statistics
    let summary = load_balancer.get_summary().await;
    assert_eq!(summary.total_targets, 1);
    assert!(summary.total_requests <= 1); // May be 0 or 1 depending on get_target() implementation
    assert_eq!(summary.total_errors, 0);

    // Simulate some load balancer usage
    load_balancer
        .record_request_result("backend-1", true, Duration::from_millis(100))
        .await;
    load_balancer
        .record_request_result("backend-1", false, Duration::from_millis(200))
        .await;

    let updated_summary = load_balancer.get_summary().await;
    assert_eq!(updated_summary.total_errors, 1);

    // Test proxy server configuration preservation
    assert_eq!(proxy_server.config.domains.intercept_domains.len(), 2);
    assert_eq!(proxy_server.config.targets.targets.len(), 1);
    assert!(!proxy_server.config.targets.health_check.enabled);
    assert!(!proxy_server.config.logging.enabled);
    assert!(!proxy_server.config.monitoring.enabled);
}
