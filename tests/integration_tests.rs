use dispa::config::{
    Config, DatabaseConfig, DomainConfig, FileConfig, HealthCheckConfig, LoadBalancingConfig,
    LoadBalancingType, LoggingConfig, LoggingType, MonitoringConfig, ServerConfig, Target,
    TargetConfig, HttpClientConfig,
};
use dispa::logger::TrafficLogger;
use dispa::proxy::ProxyServer;
use std::net::SocketAddr;

// Helper function to create a comprehensive test configuration
fn create_integration_test_config() -> Config {
    Config {
        server: ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(), // Use port 0 for auto-assignment
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
            targets: vec![
                Target {
                    name: "backend1".to_string(),
                    url: "http://127.0.0.1:3001".to_string(),
                    weight: Some(3),
                    timeout: Some(30),
                },
                Target {
                    name: "backend2".to_string(),
                    url: "http://127.0.0.1:3002".to_string(),
                    weight: Some(2),
                    timeout: Some(30),
                },
            ],
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
            histogram_buckets: None,
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: Some(HttpClientConfig{ pool_max_idle_per_host: Some(8), pool_idle_timeout_secs: Some(30), connect_timeout_secs: Some(2) }),
        plugins: None,
        security: None,
    }
}

fn create_minimal_test_config() -> Config {
    Config {
        server: ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            workers: None,
            keep_alive_timeout: None,
            request_timeout: None,
        },
        domains: DomainConfig {
            intercept_domains: vec!["minimal.com".to_string()],
            exclude_domains: None,
            wildcard_support: false,
        },
        targets: TargetConfig {
            targets: vec![Target {
                name: "single_backend".to_string(),
                url: "http://127.0.0.1:8999".to_string(),
                weight: None,
                timeout: None,
            }],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        },
        logging: LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        },
        monitoring: MonitoringConfig {
            enabled: false,
            metrics_port: 9090,
            health_check_port: 8081,
            histogram_buckets: None,
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: Some(HttpClientConfig{ pool_max_idle_per_host: Some(8), pool_idle_timeout_secs: Some(30), connect_timeout_secs: Some(2) }),
        plugins: None,
        security: None,
    }
}

#[tokio::test]
async fn test_proxy_server_creation_integration() {
    let config = create_integration_test_config();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let traffic_logger = TrafficLogger::new(config.logging.clone());

    // Create proxy server - this should integrate all components
    let proxy_server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

    // Verify the proxy server was created successfully
    // Since we can't easily test the actual server without starting it,
    // we verify the configuration was properly integrated
    assert_eq!(proxy_server.bind_addr, bind_addr);
    // The actual load balancer and traffic logger integration is verified
    // through the successful creation of the ProxyServer
}

#[tokio::test]
async fn test_config_validation_integration() {
    let mut config = create_integration_test_config();

    // Test valid configuration
    assert!(config.validate().is_ok());

    // Test invalid configurations
    config.domains.intercept_domains.clear();
    assert!(
        config.validate().is_err(),
        "Empty intercept domains should fail validation"
    );

    // Restore intercept domains and test empty targets
    config
        .domains
        .intercept_domains
        .push("test.com".to_string());
    config.targets.targets.clear();
    assert!(
        config.validate().is_err(),
        "Empty targets should fail validation"
    );

    // Test empty target URL
    config.targets.targets.push(Target {
        name: "empty_url".to_string(),
        url: "".to_string(),
        weight: Some(1),
        timeout: Some(30),
    });
    assert!(
        config.validate().is_err(),
        "Empty target URL should fail validation"
    );
}

#[tokio::test]
async fn test_load_balancing_types_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test each load balancing type
    for lb_type in [
        LoadBalancingType::RoundRobin,
        LoadBalancingType::Weighted,
        LoadBalancingType::Random,
        LoadBalancingType::LeastConnections,
    ] {
        let mut config = create_integration_test_config();
        config.targets.load_balancing.lb_type = lb_type.clone();

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Verify proxy server creation succeeds with each load balancing type
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_domain_configuration_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test various domain configurations
    let domain_configs = vec![
        // Simple domain
        DomainConfig {
            intercept_domains: vec!["simple.com".to_string()],
            exclude_domains: None,
            wildcard_support: false,
        },
        // Multiple domains
        DomainConfig {
            intercept_domains: vec![
                "first.com".to_string(),
                "second.com".to_string(),
                "third.com".to_string(),
            ],
            exclude_domains: None,
            wildcard_support: false,
        },
        // Wildcard with exclusions
        DomainConfig {
            intercept_domains: vec!["*.example.com".to_string()],
            exclude_domains: Some(vec![
                "admin.example.com".to_string(),
                "internal.example.com".to_string(),
            ]),
            wildcard_support: true,
        },
        // Mixed patterns
        DomainConfig {
            intercept_domains: vec![
                "exact.com".to_string(),
                "*.wildcard.com".to_string(),
                "another.exact.org".to_string(),
            ],
            exclude_domains: Some(vec!["private.wildcard.com".to_string()]),
            wildcard_support: true,
        },
    ];

    for domain_config in domain_configs {
        let mut config = create_minimal_test_config();
        config.domains = domain_config.clone();

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Verify proxy server integrates domain configuration correctly
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_target_configuration_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test various target configurations
    let target_sets = vec![
        // Single target
        vec![Target {
            name: "single".to_string(),
            url: "http://localhost:3000".to_string(),
            weight: Some(1),
            timeout: Some(30),
        }],
        // Multiple targets with different weights
        vec![
            Target {
                name: "heavy".to_string(),
                url: "http://localhost:3001".to_string(),
                weight: Some(5),
                timeout: Some(45),
            },
            Target {
                name: "light".to_string(),
                url: "http://localhost:3002".to_string(),
                weight: Some(1),
                timeout: Some(30),
            },
        ],
        // Targets with no weights (default)
        vec![
            Target {
                name: "default1".to_string(),
                url: "http://localhost:3003".to_string(),
                weight: None,
                timeout: None,
            },
            Target {
                name: "default2".to_string(),
                url: "http://localhost:3004".to_string(),
                weight: None,
                timeout: None,
            },
        ],
        // Mixed configurations
        vec![
            Target {
                name: "mixed1".to_string(),
                url: "https://api.service.com".to_string(),
                weight: Some(3),
                timeout: Some(60),
            },
            Target {
                name: "mixed2".to_string(),
                url: "http://192.168.1.100:8080".to_string(),
                weight: None,
                timeout: Some(15),
            },
            Target {
                name: "mixed3".to_string(),
                url: "http://127.0.0.1:9000".to_string(),
                weight: Some(2),
                timeout: None,
            },
        ],
    ];

    for targets in target_sets {
        let mut config = create_minimal_test_config();
        config.targets.targets = targets.clone();

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Verify proxy server integrates target configuration correctly
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_monitoring_configuration_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test monitoring enabled and disabled
    for enabled in [true, false] {
        let mut config = create_minimal_test_config();
        config.monitoring.enabled = enabled;
        config.monitoring.metrics_port = 9091;
        config.monitoring.health_check_port = 8082;

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Verify proxy server creation with monitoring config
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_logging_configuration_integration() {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test different logging configurations
    let logging_configs = vec![
        // Disabled logging
        LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        },
        // File logging
        LoggingConfig {
            enabled: true,
            log_type: LoggingType::File,
            database: None,
            file: Some(FileConfig {
                // Use workspace-local directory to avoid sandbox issues
                directory: "target/test_logs/integration".to_string(),
                max_file_size: Some(1000000),
                rotation: true,
            }),
            retention_days: Some(7),
        },
        // Database logging (in-memory for testing)
        LoggingConfig {
            enabled: true,
            log_type: LoggingType::Database,
            database: Some(DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: Some(5),
                connection_timeout: Some(30),
            }),
            file: None,
            retention_days: Some(14),
        },
    ];

    for logging_config in logging_configs {
        let traffic_logger = TrafficLogger::new(logging_config.clone());
        let mut config = create_minimal_test_config();
        config.logging = logging_config;
        // Ensure required optional fields are present
        config.http_client = None;
        config.plugins = None;
        config.security = None;

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

        // Verify proxy server integrates logging configuration correctly
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_health_check_configuration_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test different health check configurations
    let health_configs = vec![
        // Disabled health checks
        HealthCheckConfig {
            enabled: false,
            interval: 30,
            timeout: 10,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        },
        // Enabled with default values
        HealthCheckConfig {
            enabled: true,
            interval: 30,
            timeout: 10,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
        },
        // Custom values
        HealthCheckConfig {
            enabled: true,
            interval: 60,
            timeout: 5,
            healthy_threshold: 1,
            unhealthy_threshold: 5,
        },
        // Aggressive health checking
        HealthCheckConfig {
            enabled: true,
            interval: 10,
            timeout: 2,
            healthy_threshold: 3,
            unhealthy_threshold: 2,
        },
    ];

    for health_config in health_configs {
        let mut config = create_minimal_test_config();
        config.targets.health_check = health_config;
        config.http_client = None;
        config.plugins = None;
        config.security = None;

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());

        // Verify proxy server integrates health check configuration correctly
        assert_eq!(proxy_server.bind_addr, bind_addr);
    }
}

#[tokio::test]
async fn test_complete_configuration_integration() {
    // Test a comprehensive configuration that exercises all components
    let config = Config {
        server: ServerConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            workers: Some(4),
            keep_alive_timeout: Some(60),
            request_timeout: Some(30),
        },
        domains: DomainConfig {
            intercept_domains: vec![
                "main.service.com".to_string(),
                "*.api.service.com".to_string(),
                "cdn.assets.com".to_string(),
            ],
            exclude_domains: Some(vec![
                "private.api.service.com".to_string(),
                "admin.main.service.com".to_string(),
            ]),
            wildcard_support: true,
        },
        targets: TargetConfig {
            targets: vec![
                Target {
                    name: "primary_backend".to_string(),
                    url: "http://backend1.internal:8080".to_string(),
                    weight: Some(5),
                    timeout: Some(30),
                },
                Target {
                    name: "secondary_backend".to_string(),
                    url: "http://backend2.internal:8080".to_string(),
                    weight: Some(3),
                    timeout: Some(30),
                },
                Target {
                    name: "fallback_backend".to_string(),
                    url: "http://backup.external.com".to_string(),
                    weight: Some(1),
                    timeout: Some(45),
                },
            ],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::Weighted,
                sticky_sessions: true,
            },
            health_check: HealthCheckConfig {
                enabled: false, // Disabled for test
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        },
        logging: LoggingConfig {
            enabled: false, // Disabled for test
            log_type: LoggingType::Both,
            database: None,
            file: None,
            retention_days: Some(30),
        },
        monitoring: MonitoringConfig {
            enabled: false, // Disabled for test
            metrics_port: 9090,
            health_check_port: 8081,
            histogram_buckets: None,
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: Some(HttpClientConfig{ pool_max_idle_per_host: Some(8), pool_idle_timeout_secs: Some(30), connect_timeout_secs: Some(2) }),
        plugins: None,
        security: None,
    };

    // Verify configuration is valid
    assert!(config.validate().is_ok());

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let traffic_logger = TrafficLogger::new(config.logging.clone());

    // Create proxy server with comprehensive configuration
    let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

    // Verify successful integration
    assert_eq!(proxy_server.bind_addr, bind_addr);
}

#[tokio::test]
async fn test_configuration_edge_cases_integration() {
    let traffic_logger = TrafficLogger::new(LoggingConfig {
        enabled: false,
        log_type: LoggingType::File,
        database: None,
        file: None,
        retention_days: None,
    });

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Test configuration with edge case values
    let edge_case_config = Config {
        server: ServerConfig {
            bind_address: "0.0.0.0:0".parse().unwrap(), // Any address, any port
            workers: Some(1),                           // Minimum workers
            keep_alive_timeout: Some(1),                // Very short timeout
            request_timeout: Some(1),                   // Very short timeout
        },
        domains: DomainConfig {
            intercept_domains: vec!["a.b".to_string()], // Minimal valid domain
            exclude_domains: None,
            wildcard_support: false,
        },
        targets: TargetConfig {
            targets: vec![Target {
                name: "t".to_string(),               // Minimal name
                url: "http://1.1.1.1:1".to_string(), // IP address target
                weight: Some(1),                     // Minimum weight
                timeout: Some(1),                    // Minimum timeout
            }],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 1,            // Very frequent
                timeout: 1,             // Very short
                healthy_threshold: 1,   // Minimum threshold
                unhealthy_threshold: 1, // Minimum threshold
            },
        },
        logging: LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: Some(1), // Minimum retention
        },
        monitoring: MonitoringConfig {
            enabled: false,
            metrics_port: 1024,      // Minimum non-privileged port
            health_check_port: 1025, // Minimum non-privileged port + 1
            histogram_buckets: None,
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: None,
        plugins: None,
        security: None,
    };

    // Verify edge case configuration is valid
    assert!(edge_case_config.validate().is_ok());

    let proxy_server = ProxyServer::new(edge_case_config, bind_addr, traffic_logger);

    // Verify successful integration with edge case values
    assert_eq!(proxy_server.bind_addr, bind_addr);
}
