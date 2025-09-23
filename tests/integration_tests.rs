use dispa::config::{
    Config, DatabaseConfig, DomainConfig, FileConfig, HealthCheckConfig, HttpClientConfig,
    LoadBalancingConfig, LoadBalancingType, LoggingConfig, LoggingType, MonitoringConfig,
    ServerConfig, Target, TargetConfig,
};
use dispa::logger::TrafficLogger;
use dispa::proxy::ProxyServer;
use std::net::SocketAddr;

// Helper function to create a comprehensive test configuration
fn create_integration_test_config() -> Config {
    Config {
        server: ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(), // Use port 0 for auto-assignment
            workers: Some(2),
            max_connections: Some(1000),
            connection_timeout: Some(30),
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
                    address: "http://127.0.0.1:3001".to_string(),
                    weight: Some(3.0),
                    timeout: Some(30),
                },
                Target {
                    name: "backend2".to_string(),
                    url: "http://127.0.0.1:3002".to_string(),
                    address: "http://127.0.0.1:3002".to_string(),
                    weight: Some(2.0),
                    timeout: Some(30),
                },
            ],
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::Weighted,
                lb_type: LoadBalancingType::Weighted,
                sticky_sessions: Some(false),
            },
            health_check: HealthCheckConfig {
                enabled: false, // Disable for integration tests
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            },
        },
        logging: LoggingConfig {
            enabled: false, // Disable for integration tests
            log_type: LoggingType::Database,
            database: Some(DatabaseConfig {
                url: "sqlite:test.db".to_string(),
                max_connections: Some(5),
                connection_timeout: Some(30),
            }),
            file: None,
            retention_days: None,
        },
        monitoring: MonitoringConfig {
            enabled: false, // Disable for integration tests
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_port: 9090,
            health_check_port: 8081,
            metrics_endpoint: "/metrics".to_string(),
            health_endpoint: "/health".to_string(),
            prometheus_enabled: false,
            pushgateway: None,
            histogram_buckets: None,
            capacity: Default::default(),
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: Some(HttpClientConfig {
            pool_max_idle_per_host: Some(8),
            pool_idle_timeout: Some(30),
            pool_idle_timeout_secs: Some(30),
            connect_timeout: Some(2),
            connect_timeout_secs: Some(2),
            request_timeout: Some(30),
        }),
        plugins: None,
        security: None,
    }
}

fn create_minimal_test_config() -> Config {
    Config {
        server: ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            workers: None,
            max_connections: None,
            connection_timeout: None,
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
                address: "http://127.0.0.1:8999".to_string(),
                weight: None,
                timeout: None,
            }],
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::RoundRobin,
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: Some(false),
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
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
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_port: 9090,
            health_check_port: 8081,
            metrics_endpoint: "/metrics".to_string(),
            health_endpoint: "/health".to_string(),
            prometheus_enabled: false,
            pushgateway: None,
            histogram_buckets: None,
            capacity: Default::default(),
        },
        tls: None,
        routing: None,
        cache: None,
        http_client: Some(HttpClientConfig {
            pool_max_idle_per_host: Some(8),
            pool_idle_timeout: Some(30),
            pool_idle_timeout_secs: Some(30),
            connect_timeout: Some(2),
            connect_timeout_secs: Some(2),
            request_timeout: Some(30),
        }),
        plugins: None,
        security: None,
    }
}

#[tokio::test]
async fn test_proxy_server_creation_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let config = create_integration_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = TrafficLogger::new(config.logging.clone());

        // Create proxy server - this should integrate all components
        let proxy_server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

        // Verify the proxy server was created successfully
        assert_eq!(proxy_server.bind_addr, bind_addr);
    })
    .await
    .expect("test_proxy_server_creation_integration timed out");
}

#[tokio::test]
async fn test_config_validation_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut config = create_integration_test_config();

        // 如果验证失败，打印详细错误信息
        match config.validate() {
            Ok(_) => {
                assert!(true, "Validation should pass");
            }
            Err(e) => {
                eprintln!("Validation error: {}", e);
                assert!(false, "Validation failed: {}", e);
            }
        }
        config.domains.intercept_domains.clear();
        // 注意：空的拦截域实际上是有效的，代理将处理所有流量
        // 这只会发出警告，不会导致验证失败
        assert!(
            config.validate().is_ok(),
            "Empty intercept domains should not fail validation - only warn"
        );
        config
            .domains
            .intercept_domains
            .push("test.com".to_string());
        config.targets.targets.clear();
        assert!(
            config.validate().is_err(),
            "Empty targets should fail validation"
        );
        config.targets.targets.push(Target {
            name: "empty_url".to_string(),
            url: "".to_string(),
            address: "".to_string(),
            weight: Some(1.0),
            timeout: Some(30),
        });
        assert!(
            config.validate().is_err(),
            "Empty target URL should fail validation"
        );
    })
    .await
    .expect("test_config_validation_integration timed out");
}

#[tokio::test]
async fn test_load_balancing_types_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        for lb_type in [
            LoadBalancingType::RoundRobin,
            LoadBalancingType::Weighted,
            LoadBalancingType::Random,
            LoadBalancingType::LeastConnections,
        ] {
            let mut config = create_integration_test_config();
            config.targets.load_balancing.lb_type = lb_type.clone();
            let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_load_balancing_types_integration timed out");
}

#[tokio::test]
async fn test_domain_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
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
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_domain_configuration_integration timed out");
}

#[tokio::test]
async fn test_target_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let target_sets = vec![
            // Single target
            vec![Target {
                name: "single".to_string(),
                url: "http://localhost:3000".to_string(),
                address: "http://localhost:3000".to_string(),
                weight: Some(1.0),
                timeout: Some(30),
            }],
            // Multiple targets with different weights
            vec![
                Target {
                    name: "heavy".to_string(),
                    url: "http://localhost:3001".to_string(),
                    address: "http://localhost:3001".to_string(),
                    weight: Some(5.0),
                    timeout: Some(45),
                },
                Target {
                    name: "light".to_string(),
                    url: "http://localhost:3002".to_string(),
                    address: "http://localhost:3002".to_string(),
                    weight: Some(1.0),
                    timeout: Some(30),
                },
            ],
            // Targets with no weights (default)
            vec![
                Target {
                    name: "default1".to_string(),
                    url: "http://localhost:3003".to_string(),
                    address: "http://localhost:3003".to_string(),
                    weight: None,
                    timeout: None,
                },
                Target {
                    name: "default2".to_string(),
                    url: "http://localhost:3004".to_string(),
                    address: "http://localhost:3004".to_string(),
                    weight: None,
                    timeout: None,
                },
            ],
            // Mixed configurations
            vec![
                Target {
                    name: "mixed1".to_string(),
                    url: "https://api.service.com".to_string(),
                    address: "https://api.service.com".to_string(),
                    weight: Some(3.0),
                    timeout: Some(60),
                },
                Target {
                    name: "mixed2".to_string(),
                    url: "http://192.168.1.100:8080".to_string(),
                    address: "http://192.168.1.100:8080".to_string(),
                    weight: None,
                    timeout: Some(15),
                },
                Target {
                    name: "mixed3".to_string(),
                    url: "http://127.0.0.1:9000".to_string(),
                    address: "http://127.0.0.1:9000".to_string(),
                    weight: Some(2.0),
                    timeout: None,
                },
            ],
        ];

        for targets in target_sets {
            let mut config = create_minimal_test_config();
            config.targets.targets = targets.clone();
            let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_target_configuration_integration timed out");
}

#[tokio::test]
async fn test_monitoring_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        for enabled in [true, false] {
            let mut config = create_minimal_test_config();
            config.monitoring.enabled = enabled;
            config.monitoring.metrics_port = 9091;
            config.monitoring.health_check_port = 8082;
            let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_monitoring_configuration_integration timed out");
}

#[tokio::test]
async fn test_logging_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
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
            config.http_client = None;
            config.plugins = None;
            config.security = None;
            let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_logging_configuration_integration timed out");
}

#[tokio::test]
async fn test_health_check_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let health_configs = vec![
            // Disabled health checks
            HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            },
            // Enabled with default values
            HealthCheckConfig {
                enabled: true,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            },
            // Custom values
            HealthCheckConfig {
                enabled: true,
                interval: 60,
                timeout: 5,
                healthy_threshold: 1,
                unhealthy_threshold: 5,
                threshold: 1,
            },
            // Aggressive health checking
            HealthCheckConfig {
                enabled: true,
                interval: 10,
                timeout: 2,
                healthy_threshold: 3,
                unhealthy_threshold: 2,
                threshold: 3,
            },
        ];

        for health_config in health_configs {
            let mut config = create_minimal_test_config();
            config.targets.health_check = health_config;
            config.http_client = None;
            config.plugins = None;
            config.security = None;
            let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger.clone());
            assert_eq!(proxy_server.bind_addr, bind_addr);
        }
    })
    .await
    .expect("test_health_check_configuration_integration timed out");
}

#[tokio::test]
async fn test_complete_configuration_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let config = Config {
            server: ServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                workers: Some(4),
                max_connections: Some(1000),
                connection_timeout: Some(30),
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
                        address: "http://backend1.internal:8080".to_string(),
                        weight: Some(5.0),
                        timeout: Some(30),
                    },
                    Target {
                        name: "secondary_backend".to_string(),
                        url: "http://backend2.internal:8080".to_string(),
                        address: "http://backend2.internal:8080".to_string(),
                        weight: Some(3.0),
                        timeout: Some(30),
                    },
                    Target {
                        name: "fallback_backend".to_string(),
                        url: "http://backup.external.com".to_string(),
                        address: "http://backup.external.com".to_string(),
                        weight: Some(1.0),
                        timeout: Some(45),
                    },
                ],
                load_balancing: LoadBalancingConfig {
                    algorithm: LoadBalancingType::Weighted,
                    lb_type: LoadBalancingType::Weighted,
                    sticky_sessions: Some(true),
                },
                health_check: HealthCheckConfig {
                    enabled: false, // Disabled for test
                    interval: 30,
                    timeout: 10,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                    threshold: 2,
                },
            },
            logging: LoggingConfig {
                enabled: false, // Disabled for test
                log_type: LoggingType::Both,
                database: Some(DatabaseConfig {
                    url: "sqlite:test_complete.db".to_string(),
                    max_connections: Some(5),
                    connection_timeout: Some(30),
                }),
                file: Some(FileConfig {
                    directory: "test_logs".to_string(),
                    rotation: true,
                    max_file_size: Some(1_000_000),
                }),
                retention_days: Some(30),
            },
            monitoring: MonitoringConfig {
                enabled: false, // Disabled for test
                bind: "127.0.0.1:0".parse().unwrap(),
                metrics_port: 9090,
                health_check_port: 8081,
                metrics_endpoint: "/metrics".to_string(),
                health_endpoint: "/health".to_string(),
                prometheus_enabled: false,
                pushgateway: None,
                histogram_buckets: None,
                capacity: Default::default(),
            },
            tls: None,
            routing: None,
            cache: None,
            http_client: Some(HttpClientConfig {
                pool_max_idle_per_host: Some(8),
                pool_idle_timeout: Some(30),
                pool_idle_timeout_secs: Some(30),
                connect_timeout: Some(2),
                connect_timeout_secs: Some(2),
                request_timeout: Some(30),
            }),
            plugins: None,
            security: None,
        };

        match config.validate() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Complete configuration validation error: {}", e);
                panic!("Complete configuration validation failed: {}", e);
            }
        }
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = TrafficLogger::new(config.logging.clone());
        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);
        assert_eq!(proxy_server.bind_addr, bind_addr);
    })
    .await
    .expect("test_complete_configuration_integration timed out");
}

#[tokio::test]
async fn test_configuration_edge_cases_integration() {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let edge_case_config = Config {
            server: ServerConfig {
                bind: "0.0.0.0:0".parse().unwrap(), // Any address, any port
                workers: Some(1),                   // Minimum workers
                max_connections: Some(10),          // Small connection limit
                connection_timeout: Some(1),        // Very short timeout
            },
            domains: DomainConfig {
                intercept_domains: vec!["a.b".to_string()], // Minimal valid domain
                exclude_domains: None,
                wildcard_support: false,
            },
            targets: TargetConfig {
                targets: vec![Target {
                    name: "t".to_string(),                   // Minimal name
                    url: "http://1.1.1.1:1".to_string(),     // IP address target
                    address: "http://1.1.1.1:1".to_string(), // IP address target
                    weight: Some(1.0),                       // Minimum weight
                    timeout: Some(1),                        // Minimum timeout
                }],
                load_balancing: LoadBalancingConfig {
                    algorithm: LoadBalancingType::RoundRobin,
                    lb_type: LoadBalancingType::RoundRobin,
                    sticky_sessions: Some(false),
                },
                health_check: HealthCheckConfig {
                    enabled: false,
                    interval: 2,            // 足够的间隔
                    timeout: 1,             // 超时时间小于间隔
                    healthy_threshold: 1,   // Minimum threshold
                    unhealthy_threshold: 1, // Minimum threshold
                    threshold: 1,           // Minimum threshold
                },
            },
            logging: LoggingConfig {
                enabled: false,
                log_type: LoggingType::File,
                database: None,
                file: Some(FileConfig {
                    directory: "edge_case_logs".to_string(),
                    rotation: true,
                    max_file_size: Some(100_000), // 小文件大小
                }),
                retention_days: Some(1), // Minimum retention
            },
            monitoring: MonitoringConfig {
                enabled: false,
                bind: "127.0.0.1:0".parse().unwrap(),
                metrics_port: 1024,      // Minimum non-privileged port
                health_check_port: 1025, // Minimum non-privileged port + 1
                metrics_endpoint: "/metrics".to_string(),
                health_endpoint: "/health".to_string(),
                prometheus_enabled: false,
                pushgateway: None,
                histogram_buckets: None,
                capacity: Default::default(),
            },
            tls: None,
            routing: None,
            cache: None,
            http_client: None,
            plugins: None,
            security: None,
        };

        match edge_case_config.validate() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Edge case configuration validation error: {}", e);
                panic!("Edge case configuration validation failed: {}", e);
            }
        }
        let proxy_server = ProxyServer::new(edge_case_config, bind_addr, traffic_logger);
        assert_eq!(proxy_server.bind_addr, bind_addr);
    })
    .await
    .expect("test_configuration_edge_cases_integration timed out");
}
