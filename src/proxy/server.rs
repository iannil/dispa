use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{error, info, warn};

use super::handler::ProxyHandler;
use super::http_client;
use crate::balancer::LoadBalancer;
use crate::config::Config;
use crate::error::DispaResult;
use crate::logger::TrafficLogger;
use crate::routing::RoutingEngine;
use crate::tls::TlsManager;
use crate::plugins::{PluginEngine, SharedPluginEngine};

pub struct ProxyServer {
    pub config: Config,
    pub bind_addr: SocketAddr,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    domain_config: std::sync::Arc<std::sync::RwLock<crate::config::DomainConfig>>,
    traffic_logger: TrafficLogger,
    tls_manager: Option<TlsManager>,
    routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
    plugins: SharedPluginEngine,
}

impl ProxyServer {
    pub fn new(config: Config, bind_addr: SocketAddr, traffic_logger: TrafficLogger) -> Self {
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(LoadBalancer::new(
            config.targets.clone(),
        )));

        // Initialize shared HTTP client pool with config (first call wins)
        http_client::init(config.http_client.as_ref());

        // Initialize TLS manager if TLS is configured
        let tls_manager = if let Some(tls_config) = &config.tls {
            if tls_config.enabled {
                Some(TlsManager::new(tls_config.clone()))
            } else {
                None
            }
        } else {
            None
        };

        // Initialize routing engine if configured
        let routing_engine = if let Some(routing_config) = &config.routing {
            match RoutingEngine::new(routing_config.clone()) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    warn!("Failed to initialize routing engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        };

        // Initialize plugin engine if configured
        let plugins = if let Some(plugins_cfg) = &config.plugins {
            match PluginEngine::new(plugins_cfg) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    warn!("Failed to initialize plugin engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        };

        let domain_config = std::sync::Arc::new(std::sync::RwLock::new(config.domains.clone()));

        Self {
            config,
            bind_addr,
            load_balancer,
            domain_config,
            traffic_logger,
            tls_manager,
            routing_engine,
            plugins,
        }
    }

    /// Initialize the proxy server (including TLS if enabled)
    #[allow(dead_code)]
    pub async fn initialize(&mut self) -> DispaResult<()> {
        if let Some(ref mut tls_manager) = self.tls_manager {
            info!("Initializing TLS configuration");
            tls_manager.initialize().await?;
            info!("TLS configuration initialized successfully");
        }
        Ok(())
    }

    /// Create a proxy handler with optional routing support
    fn create_handler(&self) -> ProxyHandler {
        // Handler uses shared routing engine (may be None) and sees updates on reload
        ProxyHandler::with_shared_routing(
            std::sync::Arc::clone(&self.domain_config),
            std::sync::Arc::clone(&self.load_balancer),
            self.traffic_logger.clone(),
            std::sync::Arc::clone(&self.routing_engine),
            std::sync::Arc::clone(&self.plugins),
        )
    }

    pub async fn run(self) -> Result<()> {
        // Check if TLS is enabled
        if let Some(ref tls_manager) = self.tls_manager {
            if tls_manager.is_enabled() {
                info!("Starting HTTPS proxy server on {}", self.bind_addr);
                return self.run_https().await;
            }
        }

        info!("Starting HTTP proxy server on {}", self.bind_addr);
        self.run_http().await
    }

    /// Run HTTP server
    async fn run_http(self) -> Result<()> {
        let handler = self.create_handler();

        let make_service = make_service_fn(move |_conn| {
            let handler = handler.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let handler = handler.clone();
                    async move { handler.handle_request(req).await }
                }))
            }
        });

        let server = Server::bind(&self.bind_addr).serve(make_service);

        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }

        Ok(())
    }

    /// Run HTTPS server with TLS termination
    async fn run_https(self) -> Result<()> {
        let tls_manager = self
            .tls_manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS manager not initialized"))?;

        let _server_config = tls_manager
            .server_config()
            .ok_or_else(|| anyhow::anyhow!("TLS server config not available"))?
            .clone();

        let handler = self.create_handler();

        let make_service = make_service_fn(move |_conn| {
            let handler = handler.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let handler = handler.clone();
                    async move { handler.handle_request(req).await }
                }))
            }
        });

        // For now, use a simple implementation
        // Note: Proper HTTPS server via hyper-rustls to be implemented later
        warn!("HTTPS server implementation is simplified - using HTTP fallback");
        info!("Note: Full HTTPS implementation requires additional integration work");

        let server = Server::bind(&self.bind_addr).serve(make_service);

        if let Err(e) = server.await {
            error!("HTTPS server error: {}", e);
        }

        Ok(())
    }
}

impl ProxyServer {
    #[allow(dead_code)]
    pub fn load_balancer_handle(&self) -> std::sync::Arc<tokio::sync::RwLock<LoadBalancer>> {
        std::sync::Arc::clone(&self.load_balancer)
    }

    #[allow(dead_code)]
    pub fn routing_engine_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>> {
        std::sync::Arc::clone(&self.routing_engine)
    }

    #[allow(dead_code)]
    pub fn plugins_handle(&self) -> SharedPluginEngine {
        std::sync::Arc::clone(&self.plugins)
    }

    #[allow(dead_code)]
    pub fn domain_config_handle(
        &self,
    ) -> std::sync::Arc<std::sync::RwLock<crate::config::DomainConfig>> {
        std::sync::Arc::clone(&self.domain_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, DomainConfig, HealthCheckConfig, LoadBalancingConfig, LoadBalancingType,
        LoggingConfig, LoggingType, MonitoringConfig, ServerConfig, Target, TargetConfig,
    };
    use std::time::Duration;

    fn create_test_config() -> Config {
        Config {
            server: ServerConfig {
                bind_address: "127.0.0.1:0".parse().unwrap(), // Use port 0 for auto-assignment
                workers: Some(2),
                keep_alive_timeout: Some(30),
                request_timeout: Some(10),
            },
            domains: DomainConfig {
                intercept_domains: vec!["test.example.com".to_string()],
                exclude_domains: Some(vec!["admin.test.example.com".to_string()]),
                wildcard_support: true,
            },
            targets: TargetConfig {
                targets: vec![
                    Target {
                        name: "test-backend-1".to_string(),
                        url: "http://127.0.0.1:3001".to_string(),
                        weight: Some(1),
                        timeout: Some(30),
                    },
                    Target {
                        name: "test-backend-2".to_string(),
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
                    enabled: false, // Disable for tests to avoid network calls
                    interval: 30,
                    timeout: 5,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                },
            },
            logging: LoggingConfig {
                enabled: false, // Disable for tests
                log_type: LoggingType::File,
                database: None,
                file: None,
                retention_days: None,
            },
            monitoring: MonitoringConfig {
                enabled: false, // Disable for tests
                metrics_port: 9090,
                health_check_port: 8081,
            },
            tls: None,     // TLS disabled for tests
            routing: None, // Routing disabled for tests
            cache: None,   // Cache disabled for tests
        }
    }

    fn create_test_traffic_logger() -> TrafficLogger {
        TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        })
    }

    #[tokio::test]
    async fn test_proxy_server_creation() {
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

        assert_eq!(server.bind_addr, bind_addr);
        assert_eq!(server.config.server.workers, Some(2));
        assert_eq!(
            server.config.domains.intercept_domains,
            vec!["test.example.com".to_string()]
        );
        assert_eq!(server.config.targets.targets.len(), 2);
        assert_eq!(server.config.targets.targets[0].name, "test-backend-1");
        assert_eq!(server.config.targets.targets[1].name, "test-backend-2");
    }

    #[tokio::test]
    async fn test_proxy_server_creation_with_different_bind_addresses() {
        let config = create_test_config();
        let traffic_logger = create_test_traffic_logger();

        // Test with IPv4 loopback
        let ipv4_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let server_ipv4 = ProxyServer::new(config.clone(), ipv4_addr, traffic_logger.clone());
        assert_eq!(server_ipv4.bind_addr, ipv4_addr);

        // Test with IPv4 any address
        let any_addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let server_any = ProxyServer::new(config.clone(), any_addr, traffic_logger.clone());
        assert_eq!(server_any.bind_addr, any_addr);

        // Test with specific port
        let specific_port: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let server_port = ProxyServer::new(config, specific_port, traffic_logger);
        assert_eq!(server_port.bind_addr, specific_port);
    }

    #[tokio::test]
    async fn test_proxy_server_config_preservation() {
        let mut config = create_test_config();
        config.server.workers = Some(8);
        config.server.keep_alive_timeout = Some(120);
        config.server.request_timeout = Some(60);
        config.domains.wildcard_support = false;
        config.targets.load_balancing.sticky_sessions = true;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

        // Verify that all config values are preserved
        assert_eq!(server.config.server.workers, Some(8));
        assert_eq!(server.config.server.keep_alive_timeout, Some(120));
        assert_eq!(server.config.server.request_timeout, Some(60));
        assert!(!server.config.domains.wildcard_support);
        assert!(server.config.targets.load_balancing.sticky_sessions);
    }

    #[tokio::test]
    async fn test_proxy_server_with_single_target() {
        let mut config = create_test_config();
        config.targets.targets = vec![Target {
            name: "single-backend".to_string(),
            url: "http://127.0.0.1:4000".to_string(),
            weight: Some(5),
            timeout: Some(15),
        }];

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(server.config.targets.targets.len(), 1);
        assert_eq!(server.config.targets.targets[0].name, "single-backend");
        assert_eq!(
            server.config.targets.targets[0].url,
            "http://127.0.0.1:4000"
        );
        assert_eq!(server.config.targets.targets[0].weight, Some(5));
    }

    #[tokio::test]
    async fn test_proxy_server_with_multiple_domains() {
        let mut config = create_test_config();
        config.domains.intercept_domains = vec![
            "api.example.com".to_string(),
            "*.staging.example.com".to_string(),
            "internal.service.com".to_string(),
        ];
        config.domains.exclude_domains = Some(vec![
            "admin.api.example.com".to_string(),
            "debug.staging.example.com".to_string(),
        ]);

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(server.config.domains.intercept_domains.len(), 3);
        assert!(server
            .config
            .domains
            .intercept_domains
            .contains(&"api.example.com".to_string()));
        assert!(server
            .config
            .domains
            .intercept_domains
            .contains(&"*.staging.example.com".to_string()));
        assert!(server
            .config
            .domains
            .intercept_domains
            .contains(&"internal.service.com".to_string()));

        assert_eq!(
            server
                .config
                .domains
                .exclude_domains
                .as_ref()
                .unwrap()
                .len(),
            2
        );
        assert!(server
            .config
            .domains
            .exclude_domains
            .as_ref()
            .unwrap()
            .contains(&"admin.api.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_proxy_server_with_different_load_balancing_types() {
        let traffic_logger = create_test_traffic_logger();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Test RoundRobin
        let mut config_rr = create_test_config();
        config_rr.targets.load_balancing.lb_type = LoadBalancingType::RoundRobin;
        let server_rr = ProxyServer::new(config_rr, bind_addr, traffic_logger.clone());
        assert!(matches!(
            server_rr.config.targets.load_balancing.lb_type,
            LoadBalancingType::RoundRobin
        ));

        // Test LeastConnections
        let mut config_lc = create_test_config();
        config_lc.targets.load_balancing.lb_type = LoadBalancingType::LeastConnections;
        let server_lc = ProxyServer::new(config_lc, bind_addr, traffic_logger.clone());
        assert!(matches!(
            server_lc.config.targets.load_balancing.lb_type,
            LoadBalancingType::LeastConnections
        ));

        // Test Random
        let mut config_random = create_test_config();
        config_random.targets.load_balancing.lb_type = LoadBalancingType::Random;
        let server_random = ProxyServer::new(config_random, bind_addr, traffic_logger);
        assert!(matches!(
            server_random.config.targets.load_balancing.lb_type,
            LoadBalancingType::Random
        ));
    }

    #[tokio::test]
    async fn test_proxy_server_load_balancer_initialization() {
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

        // The load balancer should be initialized with the target config
        // We can't directly access the load balancer's internal state in this test
        // but we can verify that the server was created successfully
        assert_eq!(server.config.targets.targets.len(), 2);
        assert!(matches!(
            server.config.targets.load_balancing.lb_type,
            LoadBalancingType::Weighted
        ));
    }

    #[tokio::test]
    async fn test_proxy_server_with_health_check_enabled() {
        let mut config = create_test_config();
        config.targets.health_check.enabled = true;
        config.targets.health_check.interval = 60;
        config.targets.health_check.timeout = 10;
        config.targets.health_check.healthy_threshold = 3;
        config.targets.health_check.unhealthy_threshold = 5;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert!(server.config.targets.health_check.enabled);
        assert_eq!(server.config.targets.health_check.interval, 60);
        assert_eq!(server.config.targets.health_check.timeout, 10);
        assert_eq!(server.config.targets.health_check.healthy_threshold, 3);
        assert_eq!(server.config.targets.health_check.unhealthy_threshold, 5);
    }

    #[tokio::test]
    async fn test_proxy_server_with_logging_enabled() {
        let mut config = create_test_config();
        config.logging.enabled = true;
        config.logging.log_type = LoggingType::Both;
        config.logging.retention_days = Some(14);

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Create a new traffic logger with logging enabled for this test
        let traffic_logger = TrafficLogger::new(LoggingConfig {
            enabled: true,
            log_type: LoggingType::File,
            database: None,
            file: Some(crate::config::FileConfig {
                directory: "/tmp/test_logs".to_string(),
                max_file_size: Some(1000000),
                rotation: true,
            }),
            retention_days: Some(14),
        });

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert!(server.config.logging.enabled);
        assert!(matches!(server.config.logging.log_type, LoggingType::Both));
        assert_eq!(server.config.logging.retention_days, Some(14));
    }

    #[tokio::test]
    async fn test_proxy_server_with_monitoring_enabled() {
        let mut config = create_test_config();
        config.monitoring.enabled = true;
        config.monitoring.metrics_port = 9091;
        config.monitoring.health_check_port = 8082;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert!(server.config.monitoring.enabled);
        assert_eq!(server.config.monitoring.metrics_port, 9091);
        assert_eq!(server.config.monitoring.health_check_port, 8082);
    }

    #[tokio::test]
    async fn test_proxy_server_bind_address_variants() {
        let config = create_test_config();
        let traffic_logger = create_test_traffic_logger();

        // Test different IP address formats
        let addresses = vec![
            "127.0.0.1:8080",
            "0.0.0.0:8080",
            "127.0.0.1:0",     // Auto-assigned port
            "127.0.0.1:65535", // Max port
        ];

        for addr_str in addresses {
            let bind_addr: SocketAddr = addr_str.parse().unwrap();
            let server = ProxyServer::new(config.clone(), bind_addr, traffic_logger.clone());
            assert_eq!(server.bind_addr, bind_addr);
        }
    }

    #[tokio::test]
    async fn test_proxy_server_config_cloning() {
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        // Create multiple servers with the same config to test cloning behavior
        let server1 = ProxyServer::new(config.clone(), bind_addr, traffic_logger.clone());
        let server2 = ProxyServer::new(config.clone(), bind_addr, traffic_logger);

        // Both servers should have identical configurations
        assert_eq!(
            server1.config.domains.intercept_domains,
            server2.config.domains.intercept_domains
        );
        assert_eq!(
            server1.config.targets.targets.len(),
            server2.config.targets.targets.len()
        );
        assert_eq!(server1.config.server.workers, server2.config.server.workers);
    }

    #[tokio::test]
    async fn test_proxy_server_with_empty_exclude_domains() {
        let mut config = create_test_config();
        config.domains.exclude_domains = None;

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert!(server.config.domains.exclude_domains.is_none());
        assert_eq!(
            server.config.domains.intercept_domains,
            vec!["test.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn test_proxy_server_with_various_target_configurations() {
        let mut config = create_test_config();
        config.targets.targets = vec![
            Target {
                name: "backend-with-weight".to_string(),
                url: "http://192.168.1.100:8080".to_string(),
                weight: Some(10),
                timeout: Some(45),
            },
            Target {
                name: "backend-no-weight".to_string(),
                url: "https://api.external.com".to_string(),
                weight: None,
                timeout: Some(60),
            },
            Target {
                name: "backend-no-timeout".to_string(),
                url: "http://localhost:3000".to_string(),
                weight: Some(1),
                timeout: None,
            },
            Target {
                name: "backend-minimal".to_string(),
                url: "http://127.0.0.1:4000".to_string(),
                weight: None,
                timeout: None,
            },
        ];

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(server.config.targets.targets.len(), 4);

        // Check first target
        assert_eq!(server.config.targets.targets[0].name, "backend-with-weight");
        assert_eq!(server.config.targets.targets[0].weight, Some(10));
        assert_eq!(server.config.targets.targets[0].timeout, Some(45));

        // Check second target
        assert_eq!(server.config.targets.targets[1].name, "backend-no-weight");
        assert_eq!(server.config.targets.targets[1].weight, None);
        assert_eq!(server.config.targets.targets[1].timeout, Some(60));

        // Check third target
        assert_eq!(server.config.targets.targets[2].name, "backend-no-timeout");
        assert_eq!(server.config.targets.targets[2].weight, Some(1));
        assert_eq!(server.config.targets.targets[2].timeout, None);

        // Check fourth target
        assert_eq!(server.config.targets.targets[3].name, "backend-minimal");
        assert_eq!(server.config.targets.targets[3].weight, None);
        assert_eq!(server.config.targets.targets[3].timeout, None);
    }

    #[tokio::test]
    async fn test_proxy_server_creation_performance() {
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let start = std::time::Instant::now();

        // Create multiple servers to test creation performance
        for _ in 0..100 {
            let _server = ProxyServer::new(config.clone(), bind_addr, traffic_logger.clone());
        }

        let duration = start.elapsed();

        // Server creation should be fast (less than 100ms for 100 servers)
        assert!(
            duration.as_millis() < 100,
            "Server creation took too long: {:?}",
            duration
        );
    }

    #[tokio::test]
    async fn test_proxy_server_run_method() {
        // Test that the server run method can be called and starts successfully
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        // Test server run method by spawning it and then canceling
        let server_handle = tokio::spawn(async move { server.run().await });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel the server task
        server_handle.abort();

        // Wait for the task to complete (should be aborted)
        let result = server_handle.await;
        assert!(result.is_err(), "Server task should have been cancelled");
    }

    #[tokio::test]
    async fn test_proxy_server_run_with_different_configs() {
        // Test running servers with different configurations
        let configs = vec![
            create_test_config(),
            {
                let mut config = create_test_config();
                config.server.workers = Some(1);
                config.targets.load_balancing.lb_type = LoadBalancingType::RoundRobin;
                config
            },
            {
                let mut config = create_test_config();
                config.server.keep_alive_timeout = Some(10);
                config.server.request_timeout = Some(5);
                config
            },
        ];

        for (i, config) in configs.into_iter().enumerate() {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let traffic_logger = create_test_traffic_logger();
            let server = ProxyServer::new(config, bind_addr, traffic_logger);

            // Test that each server configuration can start
            let server_handle = tokio::spawn(async move { server.run().await });

            // Brief delay to allow server startup
            tokio::time::sleep(Duration::from_millis(30)).await;

            // Clean up
            server_handle.abort();
            let _ = server_handle.await;

            tracing::debug!("Server config {} started successfully", i);
        }
    }

    #[tokio::test]
    async fn test_proxy_server_run_error_handling() {
        // Test server behavior by cancelling it before binding issues
        let config = create_test_config();
        let traffic_logger = create_test_traffic_logger();

        // Use port 0 (auto-assign) to avoid permission issues, but test cancellation behavior
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        // Test that the server run method can be started and cancelled properly
        let server_handle = tokio::spawn(async move { server.run().await });

        // Very brief delay to let server attempt to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cancel the server before it fully starts
        server_handle.abort();

        // The handle should be cancelled
        let result = server_handle.await;
        assert!(result.is_err(), "Server should have been cancelled");
    }

    #[tokio::test]
    async fn test_proxy_server_concurrent_run_attempts() {
        // Test multiple concurrent server run attempts
        let config = create_test_config();
        let traffic_logger = create_test_traffic_logger();

        let mut handles = Vec::new();

        // Start multiple servers concurrently (they should handle port conflicts gracefully)
        for i in 0..3 {
            let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let server = ProxyServer::new(config.clone(), bind_addr, traffic_logger.clone());

            let handle = tokio::spawn(async move {
                let result = server.run().await;
                (i, result)
            });

            handles.push(handle);
        }

        // Let servers attempt to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Clean up all server tasks
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
    }

    #[tokio::test]
    async fn test_proxy_server_shutdown_behavior() {
        // Test proper server shutdown behavior
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        // Start the server
        let server_handle = tokio::spawn(async move { server.run().await });

        // Let it start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Check if the task is running
        assert!(!server_handle.is_finished(), "Server should be running");

        // Shutdown the server
        server_handle.abort();

        // Wait for shutdown
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify shutdown
        let result = server_handle.await;
        assert!(result.is_err(), "Server should have been cancelled");
    }

    #[tokio::test]
    async fn test_proxy_server_with_tls_disabled() {
        let mut config = create_test_config();
        config.tls = Some(crate::tls::TlsConfig {
            enabled: false,
            ..Default::default()
        });

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        // TLS manager should be None when TLS is disabled
        assert!(server.tls_manager.is_none());
    }

    #[tokio::test]
    async fn test_proxy_server_with_tls_enabled() {
        let mut config = create_test_config();
        config.tls = Some(crate::tls::TlsConfig {
            enabled: true,
            cert_path: Some("test.crt".to_string()),
            key_path: Some("test.key".to_string()),
            port: 8443,
            ..Default::default()
        });

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let server = ProxyServer::new(config, bind_addr, traffic_logger);

        // TLS manager should be present when TLS is enabled
        assert!(server.tls_manager.is_some());
    }

    #[tokio::test]
    async fn test_proxy_server_initialization_without_tls() {
        let config = create_test_config();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let traffic_logger = create_test_traffic_logger();

        let mut server = ProxyServer::new(config, bind_addr, traffic_logger);

        // Initialization should succeed without TLS
        let result = server.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_server_tls_configuration_validation() {
        use crate::tls::TlsConfig;

        // Test with valid TLS config
        let valid_tls_config = TlsConfig {
            enabled: true,
            cert_path: Some("valid.crt".to_string()),
            key_path: Some("valid.key".to_string()),
            port: 8443,
            sni_enabled: false,
            certificates: None,
            min_version: Some(crate::tls::TlsVersion::V1_2),
            max_version: Some(crate::tls::TlsVersion::V1_3),
            client_auth: None,
        };

        let result = valid_tls_config.validate();
        assert!(result.is_ok());

        // Test with invalid TLS config (missing cert path)
        let invalid_tls_config = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: Some("key.pem".to_string()),
            ..Default::default()
        };

        let result = invalid_tls_config.validate();
        assert!(result.is_err());
    }
}
