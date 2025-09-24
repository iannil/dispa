use anyhow::Result;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{debug, error, info, warn};

use super::handler::ProxyHandler;
use super::http_client;
use crate::balancer::LoadBalancer;
use crate::config::Config;
use crate::error::DispaResult;
use crate::logger::TrafficLogger;
use crate::plugins::{PluginEngine, SharedPluginEngine};
use crate::routing::RoutingEngine;
use crate::security::{SecurityManager, SharedSecurity};
use crate::tls::TlsManager;

/// Server configuration and initialization utilities
mod server_config {
    use super::*;

    pub fn init_http_client(config: &Config) {
        http_client::init(config.http_client.as_ref());
    }

    pub fn init_tls_manager(config: &Config) -> Option<TlsManager> {
        if let Some(tls_config) = &config.tls {
            if tls_config.enabled {
                Some(TlsManager::new(tls_config.clone()))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn init_routing_engine(
        config: &Config,
    ) -> std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>> {
        if let Some(routing_config) = &config.routing {
            match RoutingEngine::new(routing_config.clone()) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    warn!("Failed to initialize routing engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        }
    }

    pub fn init_plugin_engine(config: &Config) -> SharedPluginEngine {
        if let Some(plugins_cfg) = &config.plugins {
            match PluginEngine::new(plugins_cfg) {
                Ok(engine) => std::sync::Arc::new(tokio::sync::RwLock::new(Some(engine))),
                Err(e) => {
                    warn!("Failed to initialize plugin engine: {}", e);
                    std::sync::Arc::new(tokio::sync::RwLock::new(None))
                }
            }
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        }
    }

    pub fn init_security_manager(config: &Config) -> SharedSecurity {
        if let Some(sec_cfg) = &config.security {
            std::sync::Arc::new(tokio::sync::RwLock::new(Some(SecurityManager::new(
                sec_cfg.clone(),
            ))))
        } else {
            std::sync::Arc::new(tokio::sync::RwLock::new(None))
        }
    }

    pub fn init_load_balancer(
        config: &Config,
    ) -> std::sync::Arc<tokio::sync::RwLock<LoadBalancer>> {
        std::sync::Arc::new(tokio::sync::RwLock::new(LoadBalancer::new(
            config.targets.clone(),
        )))
    }

    pub fn init_domain_config(
        config: &Config,
    ) -> std::sync::Arc<std::sync::RwLock<crate::config::DomainConfig>> {
        std::sync::Arc::new(std::sync::RwLock::new(config.domains.clone()))
    }
}

/// HTTP server implementation
mod http_server {
    use super::*;

    pub async fn run(bind_addr: SocketAddr, handler: ProxyHandler) -> Result<()> {
        let make_service = make_service_fn(move |conn: &AddrStream| {
            let handler = handler.clone();
            let remote = conn.remote_addr();
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req| {
                    let handler = handler.clone();
                    req.extensions_mut().insert(remote);
                    async move { handler.handle_request(req).await }
                }))
            }
        });

        info!("Starting HTTP proxy server on {}", bind_addr);
        let server = Server::bind(&bind_addr).serve(make_service);

        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }

        Ok(())
    }
}

/// HTTPS server implementation
mod https_server {
    use super::*;
    use hyper::service::service_fn;

    pub async fn run(
        bind_addr: SocketAddr,
        tls_manager: &TlsManager,
        handler: ProxyHandler,
    ) -> Result<()> {
        let server_config = tls_manager
            .server_config()
            .ok_or_else(|| anyhow::anyhow!("TLS server config not available"))?
            .clone();

        info!("Starting HTTPS server on {}", bind_addr);

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

        info!("HTTPS server listening on {}", bind_addr);

        loop {
            let (tcp_stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let tls_acceptor = tls_acceptor.clone();
            let handler = handler.clone();

            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        debug!("TLS handshake failed from {}: {}", remote_addr, e);
                        return;
                    }
                };

                debug!("TLS connection established from {}", remote_addr);

                let service = service_fn(move |mut req| {
                    let handler = handler.clone();
                    req.extensions_mut().insert(remote_addr);
                    async move { handler.handle_request(req).await }
                });

                if let Err(e) = hyper::server::conn::Http::new()
                    .serve_connection(tls_stream, service)
                    .await
                {
                    debug!("Error serving HTTPS connection from {}: {}", remote_addr, e);
                }
            });
        }
    }
}

/// High-performance HTTP proxy server
pub struct ProxyServer {
    pub bind_addr: SocketAddr,
    #[allow(dead_code)]
    pub config: Config,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    domain_config: std::sync::Arc<std::sync::RwLock<crate::config::DomainConfig>>,
    traffic_logger: TrafficLogger,
    tls_manager: Option<TlsManager>,
    routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
    plugins: SharedPluginEngine,
    security: SharedSecurity,
}

impl ProxyServer {
    pub fn new(config: Config, bind_addr: SocketAddr, traffic_logger: TrafficLogger) -> Self {
        // Initialize all components using the config module
        server_config::init_http_client(&config);

        let load_balancer = server_config::init_load_balancer(&config);
        let domain_config = server_config::init_domain_config(&config);
        let tls_manager = server_config::init_tls_manager(&config);
        let routing_engine = server_config::init_routing_engine(&config);
        let plugins = server_config::init_plugin_engine(&config);
        let security = server_config::init_security_manager(&config);

        Self {
            bind_addr,
            config,
            load_balancer,
            domain_config,
            traffic_logger,
            tls_manager,
            routing_engine,
            plugins,
            security,
        }
    }

    /// Initialize the proxy server (including TLS if enabled)
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
        ProxyHandler::with_shared_routing(
            std::sync::Arc::clone(&self.domain_config),
            std::sync::Arc::clone(&self.load_balancer),
            self.traffic_logger.clone(),
            std::sync::Arc::clone(&self.routing_engine),
            std::sync::Arc::clone(&self.plugins),
            std::sync::Arc::clone(&self.security),
        )
    }

    pub async fn run(self) -> Result<()> {
        let handler = self.create_handler();

        // Check if TLS is enabled
        if let Some(ref tls_manager) = self.tls_manager {
            if tls_manager.is_enabled() {
                return https_server::run(self.bind_addr, tls_manager, handler).await;
            }
        }

        http_server::run(self.bind_addr, handler).await
    }

    // Access methods for components
    pub fn load_balancer_handle(&self) -> std::sync::Arc<tokio::sync::RwLock<LoadBalancer>> {
        std::sync::Arc::clone(&self.load_balancer)
    }

    pub fn routing_engine_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>> {
        std::sync::Arc::clone(&self.routing_engine)
    }

    pub fn plugins_handle(&self) -> SharedPluginEngine {
        std::sync::Arc::clone(&self.plugins)
    }

    pub fn security_handle(&self) -> SharedSecurity {
        std::sync::Arc::clone(&self.security)
    }

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
        Config, DomainConfig, HealthCheckConfig, HttpClientConfig, LoadBalancingConfig,
        LoadBalancingType, LoggingConfig, LoggingType, MonitoringConfig, ServerConfig, Target,
        TargetConfig,
    };

    fn create_test_config() -> Config {
        Config {
            server: ServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(), // OK in tests - valid address
                workers: Some(2),
                max_connections: Some(1000),
                connection_timeout: Some(30),
            },
            domains: DomainConfig {
                intercept_domains: vec!["test.example.com".to_string()],
                exclude_domains: Some(vec!["admin.test.example.com".to_string()]),
                wildcard_support: true,
            },
            targets: TargetConfig {
                targets: vec![Target {
                    name: "test-backend-1".to_string(),
                    url: "http://127.0.0.1:3001".to_string(),
                    address: "127.0.0.1:3001".to_string(),
                    weight: Some(1.0),
                    timeout: Some(30),
                }],
                load_balancing: LoadBalancingConfig {
                    algorithm: LoadBalancingType::Weighted,
                    lb_type: LoadBalancingType::Weighted,
                    sticky_sessions: Some(false),
                },
                health_check: HealthCheckConfig {
                    enabled: false, // Disable for tests to avoid network calls
                    interval: 30,
                    timeout: 5,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                    threshold: 2,
                },
            },
            logging: LoggingConfig {
                enabled: false, // Disable for tests
                log_type: LoggingType::File,
                database: None,
                file: None,
                retention_days: None,
            },
            monitoring: MonitoringConfig::default(),
            tls: None,     // TLS disabled for tests
            routing: None, // Routing disabled for tests
            cache: None,   // Cache disabled for tests
            http_client: Some(HttpClientConfig {
                pool_max_idle_per_host: Some(8),
                pool_idle_timeout: Some(30),
                pool_idle_timeout_secs: Some(30),
                connect_timeout: Some(2),
                connect_timeout_secs: Some(2),
                request_timeout: Some(10),
            }),
            security: None, // Security disabled for tests
            plugins: None,  // Plugins disabled for tests
        }
    }

    #[tokio::test]
    async fn test_proxy_server_creation() {
        let config = create_test_config();
        let bind_addr = "127.0.0.1:0".parse().unwrap(); // OK in tests - valid address
        let traffic_logger = crate::logger::TrafficLogger::new(config.logging.clone());

        let proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

        assert_eq!(proxy_server.bind_addr, bind_addr);
    }

    #[tokio::test]
    async fn test_proxy_server_initialization() {
        let config = create_test_config();
        let bind_addr = "127.0.0.1:0".parse().unwrap(); // OK in tests - valid address
        let traffic_logger = crate::logger::TrafficLogger::new(config.logging.clone());

        let mut proxy_server = ProxyServer::new(config, bind_addr, traffic_logger);

        // This should succeed since TLS is not enabled in test config
        let result = proxy_server.initialize().await;
        assert!(result.is_ok());
    }
}
