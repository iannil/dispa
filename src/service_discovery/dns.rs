//! DNS service discovery implementation
//!
//! This module provides service discovery functionality using DNS SRV records.

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

use crate::service_discovery::{
    HealthStatus, ServiceChangeStream, ServiceDiscovery, ServiceDiscoveryError,
    ServiceDiscoveryResult, ServiceInstance,
};

/// DNS service discovery configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS servers to use for resolution
    pub nameservers: Vec<SocketAddr>,
    /// Resolution timeout
    pub timeout: Duration,
    /// Enable DNS caching
    pub cache_enabled: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            nameservers: vec!["8.8.8.8:53".parse().unwrap(), "8.8.4.4:53".parse().unwrap()],
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// DNS service discovery implementation
pub struct DnsServiceDiscovery {
    config: DnsConfig,
    resolver: TokioAsyncResolver,
}

impl DnsServiceDiscovery {
    /// Create a new DNS service discovery instance
    pub async fn new(config: DnsConfig) -> ServiceDiscoveryResult<Self> {
        let resolver_config = ResolverConfig::from_parts(
            None,
            vec![],
            config
                .nameservers
                .clone()
                .into_iter()
                .map(|addr| {
                    trust_dns_resolver::config::NameServerConfig::new(
                        addr,
                        trust_dns_resolver::config::Protocol::Udp,
                    )
                })
                .collect::<Vec<_>>(),
        );

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = config.timeout;

        let resolver = AsyncResolver::tokio(resolver_config, resolver_opts);

        Ok(Self { config, resolver })
    }

    /// Create a new DNS service discovery instance with default configuration
    pub async fn new_default() -> ServiceDiscoveryResult<Self> {
        Self::new(DnsConfig::default()).await
    }

    /// Resolve SRV records for a service
    async fn resolve_srv(
        &self,
        service_name: &str,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>> {
        // Try to parse as SRV record format: _service._tcp.domain.com
        let srv_name = if service_name.starts_with('_') {
            service_name.to_string()
        } else {
            // Assume HTTP service if no protocol specified
            format!("_{}._tcp.local", service_name)
        };

        let srv_records = self.resolver.srv_lookup(&srv_name).await.map_err(|e| {
            ServiceDiscoveryError::BackendError(format!("DNS SRV lookup failed: {}", e))
        })?;

        let mut instances = Vec::new();
        for srv in srv_records.iter() {
            let target = srv.target().to_string();
            let port = srv.port();
            let weight = srv.weight() as u32;
            let priority = srv.priority();

            // Create service instance
            let instance = ServiceInstance {
                id: format!("{}:{}", target, port),
                name: service_name.to_string(),
                address: target,
                port,
                tags: vec![format!("priority:{}", priority)],
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("priority".to_string(), priority.to_string());
                    meta.insert("weight".to_string(), weight.to_string());
                    meta.insert("discovery_type".to_string(), "dns_srv".to_string());
                    meta
                },
                health_check: None,
                health_status: HealthStatus::Unknown, // DNS doesn't provide health status
                weight,
                version: None,
                zone: None,
            };

            instances.push(instance);
        }

        Ok(instances)
    }

    /// Resolve A/AAAA records for a service (fallback when SRV is not available)
    async fn resolve_a_record(
        &self,
        service_name: &str,
        default_port: u16,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>> {
        let addresses = lookup_host(format!("{}:{}", service_name, default_port))
            .await
            .map_err(|e| {
                ServiceDiscoveryError::NetworkError(format!("DNS A record lookup failed: {}", e))
            })?;

        let mut instances = Vec::new();
        for addr in addresses {
            let instance = ServiceInstance {
                id: format!("{}:{}", addr.ip(), addr.port()),
                name: service_name.to_string(),
                address: addr.ip().to_string(),
                port: addr.port(),
                tags: Vec::new(),
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("discovery_type".to_string(), "dns_a".to_string());
                    meta
                },
                health_check: None,
                health_status: HealthStatus::Unknown,
                weight: 100, // Default weight
                version: None,
                zone: None,
            };

            instances.push(instance);
        }

        Ok(instances)
    }
}

#[async_trait]
impl ServiceDiscovery for DnsServiceDiscovery {
    async fn discover_services(
        &self,
        service_name: &str,
    ) -> ServiceDiscoveryResult<Vec<ServiceInstance>> {
        // First try SRV record resolution
        match self.resolve_srv(service_name).await {
            Ok(instances) if !instances.is_empty() => Ok(instances),
            _ => {
                // Fallback to A record resolution with common ports
                let common_ports = [80, 443, 8080, 8443, 3000, 8000];

                for &port in &common_ports {
                    if let Ok(instances) = self.resolve_a_record(service_name, port).await {
                        if !instances.is_empty() {
                            return Ok(instances);
                        }
                    }
                }

                // If no instances found with common ports, try port 80 as default
                self.resolve_a_record(service_name, 80).await
            }
        }
    }

    async fn watch_changes(
        &self,
        _service_name: &str,
    ) -> ServiceDiscoveryResult<ServiceChangeStream> {
        // DNS doesn't support change notifications, would need to implement polling
        Err(ServiceDiscoveryError::BackendError(
            "DNS service discovery does not support change notifications".to_string(),
        ))
    }

    async fn register_service(&self, _service: &ServiceInstance) -> ServiceDiscoveryResult<()> {
        // DNS is read-only from client perspective
        Err(ServiceDiscoveryError::BackendError(
            "DNS service discovery does not support service registration".to_string(),
        ))
    }

    async fn deregister_service(&self, _service_id: &str) -> ServiceDiscoveryResult<()> {
        // DNS is read-only from client perspective
        Err(ServiceDiscoveryError::BackendError(
            "DNS service discovery does not support service deregistration".to_string(),
        ))
    }

    async fn health_check(&self, service_id: &str) -> ServiceDiscoveryResult<HealthStatus> {
        // DNS doesn't provide health status, but we can try to resolve the address
        let parts: Vec<&str> = service_id.split(':').collect();
        if parts.len() != 2 {
            return Err(ServiceDiscoveryError::ConfigurationError(
                "Invalid service ID format, expected 'address:port'".to_string(),
            ));
        }

        let address = parts[0];
        let port = parts[1].parse::<u16>().map_err(|_| {
            ServiceDiscoveryError::ConfigurationError(
                "Invalid port number in service ID".to_string(),
            )
        })?;

        // Try to resolve the address
        match lookup_host(format!("{}:{}", address, port)).await {
            Ok(mut addresses) => {
                if addresses.next().is_some() {
                    Ok(HealthStatus::Unknown) // DNS resolution successful, but can't determine actual health
                } else {
                    Ok(HealthStatus::Unhealthy) // No addresses resolved
                }
            }
            Err(_) => Ok(HealthStatus::Unhealthy), // Resolution failed
        }
    }

    async fn list_services(&self) -> ServiceDiscoveryResult<Vec<String>> {
        // DNS doesn't support service enumeration
        Err(ServiceDiscoveryError::BackendError(
            "DNS service discovery does not support service enumeration".to_string(),
        ))
    }

    async fn get_stats(&self) -> ServiceDiscoveryResult<HashMap<String, String>> {
        let mut stats = HashMap::new();
        stats.insert("backend".to_string(), "dns".to_string());
        stats.insert("status".to_string(), "active".to_string());
        stats.insert(
            "cache_enabled".to_string(),
            self.config.cache_enabled.to_string(),
        );
        stats.insert(
            "timeout".to_string(),
            format!("{}ms", self.config.timeout.as_millis()),
        );
        stats.insert(
            "nameservers".to_string(),
            self.config.nameservers.len().to_string(),
        );
        Ok(stats)
    }
}
