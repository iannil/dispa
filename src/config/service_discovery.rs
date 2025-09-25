//! Service discovery configuration module
//!
//! This module defines configuration structures for service discovery functionality

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Consul service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul HTTP API address
    pub address: String,
    /// Connection timeout
    #[serde(default = "default_consul_connect_timeout")]
    pub connect_timeout: Duration,
    /// Request timeout
    #[serde(default = "default_consul_request_timeout")]
    pub request_timeout: Duration,
    /// Health check integration interval
    #[serde(default = "default_consul_health_check_interval")]
    pub health_check_interval: Duration,
    /// Consul datacenter
    pub datacenter: Option<String>,
    /// Consul token for authentication
    pub token: Option<String>,
    /// TLS configuration
    pub tls_enabled: bool,
    /// Consul namespace (Consul Enterprise)
    pub namespace: Option<String>,
}

fn default_consul_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_consul_request_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_consul_health_check_interval() -> Duration {
    Duration::from_secs(30)
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            address: "http://localhost:8500".to_string(),
            connect_timeout: default_consul_connect_timeout(),
            request_timeout: default_consul_request_timeout(),
            health_check_interval: default_consul_health_check_interval(),
            datacenter: None,
            token: None,
            tls_enabled: false,
            namespace: None,
        }
    }
}

/// Service discovery provider type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDiscoveryProvider {
    /// Consul service discovery
    #[default]
    Consul,
    /// etcd service discovery
    Etcd,
    /// Kubernetes native service discovery
    Kubernetes,
    /// DNS-based service discovery
    Dns,
}

impl std::fmt::Display for ServiceDiscoveryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceDiscoveryProvider::Consul => write!(f, "consul"),
            ServiceDiscoveryProvider::Etcd => write!(f, "etcd"),
            ServiceDiscoveryProvider::Kubernetes => write!(f, "kubernetes"),
            ServiceDiscoveryProvider::Dns => write!(f, "dns"),
        }
    }
}

/// DNS service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS servers to use for resolution
    pub nameservers: Option<Vec<String>>,
    /// Resolution timeout in seconds
    #[serde(default = "default_dns_timeout")]
    pub timeout: u64,
    /// Enable DNS caching
    #[serde(default = "default_dns_cache")]
    pub cache_enabled: bool,
    /// Cache TTL in seconds
    #[serde(default = "default_dns_cache_ttl")]
    pub cache_ttl: u64,
}

fn default_dns_timeout() -> u64 {
    5
}
fn default_dns_cache() -> bool {
    true
}
fn default_dns_cache_ttl() -> u64 {
    300
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            nameservers: None, // Use system default
            timeout: default_dns_timeout(),
            cache_enabled: default_dns_cache(),
            cache_ttl: default_dns_cache_ttl(),
        }
    }
}

/// etcd service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtcdConfig {
    /// etcd server endpoints
    pub endpoints: Vec<String>,
    /// Connection timeout in seconds
    #[serde(default = "default_etcd_timeout")]
    pub connect_timeout: u64,
    /// Request timeout in seconds
    #[serde(default = "default_etcd_request_timeout")]
    pub request_timeout: u64,
    /// Authentication username (optional)
    pub username: Option<String>,
    /// Authentication password (optional)
    pub password: Option<String>,
    /// TLS certificate file path (optional)
    pub cert_path: Option<String>,
    /// TLS key file path (optional)
    pub key_path: Option<String>,
    /// CA certificate file path (optional)
    pub ca_path: Option<String>,
    /// Key prefix for service entries
    #[serde(default = "default_etcd_key_prefix")]
    pub key_prefix: String,
}

fn default_etcd_timeout() -> u64 {
    5
}
fn default_etcd_request_timeout() -> u64 {
    10
}
fn default_etcd_key_prefix() -> String {
    "/services".to_string()
}

impl Default for EtcdConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["http://localhost:2379".to_string()],
            connect_timeout: default_etcd_timeout(),
            request_timeout: default_etcd_request_timeout(),
            username: None,
            password: None,
            cert_path: None,
            key_path: None,
            ca_path: None,
            key_prefix: default_etcd_key_prefix(),
        }
    }
}

/// Kubernetes service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Kubernetes configuration source
    #[serde(default = "default_k8s_config")]
    pub config_source: KubernetesConfigSource,
    /// Target namespace (empty for all namespaces)
    #[serde(default)]
    pub namespace: String,
    /// Label selector for services
    pub label_selector: Option<String>,
    /// Request timeout in seconds
    #[serde(default = "default_k8s_timeout")]
    pub request_timeout: u64,
    /// Watch timeout in seconds
    #[serde(default = "default_k8s_watch_timeout")]
    pub watch_timeout: u64,
}

/// Kubernetes configuration source
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesConfigSource {
    /// Use in-cluster configuration (when running inside a pod)
    InCluster,
    /// Use kubeconfig file
    Kubeconfig,
    /// Use service account
    ServiceAccount,
}

fn default_k8s_config() -> KubernetesConfigSource {
    KubernetesConfigSource::InCluster
}
fn default_k8s_timeout() -> u64 {
    30
}
fn default_k8s_watch_timeout() -> u64 {
    300
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            config_source: default_k8s_config(),
            namespace: String::new(), // All namespaces
            label_selector: None,
            request_timeout: default_k8s_timeout(),
            watch_timeout: default_k8s_watch_timeout(),
        }
    }
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// Enable service discovery functionality
    #[serde(default)]
    pub enabled: bool,

    /// Service discovery provider type
    #[serde(default)]
    pub provider: ServiceDiscoveryProvider,

    /// Service refresh interval in seconds
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,

    /// Health check integration
    #[serde(default = "default_health_check_integration")]
    pub health_check_integration: bool,

    /// Auto-registration of this service
    #[serde(default)]
    pub auto_register: bool,

    /// Service instance configuration for auto-registration
    pub service_instance: Option<ServiceInstanceConfig>,

    /// Consul-specific configuration
    pub consul: Option<ConsulConfig>,

    /// etcd-specific configuration
    pub etcd: Option<EtcdConfig>,

    /// Kubernetes-specific configuration
    pub kubernetes: Option<KubernetesConfig>,

    /// DNS-specific configuration
    #[serde(default)]
    pub dns: DnsConfig,
}

fn default_refresh_interval() -> u64 {
    30
}
fn default_health_check_integration() -> bool {
    true
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ServiceDiscoveryProvider::default(),
            refresh_interval: default_refresh_interval(),
            health_check_integration: default_health_check_integration(),
            auto_register: false,
            service_instance: None,
            consul: None,
            etcd: None,
            kubernetes: None,
            dns: DnsConfig::default(),
        }
    }
}

/// Service instance configuration for auto-registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstanceConfig {
    /// Service ID (auto-generated if not provided)
    pub id: Option<String>,
    /// Service name
    pub name: String,
    /// Service address (auto-detected if not provided)
    pub address: Option<String>,
    /// Service port
    pub port: u16,
    /// Service tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Service metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
    /// Health check configuration
    pub health_check: Option<HealthCheckInstanceConfig>,
    /// Service weight for load balancing
    #[serde(default = "default_instance_weight")]
    pub weight: u32,
    /// Service version
    pub version: Option<String>,
    /// Service zone/region
    pub zone: Option<String>,
}

fn default_instance_weight() -> u32 {
    100
}

/// Health check configuration for service instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckInstanceConfig {
    /// Health check endpoint path
    #[serde(default = "default_health_endpoint")]
    pub endpoint: String,
    /// Health check interval in seconds
    #[serde(default = "default_health_interval")]
    pub interval: u64,
    /// Health check timeout in seconds
    #[serde(default = "default_health_timeout")]
    pub timeout: u64,
    /// HTTP method for health check
    #[serde(default = "default_health_method")]
    pub method: String,
    /// Expected HTTP status codes for healthy state
    #[serde(default = "default_health_status")]
    pub healthy_status: Vec<u16>,
    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking healthy
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_health_endpoint() -> String {
    "/health".to_string()
}
fn default_health_interval() -> u64 {
    10
}
fn default_health_timeout() -> u64 {
    5
}
fn default_health_method() -> String {
    "GET".to_string()
}
fn default_health_status() -> Vec<u16> {
    vec![200]
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_success_threshold() -> u32 {
    2
}

impl Default for HealthCheckInstanceConfig {
    fn default() -> Self {
        Self {
            endpoint: default_health_endpoint(),
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            method: default_health_method(),
            healthy_status: default_health_status(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

impl ServiceDiscoveryConfig {
    /// Validate the service discovery configuration
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Skip validation if disabled
        }

        // Validate refresh interval
        if self.refresh_interval == 0 {
            return Err(anyhow::anyhow!(
                "Service discovery refresh_interval must be greater than 0"
            ));
        }

        // Validate provider-specific configuration
        match self.provider {
            ServiceDiscoveryProvider::Consul => {
                if self.consul.is_none() {
                    return Err(anyhow::anyhow!(
                        "Consul configuration is required when provider is 'consul'"
                    ));
                }
            }
            ServiceDiscoveryProvider::Etcd => {
                if self.etcd.is_none() {
                    return Err(anyhow::anyhow!(
                        "etcd configuration is required when provider is 'etcd'"
                    ));
                }

                let etcd_config = self.etcd.as_ref().unwrap();
                if etcd_config.endpoints.is_empty() {
                    return Err(anyhow::anyhow!("etcd endpoints cannot be empty"));
                }
            }
            ServiceDiscoveryProvider::Kubernetes => {
                if self.kubernetes.is_none() {
                    return Err(anyhow::anyhow!(
                        "Kubernetes configuration is required when provider is 'kubernetes'"
                    ));
                }
            }
            ServiceDiscoveryProvider::Dns => {
                // DNS configuration is always present with defaults
                if self.dns.timeout == 0 {
                    return Err(anyhow::anyhow!("DNS timeout must be greater than 0"));
                }
            }
        }

        // Validate service instance configuration if auto-registration is enabled
        if self.auto_register {
            if let Some(instance) = &self.service_instance {
                if instance.name.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Service instance name is required when auto_register is enabled"
                    ));
                }

                if instance.port == 0 {
                    return Err(anyhow::anyhow!(
                        "Service instance port must be greater than 0"
                    ));
                }

                // Validate health check configuration
                if let Some(health) = &instance.health_check {
                    if health.interval == 0 {
                        return Err(anyhow::anyhow!(
                            "Health check interval must be greater than 0"
                        ));
                    }
                    if health.timeout == 0 {
                        return Err(anyhow::anyhow!(
                            "Health check timeout must be greater than 0"
                        ));
                    }
                    if health.timeout >= health.interval {
                        return Err(anyhow::anyhow!(
                            "Health check timeout must be less than interval"
                        ));
                    }
                    if health.healthy_status.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Health check healthy_status cannot be empty"
                        ));
                    }
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Service instance configuration is required when auto_register is enabled"
                ));
            }
        }

        Ok(())
    }

    /// Convert to service discovery Duration values
    pub fn refresh_duration(&self) -> Duration {
        Duration::from_secs(self.refresh_interval)
    }

    /// Get the effective provider configuration based on the selected provider
    pub fn get_provider_config(&self) -> Result<ProviderConfig> {
        match self.provider {
            ServiceDiscoveryProvider::Consul => {
                if let Some(consul_config) = &self.consul {
                    Ok(ProviderConfig::Consul(consul_config.clone()))
                } else {
                    Err(anyhow::anyhow!("Consul configuration not found"))
                }
            }
            ServiceDiscoveryProvider::Etcd => {
                if let Some(etcd_config) = &self.etcd {
                    Ok(ProviderConfig::Etcd(etcd_config.clone()))
                } else {
                    Err(anyhow::anyhow!("etcd configuration not found"))
                }
            }
            ServiceDiscoveryProvider::Kubernetes => {
                if let Some(k8s_config) = &self.kubernetes {
                    Ok(ProviderConfig::Kubernetes(k8s_config.clone()))
                } else {
                    Err(anyhow::anyhow!("Kubernetes configuration not found"))
                }
            }
            ServiceDiscoveryProvider::Dns => Ok(ProviderConfig::Dns(self.dns.clone())),
        }
    }
}

/// Provider-specific configuration enum
#[derive(Debug, Clone)]
pub enum ProviderConfig {
    Consul(ConsulConfig),
    Etcd(EtcdConfig),
    Kubernetes(KubernetesConfig),
    Dns(DnsConfig),
}
