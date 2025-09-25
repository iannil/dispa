//! Service discovery module
//!
//! This module provides service discovery functionality with support for multiple backends:
//! - Consul: Service registration and discovery with health checks
//! - etcd: Distributed configuration and service registry
//! - Kubernetes: Native K8s service discovery via API server
//! - DNS: Traditional DNS-based service discovery

pub mod consul;
pub mod dns;
pub mod etcd;
pub mod kubernetes;
pub mod traits;

// Unit tests
#[cfg(test)]
mod tests;

// Re-export public types for convenience
pub use traits::{
    HealthCheckConfig, HealthStatus, ServiceChangeEvent, ServiceChangeStream, ServiceDiscovery,
    ServiceDiscoveryError, ServiceDiscoveryResult, ServiceInstance,
};

pub use crate::config::service_discovery::ConsulConfig;
pub use consul::ConsulServiceDiscovery;

#[cfg(feature = "etcd-discovery")]
pub use etcd::EtcdServiceDiscovery;

#[cfg(feature = "kubernetes-discovery")]
pub use kubernetes::KubernetesServiceDiscovery;

pub use dns::DnsServiceDiscovery;
