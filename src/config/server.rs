use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub bind: std::net::SocketAddr,
    pub workers: Option<usize>,
    pub max_connections: Option<usize>,
    pub connection_timeout: Option<u64>, // seconds
}

/// Domain interception configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
    pub intercept_domains: Vec<String>,
    pub exclude_domains: Option<Vec<String>>,
    pub enable_wildcard: bool,
}
