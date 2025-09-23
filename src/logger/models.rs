use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Traffic log entry representing a single request/response cycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub target: String,
    pub status_code: u16,
    pub duration_ms: i64,
    pub request_size: Option<i64>,
    pub response_size: Option<i64>,
    pub user_agent: Option<String>,
    pub error_message: Option<String>,
}

/// Aggregated traffic statistics for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total_requests: i64,
    pub error_count: i64,
    pub avg_duration_ms: f64,
    pub total_bytes: i64,
    pub unique_clients: i64,
    pub top_hosts: Vec<(String, i64)>,
    pub top_targets: Vec<(String, i64)>,
    pub error_rate_percentage: f64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            error_count: 0,
            avg_duration_ms: 0.0,
            total_bytes: 0,
            unique_clients: 0,
            top_hosts: Vec::new(),
            top_targets: Vec::new(),
            error_rate_percentage: 0.0,
        }
    }
}

/// Traffic statistics for a specific target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTrafficStats {
    pub target: String,
    pub total_requests: i64,
    pub error_count: i64,
    pub avg_duration_ms: f64,
    pub error_rate_percentage: f64,
}
