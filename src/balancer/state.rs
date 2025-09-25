#![allow(dead_code)]
use std::collections::HashMap;
use std::time::Instant;

/// Connection statistics for a target
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub active_connections: u32,
    pub total_requests: u64,
    pub total_errors: u64,
    pub last_request: Option<Instant>,
    pub avg_response_time_ms: f64,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            active_connections: 0,
            total_requests: 0,
            total_errors: 0,
            last_request: None,
            avg_response_time_ms: 0.0,
        }
    }
}

/// Weighted round robin state tracking
#[derive(Debug, Clone)]
pub struct WeightedRoundRobinState {
    pub current_weights: Vec<i32>,
    #[allow(dead_code)]
    pub total_weight: i32,
}

impl WeightedRoundRobinState {
    pub fn new(targets_count: usize, total_weight: i32) -> Self {
        Self {
            current_weights: vec![0; targets_count],
            total_weight,
        }
    }
}

/// State manager for load balancer internal state
pub struct LoadBalancerState {
    pub current_index: usize,
    pub weighted_state: WeightedRoundRobinState,
    pub connection_stats: HashMap<String, ConnectionStats>,
}

impl LoadBalancerState {
    pub fn new(targets_count: usize, total_weight: i32) -> Self {
        Self {
            current_index: 0,
            weighted_state: WeightedRoundRobinState::new(targets_count, total_weight),
            connection_stats: HashMap::with_capacity(targets_count),
        }
    }
}
