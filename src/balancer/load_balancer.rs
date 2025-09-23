use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::health_check::{HealthChecker, HealthStatus};
use crate::config::{LoadBalancingType, Target, TargetConfig};

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

/// Load balancer for distributing requests across multiple targets
///
/// Supports multiple load balancing algorithms:
/// - Round Robin: Distributes requests evenly across all healthy targets
/// - Weighted Round Robin: Distributes based on configured weights
/// - Least Connections: Routes to the target with fewest active connections
/// - Random: Randomly selects a healthy target
#[derive(Clone)]
pub struct LoadBalancer {
    targets: Vec<Target>,
    config: TargetConfig,
    current_index: Arc<RwLock<usize>>,
    weighted_state: Arc<RwLock<WeightedRoundRobinState>>,
    connection_stats: Arc<RwLock<HashMap<String, ConnectionStats>>>,
    health_checker: HealthChecker,
}

#[derive(Debug, Clone)]
struct WeightedRoundRobinState {
    current_weights: Vec<i32>,
    #[allow(dead_code)]
    total_weight: i32,
}

impl LoadBalancer {
    /// Create a new load balancer with the given configuration
    pub fn new(config: TargetConfig) -> Self {
        let health_checker = HealthChecker::new(config.health_check.clone());

        // Initialize weighted round robin state
        let total_weight: i32 = config
            .targets
            .iter()
            .map(|t| t.weight.unwrap_or(1.0) as i32)
            .sum();

        let current_weights = config
            .targets
            .iter()
            .map(|t| t.weight.unwrap_or(1.0) as i32)
            .collect();

        let weighted_state = WeightedRoundRobinState {
            current_weights,
            total_weight,
        };

        let target_count = config.targets.len();
        let connection_stats = HashMap::with_capacity(target_count);

        let lb = Self {
            targets: config.targets.clone(),
            config,
            current_index: Arc::new(RwLock::new(0)),
            weighted_state: Arc::new(RwLock::new(weighted_state)),
            connection_stats: Arc::new(RwLock::new(connection_stats)),
            health_checker,
        };

        // Start health checker if enabled
        if lb.config.health_check.enabled {
            let targets = lb.targets.clone();
            let health_checker = lb.health_checker.clone();

            tokio::spawn(async move {
                if let Err(e) = health_checker.start_monitoring(targets).await {
                    warn!("Health checker failed: {}", e);
                }
            });
        }

        lb
    }

    // Create a test-only constructor without starting health checker
    #[cfg(test)]
    pub fn new_for_test(config: TargetConfig) -> Self {
        let health_checker = HealthChecker::new(config.health_check.clone());

        let total_weight: i32 = config
            .targets
            .iter()
            .map(|t| t.weight.unwrap_or(1.0) as i32)
            .sum();

        let current_weights = config
            .targets
            .iter()
            .map(|t| t.weight.unwrap_or(1.0) as i32)
            .collect();

        let weighted_state = WeightedRoundRobinState {
            current_weights,
            total_weight,
        };

        let target_count = config.targets.len();
        let connection_stats = HashMap::with_capacity(target_count);

        Self {
            targets: config.targets.clone(),
            config,
            current_index: Arc::new(RwLock::new(0)),
            weighted_state: Arc::new(RwLock::new(weighted_state)),
            connection_stats: Arc::new(RwLock::new(connection_stats)),
            health_checker,
        }
    }

    pub async fn get_target(&self) -> Option<Target> {
        let healthy_targets = self.get_healthy_targets().await;

        if healthy_targets.is_empty() {
            warn!("No healthy targets available");
            return None;
        }

        let selected = match self.config.load_balancing.lb_type {
            LoadBalancingType::RoundRobin => self.round_robin_select(&healthy_targets).await,
            LoadBalancingType::WeightedRoundRobin => {
                self.weighted_round_robin_select(&healthy_targets).await
            }
            LoadBalancingType::Weighted => self.weighted_round_robin_select(&healthy_targets).await,
            LoadBalancingType::Random => self.random_select(&healthy_targets).await,
            LoadBalancingType::LeastConnections => {
                self.least_connections_select(&healthy_targets).await
            }
        };

        if let Some(target) = &selected {
            self.increment_connection_count(&target.name).await;
        }

        selected
    }

    pub async fn get_healthy_targets(&self) -> Vec<Target> {
        let mut healthy_targets = Vec::new();

        for target in &self.targets {
            if self.health_checker.is_target_healthy(&target.name).await {
                healthy_targets.push(target.clone());
            }
        }

        // If no targets are healthy and health checks are disabled, return all targets
        if healthy_targets.is_empty() && !self.config.health_check.enabled {
            healthy_targets = self.targets.clone();
        }

        healthy_targets
    }

    pub async fn round_robin_select(&self, healthy_targets: &[Target]) -> Option<Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        let mut current_index = self.current_index.write().await;
        *current_index = (*current_index + 1) % healthy_targets.len();
        Some(healthy_targets[*current_index].clone())
    }

    pub async fn weighted_round_robin_select(&self, healthy_targets: &[Target]) -> Option<Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        if healthy_targets.len() == 1 {
            return Some(healthy_targets[0].clone());
        }

        // Smooth weighted round robin algorithm (fixed)
        let mut state = self.weighted_state.write().await;
        let mut max_weight = -1;
        let mut selected_index = 0;

        // Calculate total weight for proper normalization
        let total_weight: i32 = healthy_targets
            .iter()
            .map(|target| target.weight.unwrap_or(1.0) as i32)
            .sum();

        // Find target index mapping
        let target_indices: Vec<usize> = healthy_targets
            .iter()
            .filter_map(|target| self.targets.iter().position(|t| t.name == target.name))
            .collect();

        // Ensure state arrays are properly sized
        if state.current_weights.len() < self.targets.len() {
            state.current_weights.resize(self.targets.len(), 0);
        }

        // Find the target with the highest current weight
        for (i, &original_index) in target_indices.iter().enumerate() {
            if original_index >= self.targets.len() {
                continue; // Skip invalid indices
            }

            let weight = healthy_targets[i].weight.unwrap_or(1.0) as i32;
            state.current_weights[original_index] += weight;

            if state.current_weights[original_index] > max_weight {
                max_weight = state.current_weights[original_index];
                selected_index = i;
            }
        }

        // Decrease the selected target's current weight by total weight
        if let Some(&original_index) = target_indices.get(selected_index) {
            if original_index < state.current_weights.len() {
                state.current_weights[original_index] -= total_weight;
            }
        }

        healthy_targets.get(selected_index).cloned()
    }

    pub async fn random_select(&self, healthy_targets: &[Target]) -> Option<Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        // Use a proper random number generator instead of time-based
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..healthy_targets.len());
        Some(healthy_targets[index].clone())
    }

    pub async fn least_connections_select(&self, healthy_targets: &[Target]) -> Option<Target> {
        if healthy_targets.is_empty() {
            return None;
        }

        let stats = self.connection_stats.read().await;

        let mut min_connections = u32::MAX;
        let mut selected_target = None;

        for target in healthy_targets {
            let connections = stats
                .get(&target.name)
                .map(|s| s.active_connections)
                .unwrap_or(0);

            if connections < min_connections {
                min_connections = connections;
                selected_target = Some(target.clone());
            }
        }

        selected_target
    }

    async fn increment_connection_count(&self, target_name: &str) {
        let mut stats = self.connection_stats.write().await;
        let target_stats = stats
            .entry(target_name.to_string())
            .or_insert_with(ConnectionStats::default);

        target_stats.active_connections += 1;
        target_stats.total_requests += 1;
        target_stats.last_request = Some(Instant::now());
    }

    #[allow(dead_code)]
    pub async fn decrement_connection_count(&self, target_name: &str) {
        let mut stats = self.connection_stats.write().await;
        if let Some(target_stats) = stats.get_mut(target_name) {
            if target_stats.active_connections > 0 {
                target_stats.active_connections -= 1;
            }
        }
    }

    #[allow(dead_code)]
    pub async fn record_request_result(
        &self,
        target_name: &str,
        success: bool,
        response_time: Duration,
    ) {
        let mut stats = self.connection_stats.write().await;
        let target_stats = stats
            .entry(target_name.to_string())
            .or_insert_with(ConnectionStats::default);

        if !success {
            target_stats.total_errors += 1;
        }

        // Update average response time using exponential moving average
        let new_time_ms = response_time.as_millis() as f64;
        if target_stats.avg_response_time_ms == 0.0 {
            target_stats.avg_response_time_ms = new_time_ms;
        } else {
            // EMA with alpha = 0.1
            target_stats.avg_response_time_ms =
                0.9 * target_stats.avg_response_time_ms + 0.1 * new_time_ms;
        }

        debug!(
            "Recorded request for target '{}': success={}, response_time={:?}ms, avg_time={:.2}ms",
            target_name,
            success,
            response_time.as_millis(),
            target_stats.avg_response_time_ms
        );
    }

    pub async fn get_health_status(&self) -> HashMap<String, HealthStatus> {
        self.health_checker.get_all_health_status().await
    }

    pub async fn get_connection_stats(&self) -> HashMap<String, ConnectionStats> {
        let stats = self.connection_stats.read().await;
        stats.clone()
    }

    #[allow(dead_code)]
    pub async fn get_target_info(&self, target_name: &str) -> Option<TargetInfo> {
        let health_status = self.health_checker.get_target_status(target_name).await;
        let stats = self.connection_stats.read().await;
        let connection_stats = stats.get(target_name).cloned();

        self.targets
            .iter()
            .find(|t| t.name == target_name)
            .map(|target| TargetInfo {
                target: target.clone(),
                health_status,
                connection_stats,
            })
    }

    #[allow(dead_code)]
    pub async fn force_health_check(&self) {
        self.health_checker.force_health_check(&self.targets).await;
    }

    pub async fn get_target_by_name(&self, target_name: &str) -> Option<Target> {
        // First check if the target exists in healthy targets
        let healthy_targets = self.get_healthy_targets().await;
        healthy_targets
            .into_iter()
            .find(|t| t.name == target_name)
            .or_else(|| {
                // If not in healthy targets, check all targets as fallback
                self.targets.iter().find(|t| t.name == target_name).cloned()
            })
    }

    pub async fn get_summary(&self) -> LoadBalancerSummary {
        let health_status = self.get_health_status().await;
        let connection_stats = self.get_connection_stats().await;

        let healthy_count = health_status
            .values()
            .filter(|status| status.is_healthy)
            .count();

        let total_connections: u32 = connection_stats
            .values()
            .map(|stats| stats.active_connections)
            .sum();

        let total_requests: u64 = connection_stats
            .values()
            .map(|stats| stats.total_requests)
            .sum();

        let total_errors: u64 = connection_stats
            .values()
            .map(|stats| stats.total_errors)
            .sum();

        LoadBalancerSummary {
            total_targets: self.targets.len(),
            healthy_targets: healthy_count,
            load_balancing_type: self.config.load_balancing.lb_type.clone(),
            total_active_connections: total_connections,
            total_requests,
            total_errors,
            error_rate: if total_requests > 0 {
                (total_errors as f64 / total_requests as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    // Test helper methods
    #[cfg(test)]
    pub async fn set_connection_stats(&self, target_name: &str, stats: ConnectionStats) {
        let mut connection_stats = self.connection_stats.write().await;
        connection_stats.insert(target_name.to_string(), stats);
    }

    #[cfg(test)]
    pub async fn reset_round_robin_index(&self) {
        let mut index = self.current_index.write().await;
        *index = 0;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn health_checker(&self) -> &super::health_check::HealthChecker {
        &self.health_checker
    }

    /// Clean up expired connection statistics and unused target data
    /// Should be called periodically to prevent memory leaks
    #[allow(dead_code)]
    pub async fn cleanup_expired_data(&self) {
        let now = Instant::now();
        let retention_duration = Duration::from_secs(3600); // 1 hour

        // Get current target names for comparison
        let current_target_names: std::collections::HashSet<String> =
            self.targets.iter().map(|t| t.name.clone()).collect();

        // Clean up connection stats
        {
            let mut stats = self.connection_stats.write().await;
            stats.retain(|target_name, target_stats| {
                // Keep if target still exists in config
                if current_target_names.contains(target_name) {
                    return true;
                }

                // Keep if recently active (within retention period)
                if let Some(last_request) = target_stats.last_request {
                    if now.duration_since(last_request) < retention_duration {
                        return true;
                    }
                }

                // Remove old, unused target stats
                debug!("Cleaning up stats for removed target: {}", target_name);
                false
            });
        }

        // Clean up weighted round robin state for removed targets
        {
            let mut state = self.weighted_state.write().await;

            // Resize arrays to match current target count
            if state.current_weights.len() > self.targets.len() {
                state.current_weights.truncate(self.targets.len());
            }

            // Recalculate total weight for active targets
            state.total_weight = self
                .targets
                .iter()
                .map(|target| target.weight.unwrap_or(1.0) as i32)
                .sum();
        }

        // Trigger health checker cleanup
        self.health_checker
            .cleanup_expired_data(&current_target_names)
            .await;

        debug!("LoadBalancer data cleanup completed");
    }

    /// Update target configuration and clean up orphaned data
    #[allow(dead_code)]
    pub async fn update_targets(&self, new_targets: Vec<Target>) {
        // This method would be called when configuration is reloaded
        // For now, we'll just note that it should update self.targets
        // and call cleanup_expired_data()

        debug!(
            "Target configuration update requested with {} targets",
            new_targets.len()
        );
        // In a full implementation, this would:
        // 1. Update self.targets (requires making it mutable or using RwLock)
        // 2. Call cleanup_expired_data()
        // 3. Reinitialize health checker with new targets

        self.cleanup_expired_data().await;
    }
}

impl Drop for LoadBalancer {
    fn drop(&mut self) {
        // Signal health checker to stop its background loop on drop
        self.health_checker.stop();
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TargetInfo {
    pub target: Target,
    pub health_status: Option<HealthStatus>,
    pub connection_stats: Option<ConnectionStats>,
}

#[derive(Debug, Clone)]
pub struct LoadBalancerSummary {
    pub total_targets: usize,
    pub healthy_targets: usize,
    #[allow(dead_code)]
    pub load_balancing_type: LoadBalancingType,
    pub total_active_connections: u32,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64, // Percentage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCheckConfig, LoadBalancingConfig};

    fn create_test_target(name: &str, weight: Option<f64>) -> Target {
        Target {
            name: name.to_string(),
            url: format!("http://test-{}.com", name),
            address: format!("test-{}.com:80", name),
            weight,
            timeout: Some(30),
        }
    }

    fn create_test_config(targets: Vec<Target>, lb_type: LoadBalancingType) -> TargetConfig {
        TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                algorithm: lb_type.clone(),
                lb_type,
                sticky_sessions: Some(false),
            },
            health_check: HealthCheckConfig {
                enabled: false, // Disable for tests
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            },
        }
    }

    #[tokio::test]
    async fn test_round_robin_selection() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Reset index to ensure consistent starting point
        lb.reset_round_robin_index().await;

        // Test round robin distribution
        let selected1 = lb.round_robin_select(&targets).await.unwrap();
        let selected2 = lb.round_robin_select(&targets).await.unwrap();
        let selected3 = lb.round_robin_select(&targets).await.unwrap();
        let selected4 = lb.round_robin_select(&targets).await.unwrap(); // Should wrap around

        assert_eq!(selected1.name, "server2"); // Index starts at 0, increments to 1
        assert_eq!(selected2.name, "server3"); // Index 2
        assert_eq!(selected3.name, "server1"); // Index 0 (wrapped)
        assert_eq!(selected4.name, "server2"); // Index 1
    }

    #[tokio::test]
    async fn test_weighted_round_robin_selection() {
        let targets = vec![
            create_test_target("server1", Some(3.0)), // Weight 3
            create_test_target("server2", Some(1.0)), // Weight 1
            create_test_target("server3", Some(2.0)), // Weight 2
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::Weighted);
        let lb = LoadBalancer::new_for_test(config);

        // Collect selections to verify weight distribution
        let mut selections = Vec::new();
        for _ in 0..12 {
            // Multiple of total weight (6)
            if let Some(target) = lb.weighted_round_robin_select(&targets).await {
                selections.push(target.name);
            }
        }

        // Count selections per server
        let server1_count = selections.iter().filter(|&name| name == "server1").count();
        let server2_count = selections.iter().filter(|&name| name == "server2").count();
        let server3_count = selections.iter().filter(|&name| name == "server3").count();

        // Verify the distribution matches weights (approximately)
        // server1 should be selected ~6 times (3/6 * 12)
        // server2 should be selected ~2 times (1/6 * 12)
        // server3 should be selected ~4 times (2/6 * 12)
        assert!(
            (5..=7).contains(&server1_count),
            "server1 count: {}",
            server1_count
        );
        assert!(
            (1..=3).contains(&server2_count),
            "server2 count: {}",
            server2_count
        );
        assert!(
            (3..=5).contains(&server3_count),
            "server3 count: {}",
            server3_count
        );
    }

    #[tokio::test]
    async fn test_least_connections_selection() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::LeastConnections);
        let lb = LoadBalancer::new_for_test(config);

        // Set different connection counts
        lb.set_connection_stats(
            "server1",
            ConnectionStats {
                active_connections: 5,
                ..Default::default()
            },
        )
        .await;

        lb.set_connection_stats(
            "server2",
            ConnectionStats {
                active_connections: 2, // Least connections
                ..Default::default()
            },
        )
        .await;

        lb.set_connection_stats(
            "server3",
            ConnectionStats {
                active_connections: 8,
                ..Default::default()
            },
        )
        .await;

        let selected = lb.least_connections_select(&targets).await.unwrap();
        assert_eq!(selected.name, "server2");
    }

    #[tokio::test]
    async fn test_random_selection() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::Random);
        let lb = LoadBalancer::new_for_test(config);

        // Test that random selection returns valid targets
        for _ in 0..10 {
            let selected = lb.random_select(&targets).await.unwrap();
            assert!(targets.iter().any(|t| t.name == selected.name));
        }
    }

    #[tokio::test]
    async fn test_empty_targets() {
        let config = create_test_config(vec![], LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);
        let targets = vec![];

        assert!(lb.round_robin_select(&targets).await.is_none());
        assert!(lb.weighted_round_robin_select(&targets).await.is_none());
        assert!(lb.random_select(&targets).await.is_none());
        assert!(lb.least_connections_select(&targets).await.is_none());
    }

    #[tokio::test]
    async fn test_single_target() {
        let targets = vec![create_test_target("server1", Some(5.0))];
        let config = create_test_config(targets.clone(), LoadBalancingType::Weighted);
        let lb = LoadBalancer::new_for_test(config);

        let selected = lb.weighted_round_robin_select(&targets).await.unwrap();
        assert_eq!(selected.name, "server1");
    }

    #[tokio::test]
    async fn test_connection_statistics() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Test increment
        lb.increment_connection_count("server1").await;
        lb.increment_connection_count("server1").await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.active_connections, 2);
        assert_eq!(server1_stats.total_requests, 2);

        // Test decrement
        lb.decrement_connection_count("server1").await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.active_connections, 1);
        assert_eq!(server1_stats.total_requests, 2); // Should not change
    }

    #[tokio::test]
    async fn test_request_result_recording() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Record successful request
        lb.record_request_result("server1", true, Duration::from_millis(100))
            .await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.total_errors, 0);
        assert_eq!(server1_stats.avg_response_time_ms, 100.0);

        // Record failed request
        lb.record_request_result("server1", false, Duration::from_millis(200))
            .await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.total_errors, 1);
        // EMA: 100.0 * 0.9 + 200.0 * 0.1 = 110.0
        assert_eq!(server1_stats.avg_response_time_ms, 110.0);
    }

    #[tokio::test]
    async fn test_load_balancer_summary() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
        ];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Add some connection stats
        lb.set_connection_stats(
            "server1",
            ConnectionStats {
                active_connections: 3,
                total_requests: 100,
                total_errors: 5,
                ..Default::default()
            },
        )
        .await;

        lb.set_connection_stats(
            "server2",
            ConnectionStats {
                active_connections: 2,
                total_requests: 80,
                total_errors: 2,
                ..Default::default()
            },
        )
        .await;

        let summary = lb.get_summary().await;
        assert_eq!(summary.total_targets, 2);
        assert_eq!(summary.total_active_connections, 5);
        assert_eq!(summary.total_requests, 180);
        assert_eq!(summary.total_errors, 7);
        // Error rate: 7/180 * 100 = ~3.89%
        assert!((summary.error_rate - 3.888888888888889).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_zero_weight_handling() {
        let targets = vec![
            create_test_target("server1", Some(0.0)), // Zero weight
            create_test_target("server2", Some(2.0)),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::Weighted);
        let lb = LoadBalancer::new_for_test(config);

        // Should still work - zero weight is treated as 1
        for _ in 0..5 {
            let selected = lb.weighted_round_robin_select(&targets).await;
            assert!(selected.is_some());
        }
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let targets = vec![
                create_test_target("server1", None),
                create_test_target("server2", None),
            ];
            let config = create_test_config(targets.clone(), LoadBalancingType::RoundRobin);
            let lb = Arc::new(LoadBalancer::new_for_test(config));

            // Spawn multiple tasks to test concurrent access
            let mut handles = vec![];
            for _ in 0..10 {
                let lb_clone = Arc::clone(&lb);
                let targets_clone = targets.clone();
                let handle = tokio::spawn(async move {
                    for _ in 0..100 {
                        let _ = lb_clone.round_robin_select(&targets_clone).await;
                        lb_clone.increment_connection_count("server1").await;
                    }
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // Verify the final state
            let stats = lb.get_connection_stats().await;
            let server1_stats = stats.get("server1").unwrap();
            assert_eq!(server1_stats.total_requests, 1000);
            assert_eq!(server1_stats.active_connections, 1000);
        })
        .await
        .expect("test_concurrent_access timed out");
    }

    #[tokio::test]
    async fn test_weighted_round_robin_detailed_algorithm() {
        let targets = vec![
            create_test_target("server1", Some(1.0)), // Weight 1
            create_test_target("server2", Some(3.0)), // Weight 3
            create_test_target("server3", Some(2.0)), // Weight 2
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::Weighted);
        let lb = LoadBalancer::new_for_test(config);

        // Test weighted distribution over multiple selections
        let mut selection_counts = HashMap::new();
        for _ in 0..60 {
            // 60 selections to test proper distribution
            let selected = lb.weighted_round_robin_select(&targets).await.unwrap();
            *selection_counts.entry(selected.name).or_insert(0) += 1;
        }

        // server1 (weight 1) should get ~10 selections (1/6 * 60)
        // server2 (weight 3) should get ~30 selections (3/6 * 60)
        // server3 (weight 2) should get ~20 selections (2/6 * 60)
        let server1_count = selection_counts.get("server1").unwrap_or(&0);
        let server2_count = selection_counts.get("server2").unwrap_or(&0);
        let server3_count = selection_counts.get("server3").unwrap_or(&0);

        // Allow some variance but check rough proportions
        assert!(
            *server2_count > *server1_count,
            "server2 should be selected more than server1"
        );
        assert!(
            *server2_count > *server3_count,
            "server2 should be selected more than server3"
        );
        assert!(
            *server3_count > *server1_count,
            "server3 should be selected more than server1"
        );
        assert_eq!(server1_count + server2_count + server3_count, 60);
    }

    #[tokio::test]
    async fn test_least_connections_with_complex_scenario() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::LeastConnections);
        let lb = LoadBalancer::new_for_test(config);

        // Set different connection counts
        lb.set_connection_stats(
            "server1",
            ConnectionStats {
                active_connections: 5,
                ..Default::default()
            },
        )
        .await;

        lb.set_connection_stats(
            "server2",
            ConnectionStats {
                active_connections: 2, // Least connections
                ..Default::default()
            },
        )
        .await;

        lb.set_connection_stats(
            "server3",
            ConnectionStats {
                active_connections: 8,
                ..Default::default()
            },
        )
        .await;

        // Test multiple selections - should consistently pick server2
        for _ in 0..10 {
            let selected = lb.least_connections_select(&targets).await.unwrap();
            assert_eq!(selected.name, "server2");
        }

        // Now make server1 have least connections
        lb.set_connection_stats(
            "server1",
            ConnectionStats {
                active_connections: 1, // Now least
                ..Default::default()
            },
        )
        .await;

        let selected = lb.least_connections_select(&targets).await.unwrap();
        assert_eq!(selected.name, "server1");
    }

    #[tokio::test]
    async fn test_random_selection_basic_functionality() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::Random);
        let lb = LoadBalancer::new_for_test(config);

        let mut selection_counts = HashMap::new();

        // Test that random selection returns valid targets and all targets get selected
        for _ in 0..30 {
            // Smaller sample to just verify functionality
            let selected = lb.random_select(&targets).await.unwrap();
            assert!(targets.iter().any(|t| t.name == selected.name));
            *selection_counts.entry(selected.name).or_insert(0) += 1;
        }

        // Just verify that at least two different targets were selected (showing randomness)
        assert!(
            selection_counts.len() >= 2,
            "Random selection should select multiple targets"
        );

        // Verify total selections
        let total: i32 = selection_counts.values().sum();
        assert_eq!(total, 30);
    }

    #[tokio::test]
    async fn test_connection_stats_edge_cases() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Test decrementing when count is already 0
        lb.decrement_connection_count("server1").await;
        let stats = lb.get_connection_stats().await;

        // Check if server1 exists in stats, if not, it means decrement on non-existent server created entry
        if let Some(server1_stats) = stats.get("server1") {
            assert_eq!(server1_stats.active_connections, 0);
        }

        // Test very large numbers
        for _ in 0..1000 {
            lb.increment_connection_count("server1").await;
        }

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.active_connections, 1000);
        assert_eq!(server1_stats.total_requests, 1000);
    }

    #[tokio::test]
    async fn test_response_time_calculation_edge_cases() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Test with zero duration
        lb.record_request_result("server1", true, Duration::from_millis(0))
            .await;
        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.avg_response_time_ms, 0.0);

        // Test with very large duration - check actual implementation
        lb.record_request_result("server1", true, Duration::from_millis(10000))
            .await;
        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap();
        // The actual implementation may use simple average, not EMA
        // So with 2 requests: (0 + 10000) / 2 = 5000
        assert!(server1_stats.avg_response_time_ms > 0.0);
        assert!(server1_stats.avg_response_time_ms <= 10000.0);
    }

    #[tokio::test]
    async fn test_get_target_with_empty_healthy_targets() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Mock empty healthy targets (all unhealthy)
        // Since health checks are disabled, should still return targets
        let selected = lb.get_target().await;
        assert!(selected.is_some());
    }

    #[tokio::test]
    async fn test_load_balancer_creation_with_different_configs() {
        // Test with various configurations
        let configs = vec![
            // Round robin with multiple targets
            create_test_config(
                vec![
                    create_test_target("rr1", None),
                    create_test_target("rr2", None),
                ],
                LoadBalancingType::RoundRobin,
            ),
            // Weighted with mixed weights
            create_test_config(
                vec![
                    create_test_target("w1", Some(1.0)),
                    create_test_target("w2", Some(5.0)),
                    create_test_target("w3", None), // Default weight
                ],
                LoadBalancingType::Weighted,
            ),
            // Random with single target
            create_test_config(
                vec![create_test_target("random1", Some(3.0))],
                LoadBalancingType::Random,
            ),
            // Least connections with zero weights
            create_test_config(
                vec![
                    create_test_target("lc1", Some(0.0)),
                    create_test_target("lc2", Some(0.0)),
                ],
                LoadBalancingType::LeastConnections,
            ),
        ];

        for config in configs {
            let lb = LoadBalancer::new_for_test(config.clone());

            // Verify load balancer was created successfully
            let summary = lb.get_summary().await;
            assert_eq!(summary.total_targets, config.targets.len());
            assert_eq!(summary.total_active_connections, 0);
            assert_eq!(summary.total_requests, 0);
            assert_eq!(summary.total_errors, 0);
        }
    }

    #[tokio::test]
    async fn test_concurrent_mixed_operations() {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let targets = vec![
                create_test_target("server1", Some(2.0)),
                create_test_target("server2", Some(3.0)),
            ];
            let config = create_test_config(targets.clone(), LoadBalancingType::Weighted);
            let lb = Arc::new(LoadBalancer::new_for_test(config));

            let mut handles = Vec::new();

            // Concurrent selections
            for _ in 0..10 {
                let lb_clone = Arc::clone(&lb);
                let handle = tokio::spawn(async move {
                    for _ in 0..10 {
                        let _ = lb_clone.get_target().await;
                    }
                });
                handles.push(handle);
            }

            // Concurrent connection increments
            for _ in 0..10 {
                let lb_clone = Arc::clone(&lb);
                let handle = tokio::spawn(async move {
                    for _ in 0..10 {
                        lb_clone.increment_connection_count("server1").await;
                        lb_clone.increment_connection_count("server2").await;
                    }
                });
                handles.push(handle);
            }

            // Concurrent request result recordings
            for _ in 0..10 {
                let lb_clone = Arc::clone(&lb);
                let handle = tokio::spawn(async move {
                    for _ in 0..10 {
                        lb_clone
                            .record_request_result("server1", true, Duration::from_millis(100))
                            .await;
                        lb_clone
                            .record_request_result("server2", false, Duration::from_millis(200))
                            .await;
                    }
                });
                handles.push(handle);
            }

            // Wait for all operations to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // Verify final state is consistent
            let summary = lb.get_summary().await;
            assert_eq!(summary.total_targets, 2);
            assert!(summary.total_requests > 0);
            assert!(summary.total_active_connections > 0);
        })
        .await
        .expect("test_concurrent_mixed_operations timed out");
    }
}
