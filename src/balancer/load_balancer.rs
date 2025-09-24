use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::health_check::{HealthChecker, HealthStatus};
use crate::config::{LoadBalancingType, Target, TargetConfig};

// Import our new modular components
use super::algorithms::LoadBalancingAlgorithms;
use super::metrics::{LoadBalancerSummary, MetricsCollector, TargetInfo};
use super::state::{ConnectionStats, WeightedRoundRobinState};

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

impl LoadBalancer {
    /// Create a new load balancer with the given configuration
    ///
    /// This initializes a load balancer with the specified target configuration
    /// and starts health monitoring if enabled. The load balancer will use the
    /// configured algorithm (Round Robin, Weighted, Random, or Least Connections)
    /// to distribute requests.
    ///
    /// # Parameters
    ///
    /// * `config` - Target configuration including targets and load balancing settings
    ///
    /// # Returns
    ///
    /// A new LoadBalancer instance ready to serve requests
    ///
    /// # Examples
    ///
    /// ```
    /// use dispa::config::TargetConfig;
    /// let config = TargetConfig::default();
    /// let load_balancer = LoadBalancer::new(config);
    /// ```
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

    /// Select the next target for load balancing
    ///
    /// This method chooses a target based on the configured load balancing algorithm
    /// and current health status. It will only return healthy targets unless health
    /// checking is disabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(Target)` if a healthy target is available, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let target = load_balancer.get_target().await;
    /// if let Some(target) = target {
    ///     println!("Selected target: {}", target.name);
    /// }
    /// ```
    pub async fn get_target(&self) -> Option<Target> {
        let healthy_targets = self.get_healthy_targets().await;

        if healthy_targets.is_empty() {
            warn!("No healthy targets available");
            return None;
        }

        let selected = match self.config.load_balancing.lb_type {
            LoadBalancingType::RoundRobin => {
                let mut current_index = self.current_index.write().await;
                LoadBalancingAlgorithms::round_robin_select(&healthy_targets, &mut current_index)
            }
            LoadBalancingType::WeightedRoundRobin | LoadBalancingType::Weighted => {
                let mut weighted_state = self.weighted_state.write().await;
                LoadBalancingAlgorithms::weighted_round_robin_select(
                    &healthy_targets,
                    &self.targets,
                    &mut weighted_state,
                )
            }
            LoadBalancingType::Random => LoadBalancingAlgorithms::random_select(&healthy_targets),
            LoadBalancingType::LeastConnections => {
                let connection_stats = self.connection_stats.read().await;
                LoadBalancingAlgorithms::least_connections_select(
                    &healthy_targets,
                    &connection_stats,
                )
            }
        };

        if let Some(target) = &selected {
            let mut stats = self.connection_stats.write().await;
            MetricsCollector::increment_connection_count(&mut stats, &target.name);
        }

        selected
    }

    /// Get all currently healthy targets
    ///
    /// Returns a list of targets that are currently passing health checks.
    /// If health checking is disabled, returns all configured targets.
    ///
    /// # Returns
    ///
    /// Vector of healthy targets
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

    /// Decrement the connection count for a target
    ///
    /// This should be called when a connection to a target is closed
    /// to maintain accurate connection statistics for load balancing.
    ///
    /// # Parameters
    ///
    /// * `target_name` - Name of the target to update
    pub async fn decrement_connection_count(&self, target_name: &str) {
        let mut stats = self.connection_stats.write().await;
        MetricsCollector::decrement_connection_count(&mut stats, target_name);
    }

    /// Record the result of a request for metrics tracking
    ///
    /// # Parameters
    ///
    /// * `target_name` - Name of the target that handled the request
    /// * `success` - Whether the request was successful
    /// * `response_time` - Time taken to complete the request
    pub async fn record_request_result(
        &self,
        target_name: &str,
        success: bool,
        response_time: Duration,
    ) {
        let mut stats = self.connection_stats.write().await;
        MetricsCollector::record_request_result(&mut stats, target_name, success, response_time);
    }

    /// Get health status of all targets
    ///
    /// # Returns
    ///
    /// HashMap mapping target names to their current health status
    pub async fn get_health_status(&self) -> HashMap<String, HealthStatus> {
        self.health_checker.get_all_health_status().await
    }

    /// Get connection statistics for all targets
    ///
    /// # Returns
    ///
    /// HashMap mapping target names to their connection statistics
    pub async fn get_connection_stats(&self) -> HashMap<String, ConnectionStats> {
        let stats = self.connection_stats.read().await;
        stats.clone()
    }

    /// Get detailed information about a specific target
    ///
    /// # Parameters
    ///
    /// * `target_name` - Name of the target to query
    ///
    /// # Returns
    ///
    /// `Some(TargetInfo)` if the target exists, `None` otherwise
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

    /// Force an immediate health check of all targets
    ///
    /// This bypasses the normal health check interval and immediately
    /// checks all targets.
    pub async fn force_health_check(&self) {
        self.health_checker.force_health_check(&self.targets).await;
    }

    /// Get a target by name
    ///
    /// Searches for a target with the given name, preferring healthy targets
    /// but falling back to any target with the name if needed.
    ///
    /// # Parameters
    ///
    /// * `target_name` - Name of the target to find
    ///
    /// # Returns
    ///
    /// `Some(Target)` if found, `None` otherwise
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

    /// Get a summary of load balancer status and metrics
    ///
    /// # Returns
    ///
    /// LoadBalancerSummary containing overall statistics and status
    pub async fn get_summary(&self) -> LoadBalancerSummary {
        let health_status = self.get_health_status().await;
        let connection_stats = self.get_connection_stats().await;

        MetricsCollector::generate_summary(
            &self.targets,
            &health_status,
            &connection_stats,
            self.config.load_balancing.lb_type.clone(),
        )
    }

    /// Clean up expired connection statistics and unused target data
    /// Should be called periodically to prevent memory leaks
    pub async fn cleanup_expired_data(&self) {
        // Get current target names for comparison
        let current_target_names: std::collections::HashSet<String> =
            self.targets.iter().map(|t| t.name.clone()).collect();

        // Clean up connection stats
        {
            let mut stats = self.connection_stats.write().await;
            MetricsCollector::cleanup_expired_stats(&mut stats, &current_target_names);
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
    pub fn health_checker(&self) -> &super::health_check::HealthChecker {
        &self.health_checker
    }
}

impl Drop for LoadBalancer {
    fn drop(&mut self) {
        // Signal health checker to stop its background loop on drop
        self.health_checker.stop();
    }
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
    async fn test_get_target_round_robin() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];
        let config = create_test_config(targets.clone(), LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Reset index to ensure consistent starting point
        lb.reset_round_robin_index().await;

        // Test round robin distribution through get_target
        let selected1 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed
        let selected2 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed
        let selected3 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed
        let selected4 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed

        assert_eq!(selected1.name, "server2"); // Index starts at 0, increments to 1
        assert_eq!(selected2.name, "server3"); // Index 2
        assert_eq!(selected3.name, "server1"); // Index 0 (wrapped)
        assert_eq!(selected4.name, "server2"); // Index 1
    }

    #[tokio::test]
    async fn test_connection_statistics() {
        let targets = vec![create_test_target("server1", None)];
        let config = create_test_config(targets, LoadBalancingType::RoundRobin);
        let lb = LoadBalancer::new_for_test(config);

        // Test getting targets increments connection count
        let _target1 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed
        let _target2 = lb.get_target().await.unwrap(); // OK in tests - expect target selection to succeed

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap(); // OK in tests - server1 expected to exist
        assert_eq!(server1_stats.active_connections, 2);
        assert_eq!(server1_stats.total_requests, 2);

        // Test decrement
        lb.decrement_connection_count("server1").await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap(); // OK in tests - server1 expected to exist
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
        let server1_stats = stats.get("server1").unwrap(); // OK in tests - server1 expected to exist
        assert_eq!(server1_stats.total_errors, 0);
        assert_eq!(server1_stats.avg_response_time_ms, 100.0);

        // Record failed request
        lb.record_request_result("server1", false, Duration::from_millis(200))
            .await;

        let stats = lb.get_connection_stats().await;
        let server1_stats = stats.get("server1").unwrap(); // OK in tests - server1 expected to exist
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
}
