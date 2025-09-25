use super::state::ConnectionStats;
use crate::balancer::health_check::HealthStatus;
use crate::config::{LoadBalancingType, Target};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::debug;

/// Metrics collector and summary generator for load balancer
pub struct MetricsCollector;

impl MetricsCollector {
    /// Record a request result for metrics tracking
    pub fn record_request_result(
        connection_stats: &mut HashMap<String, ConnectionStats>,
        target_name: &str,
        success: bool,
        response_time: Duration,
    ) {
        let target_stats = connection_stats.entry(target_name.to_string()).or_default();

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

    /// Increment connection count for a target
    pub fn increment_connection_count(
        connection_stats: &mut HashMap<String, ConnectionStats>,
        target_name: &str,
    ) {
        let target_stats = connection_stats.entry(target_name.to_string()).or_default();

        target_stats.active_connections += 1;
        target_stats.total_requests += 1;
        target_stats.last_request = Some(Instant::now());
    }

    /// Decrement connection count for a target
    pub fn decrement_connection_count(
        connection_stats: &mut HashMap<String, ConnectionStats>,
        target_name: &str,
    ) {
        if let Some(target_stats) = connection_stats.get_mut(target_name) {
            if target_stats.active_connections > 0 {
                target_stats.active_connections -= 1;
            }
        }
    }

    /// Generate a summary of load balancer metrics
    pub fn generate_summary(
        targets: &[Target],
        health_status: &HashMap<String, HealthStatus>,
        connection_stats: &HashMap<String, ConnectionStats>,
        lb_type: LoadBalancingType,
    ) -> LoadBalancerSummary {
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
            total_targets: targets.len(),
            healthy_targets: healthy_count,
            load_balancing_type: lb_type,
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

    /// Clean up expired connection statistics
    pub fn cleanup_expired_stats(
        connection_stats: &mut HashMap<String, ConnectionStats>,
        current_target_names: &std::collections::HashSet<String>,
    ) {
        let now = Instant::now();
        let retention_duration = Duration::from_secs(3600); // 1 hour

        connection_stats.retain(|target_name, target_stats| {
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
}

/// Load balancer summary containing aggregate metrics
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

/// Target information combining configuration, health, and statistics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TargetInfo {
    pub target: Target,
    pub health_status: Option<HealthStatus>,
    pub connection_stats: Option<ConnectionStats>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::health_check::HealthStatus;
    use crate::config::LoadBalancingType;

    #[test]
    fn test_increment_connection_count() {
        let mut stats = HashMap::new();

        MetricsCollector::increment_connection_count(&mut stats, "server1");
        MetricsCollector::increment_connection_count(&mut stats, "server1");

        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.active_connections, 2);
        assert_eq!(server1_stats.total_requests, 2);
        assert!(server1_stats.last_request.is_some());
    }

    #[test]
    fn test_decrement_connection_count() {
        let mut stats = HashMap::new();

        // First increment
        MetricsCollector::increment_connection_count(&mut stats, "server1");
        MetricsCollector::increment_connection_count(&mut stats, "server1");

        // Then decrement
        MetricsCollector::decrement_connection_count(&mut stats, "server1");

        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.active_connections, 1);
        assert_eq!(server1_stats.total_requests, 2); // Should not change
    }

    #[test]
    fn test_record_request_result() {
        let mut stats = HashMap::new();

        // Record successful request
        MetricsCollector::record_request_result(
            &mut stats,
            "server1",
            true,
            Duration::from_millis(100),
        );

        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.total_errors, 0);
        assert_eq!(server1_stats.avg_response_time_ms, 100.0);

        // Record failed request
        MetricsCollector::record_request_result(
            &mut stats,
            "server1",
            false,
            Duration::from_millis(200),
        );

        let server1_stats = stats.get("server1").unwrap();
        assert_eq!(server1_stats.total_errors, 1);
        // EMA: 100.0 * 0.9 + 200.0 * 0.1 = 110.0
        assert_eq!(server1_stats.avg_response_time_ms, 110.0);
    }

    #[test]
    fn test_generate_summary() {
        let targets = vec![
            Target {
                name: "server1".to_string(),
                url: "http://server1.com".to_string(),
                address: "server1.com:80".to_string(),
                weight: None,
                timeout: Some(30),
            },
            Target {
                name: "server2".to_string(),
                url: "http://server2.com".to_string(),
                address: "server2.com:80".to_string(),
                weight: None,
                timeout: Some(30),
            },
        ];

        let mut health_status = HashMap::new();
        health_status.insert(
            "server1".to_string(),
            HealthStatus {
                is_healthy: true,
                last_check: std::time::Instant::now(),
                consecutive_failures: 0,
                consecutive_successes: 1,
                last_error: None,
                response_time_ms: Some(100),
            },
        );
        health_status.insert(
            "server2".to_string(),
            HealthStatus {
                is_healthy: true,
                last_check: std::time::Instant::now(),
                consecutive_failures: 0,
                consecutive_successes: 1,
                last_error: None,
                response_time_ms: Some(150),
            },
        );

        let mut connection_stats = HashMap::new();
        connection_stats.insert(
            "server1".to_string(),
            ConnectionStats {
                active_connections: 3,
                total_requests: 100,
                total_errors: 5,
                ..Default::default()
            },
        );
        connection_stats.insert(
            "server2".to_string(),
            ConnectionStats {
                active_connections: 2,
                total_requests: 80,
                total_errors: 2,
                ..Default::default()
            },
        );

        let summary = MetricsCollector::generate_summary(
            &targets,
            &health_status,
            &connection_stats,
            LoadBalancingType::RoundRobin,
        );

        assert_eq!(summary.total_targets, 2);
        assert_eq!(summary.healthy_targets, 2);
        assert_eq!(summary.total_active_connections, 5);
        assert_eq!(summary.total_requests, 180);
        assert_eq!(summary.total_errors, 7);
        // Error rate: 7/180 * 100 = ~3.89%
        assert!((summary.error_rate - 3.888888888888889).abs() < 0.001);
    }
}
