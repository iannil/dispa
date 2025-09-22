use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::balancer::LoadBalancer;
use crate::logger::TrafficLogger;
use crate::config::MonitoringConfig;

/// Enhanced metrics collector with accurate metric types and additional insights
pub struct EnhancedMetricsCollector {
    load_balancer: Arc<RwLock<LoadBalancer>>,
    traffic_logger: Arc<TrafficLogger>,
    start_time: SystemTime,
    request_durations: Arc<RwLock<Vec<f64>>>, // Store recent request durations for percentiles
    max_duration_samples: usize,
    monitoring_config: MonitoringConfig,
}

impl EnhancedMetricsCollector {
    pub fn new(
        load_balancer: Arc<RwLock<LoadBalancer>>,
        traffic_logger: Arc<TrafficLogger>,
        monitoring_config: MonitoringConfig,
    ) -> Self {
        Self {
            load_balancer,
            traffic_logger,
            start_time: SystemTime::now(),
            request_durations: Arc::new(RwLock::new(Vec::new())),
            max_duration_samples: monitoring_config.capacity.max_duration_samples,
            monitoring_config,
        }
    }

    /// Collect all enhanced metrics
    pub async fn collect_enhanced_metrics(&self) {
        // Collect basic metrics first
        self.collect_basic_metrics().await;

        // Collect performance metrics
        self.collect_performance_metrics().await;

        // Collect capacity metrics
        self.collect_capacity_metrics().await;

        // Collect error metrics
        self.collect_error_metrics().await;

        // Collect latency percentiles
        self.collect_latency_percentiles().await;

        // Collect throughput metrics
        self.collect_throughput_metrics().await;

        // Collect resource utilization metrics
        self.collect_resource_utilization().await;

        // Collect system health metrics
        self.collect_system_health_metrics().await;
    }

    async fn collect_basic_metrics(&self) {
        let load_balancer = self.load_balancer.read().await;
        let summary = load_balancer.get_summary().await;

        // Basic service metrics (using gauges for absolute values)
        metrics::gauge!("dispa_service_uptime_seconds").set(
            self.start_time
                .elapsed()
                .unwrap_or(Duration::ZERO)
                .as_secs() as f64
        );

        metrics::gauge!("dispa_targets_configured_total").set(summary.total_targets as f64);
        metrics::gauge!("dispa_targets_healthy_total").set(summary.healthy_targets as f64);
        metrics::gauge!("dispa_targets_unhealthy_total")
            .set((summary.total_targets - summary.healthy_targets) as f64);

        // Health ratio
        let health_ratio = if summary.total_targets > 0 {
            summary.healthy_targets as f64 / summary.total_targets as f64
        } else {
            0.0
        };
        metrics::gauge!("dispa_targets_health_ratio").set(health_ratio);

        // Request metrics (absolute values, not incremental)
        metrics::gauge!("dispa_requests_processed_total").set(summary.total_requests as f64);
        metrics::gauge!("dispa_requests_failed_total").set(summary.total_errors as f64);
        metrics::gauge!("dispa_requests_success_total")
            .set((summary.total_requests.saturating_sub(summary.total_errors)) as f64);

        // Error rate
        metrics::gauge!("dispa_error_rate_ratio").set(summary.error_rate / 100.0); // Convert percentage to ratio

        // Active connections
        metrics::gauge!("dispa_connections_active_total")
            .set(summary.total_active_connections as f64);

        debug!("Enhanced basic metrics collected");
    }

    async fn collect_performance_metrics(&self) {
        let load_balancer = self.load_balancer.read().await;
        let connection_stats = load_balancer.get_connection_stats().await;

        let mut total_avg_response_time = 0.0;
        let mut targets_with_response_time = 0;
        let mut fastest_target_time = f64::MAX;
        let mut slowest_target_time = 0.0;

        for (target_name, stats) in &connection_stats {
            let labels = &[("target", target_name.as_str())];

            // Target-specific performance metrics
            metrics::gauge!("dispa_target_response_time_avg_ms", labels)
                .set(stats.avg_response_time_ms);

            if stats.avg_response_time_ms > 0.0 {
                total_avg_response_time += stats.avg_response_time_ms;
                targets_with_response_time += 1;
                fastest_target_time = fastest_target_time.min(stats.avg_response_time_ms);
                slowest_target_time = slowest_target_time.max(stats.avg_response_time_ms);
            }

            // Target throughput (requests per second approximation)
            if let Some(last_request) = stats.last_request {
                let time_since_last = last_request.elapsed().as_secs_f64();
                let estimated_rps = if time_since_last > 0.0 && stats.total_requests > 0 {
                    stats.total_requests as f64 / time_since_last.max(1.0)
                } else {
                    0.0
                };
                metrics::gauge!("dispa_target_requests_per_second", labels).set(estimated_rps);
            }

            // Target error rate
            let target_error_rate = if stats.total_requests > 0 {
                stats.total_errors as f64 / stats.total_requests as f64
            } else {
                0.0
            };
            metrics::gauge!("dispa_target_error_rate_ratio", labels).set(target_error_rate);
        }

        // Global performance metrics
        if targets_with_response_time > 0 {
            let avg_response_time = total_avg_response_time / targets_with_response_time as f64;
            metrics::gauge!("dispa_global_response_time_avg_ms").set(avg_response_time);

            if fastest_target_time != f64::MAX {
                metrics::gauge!("dispa_global_response_time_min_ms").set(fastest_target_time);
            }
            metrics::gauge!("dispa_global_response_time_max_ms").set(slowest_target_time);
        }

        debug!("Enhanced performance metrics collected");
    }

    async fn collect_capacity_metrics(&self) {
        let load_balancer = self.load_balancer.read().await;
        let connection_stats = load_balancer.get_connection_stats().await;

        let mut total_capacity_used = 0.0;
        let mut target_count = 0;

        for (target_name, stats) in &connection_stats {
            let labels = &[("target", target_name.as_str())];

            // Estimate capacity usage using configured maximum connections
            let max_connections = self.monitoring_config.capacity.max_connections_per_target as f64;
            let capacity_ratio = stats.active_connections as f64 / max_connections;

            metrics::gauge!("dispa_target_capacity_ratio", labels).set(capacity_ratio);
            metrics::gauge!("dispa_target_capacity_used_connections", labels)
                .set(stats.active_connections as f64);

            total_capacity_used += capacity_ratio;
            target_count += 1;

            // Connection efficiency (successful requests per connection)
            let connection_efficiency = if stats.active_connections > 0 {
                (stats.total_requests.saturating_sub(stats.total_errors)) as f64
                    / stats.active_connections as f64
            } else {
                0.0
            };
            metrics::gauge!("dispa_target_connection_efficiency", labels)
                .set(connection_efficiency);
        }

        // Global capacity metrics
        if target_count > 0 {
            let avg_capacity = total_capacity_used / target_count as f64;
            metrics::gauge!("dispa_global_capacity_avg_ratio").set(avg_capacity);
        }

        debug!("Enhanced capacity metrics collected");
    }

    async fn collect_error_metrics(&self) {
        let load_balancer = self.load_balancer.read().await;
        let health_status = load_balancer.get_health_status().await;

        let mut total_consecutive_failures = 0;
        let mut targets_with_failures = 0;
        let mut max_consecutive_failures = 0;

        for (target_name, health) in &health_status {
            let labels = &[("target", target_name.as_str())];

            // Target health metrics
            metrics::gauge!("dispa_target_health_status", labels)
                .set(if health.is_healthy { 1.0 } else { 0.0 });

            metrics::gauge!("dispa_target_consecutive_failures", labels)
                .set(health.consecutive_failures as f64);

            if health.consecutive_failures > 0 {
                total_consecutive_failures += health.consecutive_failures;
                targets_with_failures += 1;
                max_consecutive_failures = max_consecutive_failures.max(health.consecutive_failures);
            }

            // Time since last successful health check
            if let Some(last_success) = health.last_success {
                let time_since_success = last_success.elapsed().as_secs_f64();
                metrics::gauge!("dispa_target_time_since_success_seconds", labels)
                    .set(time_since_success);
            }
        }

        // Global error metrics
        if targets_with_failures > 0 {
            let avg_consecutive_failures = total_consecutive_failures as f64 / targets_with_failures as f64;
            metrics::gauge!("dispa_global_avg_consecutive_failures").set(avg_consecutive_failures);
        }
        metrics::gauge!("dispa_global_max_consecutive_failures").set(max_consecutive_failures as f64);

        debug!("Enhanced error metrics collected");
    }

    async fn collect_latency_percentiles(&self) {
        let durations = self.request_durations.read().await;
        if durations.is_empty() {
            return;
        }

        let mut sorted_durations = durations.clone();
        sorted_durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let len = sorted_durations.len();

        // Calculate percentiles
        let p50 = sorted_durations[len * 50 / 100];
        let p90 = sorted_durations[len * 90 / 100];
        let p95 = sorted_durations[len * 95 / 100];
        let p99 = sorted_durations[len * 99 / 100];

        metrics::gauge!("dispa_request_duration_p50_ms").set(p50);
        metrics::gauge!("dispa_request_duration_p90_ms").set(p90);
        metrics::gauge!("dispa_request_duration_p95_ms").set(p95);
        metrics::gauge!("dispa_request_duration_p99_ms").set(p99);

        debug!("Latency percentile metrics collected from {} samples", len);
    }

    async fn collect_system_health_metrics(&self) {
        // Service status indicators
        let load_balancer = self.load_balancer.read().await;
        let summary = load_balancer.get_summary().await;

        // Service health score (0-1)
        let health_score = if summary.total_targets > 0 {
            let health_factor = summary.healthy_targets as f64 / summary.total_targets as f64;
            let error_factor = 1.0 - (summary.error_rate / 100.0).min(1.0);
            (health_factor + error_factor) / 2.0
        } else {
            0.0
        };

        metrics::gauge!("dispa_service_health_score").set(health_score);

        // Service availability (simplified)
        let availability = if summary.healthy_targets > 0 { 1.0 } else { 0.0 };
        metrics::gauge!("dispa_service_availability").set(availability);

        // Load balancer efficiency
        let efficiency = if summary.total_requests > 0 {
            (summary.total_requests.saturating_sub(summary.total_errors)) as f64
                / summary.total_requests as f64
        } else {
            1.0
        };
        metrics::gauge!("dispa_load_balancer_efficiency").set(efficiency);

        debug!("System health metrics collected");
    }

    /// Collect throughput metrics
    async fn collect_throughput_metrics(&self) {
        let load_balancer = self.load_balancer.read().await;
        let summary = load_balancer.get_summary().await;
        let connection_stats = load_balancer.get_connection_stats().await;

        let uptime_seconds = self.start_time.elapsed().unwrap_or(Duration::ZERO).as_secs_f64();

        // Requests per second
        let rps = if uptime_seconds > 0.0 {
            summary.total_requests as f64 / uptime_seconds
        } else {
            0.0
        };
        metrics::gauge!("dispa_requests_per_second").set(rps);

        // Throughput per target
        for (target_name, stats) in &connection_stats {
            let labels = &[("target", target_name.as_str())];
            let target_rps = if uptime_seconds > 0.0 {
                stats.total_requests as f64 / uptime_seconds
            } else {
                0.0
            };
            metrics::gauge!("dispa_target_requests_per_second", labels).set(target_rps);
        }

        debug!("Throughput metrics collected");
    }

    /// Collect resource utilization metrics
    async fn collect_resource_utilization(&self) {
        let load_balancer = self.load_balancer.read().await;
        let summary = load_balancer.get_summary().await;

        // Connection utilization using configured maximum connections
        let max_connections = self.monitoring_config.capacity.global_max_connections as f64;
        let connection_utilization = if max_connections > 0.0 {
            (summary.total_active_connections as f64 / max_connections) * 100.0
        } else {
            0.0
        };
        metrics::gauge!("dispa_connection_utilization_percent").set(connection_utilization);

        // Target distribution efficiency (how evenly requests are distributed)
        let connection_stats = load_balancer.get_connection_stats().await;
        if !connection_stats.is_empty() {
            let total_requests: u64 = connection_stats.values().map(|s| s.total_requests).sum();
            let avg_requests = total_requests as f64 / connection_stats.len() as f64;

            let mut variance = 0.0;
            for stats in connection_stats.values() {
                let diff = stats.total_requests as f64 - avg_requests;
                variance += diff * diff;
            }
            variance /= connection_stats.len() as f64;

            let distribution_efficiency = if avg_requests > 0.0 {
                100.0 - (variance.sqrt() / avg_requests * 100.0).min(100.0)
            } else {
                100.0
            };
            metrics::gauge!("dispa_load_distribution_efficiency_percent").set(distribution_efficiency);
        }

        debug!("Resource utilization metrics collected");
    }

    /// Record a request duration for percentile calculation
    pub async fn record_request_duration(&self, duration_ms: f64) {
        let mut durations = self.request_durations.write().await;

        durations.push(duration_ms);

        // Keep only the most recent samples to prevent unbounded memory growth
        if durations.len() > self.max_duration_samples {
            durations.drain(0..durations.len() - self.max_duration_samples);
        }
    }

    /// Reset request duration samples
    pub async fn reset_duration_samples(&self) {
        let mut durations = self.request_durations.write().await;
        durations.clear();
        debug!("Request duration samples reset");
    }

    /// Get current metrics summary
    pub async fn get_metrics_summary(&self) -> EnhancedMetricsSummary {
        let load_balancer = self.load_balancer.read().await;
        let summary = load_balancer.get_summary().await;
        let durations = self.request_durations.read().await;

        EnhancedMetricsSummary {
            service_uptime_seconds: self.start_time.elapsed().unwrap_or(Duration::ZERO).as_secs(),
            targets_total: summary.total_targets,
            targets_healthy: summary.healthy_targets,
            requests_total: summary.total_requests,
            requests_failed: summary.total_errors,
            error_rate: summary.error_rate,
            active_connections: summary.total_active_connections,
            duration_samples_count: durations.len(),
            health_score: if summary.total_targets > 0 {
                let health_factor = summary.healthy_targets as f64 / summary.total_targets as f64;
                let error_factor = 1.0 - (summary.error_rate / 100.0).min(1.0);
                (health_factor + error_factor) / 2.0
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnhancedMetricsSummary {
    pub service_uptime_seconds: u64,
    pub targets_total: usize,
    pub targets_healthy: usize,
    pub requests_total: u64,
    pub requests_failed: u64,
    pub error_rate: f64,
    pub active_connections: u32,
    pub duration_samples_count: usize,
    pub health_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, Target, TargetConfig};
    use crate::balancer::LoadBalancer;
    use crate::logger::TrafficLogger;
    use crate::config::LoggingConfig;

    #[tokio::test]
    async fn test_enhanced_metrics_collection() {
        let targets = vec![
            Target {
                name: "test1".to_string(),
                url: "http://localhost:8001".to_string(),
                weight: Some(1),
                timeout: Some(30),
            },
            Target {
                name: "test2".to_string(),
                url: "http://localhost:8002".to_string(),
                weight: Some(2),
                timeout: Some(30),
            },
        ];

        let config = TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::WeightedRoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        };

        let load_balancer = Arc::new(RwLock::new(LoadBalancer::new_for_test(config)));
        let traffic_logger = Arc::new(TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: crate::config::LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        }));

        let metrics_collector = EnhancedMetricsCollector::new(
            load_balancer,
            traffic_logger,
            crate::config::MonitoringConfig {
                enabled: true,
                metrics_port: 9090,
                health_check_port: 8081,
                histogram_buckets: None,
                capacity: Default::default(),
            },
        );

        // Record some sample durations
        metrics_collector.record_request_duration(10.5).await;
        metrics_collector.record_request_duration(25.2).await;
        metrics_collector.record_request_duration(15.8).await;

        // Collect metrics (this should not panic)
        metrics_collector.collect_enhanced_metrics().await;

        // Get summary
        let summary = metrics_collector.get_metrics_summary().await;
        assert_eq!(summary.targets_total, 2);
        assert_eq!(summary.duration_samples_count, 3);
        assert!(summary.service_uptime_seconds >= 0);
    }

    #[tokio::test]
    async fn test_duration_sample_management() {
        let load_balancer = Arc::new(RwLock::new(LoadBalancer::new_for_test(TargetConfig {
            targets: vec![],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        })));

        let traffic_logger = Arc::new(TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: crate::config::LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        }));

        let metrics_collector = EnhancedMetricsCollector::new(
            load_balancer,
            traffic_logger,
            crate::config::MonitoringConfig {
                enabled: true,
                metrics_port: 9090,
                health_check_port: 8081,
                histogram_buckets: None,
                capacity: Default::default(),
            },
        );

        // Test duration recording and reset
        metrics_collector.record_request_duration(100.0).await;
        metrics_collector.record_request_duration(200.0).await;

        let summary_before = metrics_collector.get_metrics_summary().await;
        assert_eq!(summary_before.duration_samples_count, 2);

        metrics_collector.reset_duration_samples().await;

        let summary_after = metrics_collector.get_metrics_summary().await;
        assert_eq!(summary_after.duration_samples_count, 0);
    }
}