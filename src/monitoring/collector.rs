use std::sync::Arc;
use std::time::Instant;

use crate::balancer::LoadBalancer;
use crate::logger::TrafficLogger;

#[derive(Clone)]
pub struct MetricsCollector {
    start_time: Instant,
    load_balancer: Option<Arc<LoadBalancer>>,
    traffic_logger: Option<Arc<TrafficLogger>>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            load_balancer: None,
            traffic_logger: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_load_balancer(mut self, load_balancer: Arc<LoadBalancer>) -> Self {
        self.load_balancer = Some(load_balancer);
        self
    }

    #[allow(dead_code)]
    pub fn with_traffic_logger(mut self, traffic_logger: Arc<TrafficLogger>) -> Self {
        self.traffic_logger = Some(traffic_logger);
        self
    }

    pub async fn collect_metrics(&self) {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        metrics::gauge!("dispa_uptime_seconds").set(uptime_seconds as f64);

        if let Some(ref lb) = self.load_balancer {
            self.collect_load_balancer_metrics(lb).await;
        }

        if let Some(ref logger) = self.traffic_logger {
            self.collect_traffic_metrics(logger).await;
        }

        self.collect_system_metrics();
    }

    pub async fn collect_load_balancer_metrics(&self, load_balancer: &LoadBalancer) {
        let summary = load_balancer.get_summary().await;
        let health_status = load_balancer.get_health_status().await;
        let connection_stats = load_balancer.get_connection_stats().await;

        metrics::gauge!("dispa_targets_total").set(summary.total_targets as f64);
        metrics::gauge!("dispa_targets_healthy").set(summary.healthy_targets as f64);

        metrics::gauge!("dispa_active_connections_total")
            .set(summary.total_active_connections as f64);
        metrics::gauge!("dispa_requests_total").set(summary.total_requests as f64);
        metrics::gauge!("dispa_errors_total").set(summary.total_errors as f64);
        metrics::gauge!("dispa_error_rate_percent").set(summary.error_rate);

        for (target_name, health) in health_status {
            let labels = [("target", target_name.clone())];

            metrics::gauge!("dispa_target_healthy", &labels).set(if health.is_healthy {
                1.0
            } else {
                0.0
            });

            metrics::gauge!("dispa_target_consecutive_failures", &labels)
                .set(health.consecutive_failures as f64);

            if let Some(response_time) = health.response_time_ms {
                metrics::histogram!("dispa_target_health_check_duration_ms", &labels)
                    .record(response_time as f64);
            }
        }

        for (target_name, stats) in connection_stats {
            let labels = [("target", target_name.clone())];

            metrics::gauge!("dispa_target_active_connections", &labels)
                .set(stats.active_connections as f64);

            metrics::gauge!("dispa_target_requests_total", &labels)
                .set(stats.total_requests as f64);

            metrics::gauge!("dispa_target_errors_total", &labels).set(stats.total_errors as f64);

            metrics::gauge!("dispa_target_avg_response_time_ms", &labels)
                .set(stats.avg_response_time_ms);
        }
    }

    async fn collect_traffic_metrics(&self, traffic_logger: &TrafficLogger) {
        if let Ok(stats) = traffic_logger.get_traffic_stats(1).await {
            metrics::gauge!("dispa_traffic_requests_last_hour").set(stats.total_requests as f64);
            metrics::gauge!("dispa_traffic_errors_last_hour").set(stats.error_count as f64);
            metrics::gauge!("dispa_traffic_avg_duration_ms").set(stats.avg_duration_ms);
            metrics::gauge!("dispa_traffic_unique_clients_last_hour")
                .set(stats.unique_clients as f64);
            metrics::gauge!("dispa_traffic_bytes_total").set(stats.total_bytes as f64);
        }

        if let Ok(target_stats) = traffic_logger.get_traffic_by_target(1).await {
            for stat in target_stats {
                let labels = [("target", stat.target.clone())];

                metrics::gauge!("dispa_target_traffic_requests_last_hour", &labels)
                    .set(stat.total_requests as f64);

                metrics::gauge!("dispa_target_traffic_errors_last_hour", &labels)
                    .set(stat.error_count as f64);

                metrics::gauge!("dispa_target_traffic_avg_duration_ms", &labels)
                    .set(stat.avg_duration_ms);
            }
        }
    }

    fn collect_system_metrics(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
                for line in contents.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(value_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = value_str.parse::<f64>() {
                                metrics::gauge!("dispa_memory_usage_bytes").set(kb * 1024.0);
                            }
                        }
                        break;
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            metrics::gauge!("dispa_memory_usage_bytes").set(50_000_000.0);
        }
    }

    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    pub fn load_balancer(&self) -> &Option<Arc<LoadBalancer>> {
        &self.load_balancer
    }

    pub fn traffic_logger(&self) -> &Option<Arc<TrafficLogger>> {
        &self.traffic_logger
    }
}
