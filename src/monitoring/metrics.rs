use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;
use hyper::Server;
use hyper::{Body, Method, Request, Response, StatusCode};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::balancer::LoadBalancer;
use crate::config::MonitoringConfig;
use crate::logger::TrafficLogger;
// use crate::proxy::cached_handler::CachedProxyHandler;

#[derive(Clone)]
pub struct MetricsCollector {
    start_time: Instant,
    load_balancer: Option<Arc<LoadBalancer>>,
    traffic_logger: Option<Arc<TrafficLogger>>,
    // cached_handler: Option<Arc<CachedProxyHandler>>,
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
            // cached_handler: None,
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

    // pub fn with_cached_handler(mut self, cached_handler: Arc<CachedProxyHandler>) -> Self {
    //     self.cached_handler = Some(cached_handler);
    //     self
    // }

    pub async fn collect_metrics(&self) {
        // Record uptime
        let uptime_seconds = self.start_time.elapsed().as_secs();
        metrics::gauge!("dispa_uptime_seconds").set(uptime_seconds as f64);

        // Collect load balancer metrics
        if let Some(ref lb) = self.load_balancer {
            self.collect_load_balancer_metrics(lb).await;
        }

        // Collect traffic statistics
        if let Some(ref logger) = self.traffic_logger {
            self.collect_traffic_metrics(logger).await;
        }

        // Collect cache statistics
        // if let Some(ref handler) = self.cached_handler {
        //     self.collect_cache_metrics(handler).await;
        // }

        // Record memory usage
        self.collect_system_metrics();
    }

    async fn collect_load_balancer_metrics(&self, load_balancer: &LoadBalancer) {
        let summary = load_balancer.get_summary().await;
        let health_status = load_balancer.get_health_status().await;
        let connection_stats = load_balancer.get_connection_stats().await;

        // Target health metrics
        metrics::gauge!("dispa_targets_total").set(summary.total_targets as f64);
        metrics::gauge!("dispa_targets_healthy").set(summary.healthy_targets as f64);

        // Connection metrics
        metrics::gauge!("dispa_active_connections_total")
            .set(summary.total_active_connections as f64);
        metrics::gauge!("dispa_requests_total").set(summary.total_requests as f64);
        metrics::gauge!("dispa_errors_total").set(summary.total_errors as f64);
        metrics::gauge!("dispa_error_rate_percent").set(summary.error_rate);

        // Per-target metrics
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

        // Per-target connection metrics
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
        // Get traffic stats for the last hour
        if let Ok(stats) = traffic_logger.get_traffic_stats(1).await {
            metrics::gauge!("dispa_traffic_requests_last_hour").set(stats.total_requests as f64);
            metrics::gauge!("dispa_traffic_errors_last_hour").set(stats.error_count as f64);
            metrics::gauge!("dispa_traffic_avg_duration_ms").set(stats.avg_duration);
            metrics::gauge!("dispa_traffic_unique_clients_last_hour")
                .set(stats.unique_clients as f64);
            metrics::gauge!("dispa_traffic_bytes_total").set(stats.total_bytes as f64);
        }

        // Get per-target traffic stats
        if let Ok(target_stats) = traffic_logger.get_traffic_by_target(1).await {
            for stat in target_stats {
                let labels = [("target", stat.target.clone())];

                metrics::gauge!("dispa_target_traffic_requests_last_hour", &labels)
                    .set(stat.request_count as f64);

                metrics::gauge!("dispa_target_traffic_errors_last_hour", &labels)
                    .set(stat.error_count as f64);

                metrics::gauge!("dispa_target_traffic_avg_duration_ms", &labels)
                    .set(stat.avg_duration);
            }
        }
    }

    /*
    async fn collect_cache_metrics(&self, cached_handler: &CachedProxyHandler) {
        if let Some(cache_stats) = cached_handler.get_cache_stats().await {
            // Cache hit/miss metrics
            metrics::gauge!("dispa_cache_hits_total").set(cache_stats.hits as f64);
            metrics::gauge!("dispa_cache_misses_total").set(cache_stats.misses as f64);
            metrics::gauge!("dispa_cache_hit_ratio_percent").set(cache_stats.hit_ratio);

            // Cache operations metrics
            metrics::gauge!("dispa_cache_stores_total").set(cache_stats.stores as f64);
            metrics::gauge!("dispa_cache_evictions_total").set(cache_stats.evictions as f64);

            // Cache size metrics
            metrics::gauge!("dispa_cache_size_bytes").set(cache_stats.total_size as f64);
            metrics::gauge!("dispa_cache_entry_count").set(cache_stats.entry_count as f64);

            debug!(
                "Cache metrics - hits: {}, misses: {}, hit_ratio: {:.2}%, size: {} bytes, entries: {}",
                cache_stats.hits,
                cache_stats.misses,
                cache_stats.hit_ratio,
                cache_stats.total_size,
                cache_stats.entry_count
            );
        }
    }
    */

    fn collect_system_metrics(&self) {
        // Get memory usage (simplified - in production you'd use a proper system metrics library)
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

        // For other platforms, we can estimate based on allocated memory
        #[cfg(not(target_os = "linux"))]
        {
            // Rough estimation - in production use proper system metrics
            metrics::gauge!("dispa_memory_usage_bytes").set(50_000_000.0); // ~50MB estimate
        }
    }
}

static METRICS_COLLECTOR: once_cell::sync::OnceCell<Arc<RwLock<MetricsCollector>>> =
    once_cell::sync::OnceCell::new();

#[allow(dead_code)]
pub fn init_metrics_collector(collector: MetricsCollector) {
    let _ = METRICS_COLLECTOR.set(Arc::new(RwLock::new(collector)));
}

pub async fn get_metrics_collector() -> Option<Arc<RwLock<MetricsCollector>>> {
    METRICS_COLLECTOR.get().cloned()
}

pub async fn run_metrics_server(config: MonitoringConfig) -> Result<()> {
    if !config.enabled {
        info!("Monitoring is disabled");
        return Ok(());
    }

    // Initialize Prometheus metrics exporter with custom buckets
    // Build the builder via Result-chaining to avoid move-after-error issues
    let mut has_log_write_buckets = false;
    if let Some(list) = &config.histogram_buckets {
        has_log_write_buckets = list
            .iter()
            .any(|i| i.metric == "dispa_log_write_duration_ms");
    }

    let mut res: Result<PrometheusBuilder, metrics_exporter_prometheus::BuildError> =
        Ok(PrometheusBuilder::new());

    if let Some(list) = &config.histogram_buckets {
        for item in list {
            let metric = item.metric.clone();
            // Convert ms->s when metric uses seconds to keep units consistent
            let buckets = if metric.ends_with("_seconds") {
                item.buckets_ms.iter().map(|v| v / 1000.0).collect::<Vec<f64>>()
            } else {
                item.buckets_ms.clone()
            };
            res = res.and_then(|b| b.set_buckets_for_metric(Matcher::Full(metric), &buckets));
        }
    }

    if !has_log_write_buckets {
        const DEFAULT_LOG_WRITE_MS_BUCKETS: &[f64] = &[
            0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0,
            5000.0,
        ];
        res = res.and_then(|b| {
            b.set_buckets_for_metric(
                Matcher::Full("dispa_log_write_duration_ms".to_string()),
                DEFAULT_LOG_WRITE_MS_BUCKETS,
            )
        });
    }

    // Defaults for other histograms if not provided
    // dispa_target_health_check_duration_ms (ms)
    const DEFAULT_HC_MS_BUCKETS: &[f64] = &[
        1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
    ];
    res = res.and_then(|b| {
        b.set_buckets_for_metric(
            Matcher::Full("dispa_target_health_check_duration_ms".to_string()),
            DEFAULT_HC_MS_BUCKETS,
        )
    });

    // dispa_request_duration_seconds (seconds)
    const DEFAULT_REQ_S_BUCKETS: &[f64] = &[
        0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];
    res = res.and_then(|b| {
        b.set_buckets_for_metric(
            Matcher::Full("dispa_request_duration_seconds".to_string()),
            DEFAULT_REQ_S_BUCKETS,
        )
    });

    let builder = match res {
        Ok(b) => b,
        Err(e) => {
            debug!("Failed to apply histogram buckets: {} (using defaults)", e);
            PrometheusBuilder::new()
        }
    };
    if let Err(e) = builder.install() {
        // In hot-reload scenario exporter may already be installed; ignore
        debug!("Prometheus exporter install skipped: {}", e);
    }

    // Register custom metrics
    register_metrics();

    // Bind strategy: if port is 0 (ephemeral, commonly used in tests), prefer loopback to avoid
    // sandbox/environment restrictions; otherwise, bind to all interfaces as configured.
    let metrics_addr = if config.metrics_port == 0 {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], config.metrics_port))
    };
    let health_addr = if config.health_check_port == 0 {
        SocketAddr::from(([127, 0, 0, 1], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], config.health_check_port))
    };

    // Start metrics collection loop
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            if let Some(collector) = get_metrics_collector().await {
                let collector = collector.read().await;
                collector.collect_metrics().await;
            }
        }
    });

    // Start metrics server
    let metrics_service = make_service_fn(move |conn: &AddrStream| {
        let remote = conn.remote_addr();
        async move {
            Ok::<_, Infallible>(service_fn(move |mut req| {
                req.extensions_mut().insert(remote);
                handle_metrics(req)
            }))
        }
    });

    let metrics_server = Server::bind(&metrics_addr).serve(metrics_service);

    // Start health check server
    let health_service = make_service_fn(|conn: &AddrStream| {
        let remote = conn.remote_addr();
        let svc = service_fn(move |mut req| {
            req.extensions_mut().insert(remote);
            handle_health(req)
        });
        std::future::ready(Ok::<_, Infallible>(svc))
    });

    let health_server = Server::bind(&health_addr).serve(health_service);

    info!("Metrics server listening on {}", metrics_addr);
    info!("Health check server listening on {}", health_addr);

    // Run both servers concurrently
    tokio::select! {
        result = metrics_server => {
            if let Err(e) = result {
                error!("Metrics server error: {}", e);
            }
        }
        result = health_server => {
            if let Err(e) = result {
                error!("Health check server error: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_metrics(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // Admin endpoints
    if req.uri().path().starts_with("/admin") {
        return Ok(match crate::monitoring::admin::handle_admin(req).await {
            Ok(resp) => resp,
            Err(_) => Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Admin error")).unwrap(),
        });
    }
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            // Export Prometheus metrics - fallback to basic metrics for now
            let metrics = generate_fallback_metrics().await;

            Ok(Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Body::from(metrics))
                .unwrap())
        }
        (&Method::GET, "/metrics/json") => {
            // JSON format metrics for easier consumption
            let metrics_json = generate_json_metrics().await;

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(metrics_json))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "Not found. Available endpoints: /metrics, /metrics/json",
            ))
            .unwrap()),
    }
}

async fn handle_health(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") | (&Method::GET, "/") => {
            let health_response = json!({
                "status": "healthy",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "uptime_seconds": get_uptime_seconds().await,
                "version": env!("CARGO_PKG_VERSION")
            });

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(health_response.to_string()))
                .unwrap())
        }
        (&Method::GET, "/ready") => {
            // Readiness check - more strict than health check
            let is_ready = check_readiness().await;

            let status_code = if is_ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };

            let response = json!({
                "status": if is_ready { "ready" } else { "not_ready" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            Ok(Response::builder()
                .status(status_code)
                .header("Content-Type", "application/json")
                .body(Body::from(response.to_string()))
                .unwrap())
        }
        (&Method::GET, "/metrics") => {
            // Health endpoint that returns basic metrics
            let metrics = json!({
                "uptime_seconds": get_uptime_seconds().await,
                "healthy_targets": get_healthy_targets_count().await,
                "total_requests": get_total_requests().await,
                "error_rate": get_error_rate().await
            });

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(metrics.to_string()))
                .unwrap())
        }
        // No cluster endpoints when clustering is disabled/removed
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "Not found. Available endpoints: /health, /ready, /metrics",
            ))
            .unwrap()),
    }
}

async fn generate_fallback_metrics() -> String {
    let uptime = get_uptime_seconds().await;
    let healthy_targets = get_healthy_targets_count().await;
    let total_requests = get_total_requests().await;

    format!(
        "# HELP dispa_uptime_seconds Total uptime in seconds\n\
         # TYPE dispa_uptime_seconds gauge\n\
         dispa_uptime_seconds {}\n\
         # HELP dispa_targets_healthy Number of healthy targets\n\
         # TYPE dispa_targets_healthy gauge\n\
         dispa_targets_healthy {}\n\
         # HELP dispa_requests_total Total requests processed\n\
         # TYPE dispa_requests_total counter\n\
         dispa_requests_total {}\n",
        uptime, healthy_targets, total_requests
    )
}

async fn generate_json_metrics() -> String {
    // Optional traffic overview via collector.logger
    let (avg_ms, bytes_total, unique_clients) = get_traffic_overview().await;

    // Optional per-target stats
    let targets_by_traffic = get_targets_by_traffic().await;

    let metrics = json!({
        "uptime_seconds": get_uptime_seconds().await,
        "targets": {
            "healthy": get_healthy_targets_count().await,
            "total": get_total_targets_count().await
        },
        "requests": {
            "total": get_total_requests().await,
            "errors": get_total_errors().await,
            "error_rate": get_error_rate().await
        },
        "connections": {
            "active": get_active_connections().await
        },
        "traffic": {
            "avg_duration_ms": avg_ms,
            "bytes_total": bytes_total,
            "unique_clients": unique_clients
        },
        "targets_by_traffic": targets_by_traffic,
        "cache": {
            "hits": 0.0, // get_cache_hits().await,
            "misses": 0.0, // get_cache_misses().await,
            "hit_ratio_percent": 0.0, // get_cache_hit_ratio().await,
            "size_bytes": 0.0, // get_cache_size().await,
            "entry_count": 0.0 // get_cache_entry_count().await
        },
        "memory": {
            "usage_bytes": get_memory_usage().await
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    metrics.to_string()
}

async fn get_traffic_overview() -> (f64, f64, f64) {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref logger) = collector.traffic_logger {
            if let Ok(s) = logger.get_traffic_stats(1).await {
                return (s.avg_duration, s.total_bytes as f64, s.unique_clients as f64);
            }
        }
    }
    (0.0, 0.0, 0.0)
}

async fn get_targets_by_traffic() -> serde_json::Value {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref logger) = collector.traffic_logger {
            if let Ok(list) = logger.get_traffic_by_target(1).await {
                let arr: Vec<serde_json::Value> = list.into_iter().map(|t| json!({
                    "target": t.target,
                    "request_count": t.request_count,
                    "avg_duration_ms": t.avg_duration,
                    "error_count": t.error_count,
                    "bytes_total": t.total_bytes,
                })).collect();
                return json!(arr);
            }
        }
    }
    json!([])
}

async fn get_uptime_seconds() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        collector.start_time.elapsed().as_secs_f64()
    } else {
        0.0
    }
}

async fn check_readiness() -> bool {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;

        // Check if we have at least one healthy target
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.healthy_targets > 0
        } else {
            true // If no load balancer, assume ready
        }
    } else {
        false
    }
}

async fn get_healthy_targets_count() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.healthy_targets as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_total_targets_count() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.total_targets as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_total_requests() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.total_requests as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_total_errors() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.total_errors as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_error_rate() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.error_rate
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_active_connections() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer {
            let summary = lb.get_summary().await;
            summary.total_active_connections as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

async fn get_memory_usage() -> f64 {
    // Simplified memory usage - in production use proper system metrics
    50_000_000.0 // 50MB estimate
}

/*
async fn get_cache_hits() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref handler) = collector.cached_handler {
            if let Some(stats) = handler.get_cache_stats().await {
                return stats.hits as f64;
            }
        }
    }
    0.0
}

async fn get_cache_misses() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref handler) = collector.cached_handler {
            if let Some(stats) = handler.get_cache_stats().await {
                return stats.misses as f64;
            }
        }
    }
    0.0
}

async fn get_cache_hit_ratio() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref handler) = collector.cached_handler {
            if let Some(stats) = handler.get_cache_stats().await {
                return stats.hit_ratio;
            }
        }
    }
    0.0
}

async fn get_cache_size() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref handler) = collector.cached_handler {
            if let Some(stats) = handler.get_cache_stats().await {
                return stats.total_size as f64;
            }
        }
    }
    0.0
}

async fn get_cache_entry_count() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref handler) = collector.cached_handler {
            if let Some(stats) = handler.get_cache_stats().await {
                return stats.entry_count as f64;
            }
        }
    }
    0.0
}
*/

fn register_metrics() {
    // Counter metrics
    let _ = metrics::counter!("dispa_requests_total");
    let _ = metrics::counter!("dispa_errors_total");
    let _ = metrics::counter!("dispa_target_requests_total");
    let _ = metrics::counter!("dispa_target_errors_total");

    // Gauge metrics
    let _ = metrics::gauge!("dispa_uptime_seconds");
    let _ = metrics::gauge!("dispa_targets_total");
    let _ = metrics::gauge!("dispa_targets_healthy");
    let _ = metrics::gauge!("dispa_target_healthy");
    let _ = metrics::gauge!("dispa_active_connections_total");
    let _ = metrics::gauge!("dispa_target_active_connections");
    let _ = metrics::gauge!("dispa_memory_usage_bytes");
    let _ = metrics::gauge!("dispa_error_rate_percent");
    let _ = metrics::gauge!("dispa_target_consecutive_failures");
    let _ = metrics::gauge!("dispa_target_avg_response_time_ms");

    // Histogram metrics
    let _ = metrics::histogram!("dispa_request_duration_seconds");
    let _ = metrics::histogram!("dispa_target_health_check_duration_ms");

    // Traffic metrics
    let _ = metrics::gauge!("dispa_traffic_requests_last_hour");
    let _ = metrics::gauge!("dispa_traffic_errors_last_hour");
    let _ = metrics::gauge!("dispa_traffic_avg_duration_ms");
    let _ = metrics::gauge!("dispa_traffic_unique_clients_last_hour");
    let _ = metrics::gauge!("dispa_traffic_bytes_total");
    let _ = metrics::gauge!("dispa_target_traffic_requests_last_hour");
    let _ = metrics::gauge!("dispa_target_traffic_errors_last_hour");
    let _ = metrics::gauge!("dispa_target_traffic_avg_duration_ms");

    // Cache metrics
    let _ = metrics::gauge!("dispa_cache_hits_total");
    let _ = metrics::gauge!("dispa_cache_misses_total");
    let _ = metrics::gauge!("dispa_cache_hit_ratio_percent");
    let _ = metrics::gauge!("dispa_cache_stores_total");
    let _ = metrics::gauge!("dispa_cache_evictions_total");
    let _ = metrics::gauge!("dispa_cache_size_bytes");
    let _ = metrics::gauge!("dispa_cache_entry_count");

    info!("Prometheus metrics registered successfully");
}

// Helper function to record request metrics
#[allow(dead_code)]
pub fn record_request_metric(method: &str, status_code: u16, duration: Duration, target: &str) {
    // Record basic metrics without labels for now to avoid lifetime issues
    metrics::counter!("dispa_requests_total").increment(1);

    if status_code >= 400 {
        metrics::counter!("dispa_errors_total").increment(1);
    }

    metrics::histogram!("dispa_request_duration_seconds").record(duration.as_secs_f64());

    // Log the metrics for debugging
    debug!(
        "Recorded metrics: method={}, status={}, duration={:.3}s, target={}",
        method,
        status_code,
        duration.as_secs_f64(),
        target
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::load_balancer::{ConnectionStats, LoadBalancer};
    use crate::config::{
        HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, MonitoringConfig, Target,
        TargetConfig,
    };
    use crate::config::{LoggingConfig, LoggingType};
    use crate::logger::TrafficLogger;
    use std::time::Duration;
    use tokio::time::sleep;

    fn create_test_target(name: &str) -> Target {
        Target {
            name: name.to_string(),
            url: format!("http://test-{}.com", name),
            weight: Some(1),
            timeout: Some(30),
        }
    }

    fn create_test_load_balancer() -> LoadBalancer {
        let targets = vec![create_test_target("server1"), create_test_target("server2")];

        let config = TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false, // Disable for tests
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        };

        LoadBalancer::new_for_test(config)
    }

    fn create_test_traffic_logger() -> TrafficLogger {
        let config = LoggingConfig {
            enabled: false, // Disable for tests
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        };
        TrafficLogger::new(config)
    }

    #[tokio::test]
    async fn test_metrics_collector_creation() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let collector = MetricsCollector::new();
            assert!(collector.load_balancer.is_none());
            assert!(collector.traffic_logger.is_none());
            assert!(collector.start_time.elapsed().as_millis() < 100);
        }).await.expect("test_metrics_collector_creation timed out");
    }

    #[tokio::test]
    async fn test_metrics_collector_with_load_balancer() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let collector = MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer));
            assert!(collector.load_balancer.is_some());
            assert!(collector.traffic_logger.is_none());
        }).await.expect("test_metrics_collector_with_load_balancer timed out");
    }

    #[tokio::test]
    async fn test_metrics_collector_with_traffic_logger() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let traffic_logger = Arc::new(create_test_traffic_logger());
            let collector = MetricsCollector::new().with_traffic_logger(Arc::clone(&traffic_logger));
            assert!(collector.load_balancer.is_none());
            assert!(collector.traffic_logger.is_some());
        }).await.expect("test_metrics_collector_with_traffic_logger timed out");
    }

    #[tokio::test]
    async fn test_metrics_collector_with_both_components() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let traffic_logger = Arc::new(create_test_traffic_logger());
            let collector = MetricsCollector::new()
                .with_load_balancer(Arc::clone(&load_balancer))
                .with_traffic_logger(Arc::clone(&traffic_logger));
            assert!(collector.load_balancer.is_some());
            assert!(collector.traffic_logger.is_some());
        }).await.expect("test_metrics_collector_with_both_components timed out");
    }

    #[tokio::test]
    async fn test_collect_metrics_basic() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let collector = MetricsCollector::new();
            collector.collect_metrics().await;
            let uptime = collector.start_time.elapsed().as_secs();
            assert!(uptime < 5);
        }).await.expect("test_collect_metrics_basic timed out");
    }

    #[tokio::test]
    async fn test_collect_metrics_with_load_balancer() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let load_balancer = Arc::new(create_test_load_balancer());
        let collector = MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer));

        // Add some test connection stats
        load_balancer
            .set_connection_stats(
                "server1",
                ConnectionStats {
                    active_connections: 5,
                    total_requests: 100,
                    total_errors: 2,
                    last_request: Some(std::time::Instant::now()),
                    avg_response_time_ms: 150.0,
                },
            )
            .await;

        load_balancer
            .set_connection_stats(
                "server2",
                ConnectionStats {
                    active_connections: 3,
                    total_requests: 80,
                    total_errors: 1,
                    last_request: Some(std::time::Instant::now()),
                    avg_response_time_ms: 120.0,
                },
            )
            .await;

        // This should collect load balancer metrics without panicking
        collector.collect_metrics().await;
        }).await.expect("test_collect_metrics_with_load_balancer timed out");
    }

    #[tokio::test]
    async fn test_collect_load_balancer_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let load_balancer = Arc::new(create_test_load_balancer());
        let collector = MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer));

        // Add test data
        load_balancer
            .set_connection_stats(
                "server1",
                ConnectionStats {
                    active_connections: 10,
                    total_requests: 500,
                    total_errors: 5,
                    last_request: Some(std::time::Instant::now()),
                    avg_response_time_ms: 200.0,
                },
            )
            .await;

        // Test the specific load balancer metrics collection
        collector
            .collect_load_balancer_metrics(&load_balancer)
            .await;

        // Verify the load balancer summary is accessible
        let summary = load_balancer.get_summary().await;
        assert_eq!(summary.total_targets, 2);
        assert_eq!(summary.total_active_connections, 10);
        assert_eq!(summary.total_requests, 500);
        assert_eq!(summary.total_errors, 5);
        }).await.expect("test_collect_load_balancer_metrics timed out");
    }

    #[tokio::test]
    async fn test_collect_system_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let collector = MetricsCollector::new();
            collector.collect_system_metrics();
        }).await.expect("test_collect_system_metrics timed out");
    }

    #[tokio::test]
    async fn test_uptime_measurement() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let collector = MetricsCollector::new();
            sleep(Duration::from_millis(10)).await;
            let uptime_before = collector.start_time.elapsed();
            sleep(Duration::from_millis(10)).await;
            let uptime_after = collector.start_time.elapsed();
            assert!(uptime_after > uptime_before);
            assert!(uptime_after.as_millis() >= 20);
        }).await.expect("test_uptime_measurement timed out");
    }

    #[tokio::test]
    async fn test_record_request_metric() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            record_request_metric("GET", 200, Duration::from_millis(150), "backend1");
            record_request_metric("POST", 500, Duration::from_millis(300), "backend2");
            record_request_metric("PUT", 404, Duration::from_millis(50), "backend1");
            // These calls should not panic and should record metrics
            // The actual metric values are handled by the metrics crate
        }).await.expect("test_record_request_metric timed out");
    }

    #[tokio::test]
    async fn test_monitoring_config_creation() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let config = MonitoringConfig {
            enabled: true,
            metrics_port: 9090,
            health_check_port: 8081,
            histogram_buckets: None,
            capacity: Default::default(),
        };

        assert!(config.enabled);
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.health_check_port, 8081);
        }).await.expect("test_monitoring_config_creation timed out");
    }

    #[tokio::test]
    async fn test_clone_metrics_collector() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let original = MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer));
            let cloned = original.clone();
            assert!(cloned.load_balancer.is_some());
            assert!(cloned.traffic_logger.is_none());
            original.collect_metrics().await;
            cloned.collect_metrics().await;
        }).await.expect("test_clone_metrics_collector timed out");
    }

    #[tokio::test]
    async fn test_metrics_collection_with_empty_stats() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let collector = MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer));
            collector.collect_metrics().await;
            let summary = load_balancer.get_summary().await;
            assert_eq!(summary.total_targets, 2);
            assert!(summary.healthy_targets <= 2);
            assert_eq!(summary.total_active_connections, 0);
            assert_eq!(summary.total_requests, 0);
            assert_eq!(summary.total_errors, 0);
        }).await.expect("test_metrics_collection_with_empty_stats timed out");
    }

    #[tokio::test]
    async fn test_metrics_collection_performance() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let traffic_logger = Arc::new(create_test_traffic_logger());
            let collector = MetricsCollector::new()
                .with_load_balancer(Arc::clone(&load_balancer))
                .with_traffic_logger(Arc::clone(&traffic_logger));
            for i in 0..5 {
                load_balancer
                    .set_connection_stats(
                        &format!("server{}", i),
                        ConnectionStats {
                            active_connections: i as u32,
                            total_requests: (i * 100) as u64,
                            total_errors: i as u64,
                            last_request: Some(std::time::Instant::now()),
                            avg_response_time_ms: (i * 50) as f64,
                        },
                    )
                    .await;
            }
            let start = std::time::Instant::now();
            for _ in 0..10 { collector.collect_metrics().await; }
            let duration = start.elapsed();
            assert!(duration.as_millis() < 1000, "Metrics collection took too long: {:?}", duration);
        }).await.expect("test_metrics_collection_performance timed out");
    }

    #[tokio::test]
    async fn test_request_metric_recording_edge_cases() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
            let status_codes = [200, 201, 301, 400, 401, 404, 500, 502, 503];
            let durations = [Duration::from_millis(1), Duration::from_millis(100), Duration::from_secs(1), Duration::from_secs(5)];
            for method in &methods { for &status_code in &status_codes { for &duration in &durations { record_request_metric(method, status_code, duration, "test_target"); } } }
        }).await.expect("test_request_metric_recording_edge_cases timed out");
    }

    #[tokio::test]
    async fn test_concurrent_metrics_collection() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let collector = Arc::new(MetricsCollector::new().with_load_balancer(Arc::clone(&load_balancer)));
            let mut handles = Vec::new();
            for i in 0..5 {
                let collector_clone = Arc::clone(&collector);
                let handle = tokio::spawn(async move {
                    for _ in 0..10 {
                        collector_clone.collect_metrics().await;
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    i
                });
                handles.push(handle);
            }
            for handle in handles {
                let result = handle.await.unwrap();
                assert!(result < 5);
            }
        }).await.expect("test_concurrent_metrics_collection timed out");
    }

    #[tokio::test]
    async fn test_metrics_collector_builder_pattern() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let load_balancer = Arc::new(create_test_load_balancer());
            let traffic_logger = Arc::new(create_test_traffic_logger());
            let collector = MetricsCollector::new()
                .with_load_balancer(Arc::clone(&load_balancer))
                .with_traffic_logger(Arc::clone(&traffic_logger));
            assert!(collector.load_balancer.is_some());
            assert!(collector.traffic_logger.is_some());
            let collector2 = MetricsCollector::new()
                .with_traffic_logger(Arc::clone(&traffic_logger))
                .with_load_balancer(Arc::clone(&load_balancer));
            assert!(collector2.load_balancer.is_some());
            assert!(collector2.traffic_logger.is_some());
        }).await.expect("test_metrics_collector_builder_pattern timed out");
    }

    #[tokio::test]
    async fn test_handle_metrics_prometheus_endpoint() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/metrics").body(Body::empty()).unwrap();
            let response = handle_metrics(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/plain; version=0.0.4");
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert!(!body_str.is_empty());
            assert!(body_str.contains("dispa_uptime_seconds"));
            assert!(body_str.contains("dispa_targets_healthy"));
            assert!(body_str.contains("dispa_requests_total"));
        }).await.expect("test_handle_metrics_prometheus_endpoint timed out");
    }

    #[tokio::test]
    async fn test_handle_metrics_json_endpoint() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/metrics/json").body(Body::empty()).unwrap();
            let response = handle_metrics(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert!(!body_str.is_empty());
            let json_value: serde_json::Value = serde_json::from_str(&body_str).expect("Response should be valid JSON");
            assert!(json_value.is_object());
            assert!(json_value.get("uptime_seconds").is_some());
            assert!(json_value.get("targets").is_some());
        }).await.expect("test_handle_metrics_json_endpoint timed out");
    }

    #[tokio::test]
    async fn test_handle_metrics_json_rich_fields() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/metrics/json").body(Body::empty()).unwrap();
            let response = handle_metrics(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&body_str).unwrap();
            assert!(v.get("connections").and_then(|x| x.get("active")).is_some());
            assert!(v.get("requests").and_then(|x| x.get("error_rate")).is_some());
        }).await.expect("test_handle_metrics_json_rich_fields timed out");
    }

    #[tokio::test]
    async fn test_metrics_json_numeric_consistency_with_mocked_lb() {
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
        // Build a load balancer with two targets and set known stats
        let lb = Arc::new(create_test_load_balancer());
        // names from create_test_load_balancer: server1, server2
        lb.set_connection_stats(
            "server1",
            ConnectionStats { active_connections: 2, total_requests: 100, total_errors: 5, last_request: None, avg_response_time_ms: 0.0 }
        ).await;
        lb.set_connection_stats(
            "server2",
            ConnectionStats { active_connections: 3, total_requests: 50, total_errors: 2, last_request: None, avg_response_time_ms: 0.0 }
        ).await;

        // Inject health status: 1 healthy, 1 unhealthy
        let mut map = std::collections::HashMap::new();
        map.insert("server1".to_string(), crate::balancer::health_check::HealthStatus{ is_healthy: true, ..Default::default() });
        map.insert("server2".to_string(), crate::balancer::health_check::HealthStatus{ is_healthy: false, ..Default::default() });
        lb.health_checker().set_health_status_for_test(map).await;

        // Inject collector
        let collector = MetricsCollector::new().with_load_balancer(Arc::clone(&lb));
        super::init_metrics_collector(collector);

        // Optional: attach traffic logger with DB and insert rows for per-target stats
        let cfg = crate::config::LoggingConfig{ enabled: true, log_type: crate::config::LoggingType::Database, database: Some(crate::config::DatabaseConfig{ url: "sqlite::memory:".into(), max_connections: Some(5), connection_timeout: Some(30)}), file: None, retention_days: Some(7)};
        let logger = crate::logger::TrafficLogger::new(cfg);
        logger.initialize_shared().await.unwrap();
        // We can't call log_request with sizes; simulate via DB insert
        // Note: in-memory DB scope is per-connection pool; use logger.get_traffic_by_target to avoid extra connections
        {
            // This section can't insert bytes via public API; bytes_total will be 0; we still assert structure and non-negative values below
        }
        // Inject logger
        let coll = get_metrics_collector().await.unwrap();
        coll.write().await.traffic_logger = Some(Arc::new(logger));

        // Request /metrics/json
        let req = hyper::Request::builder().method(hyper::Method::GET).uri("/metrics/json").body(hyper::Body::empty()).unwrap();
        let response = handle_metrics(req).await.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Compute expectations
        let total_req = 150.0;
        let total_err = 7.0;
        let err_rate = (total_err / total_req) * 100.0;
        let active = 5.0;

        // Assertions for core numbers
        assert!((v["requests"]["total"].as_f64().unwrap_or(-1.0) - total_req).abs() < 1e-6);
        assert!((v["requests"]["errors"].as_f64().unwrap_or(-1.0) - total_err).abs() < 1e-6);
        assert!((v["requests"]["error_rate"].as_f64().unwrap_or(-1.0) - err_rate).abs() < 1e-6);
        assert!((v["connections"]["active"].as_f64().unwrap_or(-1.0) - active).abs() < 1e-6);
        // Healthy targets: expect 1 ; total targets == 2
        let total_targets = v["targets"]["total"].as_f64().unwrap_or(0.0);
        let healthy = v["targets"]["healthy"].as_f64().unwrap_or(-1.0);
        assert_eq!(total_targets as i32, 2);
        assert_eq!(healthy as i32, 1);
        // Memory usage present and positive
        assert!(v["memory"]["usage_bytes"].as_f64().unwrap_or(0.0) > 0.0);
        // Uptime > 0
        assert!(v["uptime_seconds"].as_f64().unwrap_or(0.0) >= 0.0);
        // Traffic fields exist and non-negative
        assert!(v["traffic"]["avg_duration_ms"].as_f64().unwrap_or(-1.0) >= 0.0);
        assert!(v["traffic"]["bytes_total"].as_f64().unwrap_or(-1.0) >= 0.0);
        assert!(v["traffic"]["unique_clients"].as_f64().unwrap_or(-1.0) >= 0.0);
        // Per-target list present
        assert!(v["targets_by_traffic"].is_array());
        }).await.expect("test_metrics_json_numeric_consistency_with_mocked_lb timed out");
    }

    #[tokio::test]
    async fn test_handle_metrics_not_found() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/unknown").body(Body::empty()).unwrap();
            let response = handle_metrics(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            assert!(body_str.contains("Not found"));
            assert!(body_str.contains("/metrics"));
        }).await.expect("test_handle_metrics_not_found timed out");
    }

    #[tokio::test]
    async fn test_handle_metrics_wrong_method() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::POST).uri("/metrics").body(Body::empty()).unwrap();
            let response = handle_metrics(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
        }).await.expect("test_handle_metrics_wrong_method timed out");
    }

    #[tokio::test]
    async fn test_handle_health_endpoint() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/health").body(Body::empty()).unwrap();
            let response = handle_health(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            let json_value: serde_json::Value = serde_json::from_str(&body_str).expect("Health response should be valid JSON");
            assert_eq!(json_value["status"], "healthy");
            assert!(json_value.get("timestamp").is_some());
            assert!(json_value.get("uptime_seconds").is_some());
            assert!(json_value.get("version").is_some());
        }).await.expect("test_handle_health_endpoint timed out");
    }

    #[tokio::test]
    async fn test_handle_health_root_endpoint() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/").body(Body::empty()).unwrap();
            let response = handle_health(req).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
        }).await.expect("test_handle_health_root_endpoint timed out");
    }

    #[tokio::test]
    async fn test_handle_health_ready_endpoint() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use hyper::{Body, Method, Request};
            let req = Request::builder().method(Method::GET).uri("/ready").body(Body::empty()).unwrap();
            let response = handle_health(req).await.unwrap();
            assert!(response.status() == hyper::StatusCode::OK || response.status() == hyper::StatusCode::SERVICE_UNAVAILABLE);
            let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
            let json_value: serde_json::Value = serde_json::from_str(&body_str).expect("Ready response should be valid JSON");
            assert!(json_value.get("ready").is_some() || json_value.get("status").is_some());
            assert!(json_value.get("timestamp").is_some());
        }).await.expect("test_handle_health_ready_endpoint timed out");
    }

    #[tokio::test]
    async fn test_generate_fallback_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let metrics = generate_fallback_metrics().await;
            assert!(!metrics.is_empty());
            assert!(metrics.contains("dispa_uptime_seconds"));
            assert!(metrics.contains("dispa_targets_healthy"));
            assert!(metrics.contains("dispa_requests_total"));
            let lines: Vec<&str> = metrics.lines().collect();
            let metric_lines: Vec<&str> = lines.iter().filter(|line| !line.starts_with('#') && !line.is_empty()).copied().collect();
            assert!(!metric_lines.is_empty());
        }).await.expect("test_generate_fallback_metrics timed out");
    }

    #[tokio::test]
    async fn test_generate_json_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let metrics = generate_json_metrics().await;
            assert!(!metrics.is_empty());
            let json_value: serde_json::Value = serde_json::from_str(&metrics).expect("Should be valid JSON");
            assert!(json_value.is_object());
            assert!(json_value.get("uptime_seconds").is_some());
            assert!(json_value.get("targets").is_some());
            let targets = json_value.get("targets").unwrap();
            assert!(targets.get("healthy").is_some());
            assert!(targets.get("total").is_some());
        }).await.expect("test_generate_json_metrics timed out");
    }

    #[tokio::test]
    async fn test_register_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            register_metrics();
            register_metrics();
        }).await.expect("test_register_metrics timed out");
    }

    #[tokio::test]
    async fn test_record_request_metric_http_endpoints() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use std::time::Duration;
            record_request_metric("GET", 200, Duration::from_millis(100), "backend1");
            record_request_metric("POST", 404, Duration::from_millis(50), "backend2");
            record_request_metric("PUT", 500, Duration::from_millis(200), "backend3");
        }).await.expect("test_record_request_metric_http_endpoints timed out");
    }

    #[tokio::test]
    async fn test_request_metric_recording_http_edge_cases() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            use std::time::Duration;
            record_request_metric("", 0, Duration::from_millis(0), "");
            record_request_metric("VERY_LONG_METHOD_NAME", 999, Duration::from_secs(1000), "very_long_target_name_that_should_still_work");
            record_request_metric("PATCH", 204, Duration::from_micros(1), "fast_backend");
            record_request_metric("OPTIONS", 200, Duration::from_nanos(500), "options_backend");
        }).await.expect("test_request_metric_recording_http_edge_cases timed out");
    }

    #[tokio::test]
    async fn test_check_readiness() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let is_ready = check_readiness().await;
            assert!(!is_ready);
        }).await.expect("test_check_readiness timed out");
    }
}
