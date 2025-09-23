use anyhow::Result;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use super::collector::MetricsCollector;
use crate::config::MonitoringConfig;

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

    setup_prometheus_exporter(&config)?;
    register_metrics();

    let (metrics_addr, health_addr) = get_server_addresses(&config);

    start_metrics_collection_loop().await;
    run_servers(metrics_addr, health_addr).await
}

fn setup_prometheus_exporter(config: &MonitoringConfig) -> Result<()> {
    let mut res: Result<PrometheusBuilder, metrics_exporter_prometheus::BuildError> =
        Ok(PrometheusBuilder::new());

    if let Some(buckets_config) = &config.histogram_buckets {
        // Set latency buckets for response time metrics (in milliseconds)
        res = res.and_then(|b| {
            b.set_buckets_for_metric(
                Matcher::Full("dispa_target_health_check_duration_ms".to_string()),
                &buckets_config.latency_ms,
            )
        });

        // Set size buckets for data transfer metrics
        res = res.and_then(|b| {
            b.set_buckets_for_metric(
                Matcher::Full("dispa_request_size_bytes".to_string()),
                &buckets_config.size_bytes,
            )
        });
    }

    // Set default buckets for common metrics
    const DEFAULT_LOG_WRITE_MS_BUCKETS: &[f64] = &[
        0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
    ];
    res = res.and_then(|b| {
        b.set_buckets_for_metric(
            Matcher::Full("dispa_log_write_duration_ms".to_string()),
            DEFAULT_LOG_WRITE_MS_BUCKETS,
        )
    });

    const DEFAULT_HC_MS_BUCKETS: &[f64] = &[
        1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
    ];
    res = res.and_then(|b| {
        b.set_buckets_for_metric(
            Matcher::Full("dispa_target_health_check_duration_ms".to_string()),
            DEFAULT_HC_MS_BUCKETS,
        )
    });

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
        debug!("Prometheus exporter install skipped: {}", e);
    }

    Ok(())
}

fn get_server_addresses(config: &MonitoringConfig) -> (SocketAddr, SocketAddr) {
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

    (metrics_addr, health_addr)
}

async fn start_metrics_collection_loop() {
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
}

async fn run_servers(metrics_addr: SocketAddr, health_addr: SocketAddr) -> Result<()> {
    use hyper::server::conn::AddrStream;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::Server;
    use std::convert::Infallible;

    use super::handlers::{handle_health, handle_metrics};

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

fn register_metrics() {
    let _ = metrics::counter!("dispa_requests_total");
    let _ = metrics::counter!("dispa_errors_total");
    let _ = metrics::counter!("dispa_target_requests_total");
    let _ = metrics::counter!("dispa_target_errors_total");

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

    let _ = metrics::histogram!("dispa_request_duration_seconds");
    let _ = metrics::histogram!("dispa_target_health_check_duration_ms");

    let _ = metrics::gauge!("dispa_traffic_requests_last_hour");
    let _ = metrics::gauge!("dispa_traffic_errors_last_hour");
    let _ = metrics::gauge!("dispa_traffic_avg_duration_ms");
    let _ = metrics::gauge!("dispa_traffic_unique_clients_last_hour");
    let _ = metrics::gauge!("dispa_traffic_bytes_total");
    let _ = metrics::gauge!("dispa_target_traffic_requests_last_hour");
    let _ = metrics::gauge!("dispa_target_traffic_errors_last_hour");
    let _ = metrics::gauge!("dispa_target_traffic_avg_duration_ms");

    let _ = metrics::gauge!("dispa_cache_hits_total");
    let _ = metrics::gauge!("dispa_cache_misses_total");
    let _ = metrics::gauge!("dispa_cache_hit_ratio_percent");
    let _ = metrics::gauge!("dispa_cache_stores_total");
    let _ = metrics::gauge!("dispa_cache_evictions_total");
    let _ = metrics::gauge!("dispa_cache_size_bytes");
    let _ = metrics::gauge!("dispa_cache_entry_count");

    info!("Prometheus metrics registered successfully");
}

#[allow(dead_code)]
pub fn record_request_metric(method: &str, status_code: u16, duration: Duration, target: &str) {
    metrics::counter!("dispa_requests_total").increment(1);

    if status_code >= 400 {
        metrics::counter!("dispa_errors_total").increment(1);
    }

    metrics::histogram!("dispa_request_duration_seconds").record(duration.as_secs_f64());

    use tracing::debug;
    debug!(
        "Recorded metrics: method={}, status={}, duration={:.3}s, target={}",
        method,
        status_code,
        duration.as_secs_f64(),
        target
    );
}
