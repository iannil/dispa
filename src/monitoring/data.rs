use serde_json::json;

use super::server::get_metrics_collector;

pub async fn generate_fallback_metrics() -> String {
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

pub async fn generate_json_metrics() -> String {
    let (avg_ms, bytes_total, unique_clients) = get_traffic_overview().await;
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
            "hits": 0.0,
            "misses": 0.0,
            "hit_ratio_percent": 0.0,
            "size_bytes": 0.0,
            "entry_count": 0.0
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
        if let Some(ref logger) = collector.traffic_logger() {
            if let Ok(s) = logger.get_traffic_stats(1).await {
                return (
                    s.avg_duration_ms,
                    s.total_bytes as f64,
                    s.unique_clients as f64,
                );
            }
        }
    }
    (0.0, 0.0, 0.0)
}

async fn get_targets_by_traffic() -> serde_json::Value {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref logger) = collector.traffic_logger() {
            if let Ok(list) = logger.get_traffic_by_target(1).await {
                let arr: Vec<serde_json::Value> = list
                    .into_iter()
                    .map(|t| {
                        json!({
                            "target": t.target,
                            "request_count": t.total_requests,
                            "avg_duration_ms": t.avg_duration_ms,
                            "error_count": t.error_count,
                            "bytes_total": 0, // Field not available in TargetTrafficStats
                        })
                    })
                    .collect();
                return json!(arr);
            }
        }
    }
    json!([])
}

pub async fn get_uptime_seconds() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        collector.start_time().elapsed().as_secs_f64()
    } else {
        0.0
    }
}

pub async fn check_readiness() -> bool {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;

        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.healthy_targets > 0
        } else {
            true
        }
    } else {
        false
    }
}

pub async fn get_healthy_targets_count() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.healthy_targets as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_total_targets_count() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.total_targets as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_total_requests() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.total_requests as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_total_errors() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.total_errors as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_error_rate() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.error_rate
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_active_connections() -> f64 {
    if let Some(collector) = get_metrics_collector().await {
        let collector = collector.read().await;
        if let Some(ref lb) = collector.load_balancer() {
            let summary = lb.get_summary().await;
            summary.total_active_connections as f64
        } else {
            0.0
        }
    } else {
        0.0
    }
}

pub async fn get_memory_usage() -> f64 {
    50_000_000.0
}
