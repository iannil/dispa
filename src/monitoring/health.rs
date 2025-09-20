use serde_json::json;
use std::collections::HashMap;

pub fn get_system_health() -> serde_json::Value {
    json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": get_uptime_seconds(),
        "components": {
            "proxy_server": "healthy",
            "load_balancer": "healthy",
            "traffic_logger": "healthy",
            "metrics_collector": "healthy"
        }
    })
}

pub fn get_detailed_health(target_health: Vec<(String, bool)>) -> serde_json::Value {
    let mut targets = HashMap::new();
    for (name, healthy) in target_health {
        targets.insert(name, if healthy { "healthy" } else { "unhealthy" });
    }

    json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": get_uptime_seconds(),
        "components": {
            "proxy_server": "healthy",
            "load_balancer": "healthy",
            "traffic_logger": "healthy",
            "metrics_collector": "healthy"
        },
        "targets": targets
    })
}

fn get_uptime_seconds() -> u64 {
    // Simple uptime calculation - in production you might want to store start time
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() % 86400 // Reset daily for demo
}