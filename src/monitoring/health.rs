use serde_json::json;
use std::collections::HashMap;

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn get_uptime_seconds() -> u64 {
    // Simple uptime calculation - in production you might want to store start time
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86400 // Reset daily for demo
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_get_system_health() {
        let health = get_system_health();

        // Verify JSON structure
        assert!(health.is_object());

        // Verify required fields
        assert_eq!(health["status"], "healthy");
        assert!(health["timestamp"].is_string());
        assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
        assert!(health["uptime"].is_number());

        // Verify components
        let components = &health["components"];
        assert!(components.is_object());
        assert_eq!(components["proxy_server"], "healthy");
        assert_eq!(components["load_balancer"], "healthy");
        assert_eq!(components["traffic_logger"], "healthy");
        assert_eq!(components["metrics_collector"], "healthy");
    }

    #[test]
    fn test_get_detailed_health_with_empty_targets() {
        let target_health = vec![];
        let health = get_detailed_health(target_health);

        // Verify basic structure
        assert!(health.is_object());
        assert_eq!(health["status"], "healthy");
        assert!(health["timestamp"].is_string());
        assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
        assert!(health["uptime"].is_number());

        // Verify components
        let components = &health["components"];
        assert!(components.is_object());
        assert_eq!(components["proxy_server"], "healthy");
        assert_eq!(components["load_balancer"], "healthy");
        assert_eq!(components["traffic_logger"], "healthy");
        assert_eq!(components["metrics_collector"], "healthy");

        // Verify empty targets
        let targets = &health["targets"];
        assert!(targets.is_object());
        assert_eq!(targets.as_object().unwrap().len(), 0);
    }

    #[test]
    fn test_get_detailed_health_with_healthy_targets() {
        let target_health = vec![
            ("backend1".to_string(), true),
            ("backend2".to_string(), true),
            ("backend3".to_string(), true),
        ];
        let health = get_detailed_health(target_health);

        // Verify targets section
        let targets = &health["targets"];
        assert!(targets.is_object());

        let targets_obj = targets.as_object().unwrap();
        assert_eq!(targets_obj.len(), 3);
        assert_eq!(targets_obj["backend1"], "healthy");
        assert_eq!(targets_obj["backend2"], "healthy");
        assert_eq!(targets_obj["backend3"], "healthy");
    }

    #[test]
    fn test_get_detailed_health_with_mixed_targets() {
        let target_health = vec![
            ("healthy_backend".to_string(), true),
            ("unhealthy_backend".to_string(), false),
            ("another_healthy".to_string(), true),
            ("another_unhealthy".to_string(), false),
        ];
        let health = get_detailed_health(target_health);

        // Verify targets section
        let targets = &health["targets"];
        assert!(targets.is_object());

        let targets_obj = targets.as_object().unwrap();
        assert_eq!(targets_obj.len(), 4);
        assert_eq!(targets_obj["healthy_backend"], "healthy");
        assert_eq!(targets_obj["unhealthy_backend"], "unhealthy");
        assert_eq!(targets_obj["another_healthy"], "healthy");
        assert_eq!(targets_obj["another_unhealthy"], "unhealthy");
    }

    #[test]
    fn test_get_detailed_health_with_all_unhealthy_targets() {
        let target_health = vec![
            ("backend1".to_string(), false),
            ("backend2".to_string(), false),
        ];
        let health = get_detailed_health(target_health);

        // System should still report as healthy even if targets are unhealthy
        assert_eq!(health["status"], "healthy");

        let targets = &health["targets"];
        let targets_obj = targets.as_object().unwrap();
        assert_eq!(targets_obj["backend1"], "unhealthy");
        assert_eq!(targets_obj["backend2"], "unhealthy");
    }

    #[test]
    fn test_get_uptime_seconds() {
        let uptime1 = get_uptime_seconds();

        // Wait a tiny bit
        std::thread::sleep(std::time::Duration::from_millis(1));

        let uptime2 = get_uptime_seconds();

        // Uptime should be valid numbers
        assert!(uptime1 > 0);
        assert!(uptime2 >= uptime1); // Should be same or slightly higher

        // Should be less than a day (due to % 86400)
        assert!(uptime1 < 86400);
        assert!(uptime2 < 86400);
    }

    #[test]
    fn test_timestamp_format() {
        let health = get_system_health();
        let timestamp_str = health["timestamp"].as_str().unwrap();

        // Should be able to parse the timestamp back
        let parsed = chrono::DateTime::parse_from_rfc3339(timestamp_str);
        assert!(parsed.is_ok(), "Timestamp should be valid RFC3339 format");

        // Should be recent (within last minute)
        let now = chrono::Utc::now();
        let parsed_utc = parsed.unwrap().with_timezone(&chrono::Utc);
        let diff = now.signed_duration_since(parsed_utc);
        assert!(diff.num_seconds() < 60, "Timestamp should be recent");
    }

    #[test]
    fn test_version_consistency() {
        let health1 = get_system_health();
        let health2 = get_detailed_health(vec![]);

        // Both functions should report the same version
        assert_eq!(health1["version"], health2["version"]);
        assert_eq!(health1["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_components_consistency() {
        let health1 = get_system_health();
        let health2 = get_detailed_health(vec![("test".to_string(), true)]);

        // Both functions should report the same component states
        assert_eq!(health1["components"], health2["components"]);
    }

    #[test]
    fn test_json_serialization() {
        let health = get_system_health();

        // Should be able to serialize back to string
        let json_str = serde_json::to_string(&health);
        assert!(json_str.is_ok());

        // Should be able to deserialize back
        let reparsed: Result<Value, _> = serde_json::from_str(&json_str.unwrap());
        assert!(reparsed.is_ok());
        assert_eq!(health, reparsed.unwrap());
    }

    #[test]
    fn test_detailed_health_with_duplicate_targets() {
        // Test behavior with duplicate target names (last one wins)
        let target_health = vec![
            ("backend1".to_string(), true),
            ("backend1".to_string(), false), // This should overwrite the first one
            ("backend2".to_string(), true),
        ];
        let health = get_detailed_health(target_health);

        let targets = &health["targets"];
        let targets_obj = targets.as_object().unwrap();
        assert_eq!(targets_obj.len(), 2); // Only 2 unique targets
        assert_eq!(targets_obj["backend1"], "unhealthy"); // Last value wins
        assert_eq!(targets_obj["backend2"], "healthy");
    }

    #[test]
    fn test_large_number_of_targets() {
        // Test with many targets
        let mut target_health = Vec::new();
        for i in 0..100 {
            target_health.push((format!("backend{}", i), i % 2 == 0));
        }

        let health = get_detailed_health(target_health);
        let targets = &health["targets"];
        let targets_obj = targets.as_object().unwrap();

        assert_eq!(targets_obj.len(), 100);

        // Verify some of the targets
        assert_eq!(targets_obj["backend0"], "healthy"); // 0 % 2 == 0
        assert_eq!(targets_obj["backend1"], "unhealthy"); // 1 % 2 != 0
        assert_eq!(targets_obj["backend99"], "unhealthy"); // 99 % 2 != 0
    }
}
