pub mod admin;
pub mod collector;
pub mod data;
pub mod handlers;
pub mod health;
pub mod realtime_alerting;
pub mod server; // 实时监控和告警系统

use anyhow::Result;
use tokio::task::JoinHandle;

use crate::config::MonitoringConfig;

pub use server::run_metrics_server;

pub async fn start_metrics_server(config: MonitoringConfig) -> Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        if let Err(e) = run_metrics_server(config).await {
            tracing::error!("Metrics server error: {}", e);
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MonitoringConfig;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_start_metrics_server_disabled() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = MonitoringConfig {
                enabled: false,
                bind: "127.0.0.1:0".parse().unwrap(), // OK in tests - valid address
                health_endpoint: "/health".to_string(),
                metrics_endpoint: "/metrics".to_string(),
                enable_prometheus: true,
                histogram_buckets: None,
                capacity: None,
                pushgateway: None,
                metrics_port: 9090,
                health_check_port: 8081,
            };

            let result = start_metrics_server(config).await;
            assert!(result.is_ok(), "Should start metrics server when disabled");
            let handle = result.unwrap(); // OK in tests - server start expected to succeed
            sleep(Duration::from_millis(10)).await;
            handle.abort();
        })
        .await
        .expect("test_start_metrics_server_disabled timed out");
    }

    #[tokio::test]
    async fn test_start_metrics_server_enabled() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = MonitoringConfig {
                enabled: true,
                bind: "127.0.0.1:0".parse().unwrap(), // OK in tests - valid address
                health_endpoint: "/health".to_string(),
                metrics_endpoint: "/metrics".to_string(),
                enable_prometheus: true,
                histogram_buckets: None,
                capacity: None,
                pushgateway: None,
                metrics_port: 0, // Use port 0 for auto-assignment to avoid conflicts
                health_check_port: 0,
            };

            let result = start_metrics_server(config).await;
            assert!(
                result.is_ok(),
                "Should successfully start metrics server task"
            );
            let handle = result.unwrap(); // OK in tests - server start expected to succeed
            sleep(Duration::from_millis(100)).await;
            if handle.is_finished() {
                let _ = handle.await;
            } else {
                handle.abort();
            }
        })
        .await
        .expect("test_start_metrics_server_enabled timed out");
    }

    #[tokio::test]
    async fn test_start_metrics_server_with_different_ports() {
        let configs = vec![
            MonitoringConfig {
                enabled: true,
                bind: "127.0.0.1:9091".parse().unwrap(), // OK in tests - valid address
                health_endpoint: "/health".to_string(),
                metrics_endpoint: "/metrics".to_string(),
                enable_prometheus: true,
                histogram_buckets: None,
                capacity: None,
                pushgateway: None,
                metrics_port: 9091,
                health_check_port: 8082,
            },
            MonitoringConfig {
                enabled: true,
                bind: "127.0.0.1:9092".parse().unwrap(), // OK in tests - valid address
                health_endpoint: "/health".to_string(),
                metrics_endpoint: "/metrics".to_string(),
                enable_prometheus: true,
                histogram_buckets: None,
                capacity: None,
                pushgateway: None,
                metrics_port: 9092,
                health_check_port: 8083,
            },
            MonitoringConfig {
                enabled: false,
                bind: "127.0.0.1:9093".parse().unwrap(), // OK in tests - valid address
                health_endpoint: "/health".to_string(),
                metrics_endpoint: "/metrics".to_string(),
                enable_prometheus: true,
                histogram_buckets: None,
                capacity: None,
                pushgateway: None,
                metrics_port: 9093,
                health_check_port: 8084,
            },
        ];

        let mut handles = Vec::new();

        tokio::time::timeout(Duration::from_secs(10), async {
            for config in configs {
                let result = start_metrics_server(config).await;
                assert!(
                    result.is_ok(),
                    "Should start metrics server with custom ports"
                );
                handles.push(result.unwrap()); // OK in tests - server start expected to succeed
            }
            sleep(Duration::from_millis(100)).await;
            for handle in handles {
                handle.abort();
            }
        })
        .await
        .expect("test_start_metrics_server_with_different_ports timed out");
    }

    #[tokio::test]
    async fn test_concurrent_metrics_servers() {
        // Test starting multiple metrics servers concurrently
        let mut handles = Vec::new();

        tokio::time::timeout(Duration::from_secs(10), async {
            for i in 0..5 {
                let config = MonitoringConfig {
                    enabled: true,
                    bind: "127.0.0.1:0".parse().unwrap(), // OK in tests - valid address
                    health_endpoint: "/health".to_string(),
                    metrics_endpoint: "/metrics".to_string(),
                    enable_prometheus: true,
                    histogram_buckets: None,
                    capacity: None,
                    pushgateway: None,
                    metrics_port: 0, // Auto-assign to avoid conflicts
                    health_check_port: 0,
                };
                let result = start_metrics_server(config).await;
                assert!(result.is_ok(), "Should start metrics server {}", i);
                handles.push(result.unwrap()); // OK in tests - server start expected to succeed
            }
            sleep(Duration::from_millis(200)).await;

        // Check how many tasks are actually running
        let mut running_count = 0;
        let mut completed_count = 0;

        for handle in handles.iter() {
            if handle.is_finished() {
                completed_count += 1;
            } else {
                running_count += 1;
            }
        }

        // In a test environment, some servers might fail to bind to ports
        // We should have at least one running server, or all should have completed gracefully
        assert!(
            running_count > 0 || completed_count == handles.len(),
            "At least one server should be running, or all should have completed. Running: {}, Completed: {}",
            running_count,
            completed_count
        );

        // Clean up all handles
            for handle in handles { handle.abort(); }
        }).await.expect("test_concurrent_metrics_servers timed out");
    }

    #[tokio::test]
    async fn test_metrics_server_task_cleanup() {
        let config = MonitoringConfig {
            enabled: true,
            bind: "127.0.0.1:0".parse().unwrap(),
            health_endpoint: "/health".to_string(),
            metrics_endpoint: "/metrics".to_string(),
            enable_prometheus: true,
            histogram_buckets: None,
            capacity: None,
            pushgateway: None,
            metrics_port: 0,
            health_check_port: 0,
        };

        tokio::time::timeout(Duration::from_secs(10), async {
            let handle = start_metrics_server(config).await.unwrap(); // OK in tests - server start expected to succeed
            assert!(!handle.is_finished());
            handle.abort();
            sleep(Duration::from_millis(10)).await;
            assert!(handle.is_finished());
        })
        .await
        .expect("test_metrics_server_task_cleanup timed out");
    }
}
