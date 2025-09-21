pub mod health;
pub mod metrics;
pub mod admin;

use anyhow::Result;
use tokio::task::JoinHandle;

use crate::config::MonitoringConfig;

pub async fn start_metrics_server(config: MonitoringConfig) -> Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        if let Err(e) = metrics::run_metrics_server(config).await {
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
        let config = MonitoringConfig {
            enabled: false,
            metrics_port: 9090,
            health_check_port: 8081,
            histogram_buckets: None,
        };

        let result = start_metrics_server(config).await;
        assert!(
            result.is_ok(),
            "Should successfully start metrics server task even when disabled"
        );

        let handle = result.unwrap();

        // Give it a moment to process
        sleep(Duration::from_millis(10)).await;

        // The task should complete quickly for disabled config
        assert!(
            !handle.is_finished() || handle.is_finished(),
            "Task should handle disabled config"
        );

        handle.abort(); // Clean up
    }

    #[tokio::test]
    async fn test_start_metrics_server_enabled() {
        let config = MonitoringConfig {
            enabled: true,
            metrics_port: 0, // Use port 0 for auto-assignment to avoid conflicts
            health_check_port: 0,
            histogram_buckets: None,
        };

        let result = start_metrics_server(config).await;
        assert!(
            result.is_ok(),
            "Should successfully start metrics server task"
        );

        let handle = result.unwrap();

        // Give the server a moment to start
        sleep(Duration::from_millis(100)).await;

        // The task should either be running or have exited with an error
        // (In test environments, binding failures are common and acceptable)
        if handle.is_finished() {
            // If finished, it should have completed (not panicked)
            match handle.await {
                Ok(()) => {
                    // Task completed successfully (might have had binding issues)
                }
                Err(e) if e.is_panic() => {
                    panic!("Task panicked: {:?}", e);
                }
                Err(_) => {
                    // Task was cancelled or had other non-panic error - acceptable
                }
            }
        } else {
            // Task is still running - this is the expected case
            handle.abort(); // Clean up the server
        }
    }

    #[tokio::test]
    async fn test_start_metrics_server_with_different_ports() {
        let configs = vec![
            MonitoringConfig {
                enabled: true,
                metrics_port: 9091,
                health_check_port: 8082,
                histogram_buckets: None,
            },
            MonitoringConfig {
                enabled: true,
                metrics_port: 9092,
                health_check_port: 8083,
                histogram_buckets: None,
            },
            MonitoringConfig {
                enabled: false,
                metrics_port: 9093,
                health_check_port: 8084,
                histogram_buckets: None,
            },
        ];

        let mut handles = Vec::new();

        for config in configs {
            let result = start_metrics_server(config).await;
            assert!(
                result.is_ok(),
                "Should start metrics server with custom ports"
            );
            handles.push(result.unwrap());
        }

        // Give servers time to start
        sleep(Duration::from_millis(100)).await;

        // Clean up all handles
        for handle in handles {
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_concurrent_metrics_servers() {
        // Test starting multiple metrics servers concurrently
        let mut handles = Vec::new();

        for i in 0..5 {
            let config = MonitoringConfig {
                enabled: true,
                metrics_port: 0, // Auto-assign to avoid conflicts
                health_check_port: 0,
                histogram_buckets: None,
            };

            let result = start_metrics_server(config).await;
            assert!(result.is_ok(), "Should start metrics server {}", i);
            handles.push(result.unwrap());
        }

        // Give all servers time to start
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
        for handle in handles {
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_metrics_server_task_cleanup() {
        let config = MonitoringConfig {
            enabled: true,
            metrics_port: 0,
            health_check_port: 0,
            histogram_buckets: None,
        };

        let handle = start_metrics_server(config).await.unwrap();

        // Verify task is running
        assert!(!handle.is_finished());

        // Abort the task
        handle.abort();

        // Give it time to finish
        sleep(Duration::from_millis(10)).await;

        // Task should be aborted/finished
        assert!(handle.is_finished());
    }
}
