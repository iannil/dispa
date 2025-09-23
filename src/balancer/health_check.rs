use anyhow::Result;
use hyper::StatusCode;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::{HealthCheckConfig, Target};

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_error: Option<String>,
    pub response_time_ms: Option<u64>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_error: None,
            response_time_ms: None,
        }
    }
}

pub struct HealthChecker {
    config: HealthCheckConfig,
    health_status: Arc<RwLock<HashMap<String, HealthStatus>>>,
    shutdown: Arc<AtomicBool>,
}

impl HealthChecker {
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            health_status: Arc::new(RwLock::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub async fn set_health_status_for_test(&self, map: HashMap<String, HealthStatus>) {
        let mut status_map = self.health_status.write().await;
        *status_map = map;
    }

    pub async fn start_monitoring(&self, targets: Vec<Target>) -> Result<()> {
        if !self.config.enabled {
            info!("Health checks are disabled");
            return Ok(());
        }

        // Initialize health status for all targets
        {
            let mut status_map = self.health_status.write().await;
            for target in &targets {
                status_map.insert(target.name.clone(), HealthStatus::default());
            }
        }

        info!("Starting health checker for {} targets", targets.len());

        let mut interval = tokio::time::interval(Duration::from_secs(self.config.interval));

        loop {
            interval.tick().await;
            if self.shutdown.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.check_all_targets(&targets).await;
        }
    }

    async fn check_all_targets(&self, targets: &[Target]) {
        let mut handles = Vec::new();

        for target in targets {
            let target = target.clone();
            let checker = self.clone();

            let handle = tokio::spawn(async move {
                checker.check_single_target(&target).await;
            });

            handles.push(handle);
        }

        // Wait for all health checks to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Health check task failed: {}", e);
            }
        }
    }

    async fn check_single_target(&self, target: &Target) {
        let start_time = Instant::now();
        let check_result = self.perform_health_check(target).await;
        let response_time = start_time.elapsed();

        let mut status_map = self.health_status.write().await;
        let status = status_map
            .entry(target.name.clone())
            .or_insert_with(HealthStatus::default);

        match check_result {
            Ok(is_healthy) => {
                status.response_time_ms = Some(response_time.as_millis() as u64);
                status.last_error = None;

                if is_healthy {
                    status.consecutive_failures = 0;
                    status.consecutive_successes += 1;

                    if !status.is_healthy
                        && status.consecutive_successes >= self.config.healthy_threshold
                    {
                        status.is_healthy = true;
                        info!(
                            "Target '{}' is now healthy after {} consecutive successes",
                            target.name, status.consecutive_successes
                        );
                    }
                } else {
                    status.consecutive_successes = 0;
                    status.consecutive_failures += 1;

                    if status.is_healthy
                        && status.consecutive_failures >= self.config.unhealthy_threshold
                    {
                        status.is_healthy = false;
                        warn!(
                            "Target '{}' is now unhealthy after {} consecutive failures",
                            target.name, status.consecutive_failures
                        );
                    }
                }
            }
            Err(e) => {
                status.consecutive_successes = 0;
                status.consecutive_failures += 1;
                status.last_error = Some(e.to_string());
                status.response_time_ms = None;

                if status.is_healthy
                    && status.consecutive_failures >= self.config.unhealthy_threshold
                {
                    status.is_healthy = false;
                    warn!(
                        "Target '{}' is now unhealthy due to error: {}",
                        target.name, e
                    );
                }
            }
        }

        status.last_check = Instant::now();

        debug!(
            "Health check for '{}': healthy={}, consecutive_failures={}, consecutive_successes={}, response_time={:?}ms",
            target.name,
            status.is_healthy,
            status.consecutive_failures,
            status.consecutive_successes,
            status.response_time_ms
        );
    }

    async fn perform_health_check(&self, target: &Target) -> Result<bool> {
        // Try multiple health check endpoints in order of preference
        let health_endpoints = vec![
            format!("{}/health", target.url),
            format!("{}/healthz", target.url),
            format!("{}/ping", target.url),
            target.url.clone(), // Fallback to root
        ];

        for endpoint in health_endpoints {
            // Enforce overall timeout including connect
            let timeout = Duration::from_secs(self.config.timeout);
            match crate::proxy::http_client::get_status(&endpoint, timeout).await {
                Ok(status) => {
                    if status.is_success() || status.is_redirection() {
                        debug!(
                            "Health check successful for '{}' at {}",
                            target.name, endpoint
                        );
                        return Ok(true);
                    } else if status == StatusCode::NOT_FOUND {
                        // 404 means endpoint doesn't exist, try next one
                        continue;
                    } else {
                        debug!(
                            "Health check failed for '{}' at {}: HTTP {}",
                            target.name,
                            endpoint,
                            status.as_u16()
                        );
                        return Ok(false);
                    }
                }
                Err(e) => {
                    debug!(
                        "Health check request failed for '{}' at {}: {}",
                        target.name, endpoint, e
                    );
                    continue;
                }
            }
        }

        // If all endpoints failed, consider target unhealthy
        Err(anyhow::anyhow!(
            "All health check endpoints failed for target '{}'",
            target.name
        ))
    }

    pub async fn is_target_healthy(&self, target_name: &str) -> bool {
        let status_map = self.health_status.read().await;
        status_map
            .get(target_name)
            .map(|status| status.is_healthy)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub async fn get_target_status(&self, target_name: &str) -> Option<HealthStatus> {
        let status_map = self.health_status.read().await;
        status_map.get(target_name).cloned()
    }

    pub async fn get_all_health_status(&self) -> HashMap<String, HealthStatus> {
        let status_map = self.health_status.read().await;
        status_map.clone()
    }

    #[allow(dead_code)]
    pub async fn force_health_check(&self, targets: &[Target]) {
        info!("Forcing immediate health check for all targets");
        self.check_all_targets(targets).await;
    }

    // For compatibility with existing code
    #[allow(dead_code)]
    pub async fn check_target(&self, target: &Target) -> bool {
        self.perform_health_check(target).await.unwrap_or(false)
    }

    #[allow(dead_code)]
    pub async fn check_target_with_custom_path(&self, target: &Target, path: &str) -> bool {
        let health_url = format!("{}{}", target.url, path);
        let timeout = Duration::from_secs(self.config.timeout);
        match crate::proxy::http_client::get_status(&health_url, timeout).await {
            Ok(status) => status.is_success() || status.is_redirection(),
            Err(e) => {
                error!(
                    "Custom health check failed for '{}' at {}: {}",
                    target.name, path, e
                );
                false
            }
        }
    }
}

impl Clone for HealthChecker {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            health_status: Arc::clone(&self.health_status),
            shutdown: Arc::clone(&self.shutdown),
        }
    }
}

impl HealthChecker {
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Clean up health status for targets that no longer exist
    #[allow(dead_code)]
    pub async fn cleanup_expired_data(
        &self,
        current_target_names: &std::collections::HashSet<String>,
    ) {
        let mut health_status = self.health_status.write().await;
        health_status.retain(|target_name, _| {
            if current_target_names.contains(target_name) {
                true
            } else {
                debug!(
                    "Cleaning up health status for removed target: {}",
                    target_name
                );
                false
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCheckConfig, Target};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;
    use tokio::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_health_config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval: 1,
            timeout: 5,
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            threshold: 2, // Add missing threshold field
        }
    }

    fn create_test_target(name: &str, url: &str) -> Target {
        Target {
            name: name.to_string(),
            url: url.to_string(),
            address: url.replace("http://", "").replace("https://", ""),
            weight: Some(1.0), // Fix type from i32 to f64
            timeout: Some(5000),
        }
    }

    #[tokio::test]
    async fn test_health_checker_creation() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let config = create_test_health_config();
            let checker = HealthChecker::new(config.clone());
            assert_eq!(checker.config.enabled, config.enabled);
            assert_eq!(checker.config.interval, config.interval);
            assert_eq!(checker.config.timeout, config.timeout);
        })
        .await
        .expect("test_health_checker_creation timed out");
    }

    #[tokio::test]
    async fn test_healthy_target_check() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;
            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);
            let result = checker.check_target(&target).await;
            assert!(result, "Target should be healthy");
        })
        .await
        .expect("test_healthy_target_check timed out");
    }

    #[tokio::test]
    async fn test_unhealthy_target_check() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            let result = checker.check_target(&target).await;
            assert!(!result, "Target should be unhealthy");
        })
        .await
        .expect("test_unhealthy_target_check timed out");
    }

    #[tokio::test]
    async fn test_health_endpoint_fallback() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            // /health returns 404, /healthz returns 200
            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            Mock::given(method("GET"))
                .and(path("/healthz"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            let result = checker.check_target(&target).await;
            assert!(result, "Target should be healthy via /healthz endpoint");
        })
        .await
        .expect("test_health_endpoint_fallback timed out");
    }

    #[tokio::test]
    async fn test_consecutive_failure_threshold() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = HealthCheckConfig {
                enabled: true,
                interval: 1,
                timeout: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 2, // Fail after 2 consecutive failures
                threshold: 2,
            };
            let checker = HealthChecker::new(config);

            // First failure - should still be healthy
            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();
            assert!(status.is_healthy);
            assert_eq!(status.consecutive_failures, 1);

            // Second failure - should now be unhealthy
            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();
            assert!(!status.is_healthy);
            assert_eq!(status.consecutive_failures, 2);
        })
        .await
        .expect("test_consecutive_failure_threshold timed out");
    }

    #[tokio::test]
    async fn test_consecutive_success_threshold() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;
            let request_count = Arc::new(AtomicU16::new(0));
            let _count_clone = Arc::clone(&request_count);

            Mock::given(method("GET"))
                .respond_with({
                    let count_clone = Arc::clone(&request_count);
                    move |_req: &wiremock::Request| {
                        let count = count_clone.fetch_add(1, Ordering::SeqCst);
                        if count < 2 {
                            ResponseTemplate::new(500) // First 2 requests fail
                        } else {
                            ResponseTemplate::new(200) // Subsequent requests succeed
                        }
                    }
                })
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = HealthCheckConfig {
                enabled: true,
                interval: 1,
                timeout: 5,
                healthy_threshold: 2, // Need 2 consecutive successes to be healthy
                unhealthy_threshold: 2,
                threshold: 2,
            };
            let checker = HealthChecker::new(config);

            // Initialize with default healthy status
            {
                let mut status_map = checker.health_status.write().await;
                status_map.insert(target.name.clone(), HealthStatus::default());
            }

            // Two failures - should become unhealthy
            checker.check_single_target(&target).await;
            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();
            assert!(!status.is_healthy);

            // First success - should still be unhealthy
            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();
            assert!(!status.is_healthy);
            assert_eq!(status.consecutive_successes, 1);

            // Second success - should now be healthy
            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();
            assert!(status.is_healthy);
            assert_eq!(status.consecutive_successes, 2);
        })
        .await
        .expect("test_consecutive_success_threshold timed out");
    }

    #[tokio::test]
    async fn test_response_time_recording() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_millis(100))
                        .set_body_string("OK"),
                )
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();

            assert!(status.response_time_ms.is_some());
            let response_time = status.response_time_ms.unwrap();
            assert!(
                response_time >= 100,
                "Response time should be at least 100ms"
            );
            assert!(response_time < 1000, "Response time should be reasonable");
        })
        .await
        .expect("test_response_time_recording timed out");
    }

    #[tokio::test]
    async fn test_error_message_recording() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let target = create_test_target("test", "http://127.0.0.1:1");
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            // Initialize the target with default healthy status first
            {
                let mut status_map = checker.health_status.write().await;
                status_map.insert(target.name.clone(), HealthStatus::default());
            }

            checker.check_single_target(&target).await;
            let status = checker.get_target_status(&target.name).await.unwrap();

            assert!(status.last_error.is_some());
            // Since we start with healthy=true and unhealthy_threshold=3,
            // one failure shouldn't make it unhealthy yet
            assert!(
                status.is_healthy,
                "Should still be healthy after first failure"
            );
            assert_eq!(status.consecutive_failures, 1);
            assert!(status.response_time_ms.is_none());
        })
        .await
        .expect("test_error_message_recording timed out");
    }

    #[tokio::test]
    async fn test_custom_path_health_check() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/custom/health"))
                .respond_with(ResponseTemplate::new(200).set_body_string("Custom OK"))
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            let result = checker
                .check_target_with_custom_path(&target, "/custom/health")
                .await;
            assert!(result, "Custom path health check should succeed");
        })
        .await
        .expect("test_custom_path_health_check timed out");
    }

    #[tokio::test]
    async fn test_redirection_as_healthy() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            // Create a proper redirect: /health -> /healthz, and /healthz returns 200
            Mock::given(method("GET"))
                .and(path("/health"))
                .respond_with(ResponseTemplate::new(302).insert_header("Location", "/healthz"))
                .mount(&mock_server)
                .await;

            Mock::given(method("GET"))
                .and(path("/healthz"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let target = create_test_target("test", &mock_server.uri());
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            // Test that the health check can follow redirects and succeed
            let result = checker.check_target(&target).await;
            assert!(
                result,
                "Health check should succeed after following redirect"
            );
        })
        .await
        .expect("test_redirection_as_healthy timed out");
    }

    #[tokio::test]
    async fn test_concurrent_health_checks() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let targets = vec![
                create_test_target("target1", &mock_server.uri()),
                create_test_target("target2", &mock_server.uri()),
                create_test_target("target3", &mock_server.uri()),
            ];
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            // Initialize targets
            for target in &targets {
                let mut status_map = checker.health_status.write().await;
                status_map.insert(target.name.clone(), HealthStatus::default());
            }

            // Run concurrent health checks
            checker.check_all_targets(&targets).await;

            // Verify all targets are healthy
            for target in &targets {
                let is_healthy = checker.is_target_healthy(&target.name).await;
                assert!(is_healthy, "Target {} should be healthy", target.name);
            }
        })
        .await
        .expect("test_concurrent_health_checks timed out");
    }

    #[tokio::test]
    async fn test_get_all_health_status() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let mock_server = MockServer::start().await;

            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
                .mount(&mock_server)
                .await;

            let targets = vec![
                create_test_target("target1", &mock_server.uri()),
                create_test_target("target2", &mock_server.uri()),
            ];
            let config = create_test_health_config();
            let checker = HealthChecker::new(config);

            // Initialize and check targets
            for target in &targets {
                let mut status_map = checker.health_status.write().await;
                status_map.insert(target.name.clone(), HealthStatus::default());
            }

            checker.check_all_targets(&targets).await;

            let all_status = checker.get_all_health_status().await;
            assert_eq!(all_status.len(), 2);
            assert!(all_status.contains_key("target1"));
            assert!(all_status.contains_key("target2"));

            for (_, status) in all_status {
                assert!(status.is_healthy);
            }
        })
        .await
        .expect("test_get_all_health_status timed out");
    }

    #[tokio::test]
    async fn test_disabled_health_checks() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let config = HealthCheckConfig {
                enabled: false,
                interval: 1,
                timeout: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            };
            let checker = HealthChecker::new(config);
            let targets = vec![create_test_target("test", "http://example.com")];
            let result = checker.start_monitoring(targets).await;
            assert!(result.is_ok(), "Disabled health checks should return Ok");
        })
        .await
        .expect("test_disabled_health_checks timed out");
    }

    #[tokio::test]
    async fn test_health_status_default() {
        let status = HealthStatus::default();
        assert!(status.is_healthy);
        assert_eq!(status.consecutive_failures, 0);
        assert_eq!(status.consecutive_successes, 0);
        assert!(status.last_error.is_none());
        assert!(status.response_time_ms.is_none());
    }
}
