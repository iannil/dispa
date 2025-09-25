use dispa::config::plugins::{
    PluginConfig, PluginErrorStrategy, PluginStage, PluginType, PluginsConfig,
};
use dispa::plugins::engine::PluginEngine;
use dispa::plugins::traits::{PluginResult, RequestPlugin, ResponsePlugin};
use hyper::{Body, Request, Response, StatusCode};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Test plugin system edge cases and error handling
mod plugin_edge_tests {
    use super::*;

    /// Mock plugin that can be configured to fail
    struct FailingPlugin {
        name: String,
        should_fail: bool,
        call_count: Arc<AtomicU32>,
    }

    impl FailingPlugin {
        fn new(name: &str, should_fail: bool) -> Self {
            Self {
                name: name.to_string(),
                should_fail,
                call_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn call_count(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl RequestPlugin for FailingPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            self.call_count.fetch_add(1, Ordering::Relaxed);

            if self.should_fail {
                // Simulate plugin error by setting error flag
                // In a real implementation, this would set some internal error state
                PluginResult::Continue
            } else {
                PluginResult::Continue
            }
        }

        fn last_error_and_clear(&self) -> bool {
            self.should_fail
        }
    }

    impl ResponsePlugin for FailingPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_response(&self, _resp: &mut Response<Body>) {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }

        fn last_error_and_clear(&self) -> bool {
            self.should_fail
        }
    }

    /// Mock plugin that short-circuits requests
    struct ShortCircuitPlugin {
        name: String,
        response_status: StatusCode,
    }

    impl ShortCircuitPlugin {
        fn new(name: &str, status: StatusCode) -> Self {
            Self {
                name: name.to_string(),
                response_status: status,
            }
        }
    }

    impl RequestPlugin for ShortCircuitPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            let response = Response::builder()
                .status(self.response_status)
                .body(Body::from(format!("Short-circuited by {}", self.name)))
                .unwrap();
            PluginResult::ShortCircuit(response)
        }

        fn last_error_and_clear(&self) -> bool {
            false
        }
    }

    /// Test plugin engine with disabled plugins
    #[tokio::test]
    async fn test_disabled_plugins_engine() {
        let config = PluginsConfig {
            enabled: false, // Globally disabled
            apply_before_domain_match: false,
            plugins: vec![PluginConfig {
                name: "disabled-plugin".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                error_strategy: PluginErrorStrategy::Continue,
                config: None,
            }],
        };

        let engine = PluginEngine::new(&config).unwrap();

        // Should have no plugins loaded
        assert_eq!(engine.plugin_count(), (0, 0));
        assert!(!engine.has_plugins());
        assert_eq!(engine.request_plugin_names().len(), 0);
        assert_eq!(engine.response_plugin_names().len(), 0);

        // Request processing should pass through
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    /// Test plugin engine with empty plugin list
    #[tokio::test]
    async fn test_empty_plugin_list() {
        let config = PluginsConfig {
            enabled: true,
            apply_before_domain_match: false,
            plugins: vec![], // No plugins configured
        };

        let engine = PluginEngine::new(&config).unwrap();

        // Should have no plugins loaded
        assert_eq!(engine.plugin_count(), (0, 0));
        assert!(!engine.has_plugins());

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));

        let mut resp = Response::builder().status(200).body(Body::empty()).unwrap();

        // Should not panic with no plugins
        engine.apply_response(&mut resp).await;
    }

    /// Test applying subset of plugins with non-existent names
    #[tokio::test]
    async fn test_plugin_subset_with_invalid_names() {
        let config = PluginsConfig {
            enabled: true,
            apply_before_domain_match: false,
            plugins: vec![PluginConfig {
                name: "existing-plugin".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                error_strategy: PluginErrorStrategy::Continue,
                config: None,
            }],
        };

        let engine = PluginEngine::new(&config).unwrap();

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        // Apply subset with mix of valid and invalid plugin names
        let plugin_names = vec![
            "existing-plugin".to_string(),
            "non-existent-plugin".to_string(),
            "another-missing-plugin".to_string(),
        ];

        let result = engine.apply_request_subset(&plugin_names, &mut req).await;
        // Should continue even with invalid plugin names
        assert!(matches!(result, PluginResult::Continue));

        // Test with only invalid names
        let invalid_names = vec!["missing-1".to_string(), "missing-2".to_string()];

        let result = engine.apply_request_subset(&invalid_names, &mut req).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    /// Test plugin execution order and consistency
    #[tokio::test]
    async fn test_plugin_execution_order() {
        // This test would require a way to inject custom plugins
        // For now, we test the basic ordering behavior with HeaderInjector plugins

        let config = PluginsConfig {
            enabled: true,
            apply_before_domain_match: false,
            plugins: vec![
                PluginConfig {
                    name: "first-plugin".to_string(),
                    plugin_type: PluginType::HeaderInjector,
                    stage: PluginStage::Request,
                    enabled: true,
                    error_strategy: PluginErrorStrategy::Continue,
                    config: Some(serde_json::json!({
                        "request_headers": {
                            "X-Plugin-Order": "1"
                        }
                    })),
                },
                PluginConfig {
                    name: "second-plugin".to_string(),
                    plugin_type: PluginType::HeaderInjector,
                    stage: PluginStage::Request,
                    enabled: true,
                    error_strategy: PluginErrorStrategy::Continue,
                    config: Some(serde_json::json!({
                        "request_headers": {
                            "X-Plugin-Order": "2"
                        }
                    })),
                },
            ],
        };

        let engine = PluginEngine::new(&config).unwrap();

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));

        // Verify plugins were applied
        assert!(req.headers().contains_key("X-Plugin-Order"));

        // The last plugin should win if they set the same header
        assert_eq!(req.headers().get("X-Plugin-Order").unwrap(), "2");
    }

    /// Test plugin both-stage configuration
    #[tokio::test]
    async fn test_plugin_both_stage_execution() {
        let config = PluginsConfig {
            enabled: true,
            apply_before_domain_match: false,
            plugins: vec![PluginConfig {
                name: "both-stage-plugin".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Both, // Should be available in both stages
                enabled: true,
                error_strategy: PluginErrorStrategy::Continue,
                config: Some(serde_json::json!({
                    "request_headers": {
                        "X-Request-Plugin": "both-stage"
                    },
                    "response_headers": {
                        "X-Response-Plugin": "both-stage"
                    }
                })),
            }],
        };

        let engine = PluginEngine::new(&config).unwrap();

        // Should be registered in both stages
        assert_eq!(engine.plugin_count(), (1, 1));
        assert!(engine
            .request_plugin_names()
            .contains(&"both-stage-plugin".to_string()));
        assert!(engine
            .response_plugin_names()
            .contains(&"both-stage-plugin".to_string()));

        // Test request stage
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(req.headers().contains_key("X-Request-Plugin"));

        // Test response stage
        let mut resp = Response::builder().status(200).body(Body::empty()).unwrap();

        engine.apply_response(&mut resp).await;
        // Note: HeaderInjector for response would need to be implemented
        // This test mainly verifies the plugin is registered in both stages
    }

    /// Test concurrent plugin execution
    #[tokio::test]
    async fn test_concurrent_plugin_execution() {
        let config = PluginsConfig {
            enabled: true,
            apply_before_domain_match: false,
            plugins: vec![PluginConfig {
                name: "concurrent-plugin".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                error_strategy: PluginErrorStrategy::Continue,
                config: Some(serde_json::json!({
                    "request_headers": {
                        "X-Concurrent": "test"
                    }
                })),
            }],
        };

        let engine = std::sync::Arc::new(PluginEngine::new(&config).unwrap());

        // Spawn multiple concurrent tasks
        let mut handles = vec![];
        for i in 0..10 {
            let engine_clone = engine.clone();
            let handle = tokio::spawn(async move {
                let mut req = Request::builder()
                    .uri(format!("/test/{}", i))
                    .body(Body::empty())
                    .unwrap();

                let result = engine_clone.apply_request(&mut req).await;
                assert!(matches!(result, PluginResult::Continue));

                // Verify header was added
                assert!(req.headers().contains_key("X-Concurrent"));
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }
    }
}
