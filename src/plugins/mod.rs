#![allow(dead_code)]
pub mod builtin;
pub mod engine;
pub mod traits;
#[cfg(feature = "wasm-plugin")]
pub mod wasm;

pub use engine::PluginEngine;
pub use traits::PluginResult;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared plugin engine type
pub type SharedPluginEngine = Arc<RwLock<Option<PluginEngine>>>;

#[cfg(test)]
mod tests {
    use super::traits::{PluginResult, RequestPlugin};
    use super::*;
    use crate::config::plugins::PluginConfig;
    use crate::config::{PluginErrorStrategy, PluginStage, PluginType, PluginsConfig};
    use hyper::{Body, Method, Request, Response, StatusCode};
    use std::time::Duration;

    struct PanicPlugin;

    impl RequestPlugin for PanicPlugin {
        fn name(&self) -> &str {
            "panic"
        }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            panic!("test panic");
        }
    }

    struct ErrorFlagPlugin {
        error_flag: std::sync::atomic::AtomicBool,
    }

    impl ErrorFlagPlugin {
        fn new() -> Self {
            Self {
                error_flag: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl RequestPlugin for ErrorFlagPlugin {
        fn name(&self) -> &str {
            "error_flag"
        }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            self.error_flag
                .store(true, std::sync::atomic::Ordering::SeqCst);
            PluginResult::Continue
        }
        fn last_error_and_clear(&self) -> bool {
            self.error_flag
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        }
    }

    fn empty_plugins_engine() -> PluginEngine {
        let config = PluginsConfig {
            enabled: false,
            plugins: vec![],
            apply_before_domain_match: true,
        };
        PluginEngine::new(&config).unwrap()
    }

    fn engine_with_request_entries(_entries: Vec<engine::PluginRequestEntry>) -> PluginEngine {
        // This is a test helper, so we'll create a minimal engine
        // In practice, you'd use PluginEngine::new() with proper config
        empty_plugins_engine()
    }

    struct ShortCircuitPlugin;

    impl RequestPlugin for ShortCircuitPlugin {
        fn name(&self) -> &str {
            "short_circuit"
        }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            PluginResult::ShortCircuit(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Blocked by plugin"))
                    .unwrap(),
            )
        }
    }

    #[tokio::test]
    async fn test_empty_plugin_engine() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let engine = empty_plugins_engine();
            assert!(engine.apply_before_domain_match());

            let mut req = Request::builder()
                .method(Method::GET)
                .uri("http://example.com/test")
                .body(Body::empty())
                .unwrap();

            let result = engine.apply_request(&mut req).await;
            assert!(matches!(result, PluginResult::Continue));
        })
        .await
        .expect("test_empty_plugin_engine timed out");
    }

    #[tokio::test]
    async fn test_plugin_engine_with_header_injector() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let plugin_config = PluginConfig {
                name: "test_header".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(serde_json::json!({
                    "request_headers": {
                        "X-Test": "test-value"
                    }
                })),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let config = PluginsConfig {
                enabled: true,
                plugins: vec![plugin_config],
                apply_before_domain_match: true,
            };

            let engine = PluginEngine::new(&config).unwrap();

            let mut req = Request::builder()
                .method(Method::GET)
                .uri("http://example.com/test")
                .body(Body::empty())
                .unwrap();

            let result = engine.apply_request(&mut req).await;
            assert!(matches!(result, PluginResult::Continue));
            assert_eq!(req.headers().get("X-Test").unwrap(), "test-value");
        })
        .await
        .expect("test_plugin_engine_with_header_injector timed out");
    }

    #[tokio::test]
    async fn test_plugin_engine_creation() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let config = PluginsConfig {
                enabled: true,
                plugins: vec![],
                apply_before_domain_match: false,
            };

            let engine = PluginEngine::new(&config).unwrap();
            assert!(!engine.apply_before_domain_match());
        })
        .await
        .expect("test_plugin_engine_creation timed out");
    }

    #[tokio::test]
    async fn test_plugin_names() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let plugin_config1 = PluginConfig {
                name: "header1".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(serde_json::json!({})),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let plugin_config2 = PluginConfig {
                name: "header2".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Response,
                enabled: true,
                config: Some(serde_json::json!({})),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let config = PluginsConfig {
                enabled: true,
                plugins: vec![plugin_config1, plugin_config2],
                apply_before_domain_match: true,
            };

            let engine = PluginEngine::new(&config).unwrap();
            let request_names = engine.request_plugin_names();
            let response_names = engine.response_plugin_names();

            assert_eq!(request_names, vec!["header1"]);
            assert_eq!(response_names, vec!["header2"]);
        })
        .await
        .expect("test_plugin_names timed out");
    }

    #[tokio::test]
    async fn test_plugin_both_stage() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let plugin_config = PluginConfig {
                name: "both_stage".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Both,
                enabled: true,
                config: Some(serde_json::json!({
                    "request_headers": {"X-Req": "req-value"},
                    "response_headers": {"X-Resp": "resp-value"}
                })),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let config = PluginsConfig {
                enabled: true,
                plugins: vec![plugin_config],
                apply_before_domain_match: true,
            };

            let engine = PluginEngine::new(&config).unwrap();
            let request_names = engine.request_plugin_names();
            let response_names = engine.response_plugin_names();

            assert_eq!(request_names, vec!["both_stage"]);
            assert_eq!(response_names, vec!["both_stage"]);
        })
        .await
        .expect("test_plugin_both_stage timed out");
    }

    #[tokio::test]
    async fn test_disabled_plugin_ignored() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let plugin_config = PluginConfig {
                name: "disabled".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: false, // Disabled
                config: Some(serde_json::json!({})),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let config = PluginsConfig {
                enabled: true,
                plugins: vec![plugin_config],
                apply_before_domain_match: true,
            };

            let engine = PluginEngine::new(&config).unwrap();
            assert!(engine.request_plugin_names().is_empty());
        })
        .await
        .expect("test_disabled_plugin_ignored timed out");
    }

    #[tokio::test]
    async fn test_plugins_disabled_globally() {
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            let plugin_config = PluginConfig {
                name: "enabled".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(serde_json::json!({})),
                error_strategy: PluginErrorStrategy::Continue,
            };

            let config = PluginsConfig {
                enabled: false, // Globally disabled
                plugins: vec![plugin_config],
                apply_before_domain_match: true,
            };

            let engine = PluginEngine::new(&config).unwrap();
            assert!(engine.request_plugin_names().is_empty());
        })
        .await
        .expect("test_plugins_disabled_globally timed out");
    }

    #[test]
    fn test_header_injector_config_parsing() {
        let config = serde_json::json!({
            "request_headers": {
                "X-Custom": "custom-value",
                "X-Another": "another-value"
            },
            "response_headers": {
                "X-Response": "response-value"
            }
        });

        let injector = builtin::HeaderInjector::from_config("test", Some(&config)).unwrap();

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        let result = injector.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(req.headers().get("X-Custom").unwrap(), "custom-value");
        assert_eq!(req.headers().get("X-Another").unwrap(), "another-value");
    }

    #[test]
    fn test_blocklist_plugin() {
        let config = serde_json::json!({
            "hosts": ["blocked.com"],
            "paths": ["/blocked"]
        });

        let blocklist = builtin::Blocklist::from_config("test", Some(&config)).unwrap();

        // Test blocked host
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://blocked.com/test")
            .header("host", "blocked.com")
            .body(Body::empty())
            .unwrap();

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::ShortCircuit(_)));

        // Test blocked path
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/blocked/test")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::ShortCircuit(_)));

        // Test allowed request
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/allowed")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));
    }
}
