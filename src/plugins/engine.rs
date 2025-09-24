use crate::config::{PluginErrorStrategy, PluginStage, PluginType, PluginsConfig};
use anyhow::Result;
use hyper::{Body, Request, Response};
use std::collections::HashMap;
use tracing::warn;

use super::builtin::HeaderInjector;
use super::traits::{PluginResult, RequestPlugin, ResponsePlugin};

#[cfg(feature = "wasm-plugin")]
use super::wasm::WasmPlugin;

/// Plugin engine for managing and executing plugins
pub struct PluginEngine {
    request_plugins: Vec<PluginRequestEntry>,
    response_plugins: Vec<PluginResponseEntry>,
    /// Whether request-stage plugins should run before domain interception check
    apply_before_domain_match: bool,
    // Fast lookup by plugin name
    request_index: HashMap<String, usize>,
    response_index: HashMap<String, usize>,
}

/// Entry for request plugins
pub struct PluginRequestEntry {
    pub name: String,
    pub strategy: PluginErrorStrategy,
    pub plugin: Box<dyn RequestPlugin + Send + Sync>,
}

/// Entry for response plugins
pub struct PluginResponseEntry {
    pub name: String,
    pub strategy: PluginErrorStrategy,
    pub plugin: Box<dyn ResponsePlugin + Send + Sync>,
}

impl PluginEngine {
    /// Create a new plugin engine from configuration
    pub fn new(config: &PluginsConfig) -> Result<Self> {
        let mut req = Vec::new();
        let mut resp = Vec::new();

        if config.enabled {
            for p in &config.plugins {
                if !p.enabled {
                    continue;
                }
                match p.plugin_type {
                    PluginType::HeaderInjector => {
                        let plugin = HeaderInjector::from_config(&p.name, p.config.as_ref())?;
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin.clone()),
                            });
                        }
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            resp.push(PluginResponseEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin),
                            });
                        }
                    }
                    PluginType::HeaderOverride => {
                        let plugin = HeaderInjector::from_config(&p.name, p.config.as_ref())?;
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin.clone()),
                            });
                        }
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            resp.push(PluginResponseEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin),
                            });
                        }
                    }
                    #[cfg(feature = "wasm-plugin")]
                    PluginType::Wasm => {
                        let plugin = WasmPlugin::from_config(&p.name, p.config.as_ref())?;
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin.clone()),
                            });
                        }
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            resp.push(PluginResponseEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin),
                            });
                        }
                    }
                    #[cfg(not(feature = "wasm-plugin"))]
                    PluginType::Wasm => {
                        return Err(anyhow::anyhow!(
                            "WASM plugin '{}' requires 'wasm-plugin' feature to be enabled",
                            p.name
                        ));
                    }
                    PluginType::Blocklist => {
                        let plugin =
                            super::builtin::Blocklist::from_config(&p.name, p.config.as_ref())?;
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry {
                                name: p.name.clone(),
                                strategy: p.error_strategy.clone(),
                                plugin: Box::new(plugin),
                            });
                        }
                        // Note: Blocklist only implements RequestPlugin, not ResponsePlugin
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            warn!(
                                "Blocklist plugin '{}' does not support response stage",
                                p.name
                            );
                        }
                    }
                    PluginType::PathRewrite | PluginType::HostRewrite | PluginType::RateLimiter => {
                        // These plugin types are not yet implemented
                        warn!(
                            "Plugin type {:?} for '{}' is not yet implemented",
                            p.plugin_type, p.name
                        );
                    }
                    PluginType::Command => {
                        #[cfg(feature = "cmd-plugin")]
                        {
                            let plugin = super::builtin::CommandPlugin::from_config(
                                &p.name,
                                p.config.as_ref(),
                            )?;
                            if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                                req.push(PluginRequestEntry {
                                    name: p.name.clone(),
                                    strategy: p.error_strategy.clone(),
                                    plugin: Box::new(plugin.clone()),
                                });
                            }
                            if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                                resp.push(PluginResponseEntry {
                                    name: p.name.clone(),
                                    strategy: p.error_strategy.clone(),
                                    plugin: Box::new(plugin),
                                });
                            }
                        }
                        #[cfg(not(feature = "cmd-plugin"))]
                        {
                            return Err(anyhow::anyhow!(
                                "Command plugin '{}' requires 'cmd-plugin' feature to be enabled",
                                p.name
                            ));
                        }
                    }
                }
            }
        }

        // Build fast lookup indices
        let mut request_index = HashMap::new();
        let mut response_index = HashMap::new();
        for (i, e) in req.iter().enumerate() {
            request_index.insert(e.name.clone(), i);
        }
        for (i, e) in resp.iter().enumerate() {
            response_index.insert(e.name.clone(), i);
        }

        Ok(Self {
            request_plugins: req,
            response_plugins: resp,
            apply_before_domain_match: config.apply_before_domain_match,
            request_index,
            response_index,
        })
    }

    /// Check if request plugins should run before domain matching
    pub fn apply_before_domain_match(&self) -> bool {
        self.apply_before_domain_match
    }

    /// Apply request plugins to the given request
    pub async fn apply_request(&self, req: &mut Request<Body>) -> PluginResult {
        for entry in &self.request_plugins {
            let result = entry.plugin.on_request(req);
            match result {
                PluginResult::Continue => {
                    if entry.plugin.last_error_and_clear() {
                        match entry.strategy {
                            PluginErrorStrategy::Fail => {
                                warn!("Plugin {} reported error, failing per strategy", entry.name);
                                return PluginResult::ShortCircuit(
                                    Response::builder()
                                        .status(500)
                                        .body(Body::from("Plugin error"))
                                        .expect("Building simple HTTP response should not fail"),
                                );
                            }
                            PluginErrorStrategy::Continue => {
                                warn!(
                                    "Plugin {} reported error, continuing per strategy",
                                    entry.name
                                );
                            }
                        }
                    }
                }
                PluginResult::ShortCircuit(resp) => return PluginResult::ShortCircuit(resp),
            }
        }
        PluginResult::Continue
    }

    /// Apply response plugins to the given response
    pub async fn apply_response(&self, resp: &mut Response<Body>) {
        for entry in &self.response_plugins {
            entry.plugin.on_response(resp);
            if entry.plugin.last_error_and_clear() {
                match entry.strategy {
                    PluginErrorStrategy::Fail => {
                        warn!(
                            "Response plugin {} reported error, failing per strategy",
                            entry.name
                        );
                        break;
                    }
                    PluginErrorStrategy::Continue => {
                        warn!(
                            "Response plugin {} reported error, continuing per strategy",
                            entry.name
                        );
                    }
                }
            }
        }
    }

    /// Get names of all request plugins
    pub fn request_plugin_names(&self) -> Vec<String> {
        self.request_plugins
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }

    /// Get names of all response plugins
    pub fn response_plugin_names(&self) -> Vec<String> {
        self.response_plugins
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }

    /// Apply only a subset of request plugins by name
    pub async fn apply_request_subset(
        &self,
        names: &[String],
        req: &mut Request<Body>,
    ) -> PluginResult {
        for name in names {
            if let Some(&index) = self.request_index.get(name) {
                if let Some(entry) = self.request_plugins.get(index) {
                    let result = entry.plugin.on_request(req);
                    match result {
                        PluginResult::Continue => {
                            if entry.plugin.last_error_and_clear() {
                                match entry.strategy {
                                    PluginErrorStrategy::Fail => {
                                        warn!(
                                            "Plugin {} reported error, failing per strategy",
                                            entry.name
                                        );
                                        return PluginResult::ShortCircuit(
                                            Response::builder()
                                                .status(500)
                                                .body(Body::from("Plugin error"))
                                                .expect(
                                                    "Building simple HTTP response should not fail",
                                                ),
                                        );
                                    }
                                    PluginErrorStrategy::Continue => {
                                        warn!(
                                            "Plugin {} reported error, continuing per strategy",
                                            entry.name
                                        );
                                    }
                                }
                            }
                        }
                        PluginResult::ShortCircuit(resp) => {
                            return PluginResult::ShortCircuit(resp)
                        }
                    }
                }
            }
        }
        PluginResult::Continue
    }

    /// Apply only a subset of response plugins by name
    pub async fn apply_response_subset(&self, names: &[String], resp: &mut Response<Body>) {
        for name in names {
            if let Some(&index) = self.response_index.get(name) {
                if let Some(entry) = self.response_plugins.get(index) {
                    entry.plugin.on_response(resp);
                    if entry.plugin.last_error_and_clear() {
                        match entry.strategy {
                            PluginErrorStrategy::Fail => {
                                warn!(
                                    "Response plugin {} reported error, failing per strategy",
                                    entry.name
                                );
                                break;
                            }
                            PluginErrorStrategy::Continue => {
                                warn!(
                                    "Response plugin {} reported error, continuing per strategy",
                                    entry.name
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::plugins::PluginConfig;
    use crate::config::{PluginErrorStrategy, PluginStage, PluginType, PluginsConfig};
    use hyper::{Method, StatusCode};
    use serde_json::json;

    fn create_header_injector_config(name: &str, stage: PluginStage) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            plugin_type: PluginType::HeaderInjector,
            stage,
            enabled: true,
            config: Some(json!({
                "request_headers": {
                    "X-Test": "test-value",
                    "X-Plugin": name
                },
                "response_headers": {
                    "X-Response-Test": "response-value",
                    "X-Response-Plugin": name
                }
            })),
            error_strategy: PluginErrorStrategy::Continue,
        }
    }

    fn create_blocklist_config(name: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            plugin_type: PluginType::Blocklist,
            stage: PluginStage::Request,
            enabled: true,
            config: Some(json!({
                "hosts": ["blocked.com"],
                "paths": ["/admin"]
            })),
            error_strategy: PluginErrorStrategy::Fail,
        }
    }

    #[test]
    fn test_plugin_engine_creation_empty_config() {
        let config = PluginsConfig {
            enabled: false,
            plugins: vec![],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert!(engine.request_plugins.is_empty());
        assert!(engine.response_plugins.is_empty());
        assert!(engine.apply_before_domain_match());
        assert!(engine.request_plugin_names().is_empty());
        assert!(engine.response_plugin_names().is_empty());
    }

    #[test]
    fn test_plugin_engine_disabled_globally() {
        let config = PluginsConfig {
            enabled: false,
            plugins: vec![create_header_injector_config("test", PluginStage::Both)],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert!(engine.request_plugins.is_empty());
        assert!(engine.response_plugins.is_empty());
    }

    #[test]
    fn test_plugin_engine_single_header_injector() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_header_injector_config(
                "test-injector",
                PluginStage::Both,
            )],
            apply_before_domain_match: false,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
        assert_eq!(engine.response_plugins.len(), 1);
        assert!(!engine.apply_before_domain_match());

        let req_names = engine.request_plugin_names();
        let resp_names = engine.response_plugin_names();
        assert_eq!(req_names, vec!["test-injector"]);
        assert_eq!(resp_names, vec!["test-injector"]);
    }

    #[test]
    fn test_plugin_engine_multiple_plugins() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("injector1", PluginStage::Request),
                create_header_injector_config("injector2", PluginStage::Response),
                create_header_injector_config("injector3", PluginStage::Both),
                create_blocklist_config("blocklist1"),
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 3); // injector1, injector3, blocklist1
        assert_eq!(engine.response_plugins.len(), 2); // injector2, injector3

        let req_names = engine.request_plugin_names();
        let resp_names = engine.response_plugin_names();
        assert!(req_names.contains(&"injector1".to_string()));
        assert!(req_names.contains(&"injector3".to_string()));
        assert!(req_names.contains(&"blocklist1".to_string()));
        assert!(resp_names.contains(&"injector2".to_string()));
        assert!(resp_names.contains(&"injector3".to_string()));
    }

    #[test]
    fn test_plugin_engine_disabled_individual_plugin() {
        let mut disabled_plugin = create_header_injector_config("disabled", PluginStage::Both);
        disabled_plugin.enabled = false;

        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("enabled", PluginStage::Both),
                disabled_plugin,
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
        assert_eq!(engine.response_plugins.len(), 1);

        let req_names = engine.request_plugin_names();
        assert_eq!(req_names, vec!["enabled"]);
        assert!(!req_names.contains(&"disabled".to_string()));
    }

    #[test]
    fn test_plugin_engine_header_override_type() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![PluginConfig {
                name: "override-test".to_string(),
                plugin_type: PluginType::HeaderOverride,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(json!({
                    "request_headers": {
                        "X-Override": "override-value"
                    }
                })),
                error_strategy: PluginErrorStrategy::Continue,
            }],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
        assert_eq!(engine.request_plugin_names(), vec!["override-test"]);
    }

    #[test]
    fn test_plugin_engine_blocklist_response_warning() {
        let mut blocklist_config = create_blocklist_config("test-blocklist");
        blocklist_config.stage = PluginStage::Both; // This should warn for response stage

        let config = PluginsConfig {
            enabled: true,
            plugins: vec![blocklist_config],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
        assert_eq!(engine.response_plugins.len(), 0); // Blocklist doesn't support response
    }

    #[test]
    fn test_plugin_engine_unimplemented_plugin_types() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                PluginConfig {
                    name: "path-rewrite".to_string(),
                    plugin_type: PluginType::PathRewrite,
                    stage: PluginStage::Request,
                    enabled: true,
                    config: None,
                    error_strategy: PluginErrorStrategy::Continue,
                },
                PluginConfig {
                    name: "host-rewrite".to_string(),
                    plugin_type: PluginType::HostRewrite,
                    stage: PluginStage::Request,
                    enabled: true,
                    config: None,
                    error_strategy: PluginErrorStrategy::Continue,
                },
                PluginConfig {
                    name: "rate-limiter".to_string(),
                    plugin_type: PluginType::RateLimiter,
                    stage: PluginStage::Request,
                    enabled: true,
                    config: None,
                    error_strategy: PluginErrorStrategy::Continue,
                },
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert!(engine.request_plugins.is_empty());
        assert!(engine.response_plugins.is_empty());
    }

    #[cfg(not(feature = "wasm-plugin"))]
    #[test]
    fn test_plugin_engine_wasm_without_feature() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![PluginConfig {
                name: "wasm-test".to_string(),
                plugin_type: PluginType::Wasm,
                stage: PluginStage::Request,
                enabled: true,
                config: None,
                error_strategy: PluginErrorStrategy::Continue,
            }],
            apply_before_domain_match: true,
        };

        let result = PluginEngine::new(&config);
        assert!(result.is_err());
        let error_msg = result.err().unwrap().to_string(); // OK in tests - error expected
        assert!(error_msg.contains("wasm-plugin' feature"));
    }

    #[cfg(not(feature = "cmd-plugin"))]
    #[test]
    fn test_plugin_engine_command_without_feature() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![PluginConfig {
                name: "cmd-test".to_string(),
                plugin_type: PluginType::Command,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(json!({"exec": "echo"})),
                error_strategy: PluginErrorStrategy::Continue,
            }],
            apply_before_domain_match: true,
        };

        let result = PluginEngine::new(&config);
        assert!(result.is_err());
        let error_msg = result.err().unwrap().to_string(); // OK in tests - error expected
        assert!(error_msg.contains("cmd-plugin' feature"));
    }

    #[tokio::test]
    async fn test_apply_request_plugins_continue() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_header_injector_config("test", PluginStage::Request)],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));

        // Check that headers were added
        assert_eq!(req.headers().get("X-Test").unwrap(), "test-value"); // OK in tests - header expected to exist
        assert_eq!(req.headers().get("X-Plugin").unwrap(), "test"); // OK in tests - header expected to exist
    }

    #[tokio::test]
    async fn test_apply_request_plugins_short_circuit() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_blocklist_config("test-blocklist")],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://blocked.com/test")
            .header("host", "blocked.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = engine.apply_request(&mut req).await;
        match result {
            PluginResult::ShortCircuit(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected short circuit result from blocklist"),
        }
    }

    #[tokio::test]
    async fn test_apply_response_plugins() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_header_injector_config("test", PluginStage::Response)],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("test body"))
            .unwrap(); // OK in tests - valid response

        engine.apply_response(&mut resp).await;

        // Check that headers were added
        assert_eq!(
            resp.headers().get("X-Response-Test").unwrap(), // OK in tests - header expected to exist
            "response-value"
        );
        assert_eq!(resp.headers().get("X-Response-Plugin").unwrap(), "test"); // OK in tests - header expected to exist
    }

    #[tokio::test]
    async fn test_apply_request_subset() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("plugin1", PluginStage::Request),
                create_header_injector_config("plugin2", PluginStage::Request),
                create_header_injector_config("plugin3", PluginStage::Request),
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        // Apply only plugin1 and plugin3
        let result = engine
            .apply_request_subset(&["plugin1".to_string(), "plugin3".to_string()], &mut req)
            .await;
        assert!(matches!(result, PluginResult::Continue));

        // Check that only the specified plugins ran
        assert_eq!(req.headers().get("X-Plugin").unwrap(), "plugin3"); // OK in tests - header expected to exist (last one wins)
        assert!(req.headers().get("X-Test").is_some());
    }

    #[tokio::test]
    async fn test_apply_request_subset_nonexistent_plugin() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_header_injector_config(
                "existing",
                PluginStage::Request,
            )],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        // Try to apply non-existent plugin
        let result = engine
            .apply_request_subset(&["nonexistent".to_string()], &mut req)
            .await;
        assert!(matches!(result, PluginResult::Continue));

        // No headers should be added
        assert!(req.headers().get("X-Test").is_none());
    }

    #[tokio::test]
    async fn test_apply_response_subset() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("plugin1", PluginStage::Response),
                create_header_injector_config("plugin2", PluginStage::Response),
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("test body"))
            .unwrap(); // OK in tests - valid response

        // Apply only plugin2
        engine
            .apply_response_subset(&["plugin2".to_string()], &mut resp)
            .await;

        // Check that only plugin2 ran
        assert_eq!(resp.headers().get("X-Response-Plugin").unwrap(), "plugin2");
        // OK in tests - header expected to exist
    }

    #[tokio::test]
    async fn test_apply_response_subset_nonexistent_plugin() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![create_header_injector_config(
                "existing",
                PluginStage::Response,
            )],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("test body"))
            .unwrap(); // OK in tests - valid response

        // Try to apply non-existent plugin
        engine
            .apply_response_subset(&["nonexistent".to_string()], &mut resp)
            .await;

        // No headers should be added
        assert!(resp.headers().get("X-Response-Test").is_none());
    }

    #[test]
    fn test_plugin_error_strategies() {
        let mut continue_config = create_header_injector_config("continue", PluginStage::Request);
        continue_config.error_strategy = PluginErrorStrategy::Continue;

        let mut fail_config = create_header_injector_config("fail", PluginStage::Request);
        fail_config.error_strategy = PluginErrorStrategy::Fail;

        let config = PluginsConfig {
            enabled: true,
            plugins: vec![continue_config, fail_config],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 2);

        // Check error strategies are correctly set
        assert!(matches!(
            engine.request_plugins[0].strategy,
            PluginErrorStrategy::Continue
        ));
        assert!(matches!(
            engine.request_plugins[1].strategy,
            PluginErrorStrategy::Fail
        ));
    }

    #[test]
    fn test_plugin_index_lookup() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("first", PluginStage::Request),
                create_header_injector_config("second", PluginStage::Response),
                create_header_injector_config("both", PluginStage::Both),
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config

        // Check request index
        assert!(engine.request_index.contains_key("first"));
        assert!(engine.request_index.contains_key("both"));
        assert!(!engine.request_index.contains_key("second"));

        // Check response index
        assert!(engine.response_index.contains_key("second"));
        assert!(engine.response_index.contains_key("both"));
        assert!(!engine.response_index.contains_key("first"));
    }

    #[test]
    fn test_plugin_stage_filtering() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                create_header_injector_config("request-only", PluginStage::Request),
                create_header_injector_config("response-only", PluginStage::Response),
                create_header_injector_config("both-stages", PluginStage::Both),
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config

        let req_names = engine.request_plugin_names();
        let resp_names = engine.response_plugin_names();

        assert_eq!(req_names.len(), 2); // request-only, both-stages
        assert_eq!(resp_names.len(), 2); // response-only, both-stages

        assert!(req_names.contains(&"request-only".to_string()));
        assert!(req_names.contains(&"both-stages".to_string()));
        assert!(!req_names.contains(&"response-only".to_string()));

        assert!(resp_names.contains(&"response-only".to_string()));
        assert!(resp_names.contains(&"both-stages".to_string()));
        assert!(!resp_names.contains(&"request-only".to_string()));
    }

    #[test]
    fn test_invalid_plugin_config() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![PluginConfig {
                name: "invalid-header".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                config: Some(json!({
                    "invalid_config": "this should not break"
                })),
                error_strategy: PluginErrorStrategy::Continue,
            }],
            apply_before_domain_match: true,
        };

        // Should still create engine successfully with empty config
        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
    }

    #[test]
    fn test_empty_plugin_config() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![PluginConfig {
                name: "empty-config".to_string(),
                plugin_type: PluginType::HeaderInjector,
                stage: PluginStage::Request,
                enabled: true,
                config: None,
                error_strategy: PluginErrorStrategy::Continue,
            }],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        assert_eq!(engine.request_plugins.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_plugins_execution_order() {
        let config = PluginsConfig {
            enabled: true,
            plugins: vec![
                PluginConfig {
                    name: "first".to_string(),
                    plugin_type: PluginType::HeaderInjector,
                    stage: PluginStage::Request,
                    enabled: true,
                    config: Some(json!({
                        "request_headers": {
                            "X-Order": "first"
                        }
                    })),
                    error_strategy: PluginErrorStrategy::Continue,
                },
                PluginConfig {
                    name: "second".to_string(),
                    plugin_type: PluginType::HeaderInjector,
                    stage: PluginStage::Request,
                    enabled: true,
                    config: Some(json!({
                        "request_headers": {
                            "X-Order": "second"
                        }
                    })),
                    error_strategy: PluginErrorStrategy::Continue,
                },
            ],
            apply_before_domain_match: true,
        };

        let engine = PluginEngine::new(&config).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));

        // Last plugin should win for the same header
        assert_eq!(req.headers().get("X-Order").unwrap(), "second"); // OK in tests - header expected to exist
    }
}
