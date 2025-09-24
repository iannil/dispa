use crate::config::{PluginStage, PluginsConfig};
use anyhow::Result;
use hyper::{Body, Request, Response};

use super::executor::{PluginExecutor, PluginRequestEntry, PluginResponseEntry};
use super::factory::{PluginFactory, PluginRegistry, PluginValidator};
use super::traits::PluginResult;

/// Plugin engine for managing and executing plugins
///
/// The plugin engine is responsible for:
/// - Initializing plugins based on configuration
/// - Managing plugin execution order and error handling strategies
/// - Providing plugin lookup and subset execution capabilities
///
/// # Examples
///
/// ```
/// use dispa::config::PluginsConfig;
///
/// let config = PluginsConfig::default();
/// let engine = PluginEngine::new(&config)?;
/// ```
pub struct PluginEngine {
    request_plugins: Vec<PluginRequestEntry>,
    response_plugins: Vec<PluginResponseEntry>,
    /// Request plugins should run before domain interception check
    apply_before_domain_match: bool,
    /// Plugin registry for fast lookup
    registry: PluginRegistry,
}

impl PluginEngine {
    /// Create a new plugin engine from configuration
    ///
    /// This initializes all enabled plugins based on the provided configuration.
    /// Plugins are created for their configured stages (Request, Response, or Both)
    /// and registered for quick lookup.
    ///
    /// # Parameters
    ///
    /// * `config` - Plugin configuration including enabled plugins and their settings
    ///
    /// # Returns
    ///
    /// Returns `Ok(PluginEngine)` on success, `Err` if configuration validation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use dispa::config::PluginsConfig;
    ///
    /// let config = PluginsConfig {
    ///     enabled: true,
    ///     apply_before_domain_match: false,
    ///     plugins: vec![],
    /// };
    /// let engine = PluginEngine::new(&config).unwrap();
    /// ```
    pub fn new(config: &PluginsConfig) -> Result<Self> {
        // 验证配置
        PluginValidator::validate_plugins_config(config)?;

        if !config.enabled {
            return Ok(Self {
                request_plugins: Vec::new(),
                response_plugins: Vec::new(),
                apply_before_domain_match: false,
                registry: PluginRegistry::new(),
            });
        }

        let mut request_plugins = Vec::new();
        let mut response_plugins = Vec::new();
        let mut registry = PluginRegistry::new();

        // 处理每个插件配置
        for plugin_config in &config.plugins {
            if !plugin_config.enabled {
                continue;
            }

            // 根据阶段创建相应的插件
            match plugin_config.stage {
                PluginStage::Request | PluginStage::Both => {
                    if let Some(plugin) = PluginFactory::create_request_plugin(plugin_config)? {
                        let entry = PluginExecutor::create_request_entry(
                            plugin_config.name.clone(),
                            plugin_config.error_strategy,
                            plugin,
                        );

                        let index = request_plugins.len();
                        registry.register_request_plugin(plugin_config.name.clone(), index);
                        request_plugins.push(entry);
                    }
                }
                _ => {}
            }

            match plugin_config.stage {
                PluginStage::Response | PluginStage::Both => {
                    if let Some(plugin) = PluginFactory::create_response_plugin(plugin_config)? {
                        let entry = PluginExecutor::create_response_entry(
                            plugin_config.name.clone(),
                            plugin_config.error_strategy,
                            plugin,
                        );

                        let index = response_plugins.len();
                        registry.register_response_plugin(plugin_config.name.clone(), index);
                        response_plugins.push(entry);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            request_plugins,
            response_plugins,
            apply_before_domain_match: config.apply_before_domain_match,
            registry,
        })
    }

    /// Check if request plugins should be applied before domain matching
    ///
    /// # Returns
    ///
    /// `true` if request plugins should run before domain interception checks
    pub fn apply_before_domain_match(&self) -> bool {
        self.apply_before_domain_match
    }

    /// Apply request plugins to an HTTP request
    ///
    /// Executes all enabled request-stage plugins in order. Plugins may modify
    /// the request or return a short-circuit response.
    ///
    /// # Parameters
    ///
    /// * `req` - Mutable reference to the HTTP request
    ///
    /// # Returns
    ///
    /// * `PluginResult::Continue` - Continue processing the request
    /// * `PluginResult::ShortCircuit(response)` - Return the provided response immediately
    pub async fn apply_request(&self, req: &mut Request<Body>) -> PluginResult {
        PluginExecutor::execute_request_plugins(&self.request_plugins, req).await
    }

    /// Apply response plugins to an HTTP response
    ///
    /// Executes all enabled response-stage plugins in order. Unlike request
    /// plugins, response plugins cannot short-circuit the flow.
    ///
    /// # Parameters
    ///
    /// * `resp` - Mutable reference to the HTTP response
    pub async fn apply_response(&self, resp: &mut Response<Body>) {
        PluginExecutor::execute_response_plugins(&self.response_plugins, resp).await;
    }

    /// Get names of all request plugins
    ///
    /// # Returns
    ///
    /// Vector of plugin names configured for the request stage
    pub fn request_plugin_names(&self) -> Vec<String> {
        self.registry.request_plugin_names()
    }

    /// Get names of all response plugins
    ///
    /// # Returns
    ///
    /// Vector of plugin names configured for the response stage
    pub fn response_plugin_names(&self) -> Vec<String> {
        self.registry.response_plugin_names()
    }

    /// Apply only a subset of request plugins by name
    ///
    /// This allows selective execution of specific request plugins rather
    /// than running all configured plugins.
    ///
    /// # Parameters
    ///
    /// * `names` - Names of plugins to execute
    /// * `req` - Mutable reference to the HTTP request
    ///
    /// # Returns
    ///
    /// * `PluginResult::Continue` - Continue processing the request
    /// * `PluginResult::ShortCircuit(response)` - Return the provided response immediately
    pub async fn apply_request_subset(
        &self,
        names: &[String],
        req: &mut Request<Body>,
    ) -> PluginResult {
        let indices: Vec<usize> = names
            .iter()
            .filter_map(|name| self.registry.find_request_plugin(name))
            .collect();

        PluginExecutor::execute_request_plugins_subset(&self.request_plugins, &indices, req).await
    }

    /// Apply only a subset of response plugins by name
    ///
    /// This allows selective execution of specific response plugins rather
    /// than running all configured plugins.
    ///
    /// # Parameters
    ///
    /// * `names` - Names of plugins to execute
    /// * `resp` - Mutable reference to the HTTP response
    pub async fn apply_response_subset(&self, names: &[String], resp: &mut Response<Body>) {
        let indices: Vec<usize> = names
            .iter()
            .filter_map(|name| self.registry.find_response_plugin(name))
            .collect();

        let plugins_subset: Vec<&PluginResponseEntry> = indices
            .iter()
            .filter_map(|&index| self.response_plugins.get(index))
            .collect();

        for entry in plugins_subset {
            entry.plugin.on_response(resp);
            // 注意：这里调用私有方法，需要调整
            if entry.plugin.last_error_and_clear() {
                use crate::config::PluginErrorStrategy;
                use tracing::warn;

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

    /// Get plugin count statistics
    ///
    /// # Returns
    ///
    /// Tuple of (request_plugin_count, response_plugin_count)
    pub fn plugin_count(&self) -> (usize, usize) {
        (self.request_plugins.len(), self.response_plugins.len())
    }

    /// Check if any plugins are enabled
    ///
    /// # Returns
    ///
    /// `true` if there are any request or response plugins configured
    pub fn has_plugins(&self) -> bool {
        !self.request_plugins.is_empty() || !self.response_plugins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::plugins::{PluginConfig, PluginType, PluginStage, PluginErrorStrategy, PluginsConfig};
    use std::collections::HashMap;

    fn create_test_plugins_config(enabled: bool) -> PluginsConfig {
        PluginsConfig {
            enabled,
            apply_before_domain_match: false,
            plugins: vec![
                PluginConfig {
                    name: "header-injector".to_string(),
                    plugin_type: PluginType::HeaderInjector,
                    stage: PluginStage::Request,
                    enabled: true,
                    error_strategy: PluginErrorStrategy::Continue,
                    config: None,
                },
            ],
        }
    }

    #[tokio::test]
    async fn test_plugin_engine_disabled() {
        let config = create_test_plugins_config(false);
        let engine = PluginEngine::new(&config).unwrap();

        assert_eq!(engine.plugin_count(), (0, 0));
        assert!(!engine.has_plugins());
        assert!(!engine.apply_before_domain_match());
    }

    #[tokio::test]
    async fn test_plugin_engine_enabled() {
        let config = create_test_plugins_config(true);
        let engine = PluginEngine::new(&config).unwrap();

        assert_eq!(engine.plugin_count(), (1, 0));
        assert!(engine.has_plugins());

        let names = engine.request_plugin_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "header-injector");
    }

    #[tokio::test]
    async fn test_plugin_engine_apply_request() {
        let config = create_test_plugins_config(true);
        let engine = PluginEngine::new(&config).unwrap();

        let mut req = hyper::Request::builder()
            .uri("/test")
            .body(hyper::Body::empty())
            .unwrap();

        let result = engine.apply_request(&mut req).await;
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn test_plugin_engine_apply_response() {
        let config = create_test_plugins_config(true);
        let engine = PluginEngine::new(&config).unwrap();

        let mut resp = hyper::Response::builder()
            .status(200)
            .body(hyper::Body::empty())
            .unwrap();

        // 这应该不会panic，即使没有响应插件
        engine.apply_response(&mut resp).await;
    }

    #[tokio::test]
    async fn test_plugin_engine_subset_execution() {
        let config = create_test_plugins_config(true);
        let engine = PluginEngine::new(&config).unwrap();

        let mut req = hyper::Request::builder()
            .uri("/test")
            .body(hyper::Body::empty())
            .unwrap();

        let subset_names = vec!["header-injector".to_string()];
        let result = engine.apply_request_subset(&subset_names, &mut req).await;
        assert!(matches!(result, PluginResult::Continue));

        // 测试不存在的插件名称
        let nonexistent_names = vec!["nonexistent".to_string()];
        let result = engine.apply_request_subset(&nonexistent_names, &mut req).await;
        assert!(matches!(result, PluginResult::Continue));
    }
}