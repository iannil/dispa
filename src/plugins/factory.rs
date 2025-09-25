use crate::config::plugins::PluginConfig;
use crate::config::{PluginStage, PluginType, PluginsConfig};
use anyhow::Result;
use std::collections::HashMap;
use tracing::warn;

use super::builtin::HeaderInjector;
use super::traits::RequestPlugin;

#[cfg(feature = "wasm-plugin")]
use super::wasm::WasmPlugin;

/// 插件工厂，负责创建各种类型的插件实例
pub struct PluginFactory;

impl PluginFactory {
    /// 根据配置创建请求阶段插件
    pub fn create_request_plugin(
        config: &PluginConfig,
    ) -> Result<Option<Box<dyn RequestPlugin + Send + Sync>>> {
        if !config.enabled {
            return Ok(None);
        }

        let plugin: Box<dyn RequestPlugin + Send + Sync> = match config.plugin_type {
            PluginType::HeaderInjector => {
                let header_injector =
                    HeaderInjector::from_config(&config.name, config.config.as_ref())?;
                Box::new(header_injector)
            }
            PluginType::HeaderOverride => {
                let header_injector =
                    HeaderInjector::from_config(&config.name, config.config.as_ref())?;
                Box::new(header_injector)
            }
            #[cfg(feature = "wasm-plugin")]
            PluginType::Wasm => {
                // WASM插件需要配置中指定路径
                if let Some(config_value) = &config.config {
                    if config_value.get("path").and_then(|v| v.as_str()).is_some() {
                        let wasm_plugin =
                            WasmPlugin::from_config(&config.name, config.config.as_ref())?;
                        Box::new(wasm_plugin)
                    } else {
                        return Err(anyhow::anyhow!(
                            "WASM plugin '{}' requires 'path' parameter in config",
                            config.name
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "WASM plugin '{}' requires configuration with 'path' parameter",
                        config.name
                    ));
                }
            }
            #[cfg(not(feature = "wasm-plugin"))]
            PluginType::Wasm => {
                warn!(
                    "WASM plugin '{}' requested but feature 'wasm-plugin' not enabled",
                    config.name
                );
                return Ok(None);
            }
            _ => {
                warn!(
                    "Plugin type {:?} not implemented for request stage, plugin '{}' skipped",
                    config.plugin_type, config.name
                );
                return Ok(None);
            }
        };

        Ok(Some(plugin))
    }

    /// 根据配置创建响应阶段插件
    pub fn create_response_plugin(
        config: &PluginConfig,
    ) -> Result<Option<Box<dyn super::traits::ResponsePlugin + Send + Sync>>> {
        if !config.enabled {
            return Ok(None);
        }

        match config.plugin_type {
            PluginType::HeaderInjector => {
                let header_injector = HeaderInjector::from_config(&config.name, config.config.as_ref())?;
                Ok(Some(Box::new(header_injector)))
            }
            PluginType::Blocklist => {
                // Blocklist is typically request-only
                Ok(None)
            }
            PluginType::Wasm => {
                // WASM plugins could potentially support response stage
                // but not implemented yet
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

/// 插件注册表，管理插件的索引和查找
pub struct PluginRegistry {
    request_index: HashMap<String, usize>,
    response_index: HashMap<String, usize>,
}

impl PluginRegistry {
    /// 创建新的插件注册表
    pub fn new() -> Self {
        Self {
            request_index: HashMap::new(),
            response_index: HashMap::new(),
        }
    }

    /// 注册请求插件
    pub fn register_request_plugin(&mut self, name: String, index: usize) {
        self.request_index.insert(name, index);
    }

    /// 注册响应插件
    pub fn register_response_plugin(&mut self, name: String, index: usize) {
        self.response_index.insert(name, index);
    }

    /// 根据名称查找请求插件索引
    pub fn find_request_plugin(&self, name: &str) -> Option<usize> {
        self.request_index.get(name).copied()
    }

    /// 根据名称查找响应插件索引
    pub fn find_response_plugin(&self, name: &str) -> Option<usize> {
        self.response_index.get(name).copied()
    }

    /// 获取所有请求插件名称
    pub fn request_plugin_names(&self) -> Vec<String> {
        self.request_index.keys().cloned().collect()
    }

    /// 获取所有响应插件名称
    pub fn response_plugin_names(&self) -> Vec<String> {
        self.response_index.keys().cloned().collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// 插件配置验证器
pub struct PluginValidator;

impl PluginValidator {
    /// 验证插件配置的有效性
    pub fn validate_config(config: &PluginConfig) -> Result<()> {
        // 检查插件名称
        if config.name.trim().is_empty() {
            return Err(anyhow::anyhow!("Plugin name cannot be empty"));
        }

        // 检查WASM插件的路径
        if matches!(config.plugin_type, PluginType::Wasm) {
            if let Some(config_value) = &config.config {
                if config_value.get("path").is_none() {
                    return Err(anyhow::anyhow!(
                        "WASM plugin '{}' requires 'path' parameter in config",
                        config.name
                    ));
                }
            } else {
                return Err(anyhow::anyhow!(
                    "WASM plugin '{}' requires configuration with 'path' parameter",
                    config.name
                ));
            }
        }

        // 检查阶段设置
        if matches!(config.stage, PluginStage::Both) {
            warn!(
                "Plugin '{}' configured for both request and response stages. This may impact performance.",
                config.name
            );
        }

        Ok(())
    }

    /// 验证整个插件配置
    pub fn validate_plugins_config(config: &PluginsConfig) -> Result<()> {
        if !config.enabled {
            return Ok(());
        }

        // 检查插件名称唯一性
        let mut plugin_names = std::collections::HashSet::new();
        for plugin in &config.plugins {
            if !plugin_names.insert(&plugin.name) {
                return Err(anyhow::anyhow!("Duplicate plugin name: '{}'", plugin.name));
            }

            // 验证单个插件配置
            Self::validate_config(plugin)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::plugins::{PluginConfig, PluginErrorStrategy, PluginStage, PluginType};
    // no extra imports needed

    fn create_test_plugin_config(name: &str, plugin_type: PluginType) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            plugin_type,
            stage: PluginStage::Request,
            enabled: true,
            error_strategy: PluginErrorStrategy::Continue,
            config: None,
        }
    }

    #[test]
    fn test_plugin_factory_header_injector() {
        let config = create_test_plugin_config("test-header", PluginType::HeaderInjector);
        let result = PluginFactory::create_request_plugin(&config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_plugin_factory_disabled_plugin() {
        let mut config = create_test_plugin_config("disabled", PluginType::HeaderInjector);
        config.enabled = false;

        let result = PluginFactory::create_request_plugin(&config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_plugin_registry_request_plugins() {
        let mut registry = PluginRegistry::new();

        registry.register_request_plugin("plugin1".to_string(), 0);
        registry.register_request_plugin("plugin2".to_string(), 1);

        assert_eq!(registry.find_request_plugin("plugin1"), Some(0));
        assert_eq!(registry.find_request_plugin("plugin2"), Some(1));
        assert_eq!(registry.find_request_plugin("nonexistent"), None);

        let names = registry.request_plugin_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"plugin1".to_string()));
        assert!(names.contains(&"plugin2".to_string()));
    }

    #[test]
    fn test_plugin_validator_valid_config() {
        let config = create_test_plugin_config("valid", PluginType::HeaderInjector);
        let result = PluginValidator::validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_plugin_validator_empty_name() {
        let mut config = create_test_plugin_config("", PluginType::HeaderInjector);
        config.name = "".to_string();

        let result = PluginValidator::validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name cannot be empty"));
    }

    #[test]
    fn test_plugin_validator_wasm_without_path() {
        let config = create_test_plugin_config("wasm-plugin", PluginType::Wasm);

        let result = PluginValidator::validate_config(&config);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("requires configuration with 'path' parameter"));
    }
}
