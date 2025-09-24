use serde::{Deserialize, Serialize};

/// Plugins configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginsConfig {
    pub enabled: bool,
    pub plugins: Vec<PluginConfig>,
    /// Whether plugins should run before domain interception check
    pub apply_before_domain_match: bool,
}

impl PluginsConfig {
    /// Validate plugins configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        for plugin in &self.plugins {
            plugin.validate()?;
        }
        Ok(())
    }

    /// Get enabled plugins
    #[allow(dead_code)]
    pub fn get_enabled_plugins(&self) -> Vec<&PluginConfig> {
        self.plugins.iter().filter(|p| p.enabled).collect()
    }
}

/// Individual plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginConfig {
    pub name: String,
    pub plugin_type: PluginType,
    pub enabled: bool,
    pub stage: PluginStage,
    pub config: Option<serde_json::Value>,
    pub error_strategy: PluginErrorStrategy,
}

impl PluginConfig {
    /// Validate plugin configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            return Err(anyhow::anyhow!("Plugin name cannot be empty"));
        }

        // Plugin-specific validation could be added here
        match self.plugin_type {
            PluginType::Command => {
                // Command plugin requires 'exec' in config
                if let Some(config) = &self.config {
                    if config
                        .get("exec")
                        .and_then(|v| v.as_str())
                        .is_none_or(|s| s.is_empty())
                    {
                        return Err(anyhow::anyhow!(
                            "Command plugin '{}' requires 'exec' configuration",
                            self.name
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Command plugin '{}' requires configuration",
                        self.name
                    ));
                }
            }
            PluginType::Wasm => {
                // WASM plugin requires 'module_path' in config
                if let Some(config) = &self.config {
                    if config
                        .get("module_path")
                        .and_then(|v| v.as_str())
                        .is_none_or(|s| s.is_empty())
                    {
                        return Err(anyhow::anyhow!(
                            "WASM plugin '{}' requires 'module_path' configuration",
                            self.name
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "WASM plugin '{}' requires configuration",
                        self.name
                    ));
                }
            }
            _ => {
                // Other plugin types have optional configuration
            }
        }

        Ok(())
    }
}

/// Plugin types
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum PluginType {
    HeaderInjector,
    Blocklist,
    HeaderOverride,
    PathRewrite,
    HostRewrite,
    Command,
    RateLimiter,
    Wasm,
}

/// Plugin execution stages
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum PluginStage {
    Request,
    Response,
    Both,
}

/// Plugin error handling strategies
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub enum PluginErrorStrategy {
    Continue,
    Fail,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugins: vec![],
            apply_before_domain_match: true,
        }
    }
}

impl Default for PluginErrorStrategy {
    fn default() -> Self {
        Self::Continue
    }
}
