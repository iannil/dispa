//! 路由配置结构定义
//!
//! 本模块包含路由系统的配置结构体，包括路由规则、条件和动作的定义。

use crate::error::{DispaError, DispaResult};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// 高级路由配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// 按顺序评估的路由规则列表
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    /// 当没有规则匹配时的默认目标
    pub default_target: Option<String>,
    /// 为路由决策启用请求/响应日志记录
    #[serde(default)]
    pub enable_logging: bool,
}

impl RoutingConfig {
    /// 验证路由配置
    pub fn validate(&self) -> DispaResult<()> {
        // 验证路由规则
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(DispaError::config(format!(
                    "Routing rule {} has empty name",
                    i
                )));
            }

            if rule.target.is_empty() {
                return Err(DispaError::config(format!(
                    "Routing rule '{}' has empty target",
                    rule.name
                )));
            }

            // 验证条件中的正则表达式模式
            if let Some(path_conditions) = &rule.conditions.path {
                if let Some(regex_pattern) = &path_conditions.regex {
                    Regex::new(regex_pattern).map_err(|e| {
                        DispaError::config(format!(
                            "Invalid path regex in rule '{}': {}",
                            rule.name, e
                        ))
                    })?;
                }
            }

            // 验证头部条件中的正则表达式
            if let Some(header_conditions) = &rule.conditions.headers {
                for header_condition in header_conditions {
                    if let Some(regex_pattern) = header_condition.value_regex.as_ref() {
                        Regex::new(regex_pattern).map_err(|e| {
                            DispaError::config(format!(
                                "Invalid header regex in rule '{}': {}",
                                rule.name, e
                            ))
                        })?;
                    }
                }
            }

            // 验证查询参数条件中的正则表达式
            if let Some(query_conditions) = &rule.conditions.query_params {
                for query_condition in query_conditions {
                    if let Some(regex_pattern) = query_condition.value_regex.as_ref() {
                        Regex::new(regex_pattern).map_err(|e| {
                            DispaError::config(format!(
                                "Invalid query param regex in rule '{}': {}",
                                rule.name, e
                            ))
                        })?;
                    }
                }
            }

            // 验证主机条件中的正则表达式
            if let Some(host_condition) = &rule.conditions.host {
                if let Some(regex_pattern) = &host_condition.regex {
                    Regex::new(regex_pattern).map_err(|e| {
                        DispaError::config(format!(
                            "Invalid host regex in rule '{}': {}",
                            rule.name, e
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }
}

/// 路由规则定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// 规则名称（用于日志记录和调试）
    pub name: String,
    /// 规则的优先级（数字越小优先级越高）
    #[serde(default)]
    pub priority: i32,
    /// 目标后端服务器标识符
    pub target: String,
    /// 路由条件
    pub conditions: super::conditions::RoutingConditions,
    /// 要应用的请求修改
    pub request_actions: Option<super::actions::RoutingActions>,
    /// 要应用的响应修改
    pub response_actions: Option<super::actions::RoutingActions>,
    /// 自定义响应（如果适用）
    pub custom_response: Option<super::actions::CustomResponse>,
    /// 要应用的路由特定插件（按名称的子集）
    #[allow(dead_code)]
    pub plugins_request: Option<Vec<String>>,
    #[allow(dead_code)]
    pub plugins_response: Option<Vec<String>>,
    #[allow(dead_code)]
    pub plugins_order: Option<PluginOrder>,
    #[allow(dead_code)]
    pub plugins_dedup: Option<bool>,
}

/// 插件排序选项
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginOrder {
    AsListed,
    NameAsc,
    NameDesc,
    PriorityAsc,
    PriorityDesc,
}
