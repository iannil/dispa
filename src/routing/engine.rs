//! 路由引擎实现
//!
//! 本模块包含主要的路由决策引擎和相关功能。

use crate::error::DispaResult;
use hyper::{Body, Request};
use std::collections::HashMap;

/// 路由决策结果
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// 选择的目标后端服务器
    pub target: String,
    /// 匹配的规则名称（用于日志记录）
    pub rule_name: Option<String>,
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
    pub plugins_order: Option<super::config::PluginOrder>,
    #[allow(dead_code)]
    pub plugins_dedup: Option<bool>,
}

/// 路由引擎主结构
pub struct RoutingEngine {
    config: super::config::RoutingConfig,
    /// 编译后的正则表达式缓存
    #[allow(dead_code)]
    regex_cache: HashMap<String, regex::Regex>,
}

impl RoutingEngine {
    /// 创建新的路由引擎
    pub fn new(config: super::config::RoutingConfig) -> DispaResult<Self> {
        // 验证配置
        config.validate()?;

        Ok(Self {
            config,
            regex_cache: HashMap::new(),
        })
    }

    /// 根据请求进行路由决策
    pub async fn route_request(&self, req: &Request<Body>) -> RoutingDecision {
        // 遍历规则并找到第一个匹配的
        for rule in &self.config.rules {
            if self.matches_rule(req, rule).await {
                return RoutingDecision {
                    target: rule.target.clone(),
                    rule_name: Some(rule.name.clone()),
                    request_actions: rule.request_actions.clone(),
                    response_actions: rule.response_actions.clone(),
                    custom_response: rule.custom_response.clone(),
                    plugins_request: rule.plugins_request.clone(),
                    plugins_response: rule.plugins_response.clone(),
                    plugins_order: rule.plugins_order.clone(),
                    plugins_dedup: rule.plugins_dedup,
                };
            }
        }

        // 如果没有规则匹配，使用默认目标
        RoutingDecision {
            target: self.config.default_target.clone().unwrap_or_default(),
            rule_name: None,
            request_actions: None,
            response_actions: None,
            custom_response: None,
            plugins_request: None,
            plugins_response: None,
            plugins_order: None,
            plugins_dedup: None,
        }
    }

    /// 检查请求是否匹配指定规则
    async fn matches_rule(&self, req: &Request<Body>, rule: &super::config::RoutingRule) -> bool {
        let conditions = &rule.conditions;

        // 检查路径条件
        if let Some(path_conditions) = &conditions.path {
            if !self.matches_path_conditions(req.uri().path(), path_conditions) {
                return false;
            }
        }

        // 检查方法条件
        if let Some(methods) = &conditions.method {
            if !methods.contains(&req.method().to_string()) {
                return false;
            }
        }

        // 检查头部条件
        if let Some(header_conditions) = &conditions.headers {
            for header_condition in header_conditions {
                if !self.matches_header_condition(req.headers(), header_condition) {
                    return false;
                }
            }
        }

        // 检查主机条件
        if let Some(host_condition) = &conditions.host {
            if let Some(host_header) = req.headers().get("host") {
                if let Ok(host_str) = host_header.to_str() {
                    if !self.matches_host_condition(host_str, host_condition) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 检查查询参数条件
        if let Some(query_conditions) = &conditions.query_params {
            let query = req.uri().query().unwrap_or("");
            if !self.matches_query_conditions(query, query_conditions) {
                return false;
            }
        }

        true
    }

    /// 检查路径条件匹配
    fn matches_path_conditions(
        &self,
        path: &str,
        conditions: &super::conditions::PathConditions,
    ) -> bool {
        if let Some(exact) = &conditions.exact {
            if path != exact {
                return false;
            }
        }

        if let Some(prefix) = &conditions.prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        if let Some(suffix) = &conditions.suffix {
            if !path.ends_with(suffix) {
                return false;
            }
        }

        if let Some(contains) = &conditions.contains {
            if !path.contains(contains) {
                return false;
            }
        }

        if let Some(regex_pattern) = &conditions.regex {
            if let Ok(regex) = regex::Regex::new(regex_pattern) {
                if !regex.is_match(path) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// 检查头部条件匹配
    fn matches_header_condition(
        &self,
        headers: &hyper::HeaderMap,
        condition: &super::conditions::HeaderCondition,
    ) -> bool {
        if condition.exists {
            return headers.contains_key(&condition.name);
        }

        if let Some(header_value) = headers.get(&condition.name) {
            if let Ok(value_str) = header_value.to_str() {
                if let Some(value_match) = &condition.value {
                    return self.matches_header_value(value_str, value_match);
                }

                if let Some(regex_pattern) = &condition.value_regex {
                    if let Ok(regex) = regex::Regex::new(regex_pattern) {
                        return regex.is_match(value_str);
                    }
                }
            }
        }

        false
    }

    /// 检查头部值匹配
    fn matches_header_value(
        &self,
        value: &str,
        value_match: &super::conditions::HeaderValueMatch,
    ) -> bool {
        match value_match {
            super::conditions::HeaderValueMatch::Exact(exact) => value == exact,
            super::conditions::HeaderValueMatch::OneOf(options) => {
                options.contains(&value.to_string())
            }
            super::conditions::HeaderValueMatch::Contains { contains } => value.contains(contains),
            super::conditions::HeaderValueMatch::StartsWith { starts_with } => {
                value.starts_with(starts_with)
            }
            super::conditions::HeaderValueMatch::EndsWith { ends_with } => {
                value.ends_with(ends_with)
            }
        }
    }

    /// 检查主机条件匹配
    fn matches_host_condition(
        &self,
        host: &str,
        condition: &super::conditions::HostCondition,
    ) -> bool {
        if let Some(exact) = &condition.exact {
            if host != exact {
                return false;
            }
        }

        if let Some(contains) = &condition.contains {
            if !host.contains(contains) {
                return false;
            }
        }

        if let Some(regex_pattern) = &condition.regex {
            if let Ok(regex) = regex::Regex::new(regex_pattern) {
                if !regex.is_match(host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// 检查查询参数条件匹配
    fn matches_query_conditions(
        &self,
        query: &str,
        conditions: &[super::conditions::QueryParamCondition],
    ) -> bool {
        let query_params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        for condition in conditions {
            if let Some(param_value) = query_params.get(&condition.name) {
                if let Some(expected_value) = &condition.value {
                    if param_value != expected_value {
                        return false;
                    }
                }

                if let Some(regex_pattern) = &condition.value_regex {
                    if let Ok(regex) = regex::Regex::new(regex_pattern) {
                        if !regex.is_match(param_value) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                // 参数不存在
                return false;
            }
        }

        true
    }
}
