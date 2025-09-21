use crate::error::{DispaError, DispaResult};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Body, Request, Response, Uri};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, info};

/// Advanced routing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// List of routing rules to evaluate in order
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    /// Default target when no rules match
    pub default_target: Option<String>,
    /// Enable request/response logging for routing decisions
    #[serde(default)]
    pub enable_logging: bool,
}

impl RoutingConfig {
    /// Validate routing configuration
    pub fn validate(&self) -> DispaResult<()> {
        // Validate routing rules
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

            // Validate regex patterns in conditions
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

            // Validate header regex patterns
            if let Some(header_conditions) = &rule.conditions.headers {
                for header_condition in header_conditions {
                    if let HeaderValueMatch::Regex { pattern } = &header_condition.value {
                        Regex::new(pattern).map_err(|e| {
                            DispaError::config(format!(
                                "Invalid header regex in rule '{}': {}",
                                rule.name, e
                            ))
                        })?;
                    }
                }
            }

            // Validate host patterns
            if let Some(host_condition) = &rule.conditions.host {
                for pattern in &host_condition.patterns {
                    if pattern.is_empty() {
                        return Err(DispaError::config(format!(
                            "Empty host pattern in rule '{}'",
                            rule.name
                        )));
                    }
                }
            }

            // Validate path transformation regex
            if let Some(path_actions) = &rule.actions.path {
                if let Some(regex_replace) = &path_actions.regex_replace {
                    Regex::new(&regex_replace.pattern).map_err(|e| {
                        DispaError::config(format!(
                            "Invalid path transformation regex in rule '{}': {}",
                            rule.name, e
                        ))
                    })?;
                }
            }
        }

        // Check for duplicate rule names
        let mut rule_names = std::collections::HashSet::new();
        for rule in &self.rules {
            if !rule_names.insert(&rule.name) {
                return Err(DispaError::config(format!(
                    "Duplicate routing rule name: '{}'",
                    rule.name
                )));
            }
        }

        Ok(())
    }
}

/// Individual routing rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Rule name for identification
    pub name: String,
    /// Priority (higher number = higher priority)
    pub priority: u32,
    /// Conditions that must be met for this rule to match
    pub conditions: RoutingConditions,
    /// Actions to take when rule matches
    pub actions: RoutingActions,
    /// Optional request-stage plugins to apply for this rule (by plugin name, in order)
    #[serde(default)]
    pub plugins_request: Option<Vec<String>>,
    /// Optional response-stage plugins to apply for this rule (by plugin name, in order)
    #[serde(default)]
    pub plugins_response: Option<Vec<String>>,
    /// Optional ordering policy for plugin lists
    #[serde(default)]
    pub plugins_order: Option<PluginOrder>,
    /// Deduplicate plugin names in lists (default: false)
    #[serde(default)]
    pub plugins_dedup: Option<bool>,
    /// Target backend for this rule
    pub target: String,
    /// Whether this rule is enabled
    pub enabled: bool,
}

/// Conditions for routing rule matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConditions {
    /// Path-based matching conditions
    pub path: Option<PathConditions>,
    /// HTTP method matching
    pub method: Option<Vec<String>>,
    /// Header matching conditions
    pub headers: Option<Vec<HeaderCondition>>,
    /// Query parameter matching
    pub query_params: Option<Vec<QueryParamCondition>>,
    /// Host/domain matching (supports wildcards)
    pub host: Option<HostCondition>,
}

/// Path-based routing conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConditions {
    /// Exact path match
    pub exact: Option<String>,
    /// Path prefix match
    pub prefix: Option<String>,
    /// Path suffix match
    pub suffix: Option<String>,
    /// Regular expression pattern
    pub regex: Option<String>,
    /// Path contains substring
    pub contains: Option<String>,
}

/// Header matching condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderCondition {
    /// Header name
    pub name: String,
    /// Header value matching
    pub value: HeaderValueMatch,
    /// Whether header must be present (true) or absent (false)
    pub present: Option<bool>,
}

/// Header value matching strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HeaderValueMatch {
    /// Exact value match
    #[serde(rename = "exact")]
    Exact { value: String },
    /// Value contains substring
    #[serde(rename = "contains")]
    Contains { value: String },
    /// Value matches regex pattern
    #[serde(rename = "regex")]
    Regex { pattern: String },
    /// Value starts with prefix
    #[serde(rename = "prefix")]
    Prefix { value: String },
    /// Value ends with suffix
    #[serde(rename = "suffix")]
    Suffix { value: String },
}

/// Query parameter matching condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParamCondition {
    /// Parameter name
    pub name: String,
    /// Parameter value matching (optional, checks presence if None)
    pub value: Option<HeaderValueMatch>,
}

/// Host matching condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCondition {
    /// Host patterns (supports wildcards like *.example.com)
    pub patterns: Vec<String>,
    /// Whether to match case-sensitively
    pub case_sensitive: bool,
}

/// Actions to perform when routing rule matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingActions {
    /// Header modifications
    pub headers: Option<HeaderActions>,
    /// Path modifications
    pub path: Option<PathActions>,
    /// Request body transformation
    pub request_transform: Option<BodyTransformation>,
    /// Response body transformation
    pub response_transform: Option<BodyTransformation>,
    /// Custom response (short-circuit routing)
    pub custom_response: Option<CustomResponse>,
}

/// Header modification actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderActions {
    /// Headers to add or set
    pub set: Option<HashMap<String, String>>,
    /// Headers to add (preserve existing)
    pub add: Option<HashMap<String, String>>,
    /// Headers to remove
    pub remove: Option<Vec<String>>,
    /// Headers to rename
    pub rename: Option<HashMap<String, String>>,
}

/// Path modification actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathActions {
    /// Prepend to path
    pub prepend: Option<String>,
    /// Remove prefix from path
    pub strip_prefix: Option<String>,
    /// Replace path entirely
    pub replace: Option<String>,
    /// Regex-based path transformation
    pub regex_replace: Option<RegexReplace>,
}

/// Regex-based replacement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexReplace {
    /// Regular expression pattern
    pub pattern: String,
    /// Replacement string (supports capture groups)
    pub replacement: String,
}

/// Body transformation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyTransformation {
    /// Content type to match for transformation
    pub content_type: Option<String>,
    /// Transformation type
    pub transform: TransformationType,
}

/// Types of body transformations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TransformationType {
    /// Replace string in body
    #[serde(rename = "replace")]
    Replace {
        pattern: String,
        replacement: String,
    },
    /// Regex replacement in body
    #[serde(rename = "regex_replace")]
    RegexReplace {
        pattern: String,
        replacement: String,
    },
    /// Add prefix to body
    #[serde(rename = "prepend")]
    Prepend { content: String },
    /// Add suffix to body
    #[serde(rename = "append")]
    Append { content: String },
    /// JSON field manipulation
    #[serde(rename = "json_transform")]
    JsonTransform { operations: Vec<JsonOperation> },
}

/// JSON transformation operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum JsonOperation {
    /// Set a field value
    #[serde(rename = "set")]
    Set {
        path: String,
        value: serde_json::Value,
    },
    /// Remove a field
    #[serde(rename = "remove")]
    Remove { path: String },
    /// Rename a field
    #[serde(rename = "rename")]
    Rename { from: String, to: String },
}

/// Custom response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: Option<HashMap<String, String>>,
    /// Response body
    pub body: Option<String>,
    /// Content type
    pub content_type: Option<String>,
}

/// Routing decision result
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Matched rule name (if any)
    pub rule_name: Option<String>,
    /// Target backend
    pub target: String,
    /// Request modifications to apply
    pub request_actions: Option<RoutingActions>,
    /// Response modifications to apply
    pub response_actions: Option<RoutingActions>,
    /// Custom response (if applicable)
    pub custom_response: Option<CustomResponse>,
    /// Route-specific plugins to apply (subset by name)
    pub plugins_request: Option<Vec<String>>,
    pub plugins_response: Option<Vec<String>>,
    pub plugins_order: Option<PluginOrder>,
    pub plugins_dedup: Option<bool>,
}

/// Plugin ordering options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginOrder {
    AsListed,
    NameAsc,
    NameDesc,
}

/// Advanced routing engine
#[derive(Debug, Clone)]
pub struct RoutingEngine {
    config: RoutingConfig,
    compiled_rules: Vec<CompiledRule>,
}

/// Compiled routing rule with pre-compiled regex patterns
#[derive(Debug, Clone)]
struct CompiledRule {
    rule: RoutingRule,
    path_regex: Option<Regex>,
    header_regexes: HashMap<String, Regex>,
    host_patterns: Vec<Regex>,
}

impl RoutingEngine {
    /// Create a new routing engine
    pub fn new(config: RoutingConfig) -> DispaResult<Self> {
        let mut compiled_rules = Vec::new();

        for rule in &config.rules {
            if !rule.enabled {
                continue;
            }

            let compiled_rule = Self::compile_rule(rule)?;
            compiled_rules.push(compiled_rule);
        }

        // Sort rules by priority (higher priority first)
        compiled_rules.sort_by(|a, b| b.rule.priority.cmp(&a.rule.priority));

        Ok(Self {
            config,
            compiled_rules,
        })
    }

    /// Compile a routing rule for efficient matching
    fn compile_rule(rule: &RoutingRule) -> DispaResult<CompiledRule> {
        let mut path_regex = None;
        let mut header_regexes = HashMap::new();
        let mut host_patterns = Vec::new();

        // Compile path regex if present
        if let Some(path_conditions) = &rule.conditions.path {
            if let Some(regex_pattern) = &path_conditions.regex {
                path_regex = Some(Regex::new(regex_pattern).map_err(|e| {
                    DispaError::config(format!("Invalid path regex '{}': {}", regex_pattern, e))
                })?);
            }
        }

        // Compile header regexes
        if let Some(header_conditions) = &rule.conditions.headers {
            for header_condition in header_conditions {
                if let HeaderValueMatch::Regex { pattern } = &header_condition.value {
                    let regex = Regex::new(pattern).map_err(|e| {
                        DispaError::config(format!("Invalid header regex '{}': {}", pattern, e))
                    })?;
                    header_regexes.insert(header_condition.name.clone(), regex);
                }
            }
        }

        // Compile host patterns
        if let Some(host_condition) = &rule.conditions.host {
            for pattern in &host_condition.patterns {
                // Convert wildcard pattern to regex
                let regex_pattern = if pattern.contains('*') {
                    pattern.replace(".", r"\.").replace("*", ".*")
                } else {
                    format!("^{}$", regex::escape(pattern))
                };

                let regex = if host_condition.case_sensitive {
                    Regex::new(&regex_pattern)
                } else {
                    Regex::new(&format!("(?i){}", regex_pattern))
                }
                .map_err(|e| {
                    DispaError::config(format!("Invalid host pattern '{}': {}", pattern, e))
                })?;

                host_patterns.push(regex);
            }
        }

        Ok(CompiledRule {
            rule: rule.clone(),
            path_regex,
            header_regexes,
            host_patterns,
        })
    }

    /// Evaluate routing for a request
    pub async fn route_request(&self, req: &Request<Body>) -> RoutingDecision {
        for compiled_rule in &self.compiled_rules {
            if self.evaluate_rule(req, compiled_rule).await {
                if self.config.enable_logging {
                    info!(
                        rule = %compiled_rule.rule.name,
                        target = %compiled_rule.rule.target,
                        "Routing rule matched"
                    );
                }

                return RoutingDecision {
                    rule_name: Some(compiled_rule.rule.name.clone()),
                    target: compiled_rule.rule.target.clone(),
                    request_actions: Some(compiled_rule.rule.actions.clone()),
                    response_actions: Some(compiled_rule.rule.actions.clone()),
                    custom_response: compiled_rule.rule.actions.custom_response.clone(),
                    plugins_request: compiled_rule.rule.plugins_request.clone(),
                    plugins_response: compiled_rule.rule.plugins_response.clone(),
                    plugins_order: compiled_rule.rule.plugins_order.clone(),
                    plugins_dedup: compiled_rule.rule.plugins_dedup,
                };
            }
        }

        // No rules matched, use default
        let default_target = self
            .config
            .default_target
            .clone()
            .unwrap_or_else(|| "default".to_string());

        if self.config.enable_logging {
            debug!(target = %default_target, "No routing rules matched, using default target");
        }

        RoutingDecision {
            rule_name: None,
            target: default_target,
            request_actions: None,
            response_actions: None,
            custom_response: None,
            plugins_request: None,
            plugins_response: None,
            plugins_order: None,
            plugins_dedup: None,
        }
    }

    /// Prepare plugin list with optional ordering and deduplication
    pub fn prepare_plugin_names(
        names: &[String],
        order: &Option<PluginOrder>,
        dedup: &Option<bool>,
    ) -> Vec<String> {
        let mut v: Vec<String> = names.to_vec();
        match order {
            Some(PluginOrder::NameAsc) => v.sort(),
            Some(PluginOrder::NameDesc) => v.sort_by(|a, b| b.cmp(a)),
            _ => {}
        }
        if dedup.clone().unwrap_or(false) {
            let mut seen = std::collections::HashSet::new();
            v.retain(|n| seen.insert(n.clone()));
        }
        v
    }

    /// Evaluate if a rule matches the request
    async fn evaluate_rule(&self, req: &Request<Body>, compiled_rule: &CompiledRule) -> bool {
        let conditions = &compiled_rule.rule.conditions;

        // Check method condition
        if let Some(methods) = &conditions.method {
            let method_str = req.method().as_str();
            if !methods.iter().any(|m| m.eq_ignore_ascii_case(method_str)) {
                return false;
            }
        }

        // Check path conditions
        if let Some(path_conditions) = &conditions.path {
            if !self.evaluate_path_conditions(req.uri(), path_conditions, &compiled_rule.path_regex)
            {
                return false;
            }
        }

        // Check header conditions
        if let Some(header_conditions) = &conditions.headers {
            if !self.evaluate_header_conditions(
                req.headers(),
                header_conditions,
                &compiled_rule.header_regexes,
            ) {
                return false;
            }
        }

        // Check host conditions
        if let Some(_host_condition) = &conditions.host {
            if !self.evaluate_host_conditions(req.headers(), &compiled_rule.host_patterns) {
                return false;
            }
        }

        // Check query parameter conditions
        if let Some(query_conditions) = &conditions.query_params {
            if !self.evaluate_query_conditions(req.uri(), query_conditions) {
                return false;
            }
        }

        true
    }

    /// Evaluate path matching conditions
    fn evaluate_path_conditions(
        &self,
        uri: &Uri,
        path_conditions: &PathConditions,
        path_regex: &Option<Regex>,
    ) -> bool {
        let path = uri.path();

        if let Some(exact) = &path_conditions.exact {
            if path != exact {
                return false;
            }
        }

        if let Some(prefix) = &path_conditions.prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        if let Some(suffix) = &path_conditions.suffix {
            if !path.ends_with(suffix) {
                return false;
            }
        }

        if let Some(contains) = &path_conditions.contains {
            if !path.contains(contains) {
                return false;
            }
        }

        if let Some(regex) = path_regex {
            if !regex.is_match(path) {
                return false;
            }
        }

        true
    }

    /// Evaluate header matching conditions
    fn evaluate_header_conditions(
        &self,
        headers: &HeaderMap,
        header_conditions: &[HeaderCondition],
        header_regexes: &HashMap<String, Regex>,
    ) -> bool {
        for condition in header_conditions {
            let header_name = HeaderName::from_str(&condition.name).ok();
            let header_value = header_name.and_then(|name| headers.get(&name));

            // Check presence condition
            if let Some(should_be_present) = condition.present {
                if should_be_present && header_value.is_none() {
                    return false;
                }
                if !should_be_present && header_value.is_some() {
                    return false;
                }
            }

            // Check value condition
            if let Some(value) = header_value {
                let value_str = value.to_str().unwrap_or("");

                match &condition.value {
                    HeaderValueMatch::Exact { value: expected } => {
                        if value_str != expected {
                            return false;
                        }
                    }
                    HeaderValueMatch::Contains { value: substring } => {
                        if !value_str.contains(substring) {
                            return false;
                        }
                    }
                    HeaderValueMatch::Regex { .. } => {
                        if let Some(regex) = header_regexes.get(&condition.name) {
                            if !regex.is_match(value_str) {
                                return false;
                            }
                        }
                    }
                    HeaderValueMatch::Prefix { value: prefix } => {
                        if !value_str.starts_with(prefix) {
                            return false;
                        }
                    }
                    HeaderValueMatch::Suffix { value: suffix } => {
                        if !value_str.ends_with(suffix) {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }

    /// Evaluate host matching conditions
    fn evaluate_host_conditions(&self, headers: &HeaderMap, host_patterns: &[Regex]) -> bool {
        if host_patterns.is_empty() {
            return true;
        }

        let host = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        for pattern in host_patterns {
            if pattern.is_match(host) {
                return true;
            }
        }

        false
    }

    /// Evaluate query parameter conditions
    fn evaluate_query_conditions(
        &self,
        uri: &Uri,
        query_conditions: &[QueryParamCondition],
    ) -> bool {
        let query = uri.query().unwrap_or("");
        let query_params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();

        for condition in query_conditions {
            if let Some(value_match) = &condition.value {
                // Check parameter value
                if let Some(param_value) = query_params.get(&condition.name) {
                    match value_match {
                        HeaderValueMatch::Exact { value } => {
                            if param_value != value {
                                return false;
                            }
                        }
                        HeaderValueMatch::Contains { value } => {
                            if !param_value.contains(value) {
                                return false;
                            }
                        }
                        HeaderValueMatch::Prefix { value } => {
                            if !param_value.starts_with(value) {
                                return false;
                            }
                        }
                        HeaderValueMatch::Suffix { value } => {
                            if !param_value.ends_with(value) {
                                return false;
                            }
                        }
                        HeaderValueMatch::Regex { pattern } => {
                            if let Ok(regex) = Regex::new(pattern) {
                                if !regex.is_match(param_value) {
                                    return false;
                                }
                            }
                        }
                    }
                } else {
                    return false;
                }
            } else {
                // Just check parameter presence
                if !query_params.contains_key(&condition.name) {
                    return false;
                }
            }
        }

        true
    }

    /// Apply request transformations
    pub async fn apply_request_transformations(
        &self,
        mut req: Request<Body>,
        actions: &RoutingActions,
    ) -> DispaResult<Request<Body>> {
        // Apply header modifications
        if let Some(header_actions) = &actions.headers {
            self.apply_header_actions(req.headers_mut(), header_actions)?;
        }

        // Apply path modifications
        if let Some(path_actions) = &actions.path {
            req = self.apply_path_actions(req, path_actions)?;
        }

        // Apply body transformations
        if let Some(transform) = &actions.request_transform {
            req = self.apply_body_transformation(req, transform).await?;
        }

        Ok(req)
    }

    /// Apply response transformations
    pub async fn apply_response_transformations(
        &self,
        mut resp: Response<Body>,
        actions: &RoutingActions,
    ) -> DispaResult<Response<Body>> {
        // Apply header modifications
        if let Some(header_actions) = &actions.headers {
            self.apply_header_actions(resp.headers_mut(), header_actions)?;
        }

        // Apply body transformations
        if let Some(transform) = &actions.response_transform {
            resp = self
                .apply_response_body_transformation(resp, transform)
                .await?;
        }

        Ok(resp)
    }

    /// Apply header modifications
    fn apply_header_actions(
        &self,
        headers: &mut HeaderMap,
        actions: &HeaderActions,
    ) -> DispaResult<()> {
        // Remove headers
        if let Some(remove_headers) = &actions.remove {
            for header_name in remove_headers {
                if let Ok(name) = HeaderName::from_str(header_name) {
                    headers.remove(&name);
                }
            }
        }

        // Set headers (replace existing)
        if let Some(set_headers) = &actions.set {
            for (name, value) in set_headers {
                if let (Ok(header_name), Ok(header_value)) =
                    (HeaderName::from_str(name), HeaderValue::from_str(value))
                {
                    headers.insert(header_name, header_value);
                }
            }
        }

        // Add headers (preserve existing)
        if let Some(add_headers) = &actions.add {
            for (name, value) in add_headers {
                if let (Ok(header_name), Ok(header_value)) =
                    (HeaderName::from_str(name), HeaderValue::from_str(value))
                {
                    headers.append(header_name, header_value);
                }
            }
        }

        // Rename headers
        if let Some(rename_headers) = &actions.rename {
            for (old_name, new_name) in rename_headers {
                if let (Ok(old_header_name), Ok(new_header_name)) = (
                    HeaderName::from_str(old_name),
                    HeaderName::from_str(new_name),
                ) {
                    if let Some(value) = headers.remove(&old_header_name) {
                        headers.insert(new_header_name, value);
                    }
                }
            }
        }

        Ok(())
    }

    /// Apply path modifications to request
    fn apply_path_actions(
        &self,
        req: Request<Body>,
        actions: &PathActions,
    ) -> DispaResult<Request<Body>> {
        let original_uri = req.uri();
        let mut path = original_uri.path().to_string();

        // Apply path modifications in order
        if let Some(strip_prefix) = &actions.strip_prefix {
            if path.starts_with(strip_prefix) {
                path = path[strip_prefix.len()..].to_string();
                if !path.starts_with('/') {
                    path = format!("/{}", path);
                }
            }
        }

        if let Some(prepend) = &actions.prepend {
            path = format!("{}{}", prepend, path);
        }

        if let Some(replace) = &actions.replace {
            path = replace.clone();
        }

        if let Some(regex_replace) = &actions.regex_replace {
            if let Ok(regex) = Regex::new(&regex_replace.pattern) {
                path = regex
                    .replace_all(&path, &regex_replace.replacement)
                    .to_string();
            }
        }

        // Build new URI
        let mut uri_parts = original_uri.clone().into_parts();
        uri_parts.path_and_query = Some(if let Some(query) = original_uri.query() {
            format!("{}?{}", path, query).parse().unwrap()
        } else {
            path.parse().unwrap()
        });

        let new_uri = Uri::from_parts(uri_parts)
            .map_err(|e| DispaError::proxy(format!("Failed to build new URI: {}", e)))?;

        // Rebuild request with new URI
        let (mut parts, body) = req.into_parts();
        parts.uri = new_uri;
        Ok(Request::from_parts(parts, body))
    }

    /// Apply body transformation to request
    async fn apply_body_transformation(
        &self,
        req: Request<Body>,
        transform: &BodyTransformation,
    ) -> DispaResult<Request<Body>> {
        // Check content type if specified
        if let Some(required_content_type) = &transform.content_type {
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if !content_type.contains(required_content_type) {
                return Ok(req); // Skip transformation
            }
        }

        let (parts, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| DispaError::proxy(format!("Failed to read request body: {}", e)))?;

        let body_str = String::from_utf8_lossy(&body_bytes);
        let transformed_body = self.apply_transformation(&body_str, &transform.transform)?;

        Ok(Request::from_parts(parts, Body::from(transformed_body)))
    }

    /// Apply body transformation to response
    async fn apply_response_body_transformation(
        &self,
        resp: Response<Body>,
        transform: &BodyTransformation,
    ) -> DispaResult<Response<Body>> {
        // Check content type if specified
        if let Some(required_content_type) = &transform.content_type {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            if !content_type.contains(required_content_type) {
                return Ok(resp); // Skip transformation
            }
        }

        let (parts, body) = resp.into_parts();
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| DispaError::proxy(format!("Failed to read response body: {}", e)))?;

        let body_str = String::from_utf8_lossy(&body_bytes);
        let transformed_body = self.apply_transformation(&body_str, &transform.transform)?;

        Ok(Response::from_parts(parts, Body::from(transformed_body)))
    }

    /// Apply transformation to body content
    fn apply_transformation(
        &self,
        body: &str,
        transform_type: &TransformationType,
    ) -> DispaResult<String> {
        match transform_type {
            TransformationType::Replace {
                pattern,
                replacement,
            } => Ok(body.replace(pattern, replacement)),
            TransformationType::RegexReplace {
                pattern,
                replacement,
            } => {
                let regex = Regex::new(pattern)
                    .map_err(|e| DispaError::config(format!("Invalid regex pattern: {}", e)))?;
                Ok(regex.replace_all(body, replacement).to_string())
            }
            TransformationType::Prepend { content } => Ok(format!("{}{}", content, body)),
            TransformationType::Append { content } => Ok(format!("{}{}", body, content)),
            TransformationType::JsonTransform { operations } => {
                self.apply_json_transformations(body, operations)
            }
        }
    }

    /// Apply JSON transformations
    fn apply_json_transformations(
        &self,
        body: &str,
        operations: &[JsonOperation],
    ) -> DispaResult<String> {
        let mut json: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| DispaError::proxy(format!("Invalid JSON body: {}", e)))?;

        for operation in operations {
            match operation {
                JsonOperation::Set { path, value } => {
                    // Simple path-based setting (could be enhanced with JSONPath)
                    if let Some(obj) = json.as_object_mut() {
                        obj.insert(path.clone(), value.clone());
                    }
                }
                JsonOperation::Remove { path } => {
                    if let Some(obj) = json.as_object_mut() {
                        obj.remove(path);
                    }
                }
                JsonOperation::Rename { from, to } => {
                    if let Some(obj) = json.as_object_mut() {
                        if let Some(value) = obj.remove(from) {
                            obj.insert(to.clone(), value);
                        }
                    }
                }
            }
        }

        serde_json::to_string(&json)
            .map_err(|e| DispaError::proxy(format!("Failed to serialize JSON: {}", e)))
    }

    /// Create a custom response
    pub fn create_custom_response(
        &self,
        custom_response: &CustomResponse,
    ) -> DispaResult<Response<Body>> {
        let mut response = Response::builder().status(custom_response.status);

        // Add custom headers
        if let Some(headers) = &custom_response.headers {
            for (name, value) in headers {
                if let (Ok(header_name), Ok(header_value)) =
                    (HeaderName::from_str(name), HeaderValue::from_str(value))
                {
                    response = response.header(header_name, header_value);
                }
            }
        }

        // Set content type
        if let Some(content_type) = &custom_response.content_type {
            response = response.header("content-type", content_type);
        }

        // Set body
        let body = custom_response.body.as_deref().unwrap_or("");

        response
            .body(Body::from(body.to_string()))
            .map_err(|e| DispaError::proxy(format!("Failed to create custom response: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{HeaderMap, Method, Request};

    fn create_test_config() -> RoutingConfig {
        RoutingConfig {
            rules: vec![RoutingRule {
                name: "api-route".to_string(),
                priority: 100,
                conditions: RoutingConditions {
                    path: Some(PathConditions {
                        prefix: Some("/api".to_string()),
                        exact: None,
                        suffix: None,
                        regex: None,
                        contains: None,
                    }),
                    method: Some(vec!["GET".to_string(), "POST".to_string()]),
                    headers: Some(vec![HeaderCondition {
                        name: "X-API-Version".to_string(),
                        value: HeaderValueMatch::Exact {
                            value: "v1".to_string(),
                        },
                        present: Some(true),
                    }]),
                    query_params: None,
                    host: None,
                },
                actions: RoutingActions {
                    headers: Some(HeaderActions {
                        set: Some({
                            let mut headers = HashMap::new();
                            headers.insert("X-Routed-By".to_string(), "dispa".to_string());
                            headers
                        }),
                        add: None,
                        remove: None,
                        rename: None,
                    }),
                    path: Some(PathActions {
                        strip_prefix: Some("/api".to_string()),
                        prepend: None,
                        replace: None,
                        regex_replace: None,
                    }),
                    request_transform: None,
                    response_transform: None,
                    custom_response: None,
                },
                plugins_request: None,
                plugins_response: None,
                plugins_order: None,
                plugins_dedup: None,
                target: "api-backend".to_string(),
                enabled: true,
            }],
            default_target: Some("default-backend".to_string()),
            enable_logging: true,
        }
    }

    #[tokio::test]
    async fn test_routing_engine_creation() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = create_test_config();
            let engine = RoutingEngine::new(config).unwrap();
            assert_eq!(engine.compiled_rules.len(), 1);
        }).await.expect("test_routing_engine_creation timed out");
    }

    #[tokio::test]
    async fn test_path_based_routing() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        let req = Request::builder()
            .uri("/api/users")
            .method(Method::GET)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "api-backend");
        assert_eq!(decision.rule_name, Some("api-route".to_string()));
        }).await.expect("test_path_based_routing timed out");
    }

    #[test]
    fn test_prepare_plugin_names_order_and_dedup() {
        let names = vec!["b".to_string(), "a".to_string(), "b".to_string()];
        // As listed, no dedup
        let out = RoutingEngine::prepare_plugin_names(&names, &Some(PluginOrder::AsListed), &Some(false));
        assert_eq!(out, vec!["b", "a", "b"]);
        // Asc, dedup
        let out = RoutingEngine::prepare_plugin_names(&names, &Some(PluginOrder::NameAsc), &Some(true));
        assert_eq!(out, vec!["a", "b"]);
        // Desc, dedup
        let out = RoutingEngine::prepare_plugin_names(&names, &Some(PluginOrder::NameDesc), &Some(true));
        assert_eq!(out, vec!["b", "a"]);
        // Default (no order, no dedup)
        let out = RoutingEngine::prepare_plugin_names(&names, &None, &None);
        assert_eq!(out, names);
    }

    #[tokio::test]
    async fn test_default_routing() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        let req = Request::builder()
            .uri("/other")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "default-backend");
        assert_eq!(decision.rule_name, None);
        }).await.expect("test_default_routing timed out");
    }

    #[tokio::test]
    async fn test_header_matching() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        // Request without required header should not match
        let req = Request::builder()
            .uri("/api/users")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "default-backend");

        // Request with correct header should match
        let req = Request::builder()
            .uri("/api/users")
            .method(Method::GET)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "api-backend");
        }).await.expect("test_header_matching timed out");
    }

    #[tokio::test]
    async fn test_method_matching() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        // Allowed method should match
        let req = Request::builder()
            .uri("/api/users")
            .method(Method::POST)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "api-backend");

        // Disallowed method should not match
        let req = Request::builder()
            .uri("/api/users")
            .method(Method::DELETE)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "default-backend");
        }).await.expect("test_method_matching timed out");
    }

    #[tokio::test]
    async fn test_header_actions() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        let req = Request::builder()
            .uri("/api/users")
            .method(Method::GET)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;

        if let Some(actions) = &decision.request_actions {
            let mut headers = HeaderMap::new();
            engine
                .apply_header_actions(&mut headers, actions.headers.as_ref().unwrap())
                .unwrap();

            assert_eq!(headers.get("X-Routed-By").unwrap(), "dispa");
        }
        }).await.expect("test_header_actions timed out");
    }

    #[tokio::test]
    async fn test_path_transformation() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = create_test_config();
        let engine = RoutingEngine::new(config).unwrap();

        let req = Request::builder()
            .uri("/api/users")
            .method(Method::GET)
            .header("X-API-Version", "v1")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;

        if let Some(actions) = &decision.request_actions {
            let transformed_req = engine
                .apply_request_transformations(req, actions)
                .await
                .unwrap();
            assert_eq!(transformed_req.uri().path(), "/users");
        }
        }).await.expect("test_path_transformation timed out");
    }

    #[tokio::test]
    async fn test_regex_path_matching() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = RoutingConfig {
            rules: vec![RoutingRule {
                name: "regex-route".to_string(),
                priority: 100,
                conditions: RoutingConditions {
                    path: Some(PathConditions {
                        regex: Some(r"^/api/v\d+/users/\d+$".to_string()),
                        exact: None,
                        prefix: None,
                        suffix: None,
                        contains: None,
                    }),
                    method: None,
                    headers: None,
                    query_params: None,
                    host: None,
                },
                actions: RoutingActions {
                    headers: None,
                    path: None,
                    request_transform: None,
                    response_transform: None,
                    custom_response: None,
                },
                plugins_request: None,
                plugins_response: None,
                plugins_order: None,
                plugins_dedup: None,
                target: "user-backend".to_string(),
                enabled: true,
            }],
            default_target: Some("default".to_string()),
            ..Default::default()
        };

        let engine = RoutingEngine::new(config).unwrap();

        // Should match
        let req = Request::builder()
            .uri("/api/v1/users/123")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "user-backend");

        // Should not match
        let req = Request::builder()
            .uri("/api/v1/users/abc")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;
        assert_eq!(decision.target, "default");
        }).await.expect("test_regex_path_matching timed out");
    }

    #[tokio::test]
    async fn test_custom_response() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let config = RoutingConfig {
            rules: vec![RoutingRule {
                name: "maintenance".to_string(),
                priority: 100,
                conditions: RoutingConditions {
                    path: Some(PathConditions {
                        prefix: Some("/maintenance".to_string()),
                        exact: None,
                        suffix: None,
                        regex: None,
                        contains: None,
                    }),
                    method: None,
                    headers: None,
                    query_params: None,
                    host: None,
                },
                actions: RoutingActions {
                    custom_response: Some(CustomResponse {
                        status: 503,
                        headers: Some({
                            let mut headers = HashMap::new();
                            headers.insert("Retry-After".to_string(), "3600".to_string());
                            headers
                        }),
                        body: Some("Service under maintenance".to_string()),
                        content_type: Some("text/plain".to_string()),
                    }),
                    headers: None,
                    path: None,
                    request_transform: None,
                    response_transform: None,
                },
                plugins_request: None,
                plugins_response: None,
                plugins_order: None,
                plugins_dedup: None,
                target: "none".to_string(),
                enabled: true,
            }],
            ..Default::default()
        };

        let engine = RoutingEngine::new(config).unwrap();

        let req = Request::builder()
            .uri("/maintenance")
            .body(Body::empty())
            .unwrap();

        let decision = engine.route_request(&req).await;

        if let Some(custom_response) = &decision.custom_response {
            let resp = engine.create_custom_response(custom_response).unwrap();
            assert_eq!(resp.status().as_u16(), 503);
            assert_eq!(resp.headers().get("retry-after").unwrap(), "3600");
        }
        }).await.expect("test_custom_response timed out");
    }
}
