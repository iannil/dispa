use anyhow::Result;
use chrono::Utc;
use hyper::header::HOST;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::balancer::LoadBalancer;
use crate::config::DomainConfig;
use std::sync::RwLock as StdRwLock;
use crate::logger::TrafficLogger;
use crate::routing::RoutingEngine;
use crate::plugins::{PluginResult, SharedPluginEngine};
use crate::security::SharedSecurity;

#[derive(Clone)]
pub struct ProxyHandler {
    domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    traffic_logger: TrafficLogger,
    routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
    plugins: SharedPluginEngine,
    security: SharedSecurity,
}

impl ProxyHandler {
    #[cfg(test)]
    pub fn new(
        domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
        load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
        traffic_logger: TrafficLogger,
        ) -> Self {
        Self {
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            plugins: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            security: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub fn with_shared_routing(
        domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
        load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
        traffic_logger: TrafficLogger,
        routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
        plugins: SharedPluginEngine,
        security: SharedSecurity,
    ) -> Self {
        Self {
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine,
            plugins,
            security,
        }
    }

    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        match self.process_request(req).await {
            Ok(response) => Ok(response),
            Err(e) => {
                warn!("Request processing error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal server error"))
                    .unwrap())
            }
        }
    }

    async fn process_request(&self, mut req: Request<Body>) -> Result<Response<Body>> {
        let request_id = Uuid::new_v4();
        let start_time = Utc::now();
        // Capture client address early (extensions may be consumed later)
        let captured_client_addr = req.extensions().get::<std::net::SocketAddr>().cloned().unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());

        // Extract host and method from request headers before moving req
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        debug!("Request {} to {}", request_id, host);

        // Security checks (global, earliest)
        {
            let client_ip = req.extensions().get::<std::net::SocketAddr>().map(|sa| sa.ip());
            let guard = self.security.read().await;
            if let Some(sec) = guard.as_ref() {
                if let Some(resp) = sec.check_request(&req, client_ip).await { return Ok(resp); }
            }
        }

        // Plugins: request phase (position controlled by plugins config)
        let mut applied_request_plugins = false;
        let apply_before = {
            let guard = self.plugins.read().await;
            guard.as_ref().map(|e| e.apply_before_domain_match()).unwrap_or(true)
        };
        if apply_before {
            let guard = self.plugins.read().await;
            if let Some(engine) = guard.as_ref() {
                if let PluginResult::ShortCircuit(resp) = engine.apply_request(&mut req).await {
                    return Ok(resp);
                }
                applied_request_plugins = true;
            }
        }

        // Check if this domain should be intercepted
        if !self.should_intercept_domain(&host) {
            warn!("Domain {} not in intercept list, returning 404", host);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Domain not found"))
                .unwrap());
        }

        // Route the request using routing engine or fall back to load balancer
        let routing_decision = {
            let guard = self.routing_engine.read().await;
            if let Some(engine) = guard.as_ref() {
                Some(engine.route_request(&req).await)
            } else {
                None
            }
        };

        // If request plugins are configured to run after domain check, run them now
        if !applied_request_plugins {
            let guard = self.plugins.read().await;
            if let Some(engine) = guard.as_ref() {
                if let PluginResult::ShortCircuit(resp) = engine.apply_request(&mut req).await {
                    return Ok(resp);
                }
            }
        }

        let (target_name, processed_req) = if let Some(ref decision) = routing_decision {
            // Check for custom response first
            if let Some(custom_response) = &decision.custom_response {
                info!(
                    "Request {} matched routing rule '{}' with custom response",
                    request_id,
                    decision.rule_name.as_deref().unwrap_or("unknown")
                );
                let engine_opt = { self.routing_engine.read().await.clone() };
                if let Some(engine) = engine_opt {
                    return Ok(engine.create_custom_response(custom_response)?);
                }
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Routing engine unavailable"))
                    .unwrap());
            }

            // Apply request transformations if present
            let mut transformed_req = if let Some(actions) = &decision.request_actions {
                {
                    let engine_opt = { self.routing_engine.read().await.clone() };
                    if let Some(engine) = engine_opt {
                        engine.apply_request_transformations(req, actions).await?
                    } else {
                        req
                    }
                }
            } else {
                req
            };

            // Apply per-route request plugins (subset by name)
            if let Some(plugin_names) = &decision.plugins_request {
                let prepared = crate::routing::RoutingEngine::prepare_plugin_names(
                    plugin_names,
                    &decision.plugins_order,
                    &decision.plugins_dedup,
                );
                let guard = self.plugins.read().await;
                if let Some(engine) = guard.as_ref() {
                    if let PluginResult::ShortCircuit(resp) = engine.apply_request_subset(&prepared, &mut transformed_req).await {
                        return Ok(resp);
                    }
                }
            }

            info!(
                "Request {} routed to target '{}' by rule '{}'",
                request_id,
                decision.target,
                decision.rule_name.as_deref().unwrap_or("default")
            );

            (decision.target.clone(), transformed_req)
        } else {
            // Fallback to traditional load balancer selection
            let lb = self.load_balancer.read().await;
            let target = match lb.get_target().await {
                Some(target) => target,
                None => {
                    // No upstream. If a body-size limit is configured, opportunistically
                    // enforce it here by checking content-length or consuming up to limit+1 bytes.
                    let limit = { let guard = self.security.read().await; guard.as_ref().and_then(|s| s.max_body_bytes()) };
                    if let Some(max) = limit {
                        if let Some(len) = req.headers().get(hyper::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok()) {
                            if len > max {
                                return Ok(Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE).body(Body::from("Payload too large")).unwrap());
                            }
                        } else {
                            // Stream a small amount just to detect over-limit bodies
                            let mut total: u64 = 0;
                            let body = req.body_mut();
                            while let Some(chunk) = hyper::body::HttpBody::data(body).await {
                                match chunk {
                                    Ok(c) => {
                                        total += c.len() as u64;
                                        if total > max {
                                            return Ok(Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE).body(Body::from("Payload too large")).unwrap());
                                        }
                                        if total >= max { break; }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    warn!("No healthy targets available");
                    return Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(Body::from("Service unavailable"))
                        .unwrap());
                }
            };

            info!(
                "Request {} forwarded to target: {}",
                request_id, target.name
            );
            (target.name.clone(), req)
        };

        // Get the actual target URL
        let lb = self.load_balancer.read().await;
        let target = match lb.get_target_by_name(&target_name).await {
            Some(target) => target,
            None => {
                // No such target (or unhealthy). Build a 503 response but still
                // apply per-route/global response plugins so tests and users can
                // rely on response-phase plugins regardless of upstream.
                warn!("Target '{}' not found or not healthy", target_name);
                let mut resp = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service unavailable"))
                    .unwrap();

                // Apply per-route response plugin subset if any, then only global plugins not already applied
                let mut route_resp_names: Option<Vec<String>> = None;
                if let Some(decision) = &routing_decision {
                    if let Some(plugin_names) = &decision.plugins_response {
                        let prepared = crate::routing::RoutingEngine::prepare_plugin_names(
                            plugin_names,
                            &decision.plugins_order,
                            &decision.plugins_dedup,
                        );
                        route_resp_names = Some(prepared.clone());
                        let guard = self.plugins.read().await;
                        if let Some(engine) = guard.as_ref() {
                            engine.apply_response_subset(&prepared, &mut resp).await;
                        }
                    }
                }

                // Apply remaining global plugins only
                let guard = self.plugins.read().await;
                if let Some(engine) = guard.as_ref() {
                    if let Some(route_names) = &route_resp_names {
                        let all = engine.response_plugin_names();
                        let route_set: std::collections::HashSet<_> = route_names.iter().cloned().collect();
                        let remaining: Vec<String> = all.into_iter().filter(|n| !route_set.contains(n)).collect();
                        if !remaining.is_empty() {
                            engine.apply_response_subset(&remaining, &mut resp).await;
                        }
                    } else {
                        engine.apply_response(&mut resp).await;
                    }
                }

                return Ok(resp);
            }
        };

        // Forward the request
        let response = match self.forward_request(processed_req, &target.url).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to forward request {}: {}", request_id, e);
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Bad gateway"))
                    .unwrap()
            }
        };

        // Apply response transformations if using routing engine
        let mut final_response = if let Some(ref decision) = routing_decision
        {
            if let Some(actions) = &decision.response_actions {
                let engine_opt = { self.routing_engine.read().await.clone() };
                if let Some(engine) = engine_opt {
                    match engine.apply_response_transformations(response, actions).await {
                        Ok(transformed_response) => transformed_response,
                        Err(e) => {
                            warn!("Failed to apply response transformations: {}", e);
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Response transformation failed"))
                                .unwrap()
                        }
                    }
                } else {
                    response
                }
            } else {
                response
            }
        } else {
            response
        };

        // Apply per-route response plugins (subset by name) before global plugins
        let mut route_resp_names: Option<Vec<String>> = None;
        if let Some(decision) = &routing_decision {
            if let Some(plugin_names) = &decision.plugins_response {
                let prepared = crate::routing::RoutingEngine::prepare_plugin_names(
                    plugin_names,
                    &decision.plugins_order,
                    &decision.plugins_dedup,
                );
                route_resp_names = Some(prepared.clone());
                let guard = self.plugins.read().await;
                if let Some(engine) = guard.as_ref() {
                    engine.apply_response_subset(&prepared, &mut final_response).await;
                }
            }
        }

        // Plugins: response phase (global). If route-specific response plugins were applied,
        // do not re-run those names again; only apply global-only plugins.
        {
            let guard = self.plugins.read().await;
            if let Some(engine) = guard.as_ref() {
                if let Some(route_names) = &route_resp_names {
                    let all = engine.response_plugin_names();
                    let route_set: std::collections::HashSet<_> = route_names.iter().cloned().collect();
                    let remaining: Vec<String> = all.into_iter().filter(|n| !route_set.contains(n)).collect();
                    if !remaining.is_empty() {
                        engine.apply_response_subset(&remaining, &mut final_response).await;
                    }
                } else {
                    engine.apply_response(&mut final_response).await;
                }
            }
        }

        let status = final_response.status();
        let end_time = Utc::now();
        let duration = end_time - start_time;
        let std_duration = std::time::Duration::from_millis(duration.num_milliseconds() as u64);

        // Log the traffic
        let client_addr = captured_client_addr;
        if let Err(e) = self
            .traffic_logger
            .log_request(
                request_id,
                client_addr,
                &host,
                &method,
                &path,
                &target.name,
                status,
                start_time,
                std_duration,
                None, // user_agent
                None, // error_message
            )
            .await
        {
            warn!("Failed to log traffic: {}", e);
        }

        debug!(
            "Request {} completed with status {} in {}ms",
            request_id,
            status,
            duration.num_milliseconds()
        );

        Ok(final_response)
    }

    fn should_intercept_domain(&self, host: &str) -> bool {
        // Remove port from host if present
        let host = host.split(':').next().unwrap_or(host);
        let cfg = self.domain_config.read().unwrap();
        // Check exclude list first
        if let Some(ref exclude_domains) = cfg.exclude_domains {
            if exclude_domains
                .iter()
                .any(|domain| self.matches_domain(host, domain))
            {
                return false;
            }
        }

        // Check intercept list
        cfg.intercept_domains
            .iter()
            .any(|domain| self.matches_domain(host, domain))
    }

    fn matches_domain(&self, host: &str, pattern: &str) -> bool {
        let cfg = self.domain_config.read().unwrap();
        if !cfg.wildcard_support {
            return host == pattern;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{}", suffix))
        } else {
            host == pattern
        }
    }

    async fn forward_request(
        &self,
        req: Request<Body>,
        target_url: &str,
    ) -> Result<Response<Body>> {
        // Forward via shared pooled hyper client; apply streaming body limit if configured
        let limit = {
            let guard = self.security.read().await;
            guard.as_ref().and_then(|s| s.max_body_bytes())
        };
        match super::http_client::forward_with_limit(req, target_url, limit).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Map payload too large to 413
                if matches!(e, crate::error::DispaError::PayloadTooLarge{ .. }) {
                    return Ok(Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE).body(Body::from("Payload too large")).unwrap());
                }
                Err(anyhow::anyhow!(e))
            }
        }
    }
}

#[cfg(test)]
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::LoadBalancer;
    use crate::config::{
        DomainConfig, HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, TargetConfig, PluginsConfig, PluginConfig, PluginType, PluginStage, PluginErrorStrategy, Target,
    };
    use crate::routing::{RoutingConfig, RoutingRule, RoutingConditions, PathConditions, RoutingActions};
    use crate::logger::TrafficLogger;
    use crate::plugins::PluginEngine;

    // Helper function to create a test proxy handler
    fn create_test_handler(
        intercept_domains: Vec<String>,
        exclude_domains: Option<Vec<String>>,
        wildcard_support: bool,
    ) -> ProxyHandler {
        let domain_config = DomainConfig {
            intercept_domains,
            exclude_domains,
            wildcard_support,
        };

        let target_config = TargetConfig {
            targets: vec![],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        };

        let load_balancer = LoadBalancer::new_for_test(target_config.clone());
        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig {
            enabled: false,
            log_type: crate::config::LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(load_balancer));
        ProxyHandler::new(domain_arc, lb_arc, traffic_logger)
    }

    trait WithRouting {
        fn with_routing(self, engine: Option<RoutingEngine>) -> Self;
    }

    impl WithRouting for ProxyHandler {
        fn with_routing(mut self, engine: Option<RoutingEngine>) -> Self {
            self.routing_engine = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
            self
        }
    }

    trait WithSecurity {
        fn with_security(self, sec: Option<crate::security::SecurityManager>) -> Self;
    }

    impl WithSecurity for ProxyHandler {
        fn with_security(mut self, sec: Option<crate::security::SecurityManager>) -> Self {
            self.security = std::sync::Arc::new(tokio::sync::RwLock::new(sec));
            self
        }
    }

    #[tokio::test]
    async fn test_per_route_response_plugin_header_set() {
        use crate::config::*;
        use crate::plugins::PluginEngine;

        // Prepare plugins: a response header injector named 'route-resp'
        let plugins_cfg = PluginsConfig { enabled: true, apply_before_domain_match: false, plugins: vec![
            PluginConfig{ name: "route-resp".into(), plugin_type: PluginType::HeaderInjector, enabled: true, stage: PluginStage::Response, config: Some(serde_json::json!({"response_headers": {"x-route-resp": "ok"}})), error_strategy: PluginErrorStrategy::Continue }
        ]};
        let engine = PluginEngine::new(&plugins_cfg).unwrap();

        // Routing: rule applies response plugin subset and no custom response
        let routing_cfg = RoutingConfig {
            rules: vec![RoutingRule{
                name: "resp-rule".into(), priority: 100, enabled: true, target: "default".into(),
                conditions: RoutingConditions{ path: Some(PathConditions{ exact: None, prefix: Some("/api".into()), suffix: None, regex: None, contains: None }), method: None, headers: None, query_params: None, host: None },
                actions: RoutingActions{ headers: None, path: None, request_transform: None, response_transform: None, custom_response: None },
                plugins_request: None, plugins_response: Some(vec!["route-resp".into()]), plugins_order: None, plugins_dedup: None,
            }],
            default_target: Some("default".into()), enable_logging: false,
        };
        let routing_engine = crate::routing::RoutingEngine::new(routing_cfg).unwrap();

        // Handler with routing + plugins (no upstream targets to avoid network; will produce 503)
        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let handler = create_handler_with_plugins(domain_config, Some(engine)).with_routing(Some(routing_engine));
        let req = Request::builder().uri("http://localhost/api").header(HOST, "example.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        // Header should be injected by per-route response plugin
        assert_eq!(resp.headers().get("x-route-resp").and_then(|v| v.to_str().ok()), Some("ok"));
    }

    #[tokio::test]
    async fn test_per_route_response_order_and_dedup_affect_header() {
        use crate::config::*;
        use crate::plugins::PluginEngine;

        // Two response plugins set the same header with different values
        let plugins_cfg = PluginsConfig { enabled: true, apply_before_domain_match: false, plugins: vec![
            PluginConfig{ name: "AResp".into(), plugin_type: PluginType::HeaderInjector, enabled: true, stage: PluginStage::Response, config: Some(serde_json::json!({"response_headers": {"x-order": "A"}})), error_strategy: PluginErrorStrategy::Continue },
            PluginConfig{ name: "BResp".into(), plugin_type: PluginType::HeaderInjector, enabled: true, stage: PluginStage::Response, config: Some(serde_json::json!({"response_headers": {"x-order": "B"}})), error_strategy: PluginErrorStrategy::Continue },
        ]};
        let _engine = PluginEngine::new(&plugins_cfg).unwrap();

        // Base routing engine; we will mutate per test case
        let mut base_rule = RoutingRule{
            name: "resp-order".into(), priority: 100, enabled: true, target: "default".into(),
            conditions: RoutingConditions{ path: Some(PathConditions{ exact: None, prefix: Some("/api".into()), suffix: None, regex: None, contains: None }), method: None, headers: None, query_params: None, host: None },
            actions: RoutingActions{ headers: None, path: None, request_transform: None, response_transform: None, custom_response: None },
            plugins_request: None, plugins_response: None, plugins_order: None, plugins_dedup: None,
        };

        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };

        // Case 1: AsListed with duplicates [B,A,B] -> final should be B
        base_rule.plugins_response = Some(vec!["BResp".into(), "AResp".into(), "BResp".into()]);
        base_rule.plugins_order = Some(crate::routing::PluginOrder::AsListed);
        base_rule.plugins_dedup = Some(false);
        let routing_engine = crate::routing::RoutingEngine::new(RoutingConfig{ rules: vec![base_rule.clone()], default_target: Some("default".into()), enable_logging: false }).unwrap();
        let handler = create_handler_with_plugins(domain_config.clone(), Some(PluginEngine::new(&plugins_cfg).unwrap())).with_routing(Some(routing_engine));
        let req = Request::builder().uri("http://localhost/api").header(HOST, "example.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.headers().get("x-order").and_then(|v| v.to_str().ok()), Some("B"));

        // Case 2: NameDesc with dedup true on [B,A,B] -> sorted [B,A,B] -> dedup keeps first B -> [B,A], final should be A
        base_rule.plugins_response = Some(vec!["BResp".into(), "AResp".into(), "BResp".into()]);
        base_rule.plugins_order = Some(crate::routing::PluginOrder::NameDesc);
        base_rule.plugins_dedup = Some(true);
        let routing_engine = crate::routing::RoutingEngine::new(RoutingConfig{ rules: vec![base_rule.clone()], default_target: Some("default".into()), enable_logging: false }).unwrap();
        let handler = create_handler_with_plugins(domain_config.clone(), Some(PluginEngine::new(&plugins_cfg).unwrap())).with_routing(Some(routing_engine));
        let req = Request::builder().uri("http://localhost/api").header(HOST, "example.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.headers().get("x-order").and_then(|v| v.to_str().ok()), Some("A"));

        // Case 3: Per-route vs Global override on same key -> global runs after per-route, so global wins
        // We simulate by having global engine include 'global-resp' after 'AResp' and 'BResp', while per-route applies 'AResp'
        let plugins_cfg2 = PluginsConfig { enabled: true, apply_before_domain_match: false, plugins: vec![
            PluginConfig{ name: "AResp".into(), plugin_type: PluginType::HeaderInjector, enabled: true, stage: PluginStage::Response, config: Some(serde_json::json!({"response_headers": {"x-k": "A"}})), error_strategy: PluginErrorStrategy::Continue },
            PluginConfig{ name: "global-resp".into(), plugin_type: PluginType::HeaderInjector, enabled: true, stage: PluginStage::Response, config: Some(serde_json::json!({"response_headers": {"x-k": "G"}})), error_strategy: PluginErrorStrategy::Continue },
        ]};
        let engine2 = PluginEngine::new(&plugins_cfg2).unwrap();
        base_rule.plugins_response = Some(vec!["AResp".into()]);
        base_rule.plugins_order = Some(crate::routing::PluginOrder::AsListed);
        base_rule.plugins_dedup = Some(false);
        let routing_engine = crate::routing::RoutingEngine::new(RoutingConfig{ rules: vec![base_rule.clone()], default_target: Some("default".into()), enable_logging: false }).unwrap();
        let handler = create_handler_with_plugins(domain_config.clone(), Some(engine2)).with_routing(Some(routing_engine));
        let req = Request::builder().uri("http://localhost/api").header(HOST, "example.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        // global plugin ran after per-route subset -> G overrides A
        assert_eq!(resp.headers().get("x-k").and_then(|v| v.to_str().ok()), Some("G"));
    }

    #[tokio::test]
    async fn test_streaming_body_under_limit_not_interrupted() {
        // Ensure this test cannot hang indefinitely
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        use crate::config::*;
        // Security limit high enough so body passes
        let sec_cfg = crate::security::SecurityConfig{ enabled: true, access_control: None, auth: None, rate_limit: None, ddos: Some(crate::security::DdosConfig{ max_headers: None, max_header_bytes: None, max_body_bytes: Some(1024), require_content_length: Some(false) }), jwt: None };
        let sec_mgr = crate::security::SecurityManager::new(sec_cfg);

        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let target_config = TargetConfig{ targets: vec![], load_balancing: LoadBalancingConfig{ lb_type: LoadBalancingType::RoundRobin, sticky_sessions: false }, health_check: HealthCheckConfig{ enabled:false, interval:30, timeout:10, healthy_threshold:2, unhealthy_threshold:3 } };
        let lb = LoadBalancer::new_for_test(target_config);
        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig{ enabled:false, log_type: crate::config::LoggingType::File, database: None, file: None, retention_days: None });
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(lb));
        let handler = ProxyHandler::new(domain_arc, lb_arc, traffic_logger).with_security(Some(sec_mgr));

        // Small chunked body (16 bytes < 1024). Send asynchronously to avoid blocking before handler starts.
        let (mut tx, body) = Body::channel();
        tokio::spawn(async move {
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await;
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await;
        });
        let req = Request::builder().uri("http://localhost/").header(HOST, "example.com").method(hyper::Method::POST).body(body).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        // Not interrupted by 413; likely 503 due to no upstream targets
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }).await.expect("test_streaming_body_under_limit_not_interrupted timed out");
    }

    #[tokio::test]
    async fn test_content_length_under_limit_not_interrupted() {
        use crate::config::*;
        // Security limit high, content-length provided and below limit
        let sec_cfg = crate::security::SecurityConfig{ enabled: true, access_control: None, auth: None, rate_limit: None, ddos: Some(crate::security::DdosConfig{ max_headers: None, max_header_bytes: None, max_body_bytes: Some(1024), require_content_length: Some(true) }), jwt: None };
        let sec_mgr = crate::security::SecurityManager::new(sec_cfg);

        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let target_config = TargetConfig{ targets: vec![], load_balancing: LoadBalancingConfig{ lb_type: LoadBalancingType::RoundRobin, sticky_sessions: false }, health_check: HealthCheckConfig{ enabled:false, interval:30, timeout:10, healthy_threshold:2, unhealthy_threshold:3 } };
        let lb = LoadBalancer::new_for_test(target_config);
        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig{ enabled:false, log_type: crate::config::LoggingType::File, database: None, file: None, retention_days: None });
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(lb));
        let handler = ProxyHandler::new(domain_arc, lb_arc, traffic_logger).with_security(Some(sec_mgr));

        // Body with content-length 16 (< 1024), should not be rejected by 413
        let body = Body::from(vec![0u8; 16]);
        let req = Request::builder().uri("http://localhost/").header(HOST, "example.com").header(hyper::header::CONTENT_LENGTH, "16").method(hyper::Method::POST).body(body).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_ne!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_streaming_body_exceed_limit_413() {
        // Ensure this test cannot hang indefinitely
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        use crate::config::*;
        // Build security with small max_body_bytes
        let sec_cfg = crate::security::SecurityConfig{ enabled: true, access_control: None, auth: None, rate_limit: None, ddos: Some(crate::security::DdosConfig{ max_headers: None, max_header_bytes: None, max_body_bytes: Some(10), require_content_length: Some(false) }), jwt: None };
        let sec_mgr = crate::security::SecurityManager::new(sec_cfg);

        // Build a handler with security enabled
        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let target_config = TargetConfig{ targets: vec![], load_balancing: LoadBalancingConfig{ lb_type: LoadBalancingType::RoundRobin, sticky_sessions: false }, health_check: HealthCheckConfig{ enabled:false, interval:30, timeout:10, healthy_threshold:2, unhealthy_threshold:3 } };
        let lb = LoadBalancer::new_for_test(target_config);
        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig{ enabled:false, log_type: crate::config::LoggingType::File, database: None, file: None, retention_days: None });
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(lb));
        let handler = ProxyHandler::new(domain_arc, lb_arc, traffic_logger).with_security(Some(sec_mgr));

        // Build a chunked body exceeding limit; send asynchronously
        let (mut tx, body) = Body::channel();
        tokio::spawn(async move {
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await;
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await; // total 16 > 10
        });
        let req = Request::builder().uri("http://localhost/").header(HOST, "example.com").method(hyper::Method::POST).body(body).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }).await.expect("test_streaming_body_exceed_limit_413 timed out");
    }

    #[tokio::test]
    async fn test_streaming_limit_aborts_upstream_connection() {
        // Ensure this test cannot hang indefinitely
        let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Server, Request as HRequest};
        use std::sync::{Arc as StdArc};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Start a local upstream HTTP server that counts received bytes
        let received = StdArc::new(AtomicUsize::new(0));
        let received_clone = StdArc::clone(&received);
        let make_svc = make_service_fn(move |_conn| {
            let received = StdArc::clone(&received_clone);
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req: HRequest<Body>| {
                    let received = StdArc::clone(&received);
                    async move {
                        while let Some(chunk) = hyper::body::HttpBody::data(req.body_mut()).await { if let Ok(c)=chunk { received.fetch_add(c.len(), Ordering::SeqCst); } else { break; } }
                        Ok::<_, Infallible>(Response::new(Body::from("ok")))
                    }
                }))
            }
        });
        let server = Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(make_svc);
        let addr = server.local_addr();
        let server_handle = tokio::spawn(server);

        // Security limit = 8 bytes, will exceed after second chunk
        let sec_cfg = crate::security::SecurityConfig{ enabled: true, access_control: None, auth: None, rate_limit: None, ddos: Some(crate::security::DdosConfig{ max_headers: None, max_header_bytes: None, max_body_bytes: Some(8), require_content_length: Some(false) }), jwt: None };
        let sec_mgr = crate::security::SecurityManager::new(sec_cfg);

        // Handler with one healthy target pointing to local server
        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let target = Target{ name: "t1".into(), url: format!("http://{}", addr), weight: Some(1), timeout: Some(30) };
        let target_config = TargetConfig{ targets: vec![target.clone()], load_balancing: LoadBalancingConfig{ lb_type: LoadBalancingType::RoundRobin, sticky_sessions: false }, health_check: HealthCheckConfig{ enabled:false, interval:30, timeout:10, healthy_threshold:2, unhealthy_threshold:3 } };
        let lb = LoadBalancer::new_for_test(target_config);
        // Mark target healthy
        let mut map = std::collections::HashMap::new();
        map.insert(target.name.clone(), crate::balancer::health_check::HealthStatus{ is_healthy: true, ..Default::default() });
        lb.health_checker().set_health_status_for_test(map).await;

        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig{ enabled:false, log_type: crate::config::LoggingType::File, database: None, file: None, retention_days: None });
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(lb));
        let handler = ProxyHandler::new(domain_arc, lb_arc, traffic_logger).with_security(Some(sec_mgr));

        // Build chunked body of 8 + 8 bytes (limit 8 → exceed); send asynchronously
        let (mut tx, body) = Body::channel();
        tokio::spawn(async move {
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await;
            let _ = tx.send_data(bytes::Bytes::from(vec![0u8; 8])).await;
        });
        let req = Request::builder().uri("http://localhost/").header(HOST, "example.com").method(hyper::Method::POST).body(body).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Give upstream a moment to process partial body
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let got = received.load(Ordering::SeqCst);
        assert!(got <= 8, "upstream should receive at most one chunk before abort: got {}", got);

        server_handle.abort();
        }).await.expect("test_streaming_limit_aborts_upstream_connection timed out");
    }

    fn create_handler_with_plugins(domain_config: DomainConfig, engine: Option<PluginEngine>) -> ProxyHandler {
        let target_config = TargetConfig {
            targets: vec![],
            load_balancing: LoadBalancingConfig {
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: false,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 10,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            },
        };
        let load_balancer = LoadBalancer::new_for_test(target_config.clone());
        let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig {
            enabled: false,
            log_type: crate::config::LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        });
        let plugins = std::sync::Arc::new(tokio::sync::RwLock::new(engine));
        let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(load_balancer));
        ProxyHandler::with_shared_routing(domain_arc, lb_arc, traffic_logger, std::sync::Arc::new(tokio::sync::RwLock::new(None)), plugins, std::sync::Arc::new(tokio::sync::RwLock::new(None)))
    }

    #[tokio::test]
    async fn test_plugins_apply_before_domain_check_true_short_circuit() {
        // Domain not intercepted, but plugin runs before domain check and blocks
        let plugins_cfg = PluginsConfig { enabled: true, apply_before_domain_match: true, plugins: vec![
            PluginConfig{ name: "blk".into(), plugin_type: PluginType::Blocklist, enabled: true, stage: PluginStage::Request, config: Some(serde_json::json!({"hosts":["no.intercept.com"]})), error_strategy: PluginErrorStrategy::Continue }
        ]};
        // Build plugin engine
        let engine = PluginEngine::new(&plugins_cfg).unwrap();
        let handler = create_handler_with_plugins(DomainConfig{ intercept_domains: vec![], exclude_domains: None, wildcard_support: true }, Some(engine));
        let req = Request::builder().uri("http://localhost/").header(HOST, "no.intercept.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_plugins_apply_after_domain_check_returns_404() {
        // Domain not intercepted, plugin configured to run after domain check, so it doesn't run
        let plugins_cfg = PluginsConfig { enabled: true, apply_before_domain_match: false, plugins: vec![
            PluginConfig{ name: "blk".into(), plugin_type: PluginType::Blocklist, enabled: true, stage: PluginStage::Request, config: Some(serde_json::json!({"hosts":["no.intercept.com"]})), error_strategy: PluginErrorStrategy::Continue }
        ]};
        let engine = PluginEngine::new(&plugins_cfg).unwrap();
        let handler = create_handler_with_plugins(DomainConfig{ intercept_domains: vec![], exclude_domains: None, wildcard_support: true }, Some(engine));
        let req = Request::builder().uri("http://localhost/").header(HOST, "no.intercept.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_per_route_request_plugin_short_circuit() {
        // Plugins: add a blocklist plugin named 'route-short' that blocks host 'example.com'
        let plugins_cfg = PluginsConfig { enabled: true, apply_before_domain_match: false, plugins: vec![
            PluginConfig{ name: "route-short".into(), plugin_type: PluginType::Blocklist, enabled: true, stage: PluginStage::Request, config: Some(serde_json::json!({"hosts":["example.com"]})), error_strategy: PluginErrorStrategy::Continue }
        ]};
        let engine = PluginEngine::new(&plugins_cfg).unwrap();

        // Routing: rule matching /api, applies the route plugin subset
        let routing_cfg = RoutingConfig {
            rules: vec![RoutingRule{
                name: "api-rule".into(), priority: 100, enabled: true, target: "default".into(),
                conditions: RoutingConditions{ path: Some(PathConditions{ exact: None, prefix: Some("/api".into()), suffix: None, regex: None, contains: None }), method: None, headers: None, query_params: None, host: None },
                actions: RoutingActions{ headers: None, path: None, request_transform: None, response_transform: None, custom_response: None },
                plugins_request: Some(vec!["route-short".into()]),
                plugins_response: None,
                plugins_order: None,
                plugins_dedup: None,
            }],
            default_target: Some("default".into()),
            enable_logging: false,
        };
        let routing_engine = crate::routing::RoutingEngine::new(routing_cfg).unwrap();

        // Handler with routing + plugins
        let domain_config = DomainConfig { intercept_domains: vec!["example.com".into()], exclude_domains: None, wildcard_support: true };
        let handler = create_handler_with_plugins(domain_config, Some(engine))
            .with_routing(Some(routing_engine));

        // Build request for example.com/api (matched by rule and then blocked by route plugin subset)
        let req = Request::builder().uri("http://localhost/api").header(HOST, "example.com").body(Body::empty()).unwrap();
        let resp = handler.handle_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_should_intercept_domain_exact_match() {
        let handler = create_test_handler(
            vec!["example.com".to_string(), "test.org".to_string()],
            None,
            false, // Wildcard support disabled
        );

        // Should intercept exact matches
        assert!(handler.should_intercept_domain("example.com"));
        assert!(handler.should_intercept_domain("test.org"));

        // Should not intercept non-matches
        assert!(!handler.should_intercept_domain("notexample.com"));
        assert!(!handler.should_intercept_domain("api.example.com"));
        assert!(!handler.should_intercept_domain("example.net"));
    }

    #[test]
    fn test_should_intercept_domain_with_port() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        // Should handle hosts with ports
        assert!(handler.should_intercept_domain("example.com:8080"));
        assert!(handler.should_intercept_domain("example.com:443"));
        assert!(!handler.should_intercept_domain("other.com:8080"));
    }

    #[test]
    fn test_should_intercept_domain_exclude_list() {
        let handler = create_test_handler(
            vec!["example.com".to_string(), "*.example.com".to_string()],
            Some(vec![
                "admin.example.com".to_string(),
                "private.example.com".to_string(),
            ]),
            true, // Enable wildcard support
        );

        // Should intercept main domain
        assert!(handler.should_intercept_domain("example.com"));
        assert!(handler.should_intercept_domain("api.example.com"));
        assert!(handler.should_intercept_domain("www.example.com"));

        // Should NOT intercept excluded domains
        assert!(!handler.should_intercept_domain("admin.example.com"));
        assert!(!handler.should_intercept_domain("private.example.com"));

        // Exclude list should also handle ports
        assert!(!handler.should_intercept_domain("admin.example.com:8080"));
    }

    #[test]
    fn test_should_intercept_domain_wildcard_exclude_priority() {
        let handler = create_test_handler(
            vec!["*.example.com".to_string()],
            Some(vec!["admin.example.com".to_string()]),
            true,
        );

        // Wildcard should match
        assert!(handler.should_intercept_domain("api.example.com"));
        assert!(handler.should_intercept_domain("www.example.com"));

        // But exclude list should take priority
        assert!(!handler.should_intercept_domain("admin.example.com"));
    }

    #[test]
    fn test_matches_domain_exact_without_wildcard() {
        let handler = create_test_handler(
            vec!["example.com".to_string()],
            None,
            false, // Wildcard support disabled
        );

        // Exact matches only
        assert!(handler.matches_domain("example.com", "example.com"));
        assert!(!handler.matches_domain("api.example.com", "example.com"));
        assert!(!handler.matches_domain("example.com", "*.example.com"));
        assert!(!handler.matches_domain("api.example.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_enabled() {
        let handler = create_test_handler(
            vec![],
            None,
            true, // Wildcard support enabled
        );

        // Exact matches should still work
        assert!(handler.matches_domain("example.com", "example.com"));
        assert!(handler.matches_domain("api.example.com", "api.example.com"));

        // Wildcard matches
        assert!(handler.matches_domain("api.example.com", "*.example.com"));
        assert!(handler.matches_domain("www.example.com", "*.example.com"));
        assert!(handler.matches_domain("admin.example.com", "*.example.com"));

        // Root domain should match wildcard pattern
        assert!(handler.matches_domain("example.com", "*.example.com"));

        // Should not match different domains
        assert!(!handler.matches_domain("example.org", "*.example.com"));
        assert!(!handler.matches_domain("notexample.com", "*.example.com"));

        // Should not match partial matches
        assert!(!handler.matches_domain("fakeexample.com", "*.example.com"));
        assert!(!handler.matches_domain("example.com.evil.com", "*.example.com"));
    }

    #[test]
    fn test_matches_domain_wildcard_subdomain_levels() {
        let handler = create_test_handler(vec![], None, true);

        // Test multiple subdomain levels
        assert!(handler.matches_domain("a.b.c.example.com", "*.example.com"));
        assert!(handler.matches_domain("very.deep.subdomain.example.com", "*.example.com"));

        // Test different wildcard patterns
        assert!(handler.matches_domain("api.staging.com", "*.staging.com"));
        assert!(handler.matches_domain("staging.com", "*.staging.com"));
    }

    #[test]
    fn test_matches_domain_edge_cases() {
        let handler = create_test_handler(vec![], None, true);

        // Empty patterns or hosts
        assert!(!handler.matches_domain("", "example.com"));
        assert!(!handler.matches_domain("example.com", ""));
        assert!(handler.matches_domain("", "")); // Empty strings match

        // Invalid wildcard patterns
        assert!(!handler.matches_domain("example.com", "*"));
        assert!(!handler.matches_domain("example.com", "*."));

        // Pattern without proper wildcard prefix
        assert!(!handler.matches_domain("api.example.com", "example.com*"));
        assert!(!handler.matches_domain("api.example.com", "*example.com"));
    }

    #[test]
    fn test_should_intercept_domain_complex_scenario() {
        let handler = create_test_handler(
            vec![
                "exactmatch.com".to_string(),
                "*.wildcard.com".to_string(),
                "*.api.service.com".to_string(),
            ],
            Some(vec![
                "admin.wildcard.com".to_string(),
                "internal.api.service.com".to_string(),
            ]),
            true,
        );

        // Exact matches
        assert!(handler.should_intercept_domain("exactmatch.com"));
        assert!(!handler.should_intercept_domain("notexactmatch.com"));

        // Wildcard matches
        assert!(handler.should_intercept_domain("public.wildcard.com"));
        assert!(handler.should_intercept_domain("www.wildcard.com"));
        assert!(handler.should_intercept_domain("wildcard.com"));

        // Multi-level wildcard
        assert!(handler.should_intercept_domain("v1.api.service.com"));
        assert!(handler.should_intercept_domain("v2.api.service.com"));
        assert!(handler.should_intercept_domain("api.service.com"));

        // Excluded domains should not be intercepted
        assert!(!handler.should_intercept_domain("admin.wildcard.com"));
        assert!(!handler.should_intercept_domain("internal.api.service.com"));

        // Non-matching domains
        assert!(!handler.should_intercept_domain("other.service.com"));
        assert!(!handler.should_intercept_domain("api.other.com"));
    }

    #[test]
    fn test_wildcard_with_different_tlds() {
        let handler = create_test_handler(
            vec!["*.example.com".to_string(), "*.example.org".to_string()],
            None,
            true,
        );

        // Should match correct TLDs
        assert!(handler.should_intercept_domain("api.example.com"));
        assert!(handler.should_intercept_domain("www.example.org"));

        // Should not cross-match TLDs
        assert!(!handler.should_intercept_domain("api.example.net")); // .net not in list
        assert!(!handler.should_intercept_domain("www.example.co.uk")); // .co.uk not in list
    }

    #[test]
    fn test_case_sensitivity() {
        let handler = create_test_handler(
            vec!["Example.COM".to_string(), "*.Test.ORG".to_string()],
            Some(vec!["Admin.Example.COM".to_string()]),
            true,
        );

        // Domain matching should be case-sensitive as configured
        assert!(handler.should_intercept_domain("Example.COM"));
        assert!(!handler.should_intercept_domain("example.com")); // Different case

        assert!(handler.should_intercept_domain("api.Test.ORG"));
        assert!(!handler.should_intercept_domain("api.test.org")); // Different case

        assert!(!handler.should_intercept_domain("Admin.Example.COM"));
        assert!(!handler.should_intercept_domain("admin.example.com")); // Case doesn't match intercept list
    }

    #[test]
    fn test_empty_intercept_domains() {
        let handler = create_test_handler(
            vec![], // Empty intercept list
            None,
            true,
        );

        // Should not intercept anything when list is empty
        assert!(!handler.should_intercept_domain("example.com"));
        assert!(!handler.should_intercept_domain("api.example.com"));
        assert!(!handler.should_intercept_domain("anything.com"));
    }

    #[test]
    fn test_wildcard_subdomain_boundary() {
        let handler = create_test_handler(vec!["*.example.com".to_string()], None, true);

        // Should match subdomains
        assert!(handler.matches_domain("sub.example.com", "*.example.com"));
        assert!(handler.matches_domain("a.b.example.com", "*.example.com"));

        // Should match the root domain itself
        assert!(handler.matches_domain("example.com", "*.example.com"));

        // Should not match partial matches
        assert!(!handler.matches_domain("notexample.com", "*.example.com"));
        assert!(!handler.matches_domain("example.com.attacker.com", "*.example.com"));

        // Should not match if suffix doesn't align on subdomain boundary
        assert!(!handler.matches_domain("fakeexample.com", "*.example.com"));
        assert!(!handler.matches_domain("myexample.com", "*.example.com"));
    }

    #[tokio::test]
    async fn test_handle_request_with_unsupported_domain() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "unsupported.com")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Domain not found");
    }

    #[tokio::test]
    async fn test_handle_request_with_supported_domain_no_targets() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "example.com")
            .body(Body::empty())
            .unwrap();

        // Since we have no healthy targets, should return SERVICE_UNAVAILABLE
        let response = handler.handle_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Service unavailable");
    }

    #[tokio::test]
    async fn test_handle_request_missing_host_header() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            // No Host header
            .body(Body::empty())
            .unwrap();

        // Should treat missing host as "unknown" and reject it
        let response = handler.handle_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Domain not found");
    }

    #[tokio::test]
    async fn test_handle_request_different_http_methods() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

        for method in methods {
            let request = Request::builder()
                .method(method)
                .uri("/test")
                .header("Host", "example.com")
                .body(Body::empty())
                .unwrap();

            let response = handler.handle_request(request).await.unwrap();
            // Should be SERVICE_UNAVAILABLE since we have no targets, but it shouldn't crash
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn test_handle_request_with_invalid_host_header() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        // Test with an unusual but valid host header
        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "unusual-host") // Use a simple unusual host
            .body(Body::empty())
            .unwrap();

        // Should handle unusual host header and reject it as not in intercept list
        let response = handler.handle_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handle_request_with_query_parameters() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("GET")
            .uri("/api/test?param1=value1&param2=value2")
            .header("Host", "example.com")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();
        // Should be SERVICE_UNAVAILABLE since we have no targets
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_handle_request_with_request_body() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("POST")
            .uri("/api/data")
            .header("Host", "example.com")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"key": "value"}"#))
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();
        // Should be SERVICE_UNAVAILABLE since we have no targets
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_is_hop_by_hop_header() {
        let hop_by_hop_headers = vec![
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ];

        for header in hop_by_hop_headers {
            assert!(is_hop_by_hop_header(header));
            assert!(is_hop_by_hop_header(&header.to_uppercase()));
        }

        let regular_headers = vec![
            "content-type",
            "content-length",
            "authorization",
            "cache-control",
            "user-agent",
            "accept",
            "host",
            "x-forwarded-for",
        ];

        for header in regular_headers {
            assert!(!is_hop_by_hop_header(header));
            assert!(!is_hop_by_hop_header(&header.to_uppercase()));
        }
    }

    #[tokio::test]
    async fn test_handle_request_wildcard_domain_matching() {
        let handler = create_test_handler(vec!["*.example.com".to_string()], None, true);

        // Test various subdomain levels
        let test_hosts = vec![
            "api.example.com",
            "www.example.com",
            "staging.api.example.com",
            "v1.api.staging.example.com",
            "example.com", // Root domain should also match
        ];

        for host in test_hosts {
            let request = Request::builder()
                .method("GET")
                .uri("/test")
                .header("Host", host)
                .body(Body::empty())
                .unwrap();

            let response = handler.handle_request(request).await.unwrap();
            // Should be SERVICE_UNAVAILABLE since we have no targets, but domain should be accepted
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }

        // Test non-matching domains
        let non_matching_hosts = vec!["example.org", "notexample.com", "example.com.evil.com"];

        for host in non_matching_hosts {
            let request = Request::builder()
                .method("GET")
                .uri("/test")
                .header("Host", host)
                .body(Body::empty())
                .unwrap();

            let response = handler.handle_request(request).await.unwrap();
            // Should be NOT_FOUND since domain doesn't match
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn test_handle_request_with_exclude_domains() {
        let handler = create_test_handler(
            vec!["*.example.com".to_string()],
            Some(vec![
                "admin.example.com".to_string(),
                "internal.example.com".to_string(),
            ]),
            true,
        );

        // Should accept most subdomains
        let accepted_hosts = vec!["api.example.com", "www.example.com", "public.example.com"];

        for host in accepted_hosts {
            let request = Request::builder()
                .method("GET")
                .uri("/test")
                .header("Host", host)
                .body(Body::empty())
                .unwrap();

            let response = handler.handle_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE); // No targets
        }

        // Should reject excluded domains
        let excluded_hosts = vec!["admin.example.com", "internal.example.com"];

        for host in excluded_hosts {
            let request = Request::builder()
                .method("GET")
                .uri("/test")
                .header("Host", host)
                .body(Body::empty())
                .unwrap();

            let response = handler.handle_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn test_handle_request_internal_error_handling() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        // Create a request that should trigger internal processing but no targets available
        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "example.com")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();

        // Should handle the error gracefully and return proper response
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Service unavailable");
    }

    #[tokio::test]
    async fn test_handle_request_with_host_and_port() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        let request = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "example.com:8080") // Host with port
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();
        // Should strip the port and match successfully, then return SERVICE_UNAVAILABLE due to no targets
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_handle_request_with_large_uri() {
        let handler = create_test_handler(vec!["example.com".to_string()], None, false);

        // Create a long URI path
        let long_path = format!("/api/{}", "a".repeat(1000));

        let request = Request::builder()
            .method("GET")
            .uri(long_path)
            .header("Host", "example.com")
            .body(Body::empty())
            .unwrap();

        let response = handler.handle_request(request).await.unwrap();
        // Should handle long URIs gracefully
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_handle_request_concurrent_requests() {
        let handler = std::sync::Arc::new(create_test_handler(
            vec!["example.com".to_string()],
            None,
            false,
        ));

        let mut handles = Vec::new();

        // Create multiple concurrent requests
        for i in 0..10 {
            let handler_clone = std::sync::Arc::clone(&handler);
            let handle = tokio::spawn(async move {
                let request = Request::builder()
                    .method("GET")
                    .uri(format!("/test/{}", i))
                    .header("Host", "example.com")
                    .body(Body::empty())
                    .unwrap();

                handler_clone.handle_request(request).await.unwrap()
            });
            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let response = handle.await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn test_proxy_handler_creation_with_different_configs() {
        // Test with different domain configurations
        let domain_configs = vec![
            DomainConfig {
                intercept_domains: vec!["single.com".to_string()],
                exclude_domains: None,
                wildcard_support: false,
            },
            DomainConfig {
                intercept_domains: vec!["*.wildcard.com".to_string()],
                exclude_domains: Some(vec!["admin.wildcard.com".to_string()]),
                wildcard_support: true,
            },
            DomainConfig {
                intercept_domains: vec![
                    "first.com".to_string(),
                    "second.com".to_string(),
                    "*.multi.com".to_string(),
                ],
                exclude_domains: Some(vec![
                    "exclude1.com".to_string(),
                    "exclude2.multi.com".to_string(),
                ]),
                wildcard_support: true,
            },
        ];

        for domain_config in domain_configs {
            let target_config = TargetConfig {
                targets: vec![],
                load_balancing: LoadBalancingConfig {
                    lb_type: LoadBalancingType::RoundRobin,
                    sticky_sessions: false,
                },
                health_check: HealthCheckConfig {
                    enabled: false,
                    interval: 30,
                    timeout: 10,
                    healthy_threshold: 2,
                    unhealthy_threshold: 3,
                },
            };

            let load_balancer = LoadBalancer::new_for_test(target_config.clone());
            let traffic_logger = TrafficLogger::new(crate::config::LoggingConfig {
                enabled: false,
                log_type: crate::config::LoggingType::File,
                database: None,
                file: None,
                retention_days: None,
            });

            // Should not panic when creating handler with different configs
            let domain_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config.clone()));
            let lb_arc = std::sync::Arc::new(tokio::sync::RwLock::new(load_balancer));
            let _handler = ProxyHandler::new(domain_arc.clone(), lb_arc, traffic_logger);

            // Verify the handler was created successfully by checking it accepts its own domains
            let cfg = domain_arc.read().unwrap();
            assert_eq!(cfg.intercept_domains, domain_config.intercept_domains);
            assert_eq!(cfg.exclude_domains, domain_config.exclude_domains);
            assert_eq!(cfg.wildcard_support, domain_config.wildcard_support);
        }
    }
}
