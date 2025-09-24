use chrono::Utc;
use hyper::header::HOST;
use hyper::{Body, Request, Response};
use std::net::IpAddr;
use tracing::warn;
use uuid::Uuid;

use crate::balancer::LoadBalancer;
use crate::config::DomainConfig;
use crate::logger::TrafficLogger;
use crate::plugins::{PluginResult, SharedPluginEngine};
use crate::routing::{RoutingDecision, RoutingEngine};
use crate::security::SharedSecurity;
use std::sync::RwLock as StdRwLock;

/// Request processing context
pub struct RequestContext {
    pub request_id: Uuid,
    pub start_time: chrono::DateTime<Utc>,
    pub client_addr: std::net::SocketAddr,
    pub host: String,
    pub method: String,
    pub path: String,
}

impl RequestContext {
    pub fn new(req: &Request<Body>) -> Self {
        let request_id = Uuid::new_v4();
        let start_time = Utc::now();
        let client_addr = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());

        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        Self {
            request_id,
            start_time,
            client_addr,
            host,
            method,
            path,
        }
    }
}

/// Security processing result
pub enum SecurityResult {
    Allow,
    Deny(Response<Body>),
}

/// Plugin processing result
pub enum PluginProcessResult {
    Continue,
    ShortCircuit(Response<Body>),
}

/// Domain matching result
pub enum DomainMatchResult {
    Intercept,
    NotFound,
}

/// Request processor handles the main request processing pipeline
#[derive(Clone)]
pub struct RequestProcessor {
    domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
    #[allow(dead_code)]
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    traffic_logger: TrafficLogger,
    routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
    plugins: SharedPluginEngine,
    security: SharedSecurity,
}

impl RequestProcessor {
    pub fn new(
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

    /// Check security constraints
    pub async fn check_security(
        &self,
        req: &Request<Body>,
        client_ip: Option<IpAddr>,
    ) -> SecurityResult {
        let guard = self.security.read().await;
        if let Some(sec) = guard.as_ref() {
            if let Some(resp) = sec.check_request(req, client_ip).await {
                return SecurityResult::Deny(resp);
            }
        }
        SecurityResult::Allow
    }

    /// Apply request plugins
    pub async fn apply_request_plugins(
        &self,
        req: &mut Request<Body>,
        before_domain_check: bool,
    ) -> PluginProcessResult {
        let apply_before = {
            let guard = self.plugins.read().await;
            guard
                .as_ref()
                .map(|e| e.apply_before_domain_match())
                .unwrap_or(true)
        };

        if apply_before == before_domain_check {
            let guard = self.plugins.read().await;
            if let Some(engine) = guard.as_ref() {
                if let PluginResult::ShortCircuit(resp) = engine.apply_request(req).await {
                    return PluginProcessResult::ShortCircuit(resp);
                }
            }
        }
        PluginProcessResult::Continue
    }

    /// Check if domain should be intercepted
    pub fn check_domain_intercept(&self, host: &str) -> DomainMatchResult {
        if !self.should_intercept_domain(host) {
            warn!("Domain {} not in intercept list, returning 404", host);
            return DomainMatchResult::NotFound;
        }
        DomainMatchResult::Intercept
    }

    /// Route the request
    pub async fn route_request(&self, req: &Request<Body>) -> Option<RoutingDecision> {
        let guard = self.routing_engine.read().await;
        if let Some(engine) = guard.as_ref() {
            Some(engine.route_request(req).await)
        } else {
            None
        }
    }

    /// Check if a domain should be intercepted
    fn should_intercept_domain(&self, host: &str) -> bool {
        let cfg = self.domain_config.read().unwrap();

        // Remove port if present
        let host_without_port = host.split(':').next().unwrap_or(host);

        // Check exclude list first
        if let Some(ref exclude_domains) = cfg.exclude_domains {
            for exclude_domain in exclude_domains {
                if cfg.enable_wildcard && exclude_domain.starts_with("*.") {
                    let pattern = &exclude_domain[2..];
                    if host_without_port.ends_with(pattern) {
                        return false;
                    }
                } else if host_without_port == exclude_domain {
                    return false;
                }
            }
        }

        // Check intercept list
        for intercept_domain in &cfg.intercept_domains {
            if cfg.enable_wildcard && intercept_domain.starts_with("*.") {
                let pattern = &intercept_domain[2..];
                if host_without_port.ends_with(pattern) {
                    return true;
                }
            } else if host_without_port == intercept_domain {
                return true;
            }
        }

        false
    }

    /// Log traffic information
    pub async fn log_traffic(&self, ctx: &RequestContext, response: &Response<Body>) {
        let response_status = response.status();
        let duration = Utc::now()
            .signed_duration_since(ctx.start_time)
            .to_std()
            .unwrap_or_default();

        if let Err(e) = self
            .traffic_logger
            .log_request(
                ctx.request_id,
                ctx.client_addr,
                &ctx.host,
                &ctx.method,
                &ctx.path,
                "unknown", // target name - would need to be passed in
                response_status,
                ctx.start_time,
                duration,
                None, // user_agent
                None, // error_message
            )
            .await
        {
            warn!("Failed to log traffic: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::LoadBalancer;
    use crate::config::{DomainConfig, LoggingConfig, TargetConfig};
    use crate::logger::TrafficLogger;
    use hyper::{Body, Method, Request};
    use std::sync::Arc;
    use tokio::sync::RwLock as TokioRwLock;

    fn create_test_processor() -> RequestProcessor {
        let domain_config = Arc::new(StdRwLock::new(DomainConfig {
            intercept_domains: vec!["example.com".to_string()],
            exclude_domains: Some(vec![]),
            enable_wildcard: true,
        }));

        let load_balancer = Arc::new(TokioRwLock::new(LoadBalancer::new(TargetConfig::default())));
        let traffic_logger = TrafficLogger::new(LoggingConfig::default());
        let routing_engine = Arc::new(TokioRwLock::new(None));
        let plugins = Arc::new(TokioRwLock::new(None));
        let security = Arc::new(TokioRwLock::new(None));

        RequestProcessor::new(
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine,
            plugins,
            security,
        )
    }

    #[test]
    fn test_request_context_creation() {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();

        let ctx = RequestContext::new(&req);
        assert_eq!(ctx.host, "example.com");
        assert_eq!(ctx.method, "GET");
        assert_eq!(ctx.path, "/test");
    }

    #[tokio::test]
    async fn test_domain_intercept_matching() {
        let processor = create_test_processor();

        match processor.check_domain_intercept("example.com") {
            DomainMatchResult::Intercept => {}
            _ => panic!("Should intercept example.com"),
        }

        match processor.check_domain_intercept("other.com") {
            DomainMatchResult::NotFound => {}
            _ => panic!("Should not intercept other.com"),
        }
    }

    #[tokio::test]
    async fn test_security_check_allow() {
        let processor = create_test_processor();
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap();

        match processor.check_security(&req, None).await {
            SecurityResult::Allow => {}
            _ => panic!("Should allow request when no security configured"),
        }
    }
}
