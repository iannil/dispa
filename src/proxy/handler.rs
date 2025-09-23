use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use tracing::{info, warn};

use crate::balancer::LoadBalancer;
use crate::config::DomainConfig;
use crate::logger::TrafficLogger;
use crate::plugins::SharedPluginEngine;
use crate::routing::RoutingEngine;
use crate::security::SharedSecurity;
use std::sync::RwLock as StdRwLock;

use super::request_forwarder::RequestForwarder;
use super::request_processor::{
    DomainMatchResult, PluginProcessResult, RequestContext, RequestProcessor, SecurityResult,
};

#[derive(Clone)]
pub struct ProxyHandler {
    request_processor: RequestProcessor,
    request_forwarder: RequestForwarder,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
}

impl ProxyHandler {
    #[cfg(test)]
    pub fn new(
        domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
        load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
        traffic_logger: TrafficLogger,
    ) -> Self {
        let routing_engine = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let plugins = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let security = std::sync::Arc::new(tokio::sync::RwLock::new(None));

        let request_processor = RequestProcessor::new(
            domain_config,
            load_balancer.clone(),
            traffic_logger,
            routing_engine,
            plugins,
            security.clone(),
        );

        let request_forwarder = RequestForwarder::new(security);

        Self {
            request_processor,
            request_forwarder,
            load_balancer,
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
        let request_processor = RequestProcessor::new(
            domain_config,
            load_balancer.clone(),
            traffic_logger,
            routing_engine,
            plugins,
            security.clone(),
        );

        let request_forwarder = RequestForwarder::new(security);

        Self {
            request_processor,
            request_forwarder,
            load_balancer,
        }
    }

    pub async fn handle(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        match self.process_request(req).await {
            Ok(response) => Ok(response),
            Err(e) => {
                warn!("Request processing error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal Server Error"))
                    .unwrap())
            }
        }
    }

    // Alias method for backward compatibility
    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        self.handle(req).await
    }

    async fn process_request(&self, mut req: Request<Body>) -> Result<Response<Body>> {
        // Create request context
        let ctx = RequestContext::new(&req);

        // Security checks (global, earliest)
        let client_ip = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(|sa| sa.ip());

        match self.request_processor.check_security(&req, client_ip).await {
            SecurityResult::Allow => {}
            SecurityResult::Deny(resp) => return Ok(resp),
        }

        // Plugins: request phase (position controlled by plugins config)
        let applied_request_plugins = match self
            .request_processor
            .apply_request_plugins(&mut req, true)
            .await
        {
            PluginProcessResult::Continue => true,
            PluginProcessResult::ShortCircuit(resp) => return Ok(resp),
        };

        // Check if this domain should be intercepted
        match self.request_processor.check_domain_intercept(&ctx.host) {
            DomainMatchResult::Intercept => {}
            DomainMatchResult::NotFound => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("Domain not found"))
                    .unwrap());
            }
        }

        // Route the request using routing engine or fall back to load balancer
        let routing_decision = self.request_processor.route_request(&req).await;

        // If request plugins are configured to run after domain check, run them now
        if !applied_request_plugins {
            match self
                .request_processor
                .apply_request_plugins(&mut req, false)
                .await
            {
                PluginProcessResult::Continue => {}
                PluginProcessResult::ShortCircuit(resp) => return Ok(resp),
            }
        }

        let (target_name, processed_req) = if let Some(ref decision) = routing_decision {
            // Check for custom response first
            if let Some(_custom_response) = &decision.custom_response {
                info!(
                    "Request {} matched routing rule '{}' with custom response",
                    ctx.request_id,
                    decision.rule_name.as_deref().unwrap_or("unknown")
                );
                // Create custom response using routing engine
                // For now, return a simple response
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("Custom response"))
                    .unwrap());
            }

            // Handle per-route request plugins
            let modified_req = req;
            if let Some(ref actions) = decision.request_actions {
                if actions.headers.is_some()
                    || actions.path.is_some()
                    || actions.request_transform.is_some()
                {
                    // Apply per-route plugins would go here
                    // For now, just pass through
                }
            }

            (decision.target.clone(), modified_req)
        } else {
            // Use load balancer to select target
            let guard = self.load_balancer.read().await;
            let target = guard
                .get_target()
                .await
                .ok_or_else(|| anyhow::anyhow!("No target available"))?;
            (target.name.clone(), req)
        };

        // Forward the request
        let target = {
            let guard = self.load_balancer.read().await;
            guard
                .get_target()
                .await
                .ok_or_else(|| anyhow::anyhow!("Target '{}' not found", target_name))?
        };

        let response = match self
            .request_forwarder
            .forward_request(processed_req, &target.url)
            .await
        {
            Ok(resp) => {
                // Apply response plugins if configured
                if let Some(ref decision) = routing_decision {
                    if let Some(ref actions) = decision.response_actions {
                        if actions.headers.is_some() || actions.response_transform.is_some() {
                            // Apply per-route response plugins would go here
                            // For now, just pass through
                        }
                    }
                } else {
                    // Apply global response plugins would go here
                    // For now, just pass through
                }

                // Log the traffic
                self.request_processor.log_traffic(&ctx, &resp).await;

                resp
            }
            Err(e) => {
                warn!(
                    "Failed to forward request {} to target {}: {}",
                    ctx.request_id, target_name, e
                );

                // Log the failed request
                let error_response = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Bad Gateway"))
                    .unwrap();

                self.request_processor
                    .log_traffic(&ctx, &error_response)
                    .await;
                error_response
            }
        };

        Ok(response)
    }
}
