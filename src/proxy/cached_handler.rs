use anyhow::Result;
use chrono::Utc;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode, Uri};
use std::convert::Infallible;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::balancer::LoadBalancer;
use dispa::cache::{CacheEntry, CacheStats, ConditionalResult, ETagManager, InMemoryCache, PolicyEngine};
use crate::config::{CacheConfig, DomainConfig};
use std::sync::RwLock as StdRwLock;
use crate::logger::TrafficLogger;
use crate::routing::RoutingEngine;

/// Cache-enabled proxy handler
#[derive(Clone)]
pub struct CachedProxyHandler {
    domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    traffic_logger: TrafficLogger,
    routing_engine: Option<RoutingEngine>,
    cache: Option<InMemoryCache>,
    policy_engine: Option<PolicyEngine>,
    etag_manager: Option<ETagManager>,
}

impl CachedProxyHandler {
    /// Create a new cache-enabled proxy handler
    pub fn new(
        domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
        load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
        traffic_logger: TrafficLogger,
        cache_config: Option<CacheConfig>,
    ) -> Self {
        let (cache, policy_engine, etag_manager) = if let Some(config) = cache_config {
            if config.enabled {
                let cache = InMemoryCache::new(config.clone());
                let policy_engine = PolicyEngine::new(config.clone());
                let etag_manager = ETagManager::new(config.etag_enabled);
                (Some(cache), Some(policy_engine), Some(etag_manager))
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        Self {
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine: None,
            cache,
            policy_engine,
            etag_manager,
        }
    }

    /// Create a new cache-enabled proxy handler with routing
    pub fn with_routing(
        domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
        load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
        traffic_logger: TrafficLogger,
        routing_engine: RoutingEngine,
        cache_config: Option<CacheConfig>,
    ) -> Self {
        let mut handler = Self::new(domain_config, load_balancer, traffic_logger, cache_config);
        handler.routing_engine = Some(routing_engine);
        handler
    }

    /// Handle incoming request with caching support
    pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        match self.process_request_with_cache(req).await {
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

    /// Process request with caching logic
    async fn process_request_with_cache(&self, req: Request<Body>) -> Result<Response<Body>> {
        let request_id = Uuid::new_v4();
        let start_time = Utc::now();

        // Extract host and method from request headers before moving req
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();

        debug!("Request {} to {} {}", request_id, method, uri);

        // Check if this domain should be intercepted
        if !self.should_intercept_domain(&host) {
            warn!("Domain {} not in intercept list, returning 404", host);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Domain not found"))
                .unwrap());
        }

        // Only cache GET requests by default
        if method == Method::GET {
            // Try to serve from cache
            if let Some(cached_response) = self.try_serve_from_cache(&req).await {
                info!("Request {} served from cache", request_id);
                return Ok(cached_response);
            }
        }

        // Process request normally and potentially cache the response
        let response = self.process_request_and_cache(req, request_id).await?;

        let status = response.status();
        let end_time = Utc::now();
        let duration = end_time - start_time;
        let std_duration = std::time::Duration::from_millis(duration.num_milliseconds() as u64);

        // Log the traffic
        if let Err(e) = self
            .traffic_logger
            .log_request(
                request_id,
                "127.0.0.1:0".parse().unwrap(),
                &host,
                method.as_ref(),
                &path,
                "unknown", // Will be updated when we get the actual target
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

        Ok(response)
    }

    /// Try to serve request from cache
    async fn try_serve_from_cache(&self, req: &Request<Body>) -> Option<Response<Body>> {
        let cache = self.cache.as_ref()?;
        let policy_engine = self.policy_engine.as_ref()?;
        let etag_manager = self.etag_manager.as_ref()?;

        // Generate cache key
        let cache_key = policy_engine.generate_cache_key(req.uri(), req.headers(), "");

        // Try to get cached entry
        if let Some(cached_entry) = cache.get(&cache_key).await {
            debug!("Found cached entry for key: {}", cache_key);

            // Check conditional headers (If-None-Match, etc.)
            match etag_manager.process_conditional_request(req.headers(), &cached_entry) {
                ConditionalResult::NotModified => {
                    debug!("Returning 304 Not Modified from cache");
                    return Some(etag_manager.create_not_modified_response(&cached_entry.headers));
                }
                ConditionalResult::PreconditionFailed => {
                    debug!("Returning 412 Precondition Failed");
                    return Some(etag_manager.create_precondition_failed_response());
                }
                ConditionalResult::Continue => {
                    // Return cached response
                    debug!("Returning cached response");
                    match cached_entry.to_response() {
                        Ok(response) => return Some(response),
                        Err(e) => {
                            warn!("Failed to convert cached entry to response: {}", e);
                        }
                    }
                }
            }
        }

        None
    }

    /// Process request normally and cache the response if appropriate
    async fn process_request_and_cache(
        &self,
        req: Request<Body>,
        request_id: Uuid,
    ) -> Result<Response<Body>> {
        // Extract information needed for caching before moving req
        let req_uri = req.uri().clone();
        let req_headers = req.headers().clone();

        // Route the request using routing engine or fall back to load balancer
        let routing_decision = if let Some(routing_engine) = &self.routing_engine {
            Some(routing_engine.route_request(&req).await)
        } else {
            None
        };

        let (target_name, processed_req) = if let Some(ref decision) = routing_decision {
            // Check for custom response first
            if let Some(custom_response) = &decision.custom_response {
                info!(
                    "Request {} matched routing rule '{}' with custom response",
                    request_id,
                    decision.rule_name.as_deref().unwrap_or("unknown")
                );
                return Ok(self
                    .routing_engine
                    .as_ref()
                    .unwrap()
                    .create_custom_response(custom_response)?);
            }

            // Apply request transformations if present
            let transformed_req = if let Some(actions) = &decision.request_actions {
                self.routing_engine
                    .as_ref()
                    .unwrap()
                    .apply_request_transformations(req, actions)
                    .await?
            } else {
                req
            };

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
                warn!("Target '{}' not found or not healthy", target_name);
                return Ok(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::from("Service unavailable"))
                    .unwrap());
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
        let final_response = if let (Some(routing_engine), Some(ref decision)) =
            (&self.routing_engine, &routing_decision)
        {
            if let Some(actions) = &decision.response_actions {
                match routing_engine
                    .apply_response_transformations(response, actions)
                    .await
                {
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
        };

        // Try to cache the response using the original request info
        let cacheable_response = self
            .try_cache_response_with_info(&req_uri, &req_headers, final_response)
            .await;

        Ok(cacheable_response)
    }

    /// Try to cache the response with separated request information
    async fn try_cache_response_with_info(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
        response: Response<Body>,
    ) -> Response<Body> {
        let cache = match self.cache.as_ref() {
            Some(cache) => cache,
            None => return response,
        };

        let policy_engine = match self.policy_engine.as_ref() {
            Some(engine) => engine,
            None => return response,
        };

        let etag_manager = match self.etag_manager.as_ref() {
            Some(manager) => manager,
            None => return response,
        };

        // Check if response should be cached
        let cache_decision =
            policy_engine.should_cache(uri, headers, response.status(), response.headers());

        if !cache_decision.should_cache() {
            debug!(
                "Response not cacheable: {}",
                cache_decision.no_cache_reason().unwrap_or("Unknown")
            );
            return response;
        }

        // Read response body for caching
        let (parts, body) = response.into_parts();
        let body_bytes = match hyper::body::to_bytes(body).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to read response body for caching: {}", e);
                return Response::from_parts(parts, Body::empty());
            }
        };

        // Generate ETag if needed
        let mut headers = parts.headers.clone();
        let etag_opt = etag_manager.generate_etag(&body_bytes);
        if let Some(etag_string) = etag_opt {
            if let Ok(etag_value) = HeaderValue::from_str(&etag_string) {
                headers.insert("etag", etag_value);
            }
        }

        // Create cache entry
        let ttl = cache_decision
            .ttl()
            .unwrap_or(std::time::Duration::from_secs(3600));
        let cache_entry = CacheEntry::new(parts.status, headers.clone(), body_bytes.to_vec(), ttl);

        // Generate cache key with vary suffix
        let vary_suffix = cache_decision.vary_suffix().unwrap_or("");
        let cache_key = policy_engine.generate_cache_key(uri, &headers, vary_suffix);

        // Store in cache
        if let Err(e) = cache.put(cache_key.clone(), cache_entry).await {
            warn!("Failed to cache response for key '{}': {}", cache_key, e);
        } else {
            debug!("Cached response for key: {}", cache_key);
        }

        // Return response with cache headers
        let mut builder = Response::builder().status(parts.status);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }

        // Add cache miss header
        builder = builder.header("X-Cache", "MISS");

        builder.body(Body::from(body_bytes)).unwrap_or_else(|e| {
            warn!("Failed to rebuild response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Response building failed"))
                .unwrap()
        })
    }

    /// Check if domain should be intercepted
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

    /// Check if host matches domain pattern
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

    /// Forward request to target using shared pooled hyper client (streaming bodies)
    async fn forward_request(
        &self,
        req: Request<Body>,
        target_url: &str,
    ) -> Result<Response<Body>> {
        super::http_client::forward(req, target_url).await
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> Option<CacheStats> {
        if let Some(cache) = &self.cache {
            Some(cache.stats().await)
        } else {
            None
        }
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.clear().await;
        }
    }
}

/// Check if header is hop-by-hop
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
