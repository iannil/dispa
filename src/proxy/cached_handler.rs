#![allow(dead_code)]
use anyhow::Result;
use chrono::Utc;
use hyper::header::HOST;
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode, Uri};
use std::convert::Infallible;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::balancer::LoadBalancer;
use crate::cache::{CacheEntry, CacheMetrics, ETagManager, InMemoryCache, PolicyEngine};
use crate::config::{CacheConfig, DomainConfig};
use crate::logger::TrafficLogger;
use crate::routing::RoutingEngine;
use std::sync::RwLock as StdRwLock;

/// Cache-enabled proxy handler
#[derive(Clone)]
pub struct CachedProxyHandler {
    domain_config: std::sync::Arc<StdRwLock<DomainConfig>>,
    load_balancer: std::sync::Arc<tokio::sync::RwLock<LoadBalancer>>,
    traffic_logger: TrafficLogger,
    routing_engine: Option<std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>>,
    cache: Option<std::sync::Arc<tokio::sync::RwLock<InMemoryCache>>>,
    policy_engine: Option<std::sync::Arc<PolicyEngine>>,
    #[allow(dead_code)]
    etag_manager: Option<std::sync::Arc<ETagManager>>,
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
                let cache = std::sync::Arc::new(tokio::sync::RwLock::new(InMemoryCache::new(
                    config.clone(),
                )));
                let policy_engine = std::sync::Arc::new(PolicyEngine::new(config.clone()));
                let etag_manager = std::sync::Arc::new(ETagManager::new(config.enable_etag));
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
        routing_engine: std::sync::Arc<tokio::sync::RwLock<Option<RoutingEngine>>>,
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
                    .expect("Building internal server error response should not fail"))
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
                .expect("Building not found response should not fail"));
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
                "127.0.0.1:0"
                    .parse()
                    .expect("Default localhost address parsing should not fail"),
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
        let cache = self.cache.as_ref()?.read().await;
        let _policy_engine = self.policy_engine.as_ref()?;

        // Generate cache key
        let cache_key = format!("{}:{}", req.method(), req.uri().path());

        // Try to get cached entry
        if let Some(cached_entry) = cache.get(&cache_key).await {
            debug!("Found cached entry for key: {}", cache_key);

            // Check if entry is expired
            if cached_entry.is_expired() {
                debug!("Cached entry expired for key: {}", cache_key);
                return None;
            }

            // Check conditional headers (If-None-Match)
            if let Some(if_none_match) = req.headers().get("if-none-match") {
                if let Ok(etag_value) = if_none_match.to_str() {
                    if cached_entry.matches_etag(etag_value) {
                        debug!("ETag match, returning 304 Not Modified");
                        return Some(
                            Response::builder()
                                .status(StatusCode::NOT_MODIFIED)
                                .header(
                                    "ETag",
                                    cached_entry
                                        .etag
                                        .as_ref()
                                        .expect("Cached entry should have ETag"),
                                )
                                .header("X-Cache", "HIT-CONDITIONAL")
                                .body(Body::empty())
                                .expect("Building 304 response should not fail"),
                        );
                    }
                }
            }

            // Return cached response
            debug!("Returning cached response");
            match cached_entry.to_response() {
                Ok(response) => return Some(response),
                Err(e) => {
                    warn!("Failed to convert cached entry to response: {}", e);
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
        let routing_decision = if let Some(routing_engine_arc) = &self.routing_engine {
            if let Some(routing_engine) = routing_engine_arc.read().await.as_ref() {
                Some(routing_engine.route_request(&req).await)
            } else {
                None
            }
        } else {
            None
        };

        let (target_name, processed_req) = if let Some(ref decision) = routing_decision {
            // Check for custom response first
            if let Some(_custom_response) = &decision.custom_response {
                info!(
                    "Request {} matched routing rule '{}' with custom response",
                    request_id,
                    decision.rule_name.as_deref().unwrap_or("unknown")
                );
                // For now, return a simple response since we can't access routing engine methods easily
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("Custom response"))
                    .expect("Building custom response should not fail"));
            }

            // Apply request transformations if present
            let transformed_req = req; // Simplified for now

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
                        .expect("Building service unavailable response should not fail"));
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
                    .expect("Building service unavailable response should not fail"));
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
                    .expect("Building bad gateway response should not fail")
            }
        };

        // Apply response transformations if using routing engine
        let final_response = response; // Simplified for now - routing transformations disabled

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

        // Check if response should be cached using the correct API
        let status = response.status();
        let cache_decision = policy_engine.should_cache(uri, headers, status, response.headers());

        if !cache_decision.should_cache() {
            if let Some(reason) = cache_decision.no_cache_reason() {
                debug!("Response not cacheable: {}", reason);
            }
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

        // Create cache entry
        let ttl = cache_decision
            .ttl()
            .unwrap_or(std::time::Duration::from_secs(3600));
        let cache_entry = CacheEntry::new(
            parts.status,
            parts.headers.clone(),
            body_bytes.to_vec(),
            ttl,
        );

        // Generate cache key
        let cache_key = format!("{}:{}", "GET", uri.path());
        if let Some(vary_suffix) = cache_decision.vary_suffix() {
            if !vary_suffix.is_empty() {
                // cache_key.push_str(vary_suffix); // Would need to modify cache_key to be mutable
            }
        }

        // Store in cache
        {
            let cache_guard = cache.write().await;
            if let Err(e) = cache_guard.put(cache_key.clone(), cache_entry).await {
                warn!("Failed to cache response for key '{}': {}", cache_key, e);
            } else {
                debug!("Cached response for key: {}", cache_key);
            }
        }

        // Return response with cache headers
        let mut builder = Response::builder().status(parts.status);
        for (name, value) in &parts.headers {
            builder = builder.header(name, value);
        }

        // Add cache miss header
        builder = builder.header("X-Cache", "MISS");

        builder.body(Body::from(body_bytes)).unwrap_or_else(|e| {
            warn!("Failed to rebuild response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Response building failed"))
                .expect("Building error response should not fail")
        })
    }

    /// Check if domain should be intercepted
    fn should_intercept_domain(&self, host: &str) -> bool {
        // Remove port from host if present
        let host = host.split(':').next().unwrap_or(host);
        let cfg = match self.domain_config.read() {
            Ok(config) => config,
            Err(e) => {
                warn!("Failed to read domain config: {}", e);
                return false;
            }
        };

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
        let cfg = match self.domain_config.read() {
            Ok(config) => config,
            Err(e) => {
                warn!("Failed to read domain config: {}", e);
                return false;
            }
        };
        if !cfg.enable_wildcard {
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
        super::http_client::forward_with_limit(req, target_url, None)
            .await
            .map_err(|e| anyhow::anyhow!("Forward request failed: {}", e))
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> Option<CacheMetrics> {
        if let Some(cache_arc) = &self.cache {
            let cache = cache_arc.read().await;
            Some(cache.get_metrics().await)
        } else {
            None
        }
    }

    /// Clear cache
    pub async fn clear_cache(&self) {
        if let Some(cache_arc) = &self.cache {
            let cache = cache_arc.write().await;
            cache.clear().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::LoadBalancer;
    use crate::config::cache::CachePolicyPattern;
    use crate::config::LoggingConfig;
    use crate::config::{
        CacheConfig, CachePolicy, DomainConfig, HealthCheckConfig, LoadBalancingConfig,
        LoadBalancingType, Target, TargetConfig,
    };
    use crate::logger::TrafficLogger;

    fn create_test_cache_config() -> CacheConfig {
        CacheConfig {
            enabled: true,
            max_size: 1024 * 1024, // 1MB
            default_ttl: 300,      // 5 minutes
            enable_etag: true,
            key_prefix: Some("test_".to_string()),
            enable_metrics: true,
            policies: vec![CachePolicy {
                name: "api_cache".to_string(),
                pattern: CachePolicyPattern::PathPrefix("/api/".to_string()),
                ttl: Some(600),
                cacheable_status_codes: vec![200, 301, 302],
                vary_headers: Some(vec!["Accept-Language".to_string()]),
                no_cache_headers: vec!["Cache-Control".to_string()],
            }],
        }
    }

    fn create_test_domain_config() -> DomainConfig {
        DomainConfig {
            intercept_domains: vec!["test.example.com".to_string()],
            exclude_domains: Some(vec!["admin.test.example.com".to_string()]),
            enable_wildcard: true,
        }
    }

    fn create_test_target_config() -> TargetConfig {
        TargetConfig {
            targets: vec![Target {
                name: "test-backend-1".to_string(),
                url: "http://127.0.0.1:3001".to_string(),
                address: "127.0.0.1:3001".to_string(),
                weight: Some(1.0),
                timeout: Some(30),
            }],
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::RoundRobin,
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: Some(false),
            },
            health_check: HealthCheckConfig {
                enabled: false,
                interval: 30,
                timeout: 5,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
                threshold: 2,
            },
        }
    }

    fn create_test_traffic_logger() -> TrafficLogger {
        TrafficLogger::new(LoggingConfig {
            enabled: false,
            log_type: crate::config::LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        })
    }

    #[tokio::test]
    async fn test_cached_proxy_handler_creation() {
        let domain_config =
            std::sync::Arc::new(std::sync::RwLock::new(create_test_domain_config()));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();
        let cache_config = Some(create_test_cache_config());

        let handler =
            CachedProxyHandler::new(domain_config, load_balancer, traffic_logger, cache_config);

        // Verify handler was created successfully
        assert!(handler.cache.is_some());
        assert!(handler.policy_engine.is_some());
        assert!(handler.etag_manager.is_some());
    }

    #[tokio::test]
    async fn test_cached_proxy_handler_without_cache() {
        let domain_config =
            std::sync::Arc::new(std::sync::RwLock::new(create_test_domain_config()));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();

        let handler = CachedProxyHandler::new(
            domain_config,
            load_balancer,
            traffic_logger,
            None, // No cache config
        );

        // Verify cache components are disabled
        assert!(handler.cache.is_none());
        assert!(handler.policy_engine.is_none());
        assert!(handler.etag_manager.is_none());
    }

    #[tokio::test]
    async fn test_cached_proxy_handler_with_routing() {
        let domain_config =
            std::sync::Arc::new(std::sync::RwLock::new(create_test_domain_config()));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();
        let routing_engine = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let cache_config = Some(create_test_cache_config());

        let handler = CachedProxyHandler::with_routing(
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine,
            cache_config,
        );

        // Verify handler was created with routing
        assert!(handler.routing_engine.is_some());
        assert!(handler.cache.is_some());
    }

    #[tokio::test]
    async fn test_domain_interception() {
        let mut domain_config = create_test_domain_config();
        domain_config.intercept_domains = vec!["api.example.com".to_string()];

        let domain_config_arc = std::sync::Arc::new(std::sync::RwLock::new(domain_config));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();

        let handler =
            CachedProxyHandler::new(domain_config_arc, load_balancer, traffic_logger, None);

        // Test domain matching
        assert!(handler.should_intercept_domain("api.example.com"));
        assert!(!handler.should_intercept_domain("other.example.com"));
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let domain_config =
            std::sync::Arc::new(std::sync::RwLock::new(create_test_domain_config()));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();
        let cache_config = Some(create_test_cache_config());

        let handler =
            CachedProxyHandler::new(domain_config, load_balancer, traffic_logger, cache_config);

        // Clear cache should not panic
        handler.clear_cache().await;
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let domain_config =
            std::sync::Arc::new(std::sync::RwLock::new(create_test_domain_config()));
        let load_balancer = std::sync::Arc::new(tokio::sync::RwLock::new(
            LoadBalancer::new_for_test(create_test_target_config()),
        ));
        let traffic_logger = create_test_traffic_logger();
        let cache_config = Some(create_test_cache_config());

        let handler =
            CachedProxyHandler::new(domain_config, load_balancer, traffic_logger, cache_config);

        // Get cache stats should return valid metrics
        let stats = handler.get_cache_stats().await;
        assert!(stats.is_some());
    }
}
