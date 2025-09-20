use anyhow::Result;
use chrono::Utc;
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::{Body, Method, Request, Response, StatusCode, Uri};
use std::convert::Infallible;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::balancer::LoadBalancer;
use crate::config::DomainConfig;
use crate::logger::TrafficLogger;
use crate::routing::RoutingEngine;

#[derive(Clone)]
pub struct ProxyHandler {
    domain_config: DomainConfig,
    load_balancer: LoadBalancer,
    traffic_logger: TrafficLogger,
    routing_engine: Option<RoutingEngine>,
}

impl ProxyHandler {
    pub fn new(
        domain_config: DomainConfig,
        load_balancer: LoadBalancer,
        traffic_logger: TrafficLogger,
    ) -> Self {
        Self {
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine: None,
        }
    }

    pub fn with_routing(
        domain_config: DomainConfig,
        load_balancer: LoadBalancer,
        traffic_logger: TrafficLogger,
        routing_engine: RoutingEngine,
    ) -> Self {
        Self {
            domain_config,
            load_balancer,
            traffic_logger,
            routing_engine: Some(routing_engine),
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

    async fn process_request(&self, req: Request<Body>) -> Result<Response<Body>> {
        let request_id = Uuid::new_v4();
        let start_time = Utc::now();

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

        // Check if this domain should be intercepted
        if !self.should_intercept_domain(&host) {
            warn!("Domain {} not in intercept list, returning 404", host);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Domain not found"))
                .unwrap());
        }

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
            let target = match self.load_balancer.get_target().await {
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
        let target = match self.load_balancer.get_target_by_name(&target_name).await {
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
                        // Since we can't return the original response (it was moved), create an error response
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

        let status = final_response.status();
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

        // Check exclude list first
        if let Some(ref exclude_domains) = self.domain_config.exclude_domains {
            if exclude_domains
                .iter()
                .any(|domain| self.matches_domain(host, domain))
            {
                return false;
            }
        }

        // Check intercept list
        self.domain_config
            .intercept_domains
            .iter()
            .any(|domain| self.matches_domain(host, domain))
    }

    fn matches_domain(&self, host: &str, pattern: &str) -> bool {
        if !self.domain_config.wildcard_support {
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
        mut req: Request<Body>,
        target_url: &str,
    ) -> Result<Response<Body>> {
        let client = reqwest::Client::new();

        // Build target URL
        let target_uri: Uri = target_url.parse()?;
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let url = format!(
            "{}://{}{}",
            target_uri.scheme_str().unwrap_or("http"),
            target_uri.authority().unwrap(),
            path_and_query
        );

        // Convert method
        let method = match *req.method() {
            Method::GET => reqwest::Method::GET,
            Method::POST => reqwest::Method::POST,
            Method::PUT => reqwest::Method::PUT,
            Method::DELETE => reqwest::Method::DELETE,
            Method::HEAD => reqwest::Method::HEAD,
            Method::OPTIONS => reqwest::Method::OPTIONS,
            Method::PATCH => reqwest::Method::PATCH,
            _ => reqwest::Method::GET,
        };

        // Collect body
        let body_bytes = hyper::body::to_bytes(req.body_mut())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read request body: {}", e))?;

        // Build request
        let mut request_builder = client.request(method, &url);

        // Copy headers (excluding hop-by-hop headers)
        for (name, value) in req.headers() {
            let name_str = name.as_str();
            if !is_hop_by_hop_header(name_str) {
                if let Ok(value_str) = value.to_str() {
                    request_builder = request_builder.header(name_str, value_str);
                }
            }
        }

        // Add forwarding headers
        request_builder = request_builder
            .header("X-Forwarded-For", "127.0.0.1")
            .header("X-Forwarded-Proto", "http")
            .body(body_bytes);

        // Send request
        let response = request_builder
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        // Convert response
        let status_code = response.status().as_u16();
        let headers = response.headers().clone();
        let body_text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

        let mut response_builder = Response::builder().status(status_code);

        // Copy response headers (excluding hop-by-hop headers)
        for (name, value) in headers {
            if let Some(name) = name {
                if !is_hop_by_hop_header(name.as_str()) {
                    if let Ok(value_str) = value.to_str() {
                        if let (Ok(header_name), Ok(header_value)) = (
                            HeaderName::from_bytes(name.as_str().as_bytes()),
                            HeaderValue::from_str(value_str),
                        ) {
                            response_builder = response_builder.header(header_name, header_value);
                        }
                    }
                }
            }
        }

        Ok(response_builder.body(Body::from(body_text))?)
    }
}

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
        DomainConfig, HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, TargetConfig,
    };
    use crate::logger::TrafficLogger;

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

        ProxyHandler::new(domain_config, load_balancer, traffic_logger)
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
            let handler = ProxyHandler::new(domain_config.clone(), load_balancer, traffic_logger);

            // Verify the handler was created successfully by checking it accepts its own domains
            assert_eq!(
                handler.domain_config.intercept_domains,
                domain_config.intercept_domains
            );
            assert_eq!(
                handler.domain_config.exclude_domains,
                domain_config.exclude_domains
            );
            assert_eq!(
                handler.domain_config.wildcard_support,
                domain_config.wildcard_support
            );
        }
    }
}
