use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode, Method, Uri};
use hyper::header::{HOST, HeaderName, HeaderValue};
use std::convert::Infallible;
use tracing::{debug, info, warn};
use uuid::Uuid;
use chrono::Utc;

use crate::config::DomainConfig;
use crate::balancer::LoadBalancer;
use crate::logger::TrafficLogger;

#[derive(Clone)]
pub struct ProxyHandler {
    domain_config: DomainConfig,
    load_balancer: LoadBalancer,
    traffic_logger: TrafficLogger,
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
        }
    }

    pub async fn handle_request(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
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

        // Extract host from request headers before moving req
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        debug!("Request {} to {}", request_id, host);

        // Check if this domain should be intercepted
        if !self.should_intercept_domain(&host) {
            warn!("Domain {} not in intercept list, returning 404", host);
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Domain not found"))
                .unwrap());
        }

        // Get target from load balancer
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

        info!("Forwarding request {} to target: {}", request_id, target.name);

        // Forward the request
        let response = match self.forward_request(req, &target.url).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to forward request {}: {}", request_id, e);
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Bad gateway"))
                    .unwrap()
            }
        };

        let status = response.status();
        let end_time = Utc::now();
        let duration = end_time - start_time;

        // Log the traffic
        if let Err(e) = self.traffic_logger.log_request(
            request_id,
            "127.0.0.1:0".parse().unwrap(),
            &host,
            &target.name,
            status,
            start_time,
            duration,
        ).await {
            warn!("Failed to log traffic: {}", e);
        }

        debug!("Request {} completed with status {} in {}ms",
               request_id, status, duration.num_milliseconds());

        Ok(response)
    }

    fn should_intercept_domain(&self, host: &str) -> bool {
        // Remove port from host if present
        let host = host.split(':').next().unwrap_or(host);

        // Check exclude list first
        if let Some(ref exclude_domains) = self.domain_config.exclude_domains {
            if exclude_domains.iter().any(|domain| self.matches_domain(host, domain)) {
                return false;
            }
        }

        // Check intercept list
        self.domain_config.intercept_domains
            .iter()
            .any(|domain| self.matches_domain(host, domain))
    }

    fn matches_domain(&self, host: &str, pattern: &str) -> bool {
        if !self.domain_config.wildcard_support {
            return host == pattern;
        }

        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
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
        let path_and_query = req.uri().path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let url = format!("{}://{}{}",
                         target_uri.scheme_str().unwrap_or("http"),
                         target_uri.authority().unwrap(),
                         path_and_query);

        // Convert method
        let method = match req.method() {
            &Method::GET => reqwest::Method::GET,
            &Method::POST => reqwest::Method::POST,
            &Method::PUT => reqwest::Method::PUT,
            &Method::DELETE => reqwest::Method::DELETE,
            &Method::HEAD => reqwest::Method::HEAD,
            &Method::OPTIONS => reqwest::Method::OPTIONS,
            &Method::PATCH => reqwest::Method::PATCH,
            _ => reqwest::Method::GET,
        };

        // Collect body
        let body_bytes = hyper::body::to_bytes(req.body_mut()).await
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
        let response = request_builder.send().await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        // Convert response
        let status_code = response.status().as_u16();
        let headers = response.headers().clone();
        let body_text = response.text().await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;

        let mut response_builder = Response::builder().status(status_code);

        // Copy response headers (excluding hop-by-hop headers)
        for (name, value) in headers {
            if let Some(name) = name {
                if !is_hop_by_hop_header(name.as_str()) {
                    if let Ok(value_str) = value.to_str() {
                        if let (Ok(header_name), Ok(header_value)) = (
                            HeaderName::from_bytes(name.as_str().as_bytes()),
                            HeaderValue::from_str(value_str)
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
    matches!(name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" |
        "proxy-authorization" | "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}