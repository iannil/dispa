use hyper::{Body, Method, Request, Response, StatusCode};
use serde_json::json;
use std::convert::Infallible;

use super::data::{
    check_readiness, generate_fallback_metrics, generate_json_metrics, get_error_rate,
    get_healthy_targets_count, get_total_requests, get_uptime_seconds,
};

pub async fn handle_metrics(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if req.uri().path().starts_with("/admin") {
        return Ok(match crate::monitoring::admin::handle_admin(req).await {
            Ok(resp) => resp,
            Err(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Admin error"))
                .unwrap(),
        });
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metrics = generate_fallback_metrics().await;

            Ok(Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(Body::from(metrics))
                .unwrap())
        }
        (&Method::GET, "/metrics/json") => {
            let metrics_json = generate_json_metrics().await;

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(metrics_json))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "Not found. Available endpoints: /metrics, /metrics/json",
            ))
            .unwrap()),
    }
}

pub async fn handle_health(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") | (&Method::GET, "/") => {
            let health_response = json!({
                "status": "healthy",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "uptime_seconds": get_uptime_seconds().await,
                "version": env!("CARGO_PKG_VERSION")
            });

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(health_response.to_string()))
                .unwrap())
        }
        (&Method::GET, "/ready") => {
            let is_ready = check_readiness().await;

            let status_code = if is_ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };

            let response = json!({
                "status": if is_ready { "ready" } else { "not_ready" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            Ok(Response::builder()
                .status(status_code)
                .header("Content-Type", "application/json")
                .body(Body::from(response.to_string()))
                .unwrap())
        }
        (&Method::GET, "/metrics") => {
            let metrics = json!({
                "uptime_seconds": get_uptime_seconds().await,
                "healthy_targets": get_healthy_targets_count().await,
                "total_requests": get_total_requests().await,
                "error_rate": get_error_rate().await
            });

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(metrics.to_string()))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "Not found. Available endpoints: /health, /ready, /metrics",
            ))
            .unwrap()),
    }
}
