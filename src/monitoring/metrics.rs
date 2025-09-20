use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::convert::Infallible;
use std::net::SocketAddr;
use tracing::{info, error};

use crate::config::MonitoringConfig;

pub async fn run_metrics_server(config: MonitoringConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    // Initialize Prometheus metrics exporter
    let builder = PrometheusBuilder::new();
    let handle = builder.install()?;

    // Register custom metrics
    register_metrics();

    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], config.metrics_port));
    let health_addr = SocketAddr::from(([0, 0, 0, 0], config.health_check_port));

    // Start metrics server
    let metrics_service = make_service_fn(move |_conn| {
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_metrics(req)
            }))
        }
    });

    let metrics_server = Server::bind(&metrics_addr)
        .serve(metrics_service);

    // Start health check server
    let health_service = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_health))
    });

    let health_server = Server::bind(&health_addr)
        .serve(health_service);

    info!("Metrics server listening on {}", metrics_addr);
    info!("Health check server listening on {}", health_addr);

    // Run both servers concurrently
    tokio::select! {
        result = metrics_server => {
            if let Err(e) = result {
                error!("Metrics server error: {}", e);
            }
        }
        result = health_server => {
            if let Err(e) = result {
                error!("Health check server error: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_metrics(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        "/metrics" => {
            // Create a simple response - in production you'd want proper metrics
            let metrics = "# HELP dispa_requests_total Total requests\n# TYPE dispa_requests_total counter\ndispa_requests_total 0\n";
            Ok(Response::new(Body::from(metrics)))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap()),
    }
}

async fn handle_health(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from(r#"{"status":"healthy"}"#)))
}

fn register_metrics() {
    use metrics::{counter, histogram, gauge};

    // Create metrics (they're automatically registered)
    let _ = counter!("dispa_requests_total");
    let _ = counter!("dispa_requests_errors_total");
    let _ = histogram!("dispa_request_duration_seconds");
    let _ = gauge!("dispa_target_healthy");
    let _ = counter!("dispa_target_requests_total");
    let _ = gauge!("dispa_active_connections");
    let _ = gauge!("dispa_memory_usage_bytes");
}