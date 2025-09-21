use anyhow::Result;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request, Response, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::time::Duration;
use crate::config::HttpClientConfig;

/// Shared hyper client with connection pooling (HTTP/HTTPS via rustls)
///
/// - Single client instance reused across requests to enable pooling
/// - Tuned pool settings to reduce connection churn under load
/// - Supports both http and https upstreams
static SHARED_CLIENT: Lazy<RwLock<std::sync::Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>>>> =
    Lazy::new(|| RwLock::new(std::sync::Arc::new(build_client(None))));

/// Initialize or reinitialize the shared HTTP client with optional configuration.
/// Safe to call multiple times; later calls will replace the client (best-effort hot-reload).
pub fn init(config: Option<&HttpClientConfig>) {
    let new_client = std::sync::Arc::new(build_client(config));
    if let Ok(mut guard) = SHARED_CLIENT.write() {
        *guard = new_client;
    }
}

fn get_client() -> std::sync::Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>> {
    SHARED_CLIENT
        .read()
        .ok()
        .map(|g| std::sync::Arc::clone(&*g))
        .unwrap_or_else(|| std::sync::Arc::new(build_client(None)))
}

fn build_client(config: Option<&HttpClientConfig>) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
    // Base TCP connector
    let mut http = HttpConnector::new();
    http.enforce_http(false); // allow absolute-form URIs
    http.set_nodelay(true);
    // Connect timeout is not directly available on hyper 0.14's HttpConnector in all builds; request-level timeout will be used.

    // Wrap with rustls HTTPS support and allow both https and http
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();

    // Pull tunables from config or use defaults
    let pool_idle_timeout_secs = config
        .and_then(|c| c.pool_idle_timeout_secs)
        .unwrap_or(90);
    let pool_max_idle_per_host = config
        .and_then(|c| c.pool_max_idle_per_host)
        .unwrap_or(32);

    Client::builder()
        .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_secs))
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .build::<_, Body>(https)
}

/// Forward an incoming request to a target base URL using the shared client.
///
/// This implementation:
/// - Reuses connections via a shared Client (connection pool)
/// - Streams request and response bodies without buffering them entirely (zero-copy friendly)
/// - Strips hop-by-hop headers as per RFC 7230
pub async fn forward(req: Request<Body>, target_base: &str) -> Result<Response<Body>> {
    let upstream_req = build_upstream_request(req, target_base)?;
    let client = get_client();
    let upstream_res = client.request(upstream_req).await?;
    Ok(build_downstream_response(upstream_res))
}

/// Lightweight GET that returns only status code. Request-level timeout is enforced.
pub async fn get_status(url: &str, timeout: Duration) -> Result<hyper::StatusCode> {
    let uri: Uri = url.parse()?;
    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .body(Body::empty())?;

    let client = get_client();
    let fut = client.request(req);
    let resp = tokio::time::timeout(timeout, fut).await??;
    Ok(resp.status())
}

// Cluster-related POST helpers removed

fn build_upstream_request(mut req: Request<Body>, target_base: &str) -> Result<Request<Body>> {
    // Parse base target URI
    let base: Uri = target_base.parse()?;

    // Split request to parts to rewrite URI and headers without copying body
    let (mut parts, body) = req.into_parts();

    // Preserve original path and query as a string
    let pq = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Construct absolute URI for upstream
    let scheme = base.scheme_str().unwrap_or("http");
    let authority = base
        .authority()
        .ok_or_else(|| anyhow::anyhow!("target URI missing authority: {}", target_base))?;

    let new_uri: Uri = format!("{}://{}{}", scheme, authority, pq).parse()?;
    parts.uri = new_uri;

    // Strip hop-by-hop headers and set Host to upstream authority
    strip_hop_by_hop_headers(&mut parts.headers);
    parts
        .headers
        .insert(hyper::header::HOST, authority.as_str().parse()?);

    // Add standard forwarding headers (best-effort; do not overwrite if present)
    parts.headers.entry("x-forwarded-proto").or_insert_with(|| {
        if scheme == "https" {
            hyper::header::HeaderValue::from_static("https")
        } else {
            hyper::header::HeaderValue::from_static("http")
        }
    });
    parts.headers.entry("x-forwarded-for").or_insert_with(|| {
        // If the original remote IP is not available here, set placeholder
        hyper::header::HeaderValue::from_static("127.0.0.1")
    });

    Ok(Request::from_parts(parts, body))
}

fn build_downstream_response(upstream: Response<Body>) -> Response<Body> {
    let (parts, body) = upstream.into_parts();
    let mut builder = Response::builder().status(parts.status);

    // Copy headers except hop-by-hop
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    builder.body(body).unwrap_or_else(|_| Response::new(Body::empty()))
}

// Keep this small helper local; duplicate of handler.rs but isolated to avoid coupling
fn is_hop_by_hop_header(name: &str) -> bool {
    match name.to_ascii_lowercase().as_str() {
        "connection"
        | "keep-alive"
        | "proxy-authenticate"
        | "proxy-authorization"
        | "te"
        | "trailers"
        | "transfer-encoding"
        | "upgrade" => true,
        _ => false,
    }
}

fn strip_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    // Remove the standard hop-by-hop headers
    const HOP_HEADERS: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];
    for h in HOP_HEADERS {
        headers.remove(*h);
    }

    // If the Connection header listed additional hop-by-hop headers, remove them too
    if let Some(conn_val) = headers.get("connection").and_then(|v| v.to_str().ok()) {
        let extra: Vec<String> = conn_val
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();
        for name in extra {
            headers.remove(name);
        }
    }
}
