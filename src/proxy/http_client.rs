use crate::config::HttpClientConfig;
use crate::error::{DispaError, DispaResult};
use hyper::body::HttpBody as _;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request, Response, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::time::Duration;
use tokio::sync::oneshot;

/// Shared hyper client with connection pooling (HTTP/HTTPS via rustls)
///
/// - Single client instance reused across requests to enable pooling
/// - Tuned pool settings to reduce connection churn under load
/// - Supports both http and https upstreams
#[allow(clippy::type_complexity)]
static SHARED_CLIENT: Lazy<
    RwLock<std::sync::Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>>>,
> = Lazy::new(|| RwLock::new(std::sync::Arc::new(build_client(None))));

// Request-level timeout for upstream calls (connect + first response byte)
// Kept configurable via HttpClientConfig.connect_timeout_secs; defaults to 5s.
static REQUEST_TIMEOUT_SECS: Lazy<RwLock<u64>> = Lazy::new(|| RwLock::new(5));

/// Initialize or reinitialize the shared HTTP client with optional configuration.
/// Safe to call multiple times; later calls will replace the client (best-effort hot-reload).
pub fn init(config: Option<&HttpClientConfig>) {
    let new_client = std::sync::Arc::new(build_client(config));
    if let Ok(mut guard) = SHARED_CLIENT.write() {
        *guard = new_client;
    }
    // Update request timeout from config if provided
    if let Some(c) = config {
        if let Some(secs) = c.connect_timeout_secs {
            if let Ok(mut g) = REQUEST_TIMEOUT_SECS.write() {
                *g = secs.max(1);
            }
        }
    }
}

fn get_client() -> std::sync::Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>> {
    SHARED_CLIENT
        .read()
        .ok()
        .map(|g| std::sync::Arc::clone(&*g))
        .unwrap_or_else(|| std::sync::Arc::new(build_client(None)))
}

fn build_client(
    config: Option<&HttpClientConfig>,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
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
    let pool_idle_timeout_secs = config.and_then(|c| c.pool_idle_timeout_secs).unwrap_or(90);
    let pool_max_idle_per_host = config.and_then(|c| c.pool_max_idle_per_host).unwrap_or(32);

    Client::builder()
        .pool_idle_timeout(Duration::from_secs(pool_idle_timeout_secs))
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .build::<_, Body>(https)
}

// Note: single code-path kept via `forward_with_limit`; the old `forward` helper
// was removed to avoid duplication and dead-code warnings.

/// Forward with optional streaming body limit (does not aggregate the full body).
/// If `limit` is set and `Content-Length` is present and exceeds the limit, returns PayloadTooLarge immediately.
/// If `Content-Length` is absent, streams the body and aborts when limit is exceeded, mapping to PayloadTooLarge.
pub async fn forward_with_limit(
    req: Request<Body>,
    target_base: &str,
    limit: Option<u64>,
) -> DispaResult<Response<Body>> {
    if let Some(max) = limit {
        if let Some(len) = req
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if len > max {
                return Err(DispaError::PayloadTooLarge {
                    message: format!("content-length {} exceeds limit {}", len, max),
                });
            }
        }
    }

    // Build upstream request parts first (we will replace body if limit enforced)
    let base: Uri = target_base
        .parse()
        .map_err(|e| DispaError::proxy(format!("invalid target url: {}", e)))?;
    let (mut parts, orig_body) = req.into_parts();

    let pq = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let scheme = base.scheme_str().unwrap_or("http");
    let authority = base.authority().ok_or_else(|| {
        DispaError::proxy(format!("target URI missing authority: {}", target_base))
    })?;
    let new_uri: Uri = format!("{}://{}{}", scheme, authority, pq)
        .parse()
        .map_err(|e| DispaError::proxy(format!("invalid upstream uri: {}", e)))?;
    parts.uri = new_uri;
    strip_hop_by_hop_headers(&mut parts.headers);
    parts.headers.insert(
        hyper::header::HOST,
        authority
            .as_str()
            .parse()
            .map_err(|e| DispaError::proxy(format!("bad host header: {}", e)))?,
    );
    parts.headers.entry("x-forwarded-proto").or_insert_with(|| {
        if scheme == "https" {
            hyper::header::HeaderValue::from_static("https")
        } else {
            hyper::header::HeaderValue::from_static("http")
        }
    });
    parts
        .headers
        .entry("x-forwarded-for")
        .or_insert_with(|| hyper::header::HeaderValue::from_static("127.0.0.1"));

    let client = get_client();

    if let Some(max) = limit {
        // Wrap body with a streaming limiter
        let (mut tx, body) = Body::channel();
        let (signal_tx, mut signal_rx) = oneshot::channel::<()>();
        let mut b = orig_body;
        tokio::spawn(async move {
            let mut sent: u64 = 0;
            let mut _chunks: u64 = 0;
            let labels = [("limited", "true".to_string())];
            loop {
                match b.data().await {
                    Some(Ok(chunk)) => {
                        sent += chunk.len() as u64;
                        _chunks += 1;
                        metrics::counter!("dispa_request_body_stream_chunks_total", &labels)
                            .increment(1);
                        metrics::counter!("dispa_request_body_stream_bytes_total", &labels)
                            .increment(chunk.len() as u64);
                        if sent > max {
                            // exceed: drop sender and notify
                            metrics::counter!(
                                "dispa_security_denied_total",
                                &[("kind", "body_stream_too_large")]
                            )
                            .increment(1);
                            let _ = signal_tx.send(());
                            tx.abort();
                            break;
                        }
                        if let Err(_e) = tx.send_data(chunk).await {
                            break;
                        }
                    }
                    Some(Err(_e)) => {
                        tx.abort();
                        break;
                    }
                    None => {
                        break;
                    }
                }
            }
        });

        let upstream_req = Request::from_parts(parts, body);
        let fut = client.request(upstream_req);
        let timeout = {
            let g = REQUEST_TIMEOUT_SECS.read().unwrap();
            Duration::from_secs(*g)
        };
        let out: DispaResult<Response<Body>> = tokio::select! {
            _ = &mut signal_rx => {
                Err(DispaError::PayloadTooLarge { message: "streamed body exceeded limit".into() })
            }
            res = tokio::time::timeout(timeout, fut) => {
                match res {
                    Ok(Ok(r)) => Ok(build_downstream_response(r)),
                    Ok(Err(e)) => Err(DispaError::from(e)),
                    Err(_) => Err(DispaError::timeout(timeout, "HTTP request")),
                }
            }
        };
        out
    } else {
        // No limit: use original body
        let upstream_req = Request::from_parts(parts, orig_body);
        let timeout = {
            let g = REQUEST_TIMEOUT_SECS.read().unwrap();
            Duration::from_secs(*g)
        };
        let fut = client.request(upstream_req);
        let upstream_res = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| DispaError::timeout(timeout, "HTTP request"))?
            .map_err(DispaError::from)?;
        Ok(build_downstream_response(upstream_res))
    }
}

/// Lightweight GET that returns only status code. Request-level timeout is enforced.
pub async fn get_status(url: &str, timeout: Duration) -> DispaResult<hyper::StatusCode> {
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

fn build_downstream_response(upstream: Response<Body>) -> Response<Body> {
    let (parts, body) = upstream.into_parts();
    let mut builder = Response::builder().status(parts.status);

    // Copy headers except hop-by-hop
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    builder
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// Keep this small helper local; duplicate of handler.rs but isolated to avoid coupling
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};

    #[tokio::test]
    async fn test_forward_with_limit_content_length_exceed() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Body of 20 bytes, limit = 10 -> pre-check rejects without network
            let body = Body::from(vec![1u8; 20]);
            let req = Request::builder()
                .uri("http://localhost/")
                .method(hyper::Method::POST)
                .header(hyper::header::CONTENT_LENGTH, "20")
                .body(body)
                .unwrap();
            let res = forward_with_limit(req, "http://127.0.0.1:9", Some(10)).await;
            assert!(matches!(
                res,
                Err(crate::error::DispaError::PayloadTooLarge { .. })
            ));
        })
        .await
        .expect("test_forward_with_limit_content_length_exceed timed out");
    }
}
