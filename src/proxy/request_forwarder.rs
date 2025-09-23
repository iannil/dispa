use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use tracing::debug;

use crate::security::SharedSecurity;

/// Request forwarder handles forwarding requests to target servers
#[derive(Clone)]
pub struct RequestForwarder {
    security: SharedSecurity,
}

impl RequestForwarder {
    pub fn new(security: SharedSecurity) -> Self {
        Self { security }
    }

    /// Forward a request to the target URL
    pub async fn forward_request(
        &self,
        req: Request<Body>,
        target_url: &str,
    ) -> Result<Response<Body>> {
        debug!("Forwarding request to {}", target_url);

        // Apply streaming body limit if configured
        let limit = {
            let guard = self.security.read().await;
            guard.as_ref().and_then(|s| s.max_body_bytes())
        };

        match super::http_client::forward_with_limit(req, target_url, limit).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // Map payload too large to 413
                if matches!(e, crate::error::DispaError::PayloadTooLarge { .. }) {
                    return Ok(Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from("Payload too large"))
                        .unwrap());
                }
                Err(anyhow::anyhow!(e))
            }
        }
    }
}

/// Helper function to check if a header is hop-by-hop
#[cfg(test)]
pub fn is_hop_by_hop_header(name: &str) -> bool {
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
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[test]
    fn test_hop_by_hop_header_detection() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("TRANSFER-ENCODING"));
        assert!(!is_hop_by_hop_header("Content-Type"));
        assert!(!is_hop_by_hop_header("Authorization"));
    }

    #[tokio::test]
    async fn test_request_forwarder_creation() {
        let security = Arc::new(RwLock::new(None));
        let forwarder = RequestForwarder::new(security);

        // Test basic creation
        assert!(std::ptr::addr_of!(forwarder) as usize != 0);
    }
}
