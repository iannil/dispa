use hyper::{Body, Response, StatusCode};

/// HTTP response utility functions for security-related responses
pub fn resp_429() -> Option<Response<Body>> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "1")
        .body(Body::from("Rate limited"))
        .ok()
}

pub fn resp_431() -> Option<Response<Body>> {
    Response::builder()
        .status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
        .body(Body::from("Headers too large"))
        .ok()
}

pub fn resp_413() -> Option<Response<Body>> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(Body::from("Payload too large"))
        .ok()
}

pub fn resp_411() -> Option<Response<Body>> {
    Response::builder()
        .status(StatusCode::LENGTH_REQUIRED)
        .body(Body::from("Content-Length required"))
        .ok()
}

pub fn resp_403() -> Option<Response<Body>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("Forbidden"))
        .ok()
}

pub fn resp_401(msg: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer")
        .body(Body::from(msg.to_string()))
        .unwrap() // OK in tests - building simple response
}
