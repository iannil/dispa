use hyper::{Body, Request, Response};

/// Plugin result for request processing
pub enum PluginResult {
    Continue,
    ShortCircuit(Response<Body>),
}

/// Trait for request-processing plugins
pub trait RequestPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult;
    /// Optional hook for reporting if last invocation had an internal error
    /// Default: always false. Implementations like CommandPlugin can override
    /// this to report execution failures which allows the engine to enforce
    /// per-plugin error strategy.
    fn last_error_and_clear(&self) -> bool {
        false
    }
}

/// Trait for response-processing plugins
pub trait ResponsePlugin: Send + Sync {
    fn name(&self) -> &str;
    fn on_response(&self, resp: &mut Response<Body>);
    /// See RequestPlugin::last_error_and_clear
    fn last_error_and_clear(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    struct TestRequestPlugin {
        name: String,
        should_short_circuit: bool,
    }

    impl TestRequestPlugin {
        fn new(name: &str, should_short_circuit: bool) -> Self {
            Self {
                name: name.to_string(),
                should_short_circuit,
            }
        }
    }

    impl RequestPlugin for TestRequestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
            // Add a test header to verify the plugin ran
            req.headers_mut()
                .insert("x-test-plugin", self.name.parse().unwrap()); // OK in tests - test plugin name parsing expected to succeed

            if self.should_short_circuit {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("Short circuited by plugin"))
                    .unwrap(); // OK in tests - test response builder expected to succeed
                PluginResult::ShortCircuit(response)
            } else {
                PluginResult::Continue
            }
        }
    }

    struct TestResponsePlugin {
        name: String,
    }

    impl TestResponsePlugin {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    impl ResponsePlugin for TestResponsePlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_response(&self, resp: &mut Response<Body>) {
            // Add a test header to verify the plugin ran
            resp.headers_mut()
                .insert("x-test-response-plugin", self.name.parse().unwrap()); // OK in tests - test plugin name parsing expected to succeed
        }
    }

    #[test]
    fn test_request_plugin_continue() {
        let plugin = TestRequestPlugin::new("test-plugin", false);
        let mut request = Request::builder()
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - test request builder expected to succeed

        let result = plugin.on_request(&mut request);

        assert_eq!(plugin.name(), "test-plugin");
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            request.headers().get("x-test-plugin").unwrap(), // OK in tests - test header expected to exist
            "test-plugin"
        );
    }

    #[test]
    fn test_request_plugin_short_circuit() {
        let plugin = TestRequestPlugin::new("short-circuit-plugin", true);
        let mut request = Request::builder()
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - test request builder expected to succeed

        let result = plugin.on_request(&mut request);

        match result {
            PluginResult::ShortCircuit(response) => {
                assert_eq!(response.status(), StatusCode::OK);
            }
            _ => panic!("Expected short circuit result"),
        }
    }

    #[test]
    fn test_response_plugin() {
        let plugin = TestResponsePlugin::new("response-plugin");
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("test"))
            .unwrap(); // OK in tests - test response builder expected to succeed

        plugin.on_response(&mut response);

        assert_eq!(plugin.name(), "response-plugin");
        assert_eq!(
            response.headers().get("x-test-response-plugin").unwrap(), // OK in tests - test header expected to exist
            "response-plugin"
        );
    }

    #[test]
    fn test_plugin_error_handling_default() {
        let plugin = TestRequestPlugin::new("error-test", false);
        assert!(!plugin.last_error_and_clear());
    }
}
