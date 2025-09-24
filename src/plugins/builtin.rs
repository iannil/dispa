use anyhow::Result;
use hyper::{Body, Request, Response};
use serde_json::Value;
#[cfg(feature = "cmd-plugin")]
use std::sync::Arc;

use super::traits::{PluginResult, RequestPlugin, ResponsePlugin};

/// Header injection plugin
#[derive(Clone)]
pub struct HeaderInjector {
    #[allow(dead_code)]
    name: String,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
}

impl HeaderInjector {
    pub fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let mut req_headers = Vec::new();
        let mut resp_headers = Vec::new();

        if let Some(v) = cfg {
            if let Some(obj) = v.get("request_headers").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(s) = val.as_str() {
                        req_headers.push((k.to_string(), s.to_string()));
                    }
                }
            }
            if let Some(obj) = v.get("response_headers").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(s) = val.as_str() {
                        resp_headers.push((k.to_string(), s.to_string()));
                    }
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            req_headers,
            resp_headers,
        })
    }
}

impl RequestPlugin for HeaderInjector {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        let headers = req.headers_mut();
        for (k, v) in &self.req_headers {
            if let (Ok(name), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                v.parse(),
            ) {
                headers.insert(name, hv);
            }
        }
        PluginResult::Continue
    }
}

impl ResponsePlugin for HeaderInjector {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_response(&self, resp: &mut Response<Body>) {
        let headers = resp.headers_mut();
        for (k, v) in &self.resp_headers {
            if let (Ok(name), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                v.parse(),
            ) {
                headers.insert(name, hv);
            }
        }
    }
}

/// Blocklist plugin for filtering requests
#[derive(Clone)]
pub struct Blocklist {
    #[allow(dead_code)]
    name: String,
    hosts: Vec<String>,
    paths: Vec<String>,
}

impl Blocklist {
    pub fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let mut hosts = Vec::new();
        let mut paths = Vec::new();

        if let Some(v) = cfg {
            if let Some(arr) = v.get("hosts").and_then(|x| x.as_array()) {
                for it in arr {
                    if let Some(s) = it.as_str() {
                        hosts.push(s.to_string());
                    }
                }
            }
            if let Some(arr) = v.get("paths").and_then(|x| x.as_array()) {
                for it in arr {
                    if let Some(s) = it.as_str() {
                        paths.push(s.to_string());
                    }
                }
            }
        }

        Ok(Self {
            name: name.to_string(),
            hosts,
            paths,
        })
    }
}

impl RequestPlugin for Blocklist {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        // Check host blocklist
        if let Some(host) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
            if self
                .hosts
                .iter()
                .any(|blocked_host| host.contains(blocked_host))
            {
                return PluginResult::ShortCircuit(
                    Response::builder()
                        .status(403)
                        .body(Body::from("Blocked by host filter"))
                        .expect("Building simple HTTP response should not fail"),
                );
            }
        }

        // Check path blocklist
        let path = req.uri().path();
        if self
            .paths
            .iter()
            .any(|blocked_path| path.contains(blocked_path))
        {
            return PluginResult::ShortCircuit(
                Response::builder()
                    .status(403)
                    .body(Body::from("Blocked by path filter"))
                    .expect("Building simple HTTP response should not fail"),
            );
        }

        PluginResult::Continue
    }
}

/// Command execution plugin
#[cfg(feature = "cmd-plugin")]
#[derive(Debug)]
pub struct CommandPlugin {
    name: String,
    exec: String,
    args: Vec<String>,
    timeout_ms: u64,
    semaphore: Option<Arc<tokio::sync::Semaphore>>,
    exec_allowlist: Option<Vec<String>>,
    cwd: Option<String>,
    env: Option<std::collections::BTreeMap<String, String>>,
    // Track last invocation error for error_strategy enforcement
    last_error: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "cmd-plugin")]
impl Clone for CommandPlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            exec: self.exec.clone(),
            args: self.args.clone(),
            timeout_ms: self.timeout_ms,
            semaphore: self.semaphore.clone(),
            exec_allowlist: self.exec_allowlist.clone(),
            cwd: self.cwd.clone(),
            env: self.env.clone(),
            last_error: Arc::clone(&self.last_error),
        }
    }
}

#[cfg(feature = "cmd-plugin")]
impl CommandPlugin {
    pub fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let exec = cfg
            .and_then(|v| v.get("exec"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        let args = cfg
            .and_then(|v| v.get("args"))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        if exec.is_empty() {
            return Err(anyhow::anyhow!("command plugin requires 'exec'"));
        }

        let timeout_ms = cfg
            .and_then(|v| v.get("timeout_ms"))
            .and_then(|x| x.as_u64())
            .unwrap_or(100);

        let max_conc = cfg
            .and_then(|v| v.get("max_concurrency"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);

        let semaphore = if max_conc > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(max_conc as usize)))
        } else {
            None
        };

        let exec_allowlist = cfg
            .and_then(|v| v.get("exec_allowlist"))
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            });

        let cwd = cfg
            .and_then(|v| v.get("cwd"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());

        let env = cfg
            .and_then(|v| v.get("env"))
            .and_then(|x| x.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            });

        Ok(Self {
            name: name.to_string(),
            exec,
            args,
            timeout_ms,
            semaphore,
            exec_allowlist,
            cwd,
            env,
            last_error: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    async fn execute_command(&self, req: &Request<Body>) -> Result<()> {
        // Security check: validate executable against allowlist
        if let Some(ref allowlist) = self.exec_allowlist {
            if !allowlist.contains(&self.exec) {
                return Err(anyhow::anyhow!(
                    "Executable not in allowlist: {}",
                    self.exec
                ));
            }
        }

        // Acquire semaphore if concurrency limiting is enabled
        let _permit = if let Some(ref sem) = self.semaphore {
            Some(sem.acquire().await?)
        } else {
            None
        };

        let mut cmd = tokio::process::Command::new(&self.exec);
        cmd.args(&self.args);

        if let Some(ref cwd) = self.cwd {
            cmd.current_dir(cwd);
        }

        if let Some(ref env) = self.env {
            for (k, v) in env {
                cmd.env(k, v);
            }
        }

        // Set environment variables with request information
        if let Some(host) = req.headers().get("host").and_then(|h| h.to_str().ok()) {
            cmd.env("DISPA_HOST", host);
        }
        cmd.env("DISPA_METHOD", req.method().as_str());
        cmd.env("DISPA_PATH", req.uri().path());
        if let Some(query) = req.uri().query() {
            cmd.env("DISPA_QUERY", query);
        }

        let timeout = std::time::Duration::from_millis(self.timeout_ms);
        let _output = tokio::time::timeout(timeout, cmd.output()).await??;

        Ok(())
    }
}

#[cfg(feature = "cmd-plugin")]
impl RequestPlugin for CommandPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        let rt = tokio::runtime::Handle::current();
        let plugin = self.clone();

        // Extract request info for the command since we can't clone Request
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();

        // Create a minimal request for the command execution
        let req_for_cmd = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("Building request with valid method and URI should not fail");

        // Copy headers to the new request
        let mut req_with_headers = req_for_cmd;
        *req_with_headers.headers_mut() = headers;

        // Execute in blocking context since this trait method is sync
        let result =
            std::thread::spawn(move || rt.block_on(plugin.execute_command(&req_with_headers)))
                .join();

        match result {
            Ok(Ok(())) => {
                self.last_error
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                PluginResult::Continue
            }
            Ok(Err(_)) | Err(_) => {
                self.last_error
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                PluginResult::Continue
            }
        }
    }

    fn last_error_and_clear(&self) -> bool {
        self.last_error
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "cmd-plugin")]
impl ResponsePlugin for CommandPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_response(&self, _resp: &mut Response<Body>) {
        // Command plugin doesn't modify responses directly
        // Could be extended to run commands on response
    }

    fn last_error_and_clear(&self) -> bool {
        self.last_error
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Method, StatusCode};
    use serde_json::json;

    #[test]
    fn test_header_injector_creation_empty_config() {
        let injector = HeaderInjector::from_config("test", None).unwrap(); // OK in tests - valid config
        assert_eq!(RequestPlugin::name(&injector), "test");
        assert!(injector.req_headers.is_empty());
        assert!(injector.resp_headers.is_empty());
    }

    #[test]
    fn test_header_injector_creation_with_config() {
        let config = json!({
            "request_headers": {
                "X-Custom": "custom-value",
                "X-Another": "another-value"
            },
            "response_headers": {
                "X-Response": "response-value"
            }
        });

        let injector = HeaderInjector::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
        assert_eq!(RequestPlugin::name(&injector), "test");
        assert_eq!(injector.req_headers.len(), 2);
        assert_eq!(injector.resp_headers.len(), 1);

        // Check specific headers
        assert!(injector
            .req_headers
            .iter()
            .any(|(k, v)| k == "X-Custom" && v == "custom-value"));
        assert!(injector
            .req_headers
            .iter()
            .any(|(k, v)| k == "X-Another" && v == "another-value"));
        assert!(injector
            .resp_headers
            .iter()
            .any(|(k, v)| k == "X-Response" && v == "response-value"));
    }

    #[test]
    fn test_header_injector_request_plugin() {
        let config = json!({
            "request_headers": {
                "X-Test": "test-value",
                "User-Agent": "DispaProxy/1.0"
            }
        });

        let injector = HeaderInjector::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request // OK in tests - valid request

        let result = injector.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));

        // Check that headers were added
        assert_eq!(req.headers().get("X-Test").unwrap(), "test-value"); // OK in tests - header expected to exist
        assert_eq!(req.headers().get("User-Agent").unwrap(), "DispaProxy/1.0"); // OK in tests - header expected to exist
    }

    #[test]
    fn test_header_injector_response_plugin() {
        let config = json!({
            "response_headers": {
                "X-Powered-By": "Dispa",
                "X-Custom-Response": "response-header"
            }
        });

        let injector = HeaderInjector::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("test body"))
            .unwrap(); // OK in tests - valid response

        injector.on_response(&mut resp);

        // Check that headers were added
        assert_eq!(resp.headers().get("X-Powered-By").unwrap(), "Dispa"); // OK in tests - header expected to exist
        assert_eq!(
            resp.headers().get("X-Custom-Response").unwrap(), // OK in tests - header expected to exist
            "response-header"
        );
    }

    #[test]
    fn test_header_injector_invalid_header_names() {
        let config = json!({
            "request_headers": {
                "Valid-Header": "valid-value",
                "": "empty-name",  // Invalid: empty header name
                "Invalid\nHeader": "invalid-value"  // Invalid: contains newline
            }
        });

        let injector = HeaderInjector::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request // OK in tests - valid request

        let result = injector.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));

        // Only valid header should be present
        assert_eq!(req.headers().get("Valid-Header").unwrap(), "valid-value"); // OK in tests - header expected to exist
        assert!(req.headers().get("").is_none());
        assert!(req.headers().get("Invalid\nHeader").is_none());
    }

    #[test]
    fn test_blocklist_creation_empty_config() {
        let blocklist = Blocklist::from_config("test", None).unwrap(); // OK in tests - valid config
        assert_eq!(blocklist.name(), "test");
        assert!(blocklist.hosts.is_empty());
        assert!(blocklist.paths.is_empty());
    }

    #[test]
    fn test_blocklist_creation_with_config() {
        let config = json!({
            "hosts": ["blocked.com", "evil.example.com"],
            "paths": ["/admin", "/private"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
        assert_eq!(blocklist.name(), "test");
        assert_eq!(blocklist.hosts.len(), 2);
        assert_eq!(blocklist.paths.len(), 2);

        assert!(blocklist.hosts.contains(&"blocked.com".to_string()));
        assert!(blocklist.hosts.contains(&"evil.example.com".to_string()));
        assert!(blocklist.paths.contains(&"/admin".to_string()));
        assert!(blocklist.paths.contains(&"/private".to_string()));
    }

    #[test]
    fn test_blocklist_host_blocking() {
        let config = json!({
            "hosts": ["blocked.com", "evil.example.com"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Test blocked host
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://blocked.com/test")
            .header("host", "blocked.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected short circuit response for blocked host"),
        }

        // Test allowed host
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://allowed.com/test")
            .header("host", "allowed.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));
    }

    #[test]
    fn test_blocklist_path_blocking() {
        let config = json!({
            "paths": ["/admin", "/private"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Test blocked path
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/admin/users")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected short circuit response for blocked path"),
        }

        // Test allowed path
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/public/info")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));
    }

    #[test]
    fn test_blocklist_partial_host_matching() {
        let config = json!({
            "hosts": ["evil"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Should block hosts containing "evil"
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://evil.example.com/test")
            .header("host", "evil.example.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected short circuit response for host containing blocked pattern"),
        }
    }

    #[test]
    fn test_blocklist_partial_path_matching() {
        let config = json!({
            "paths": ["admin"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Should block paths containing "admin"
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/user/admin/settings")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            }
            _ => panic!("Expected short circuit response for path containing blocked pattern"),
        }
    }

    #[test]
    fn test_blocklist_no_host_header() {
        let config = json!({
            "hosts": ["blocked.com"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Request without host header should not be blocked by host filter
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://blocked.com/test")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        assert!(matches!(result, PluginResult::Continue));
    }

    #[test]
    fn test_blocklist_both_host_and_path_configured() {
        let config = json!({
            "hosts": ["blocked.com"],
            "paths": ["/admin"]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Test host blocking takes precedence
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://blocked.com/public")
            .header("host", "blocked.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(_) => {
                // Expected - blocked by host
            }
            _ => panic!("Expected short circuit response for blocked host"),
        }

        // Test path blocking on allowed host
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("http://allowed.com/admin/users")
            .header("host", "allowed.com")
            .body(Body::empty())
            .unwrap(); // OK in tests - valid request

        let result = blocklist.on_request(&mut req);
        match result {
            PluginResult::ShortCircuit(_) => {
                // Expected - blocked by path
            }
            _ => panic!("Expected short circuit response for blocked path"),
        }
    }

    #[test]
    fn test_blocklist_config_parsing_edge_cases() {
        // Test with non-string values in arrays
        let config = json!({
            "hosts": ["valid.com", 123, null, {"invalid": "object"}],
            "paths": ["/valid", true, ["nested", "array"], 456]
        });

        let blocklist = Blocklist::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

        // Only valid string values should be parsed
        assert_eq!(blocklist.hosts.len(), 1);
        assert_eq!(blocklist.paths.len(), 1);
        assert!(blocklist.hosts.contains(&"valid.com".to_string()));
        assert!(blocklist.paths.contains(&"/valid".to_string()));
    }

    #[test]
    fn test_plugin_name_consistency() {
        let injector = HeaderInjector::from_config("header-plugin", None).unwrap(); // OK in tests - valid config
        assert_eq!(RequestPlugin::name(&injector), "header-plugin");

        let blocklist = Blocklist::from_config("blocklist-plugin", None).unwrap(); // OK in tests - valid config
        assert_eq!(RequestPlugin::name(&blocklist), "blocklist-plugin");
    }

    #[cfg(feature = "cmd-plugin")]
    mod cmd_plugin_tests {
        use super::*;

        #[test]
        fn test_command_plugin_creation_minimal() {
            let config = json!({
                "exec": "echo"
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
            assert_eq!(RequestPlugin::name(&plugin), "test");
            assert_eq!(plugin.exec, "echo");
            assert!(plugin.args.is_empty());
            assert_eq!(plugin.timeout_ms, 100); // default
            assert!(plugin.semaphore.is_none());
        }

        #[test]
        fn test_command_plugin_creation_full_config() {
            let config = json!({
                "exec": "curl",
                "args": ["-X", "POST", "--data", "test"],
                "timeout_ms": 5000,
                "max_concurrency": 2,
                "exec_allowlist": ["curl", "wget"],
                "cwd": "/tmp",
                "env": {
                    "API_KEY": "secret",
                    "DEBUG": "true"
                }
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
            assert_eq!(RequestPlugin::name(&plugin), "test");
            assert_eq!(plugin.exec, "curl");
            assert_eq!(plugin.args, vec!["-X", "POST", "--data", "test"]);
            assert_eq!(plugin.timeout_ms, 5000);
            assert!(plugin.semaphore.is_some());
            assert!(plugin.exec_allowlist.is_some());
            assert_eq!(plugin.cwd, Some("/tmp".to_string()));
            assert!(plugin.env.is_some());
        }

        #[test]
        fn test_command_plugin_creation_missing_exec() {
            let config = json!({
                "args": ["--help"]
            });

            let result = CommandPlugin::from_config("test", Some(&config));
            assert!(result.is_err());
            assert!(result
                .unwrap_err() // OK in tests - error expected
                .to_string()
                .contains("command plugin requires 'exec'"));
        }

        #[test]
        fn test_command_plugin_creation_empty_exec() {
            let config = json!({
                "exec": ""
            });

            let result = CommandPlugin::from_config("test", Some(&config));
            assert!(result.is_err());
            assert!(result
                .unwrap_err() // OK in tests - error expected
                .to_string()
                .contains("command plugin requires 'exec'"));
        }

        #[test]
        fn test_command_plugin_semaphore_creation() {
            let config = json!({
                "exec": "echo",
                "max_concurrency": 5
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
            assert!(plugin.semaphore.is_some());

            // Verify semaphore has correct capacity
            if let Some(ref sem) = plugin.semaphore {
                assert_eq!(sem.available_permits(), 5);
            }
        }

        #[test]
        fn test_command_plugin_no_semaphore_when_zero_concurrency() {
            let config = json!({
                "exec": "echo",
                "max_concurrency": 0
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
            assert!(plugin.semaphore.is_none());
        }

        #[test]
        fn test_command_plugin_last_error_tracking() {
            let config = json!({
                "exec": "echo"
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config

            // Initially no error
            assert!(!RequestPlugin::last_error_and_clear(&plugin));

            // Set error and check
            plugin
                .last_error
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(RequestPlugin::last_error_and_clear(&plugin));

            // Should be cleared after reading
            assert!(!RequestPlugin::last_error_and_clear(&plugin));
        }

        #[test]
        fn test_command_plugin_config_parsing_edge_cases() {
            // Test with invalid types
            let config = json!({
                "exec": "echo",
                "args": "not_an_array",  // Should be array
                "timeout_ms": "not_a_number",  // Should be number
                "max_concurrency": -1,  // Invalid number
                "exec_allowlist": {"not": "array"},  // Should be array
                "env": ["not", "object"]  // Should be object
            });

            let plugin = CommandPlugin::from_config("test", Some(&config)).unwrap(); // OK in tests - valid config
            assert_eq!(plugin.exec, "echo");
            assert!(plugin.args.is_empty()); // Invalid args ignored
            assert_eq!(plugin.timeout_ms, 100); // Default used
            assert!(plugin.semaphore.is_none()); // Invalid max_concurrency ignored
            assert!(plugin.exec_allowlist.is_none()); // Invalid allowlist ignored
            assert!(plugin.env.is_none()); // Invalid env ignored
        }
    }
}
