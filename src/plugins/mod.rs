use crate::config::{PluginErrorStrategy, PluginStage, PluginType, PluginsConfig};
use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use std::time::Instant;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{warn};

pub enum PluginResult {
    Continue,
    ShortCircuit(Response<Body>),
}

pub trait RequestPlugin: Send + Sync {
    #[allow(dead_code)]
    fn name(&self) -> &str;
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult;
    /// Optional hook for reporting if last invocation had an internal error
    /// Default: always false. Implementations like CommandPlugin can override
    /// this to report execution failures which allows the engine to enforce
    /// per-plugin error strategy.
    fn last_error_and_clear(&self) -> bool { false }
}

pub trait ResponsePlugin: Send + Sync {
    #[allow(dead_code)]
    fn name(&self) -> &str;
    fn on_response(&self, resp: &mut Response<Body>);
    /// See RequestPlugin::last_error_and_clear
    fn last_error_and_clear(&self) -> bool { false }
}

// --- WASM plugin support (PoC) ---
#[cfg(feature = "wasm-plugin")]
mod wasm_support {
    use super::*;
    use anyhow::Result as AnyResult;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use wasmtime::{Engine, Linker, Module, Store};
    use wasmtime_wasi::WasiCtxBuilder;

    pub struct WasmPlugin {
        name: String,
        module_path: String,
        timeout_ms: u64,
        semaphore: Option<Arc<Semaphore>>,
        last_error: std::sync::atomic::AtomicBool,
    }

    impl Clone for WasmPlugin {
        fn clone(&self) -> Self {
            Self {
                name: self.name.clone(),
                module_path: self.module_path.clone(),
                timeout_ms: self.timeout_ms,
                semaphore: self.semaphore.clone(),
                last_error: std::sync::atomic::AtomicBool::new(self.last_error.load(std::sync::atomic::Ordering::SeqCst)),
            }
        }
    }

    impl WasmPlugin {
        pub fn from_config(name: &str, cfg: Option<&serde_json::Value>) -> AnyResult<Self> {
            let module_path = cfg.and_then(|v| v.get("module_path")).and_then(|x| x.as_str()).unwrap_or("").to_string();
            if module_path.is_empty() { return Err(anyhow::anyhow!("wasm plugin requires 'module_path'")); }
            let timeout_ms = cfg.and_then(|v| v.get("timeout_ms")).and_then(|x| x.as_u64()).unwrap_or(100);
            let max_conc = cfg.and_then(|v| v.get("max_concurrency")).and_then(|x| x.as_u64()).unwrap_or(0);
            let semaphore = if max_conc > 0 { Some(Arc::new(Semaphore::new(max_conc as usize))) } else { None };
            Ok(Self { name: name.to_string(), module_path, timeout_ms, semaphore, last_error: std::sync::atomic::AtomicBool::new(false) })
        }

        fn call_guest(&self, stage: &str, input: &str) -> AnyResult<Option<String>> {
            let engine = Engine::default();
            let module = Module::from_file(&engine, &self.module_path)?;
            let mut linker = Linker::new(&engine);
            wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;
            let wasi = WasiCtxBuilder::new()
                .inherit_stdout()
                .inherit_stderr()
                .inherit_stdin()
                .build();
            let mut store = Store::new(&engine, wasi);
            let instance = linker.instantiate(&mut store, &module)?;
            // Expect guest to export functions: alloc, dealloc, dispa_on_request, dispa_on_response, dispa_get_result_len
            let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| anyhow::anyhow!("missing memory export"))?;
            let alloc = instance.get_typed_func::<i32, i32>(&mut store, "alloc")?;
            let dealloc = instance.get_typed_func::<(i32,i32), ()>(&mut store, "dealloc")?;
            let func_name = match stage { "request" => "dispa_on_request", _ => "dispa_on_response" };
            let guest = instance.get_typed_func::<(i32,i32), i32>(&mut store, func_name)?;
            let get_len = instance.get_typed_func::<(), i32>(&mut store, "dispa_get_result_len")?;

            let bytes = input.as_bytes();
            let ptr = alloc.call(&mut store, bytes.len() as i32)?;
            memory.data_mut(&mut store)[ptr as usize..ptr as usize + bytes.len()].copy_from_slice(bytes);
            let out_ptr = guest.call(&mut store, (ptr, bytes.len() as i32))?;
            let out_len = get_len.call(&mut store, ())?;
            let out = memory.data(&store)[out_ptr as usize..out_ptr as usize + out_len as usize].to_vec();
            dealloc.call(&mut store, (ptr, bytes.len() as i32))?;
            dealloc.call(&mut store, (out_ptr, out_len))?;
            let s = String::from_utf8(out).ok();
            Ok(s)
        }
    }

    impl RequestPlugin for WasmPlugin {
        fn name(&self) -> &str { &self.name }
        fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
            let _permit = if let Some(sem) = &self.semaphore {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(sem.clone().acquire_owned())).ok()
            } else { None };
            let mut hdr_map = serde_json::Map::new();
            for (k, v) in req.headers().iter() { if let Ok(val) = v.to_str() { hdr_map.insert(k.as_str().to_string(), Value::String(val.to_string())); } }
            let input = serde_json::json!({ "stage": "request", "method": req.method().as_str(), "path": req.uri().path(), "headers": Value::Object(hdr_map) }).to_string();
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.call_guest("request", &input)));
            let out = match out { Ok(Ok(s)) => s, _ => { self.last_error.store(true, std::sync::atomic::Ordering::SeqCst); return PluginResult::Continue; } };
            if let Some(s) = out { if let Ok(val) = serde_json::from_str::<Value>(&s) {
                if let Some(obj) = val.get("set_headers").and_then(|x| x.as_object()) { let h = req.headers_mut(); for (k, v) in obj { if let Some(s)=v.as_str(){ if let (Ok(name), Ok(hv))=(hyper::header::HeaderName::from_bytes(k.as_bytes()), s.parse()){ h.insert(name, hv);} } } }
                if let Some(sc) = val.get("short_circuit").and_then(|x| x.as_object()) { let status = sc.get("status").and_then(|x| x.as_u64()).unwrap_or(403) as u16; let body = sc.get("body").and_then(|x| x.as_str()).unwrap_or(""); let resp = Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN)).body(Body::from(body.to_string())).unwrap(); return PluginResult::ShortCircuit(resp); }
                self.last_error.store(false, std::sync::atomic::Ordering::SeqCst);
            }}
            PluginResult::Continue
        }
        fn last_error_and_clear(&self) -> bool { self.last_error.swap(false, std::sync::atomic::Ordering::SeqCst) }
    }

    impl ResponsePlugin for WasmPlugin {
        fn name(&self) -> &str { &self.name }
        fn on_response(&self, resp: &mut Response<Body>) {
            let _permit = if let Some(sem) = &self.semaphore {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(sem.clone().acquire_owned())).ok()
            } else { None };
            let mut hdr_map = serde_json::Map::new();
            for (k, v) in resp.headers().iter() { if let Ok(val) = v.to_str() { hdr_map.insert(k.as_str().to_string(), Value::String(val.to_string())); } }
            let input = serde_json::json!({ "stage": "response", "status": resp.status().as_u16(), "headers": Value::Object(hdr_map) }).to_string();
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.call_guest("response", &input)));
            if let Ok(Ok(Some(s))) = out { if let Ok(val) = serde_json::from_str::<Value>(&s) { if let Some(obj) = val.get("set_headers").and_then(|x| x.as_object()) { let h = resp.headers_mut(); for (k, v) in obj { if let Some(s)=v.as_str(){ if let (Ok(name), Ok(hv))=(hyper::header::HeaderName::from_bytes(k.as_bytes()), s.parse()){ h.insert(name, hv);} } } } self.last_error.store(false, std::sync::atomic::Ordering::SeqCst); } } else { self.last_error.store(true, std::sync::atomic::Ordering::SeqCst); }
        }
        fn last_error_and_clear(&self) -> bool { self.last_error.swap(false, std::sync::atomic::Ordering::SeqCst) }
    }
}

#[cfg(feature = "wasm-plugin")]
use wasm_support::WasmPlugin;

pub struct PluginEngine {
    request_plugins: Vec<PluginRequestEntry>,
    response_plugins: Vec<PluginResponseEntry>,
    /// Whether request-stage plugins should run before domain interception check
    apply_before_domain_match: bool,
    // Fast lookup by plugin name
    request_index: std::collections::HashMap<String, usize>,
    response_index: std::collections::HashMap<String, usize>,
}

struct PluginRequestEntry {
    name: String,
    strategy: PluginErrorStrategy,
    plugin: Box<dyn RequestPlugin + Send + Sync>,
}

struct PluginResponseEntry {
    name: String,
    strategy: PluginErrorStrategy,
    plugin: Box<dyn ResponsePlugin + Send + Sync>,
}

impl PluginEngine {
    pub fn new(config: &PluginsConfig) -> Result<Self> {
        let mut req = Vec::new();
        let mut resp = Vec::new();
        if config.enabled {
            for p in &config.plugins {
                if !p.enabled { continue; }
                match p.plugin_type {
                    PluginType::HeaderInjector => {
                        let plugin = HeaderInjector::from_config(&p.name, p.config.as_ref())?;
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin.clone()) });
                        }
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            resp.push(PluginResponseEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                        }
                    }
                    PluginType::Blocklist => {
                        let plugin = Blocklist::from_config(&p.name, p.config.as_ref())?;
                        if p.stage == PluginStage::Response {
                            warn!("Blocklist configured for response stage has no effect");
                        }
                        req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                    }
                    PluginType::HeaderOverride => {
                        let plugin = HeaderInjector::from_config(&p.name, p.config.as_ref())?; // same impl, always sets
                        if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                            req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin.clone()) });
                        }
                        if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                            resp.push(PluginResponseEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                        }
                    }
                    PluginType::PathRewrite => {
                        let plugin = PathRewrite::from_config(&p.name, p.config.as_ref())?;
                        req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                    }
                    PluginType::HostRewrite => {
                        let plugin = HostRewrite::from_config(&p.name, p.config.as_ref())?;
                        req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                    }
                    PluginType::Command => {
                        #[cfg(feature = "cmd-plugin")]
                        {
                            let plugin = CommandPlugin::from_config(&p.name, p.config.as_ref())?;
                            if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                                req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin.clone()) });
                            }
                            if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                                resp.push(PluginResponseEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                            }
                        }
                        #[cfg(not(feature = "cmd-plugin"))]
                        {
                            warn!("Command plugin type not supported in this build; skipping");
                        }
                    }
                    PluginType::RateLimiter => {
                        let plugin = RateLimiter::from_config(&p.name, p.config.as_ref())?;
                        req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                    }
                    PluginType::Wasm => {
                        #[cfg(feature = "wasm-plugin")]
                        {
                            let plugin = WasmPlugin::from_config(&p.name, p.config.as_ref())?;
                            if matches!(p.stage, PluginStage::Request | PluginStage::Both) {
                                req.push(PluginRequestEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin.clone()) });
                            }
                            if matches!(p.stage, PluginStage::Response | PluginStage::Both) {
                                resp.push(PluginResponseEntry{ name: p.name.clone(), strategy: p.error_strategy.clone(), plugin: Box::new(plugin) });
                            }
                        }
                        #[cfg(not(feature = "wasm-plugin"))]
                        {
                            warn!("WASM plugin type not supported in this build; skipping");
                        }
                    }
                }
            }
        }
        // Build indices for subset lookup
        let mut request_index = std::collections::HashMap::new();
        for (i, e) in req.iter().enumerate() { request_index.insert(e.name.clone(), i); }
        let mut response_index = std::collections::HashMap::new();
        for (i, e) in resp.iter().enumerate() { response_index.insert(e.name.clone(), i); }

        Ok(Self { request_plugins: req, response_plugins: resp, apply_before_domain_match: config.apply_before_domain_match, request_index, response_index })
    }

    /// Returns whether request plugins should be applied before domain check
    pub fn apply_before_domain_match(&self) -> bool { self.apply_before_domain_match }

    pub async fn apply_request(&self, req: &mut Request<Body>) -> PluginResult {
        for entry in &self.request_plugins {
            let start = Instant::now();
            let labels = [("plugin", entry.name.clone()), ("stage", "request".to_string())];
            metrics::counter!("dispa_plugin_invocations_total", &labels).increment(1);

            // Catch panics from plugin and enforce error strategy
            let call = std::panic::AssertUnwindSafe(|| entry.plugin.on_request(req));
            let result = match std::panic::catch_unwind(call) {
                Ok(r) => r,
                Err(_) => {
                    metrics::counter!("dispa_plugin_errors_total", &[("plugin", entry.name.clone()), ("stage", "request".to_string()), ("kind", "panic".to_string())]).increment(1);
                    if matches!(entry.strategy, PluginErrorStrategy::Fail) {
                        let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                        metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                        return PluginResult::ShortCircuit(resp);
                    }
                    PluginResult::Continue
                }
            };

            // If plugin reported last error (e.g., command exec), enforce strategy
            if entry.plugin.last_error_and_clear() && matches!(entry.strategy, PluginErrorStrategy::Fail) {
                let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                return PluginResult::ShortCircuit(resp);
            }

            match result {
                PluginResult::Continue => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
                }
                s @ PluginResult::ShortCircuit(_) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
                    metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                    return s
                }
            }
        }
        PluginResult::Continue
    }

    pub async fn apply_response(&self, resp: &mut Response<Body>) {
        for entry in &self.response_plugins {
            let start = Instant::now();
            let labels = [("plugin", entry.name.clone()), ("stage", "response".to_string())];
            metrics::counter!("dispa_plugin_invocations_total", &labels).increment(1);

            let call = std::panic::AssertUnwindSafe(|| entry.plugin.on_response(resp));
            if let Err(_) = std::panic::catch_unwind(call) {
                metrics::counter!("dispa_plugin_errors_total", &[("plugin", entry.name.clone()), ("stage", "response".to_string()), ("kind", "panic".to_string())]).increment(1);
                if matches!(entry.strategy, PluginErrorStrategy::Fail) {
                    *resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                    metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                    return;
                }
            }

            if entry.plugin.last_error_and_clear() && matches!(entry.strategy, PluginErrorStrategy::Fail) {
                *resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                return;
            }

            let ms = start.elapsed().as_secs_f64() * 1000.0;
            metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
        }
    }

    /// Return the names of all configured response plugins in their execution order
    pub fn response_plugin_names(&self) -> Vec<String> {
        self.response_plugins.iter().map(|e| e.name.clone()).collect()
    }

    /// Apply only selected request plugins by name, in the provided order
    pub async fn apply_request_subset(&self, names: &[String], req: &mut Request<Body>) -> PluginResult {
        for name in names {
            let Some(&idx) = self.request_index.get(name) else { continue };
            let entry = &self.request_plugins[idx];
            let start = Instant::now();
            let labels = [("plugin", entry.name.clone()), ("stage", "request".to_string())];
            metrics::counter!("dispa_plugin_invocations_total", &labels).increment(1);
            let call = std::panic::AssertUnwindSafe(|| entry.plugin.on_request(req));
            let result = match std::panic::catch_unwind(call) {
                Ok(r) => r,
                Err(_) => {
                    metrics::counter!("dispa_plugin_errors_total", &[("plugin", entry.name.clone()), ("stage", "request".to_string()), ("kind", "panic".to_string())]).increment(1);
                    if matches!(entry.strategy, PluginErrorStrategy::Fail) {
                        let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                        metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                        return PluginResult::ShortCircuit(resp);
                    }
                    PluginResult::Continue
                }
            };
            if entry.plugin.last_error_and_clear() && matches!(entry.strategy, PluginErrorStrategy::Fail) {
                let resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                return PluginResult::ShortCircuit(resp);
            }
            match result {
                PluginResult::Continue => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
                }
                s @ PluginResult::ShortCircuit(_) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
                    metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                    return s
                }
            }
        }
        PluginResult::Continue
    }

    /// Apply only selected response plugins by name, in the provided order
    pub async fn apply_response_subset(&self, names: &[String], resp: &mut Response<Body>) {
        for name in names {
            let Some(&idx) = self.response_index.get(name) else { continue };
            let entry = &self.response_plugins[idx];
            let start = Instant::now();
            let labels = [("plugin", entry.name.clone()), ("stage", "response".to_string())];
            metrics::counter!("dispa_plugin_invocations_total", &labels).increment(1);
            let call = std::panic::AssertUnwindSafe(|| entry.plugin.on_response(resp));
            if let Err(_) = std::panic::catch_unwind(call) {
                metrics::counter!("dispa_plugin_errors_total", &[("plugin", entry.name.clone()), ("stage", "response".to_string()), ("kind", "panic".to_string())]).increment(1);
                if matches!(entry.strategy, PluginErrorStrategy::Fail) {
                    *resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                    metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                    return;
                }
            }
            if entry.plugin.last_error_and_clear() && matches!(entry.strategy, PluginErrorStrategy::Fail) {
                *resp = Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Plugin error")).unwrap();
                metrics::counter!("dispa_plugin_short_circuits_total", &labels).increment(1);
                return;
            }
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            metrics::histogram!("dispa_plugin_duration_ms", &labels).record(ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct PanicPlugin;
    impl RequestPlugin for PanicPlugin {
        fn name(&self) -> &str { "panic" }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult { panic!("boom") }
    }

    struct ErrorFlagPlugin { flag: AtomicBool }
    impl ErrorFlagPlugin { fn new() -> Self { Self{ flag: AtomicBool::new(true) } } }
    impl RequestPlugin for ErrorFlagPlugin {
        fn name(&self) -> &str { "error-flag" }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult { PluginResult::Continue }
        fn last_error_and_clear(&self) -> bool { self.flag.swap(false, Ordering::SeqCst) }
    }

    fn empty_plugins_engine() -> PluginEngine {
        PluginEngine { request_plugins: vec![], response_plugins: vec![], apply_before_domain_match: true, request_index: std::collections::HashMap::new(), response_index: std::collections::HashMap::new() }
    }

    fn engine_with_request_entries(mut entries: Vec<PluginRequestEntry>) -> PluginEngine {
        let mut idx = std::collections::HashMap::new();
        for (i, e) in entries.iter().enumerate() { idx.insert(e.name.clone(), i); }
        let request_plugins = std::mem::take(&mut entries);
        PluginEngine { request_plugins, response_plugins: vec![], apply_before_domain_match: true, request_index: idx, response_index: std::collections::HashMap::new() }
    }

    struct ShortCircuitPlugin;
    impl RequestPlugin for ShortCircuitPlugin {
        fn name(&self) -> &str { "short" }
        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            let resp = Response::builder().status(StatusCode::IM_A_TEAPOT).body(Body::empty()).unwrap();
            PluginResult::ShortCircuit(resp)
        }
    }

    #[test]
    fn test_apply_request_subset_short_circuit_by_name() {
        let engine = engine_with_request_entries(vec![
            PluginRequestEntry { name: "noop".into(), strategy: PluginErrorStrategy::Continue, plugin: Box::new(HeaderInjector{ name: "noop".into(), req_headers: vec![], resp_headers: vec![] }) },
            PluginRequestEntry { name: "sc".into(), strategy: PluginErrorStrategy::Continue, plugin: Box::new(ShortCircuitPlugin) },
        ]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut req = Request::new(Body::empty());
        match rt.block_on(engine.apply_request_subset(&["sc".into()], &mut req)) {
            PluginResult::ShortCircuit(resp) => assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT),
            _ => panic!("expected short circuit from subset plugin"),
        }
    }

    #[test]
    fn test_error_strategy_panic_fail_short_circuits() {
        let mut engine = empty_plugins_engine();
        engine.request_plugins.push(PluginRequestEntry{
            name: "p1".to_string(),
            strategy: PluginErrorStrategy::Fail,
            plugin: Box::new(PanicPlugin)
        });
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut req = Request::new(Body::empty());
        match rt.block_on(engine.apply_request(&mut req)) {
            PluginResult::ShortCircuit(resp) => assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("expected short circuit on panic with Fail strategy"),
        }
    }

    #[test]
    fn test_error_strategy_panic_continue_passes() {
        let mut engine = empty_plugins_engine();
        engine.request_plugins.push(PluginRequestEntry{
            name: "p1".to_string(),
            strategy: PluginErrorStrategy::Continue,
            plugin: Box::new(PanicPlugin)
        });
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut req = Request::new(Body::empty());
        match rt.block_on(engine.apply_request(&mut req)) {
            PluginResult::Continue => {},
            _ => panic!("expected continue on panic with Continue strategy"),
        }
    }

    #[test]
    fn test_error_strategy_last_error_fail_short_circuits() {
        let mut engine = empty_plugins_engine();
        engine.request_plugins.push(PluginRequestEntry{
            name: "p1".to_string(),
            strategy: PluginErrorStrategy::Fail,
            plugin: Box::new(ErrorFlagPlugin::new())
        });
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut req = Request::new(Body::empty());
        match rt.block_on(engine.apply_request(&mut req)) {
            PluginResult::ShortCircuit(resp) => assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("expected short circuit due to last_error with Fail strategy"),
        }
    }

    #[test]
    fn test_apply_before_domain_match_flag_kept() {
        let engine = PluginEngine { request_plugins: vec![], response_plugins: vec![], apply_before_domain_match: false, request_index: std::collections::HashMap::new(), response_index: std::collections::HashMap::new() };
        assert!(!engine.apply_before_domain_match());
        let engine2 = PluginEngine { request_plugins: vec![], response_plugins: vec![], apply_before_domain_match: true, request_index: std::collections::HashMap::new(), response_index: std::collections::HashMap::new() };
        assert!(engine2.apply_before_domain_match());
    }
}

#[derive(Clone)]
struct HeaderInjector {
    #[allow(dead_code)]
    name: String,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
}

impl HeaderInjector {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let mut req_headers = Vec::new();
        let mut resp_headers = Vec::new();
        if let Some(v) = cfg {
            if let Some(obj) = v.get("request_headers").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(s) = val.as_str() { req_headers.push((k.to_string(), s.to_string())); }
                }
            }
            if let Some(obj) = v.get("response_headers").and_then(|x| x.as_object()) {
                for (k, val) in obj {
                    if let Some(s) = val.as_str() { resp_headers.push((k.to_string(), s.to_string())); }
                }
            }
        }
        Ok(Self { name: name.to_string(), req_headers, resp_headers })
    }
}

impl RequestPlugin for HeaderInjector {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        let headers = req.headers_mut();
        for (k,v) in &self.req_headers {
            if let (Ok(name), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                v.parse()
            ) {
                headers.insert(name, hv);
            }
        }
        PluginResult::Continue
    }
}

impl ResponsePlugin for HeaderInjector {
    fn name(&self) -> &str { &self.name }
    fn on_response(&self, resp: &mut Response<Body>) {
        let headers = resp.headers_mut();
        for (k,v) in &self.resp_headers {
            if let (Ok(name), Ok(hv)) = (
                hyper::header::HeaderName::from_bytes(k.as_bytes()),
                v.parse()
            ) {
                headers.insert(name, hv);
            }
        }
    }
}

struct Blocklist {
    #[allow(dead_code)]
    name: String,
    hosts: Vec<String>,
    paths: Vec<String>,
}

impl Blocklist {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let mut hosts = Vec::new();
        let mut paths = Vec::new();
        if let Some(v) = cfg {
            if let Some(arr) = v.get("hosts").and_then(|x| x.as_array()) {
                for it in arr { if let Some(s)=it.as_str(){ hosts.push(s.to_string()); } }
            }
            if let Some(arr) = v.get("paths").and_then(|x| x.as_array()) {
                for it in arr { if let Some(s)=it.as_str(){ paths.push(s.to_string()); } }
            }
        }
        Ok(Self { name: name.to_string(), hosts, paths })
    }
}

impl RequestPlugin for Blocklist {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        // Simple host/path block
        let host = req.headers().get(hyper::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        let path = req.uri().path();
        if (!self.hosts.is_empty() && self.hosts.iter().any(|h| host == h)) ||
           (!self.paths.is_empty() && self.paths.iter().any(|p| path.starts_with(p))) {
            let resp = Response::builder().status(StatusCode::FORBIDDEN).body(Body::from("Blocked by policy")).unwrap();
            return PluginResult::ShortCircuit(resp);
        }
        PluginResult::Continue
    }
}

#[derive(Clone)]
struct PathRewrite { #[allow(dead_code)] name: String, from_prefix: String, to_prefix: String }
impl PathRewrite {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let from = cfg.and_then(|v| v.get("from_prefix")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let to = cfg.and_then(|v| v.get("to_prefix")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        Ok(Self { name: name.to_string(), from_prefix: from, to_prefix: to })
    }
}
impl RequestPlugin for PathRewrite {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        let path = req.uri().path().to_string();
        if !self.from_prefix.is_empty() && path.starts_with(&self.from_prefix) {
            let rest = &path[self.from_prefix.len()..];
            let new_path = format!("{}{}", self.to_prefix, rest);
            if let Some(pq) = req.uri().path_and_query().and_then(|pq| pq.query()) {
                let new_uri = format!("{}?{}", new_path, pq).parse().unwrap_or(req.uri().clone());
                *req.uri_mut() = new_uri;
            } else {
                *req.uri_mut() = new_path.parse().unwrap_or(req.uri().clone());
            }
        }
        PluginResult::Continue
    }
}

#[derive(Clone)]
struct HostRewrite { #[allow(dead_code)] name: String, host: String }
impl HostRewrite {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let host = cfg.and_then(|v| v.get("host")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        Ok(Self { name: name.to_string(), host })
    }
}
impl RequestPlugin for HostRewrite {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        if !self.host.is_empty() {
            req.headers_mut().insert(hyper::header::HOST, hyper::header::HeaderValue::from_str(&self.host).unwrap_or_else(|_| hyper::header::HeaderValue::from_static("invalid")));
        }
        PluginResult::Continue
    }
}

struct RateLimiter {
    #[allow(dead_code)]
    name: String,
    rate_per_sec: f64,
    burst: f64,
    map: tokio::sync::Mutex<std::collections::HashMap<String, RateState>>,
}

#[derive(Clone, Copy)]
struct RateState { tokens: f64, last: Instant }

impl RateLimiter {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let rate = cfg.and_then(|v| v.get("rate_per_sec")).and_then(|x| x.as_f64()).unwrap_or(100.0);
        let burst = cfg.and_then(|v| v.get("burst")).and_then(|x| x.as_f64()).unwrap_or(rate);
        Ok(Self { name: name.to_string(), rate_per_sec: rate, burst, map: tokio::sync::Mutex::new(std::collections::HashMap::new()) })
    }
}

impl RequestPlugin for RateLimiter {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        let method = req.method().as_str();
        let host = req.headers().get(hyper::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        let path = req.uri().path();
        let key = format!("{}:{}:{}", method, host, path);
        let now = Instant::now();
        let mut map = self.map.blocking_lock();
        let mut st = *map.get(&key).unwrap_or(&RateState { tokens: self.burst, last: now });
        let dt = now.duration_since(st.last).as_secs_f64();
        st.tokens = (st.tokens + dt * self.rate_per_sec).min(self.burst);
        st.last = now;
        let allow = if st.tokens >= 1.0 { st.tokens -= 1.0; true } else { false };
        map.insert(key, st);
        drop(map);
        if allow { PluginResult::Continue } else {
            let resp = Response::builder().status(StatusCode::TOO_MANY_REQUESTS).header("Retry-After", "1").body(Body::from("Rate limited")).unwrap();
            PluginResult::ShortCircuit(resp)
        }
    }
}

// ------------------ Command Plugin (external executable) ------------------
#[cfg(feature = "cmd-plugin")]
struct CommandPlugin {
    name: String,
    exec: String,
    args: Vec<String>,
    timeout_ms: u64,
    semaphore: Option<Arc<tokio::sync::Semaphore>>,
    exec_allowlist: Option<Vec<String>>,
    cwd: Option<String>,
    env: Option<std::collections::BTreeMap<String, String>>,
    // Track last invocation error for error_strategy enforcement
    last_error: std::sync::atomic::AtomicBool,
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
            last_error: std::sync::atomic::AtomicBool::new(self.last_error.load(std::sync::atomic::Ordering::SeqCst)),
        }
    }
}

#[cfg(feature = "cmd-plugin")]
impl CommandPlugin {
    fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let exec = cfg.and_then(|v| v.get("exec")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let args = cfg.and_then(|v| v.get("args")).and_then(|x| x.as_array()).map(|a| {
            a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>()
        }).unwrap_or_default();
        if exec.is_empty() {
            return Err(anyhow::anyhow!("command plugin requires 'exec'"));
        }
        let timeout_ms = cfg.and_then(|v| v.get("timeout_ms")).and_then(|x| x.as_u64()).unwrap_or(100);
        let max_conc = cfg.and_then(|v| v.get("max_concurrency")).and_then(|x| x.as_u64()).unwrap_or(0);
        let semaphore = if max_conc > 0 { Some(Arc::new(tokio::sync::Semaphore::new(max_conc as usize))) } else { None };
        let exec_allowlist = cfg.and_then(|v| v.get("exec_allowlist")).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<String>>());
        let cwd = cfg.and_then(|v| v.get("cwd")).and_then(|x| x.as_str()).map(|s| s.to_string());
        let env = cfg.and_then(|v| v.get("env")).and_then(|m| m.as_object()).map(|obj| {
            obj.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect::<std::collections::BTreeMap<_, _>>()
        });
        Ok(Self { name: name.to_string(), exec, args, timeout_ms, semaphore, exec_allowlist, cwd, env, last_error: std::sync::atomic::AtomicBool::new(false) })
    }

    async fn run_command_async(&self, input: &str, timeout_ms: u64) -> Result<String> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};
        if let Some(list) = &self.exec_allowlist {
            if !list.iter().any(|s| s == &self.exec) {
                self.last_error.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(anyhow::anyhow!("exec not in allowlist"));
            }
        }
        let _permit = if let Some(sem) = &self.semaphore { Some(sem.clone().acquire_owned().await?) } else { None };
        let mut child = Command::new(&self.exec)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(self.cwd.as_deref().unwrap_or("."))
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn failed: {}", e))?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(input.as_bytes()).await.ok();
        }
        let dur = Duration::from_millis(timeout_ms);
        let started = Instant::now();
        match timeout(dur, child.wait_with_output()).await {
            Ok(Ok(out)) => {
                let ms = started.elapsed().as_secs_f64() * 1000.0;
                metrics::histogram!("dispa_plugin_cmd_exec_duration_ms", &[("plugin", self.name.clone())]).record(ms);
                if !out.status.success() {
                    metrics::counter!("dispa_plugin_cmd_errors_total", &[("plugin", self.name.clone()), ("kind", "status".to_string())]).increment(1);
                    self.last_error.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(anyhow::anyhow!("command exited with status {:?}", out.status.code()));
                }
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                self.last_error.store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(stdout)
            }
            Ok(Err(e)) => {
                metrics::counter!("dispa_plugin_cmd_errors_total", &[("plugin", self.name.clone()), ("kind", "io".to_string())]).increment(1);
                self.last_error.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(anyhow::anyhow!("wait failed: {}", e))
            }
            Err(_) => {
                metrics::counter!("dispa_plugin_cmd_timeouts_total", &[("plugin", self.name.clone())]).increment(1);
                self.last_error.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(anyhow::anyhow!("command timeout"))
            }
        }
    }
}

#[cfg(feature = "cmd-plugin")]
impl RequestPlugin for CommandPlugin {
    fn name(&self) -> &str { &self.name }
    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        // Fallback sync path
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.on_request_async(req)))
    }
    fn last_error_and_clear(&self) -> bool { self.last_error.swap(false, std::sync::atomic::Ordering::SeqCst) }
}

#[cfg(feature = "cmd-plugin")]
impl CommandPlugin {
    async fn on_request_async(&self, req: &mut Request<Body>) -> PluginResult {
        // Build minimal JSON input
        let mut hdr_map = serde_json::Map::new();
        for (k, v) in req.headers().iter() {
            if let Ok(val) = v.to_str() {
                hdr_map.insert(k.as_str().to_string(), Value::String(val.to_string()));
            }
        }
        let input = serde_json::json!({
            "stage": "request",
            "method": req.method().as_str(),
            "path": req.uri().path(),
            "headers": Value::Object(hdr_map),
        });
        let output = match self.run_command_async(&input.to_string(), self.timeout_ms).await {
            Ok(s) => s,
            Err(e) => {
                metrics::counter!("dispa_plugin_errors_total", &[("plugin", self.name.clone()), ("stage", "request".to_string()), ("kind", "exec".to_string())]).increment(1);
                warn!("Command plugin '{}' failed: {}", self.name, e);
                return PluginResult::Continue;
            }
        };
        if let Ok(val) = serde_json::from_str::<Value>(&output) {
            // set_headers: { "Header":"Value" }
            if let Some(obj) = val.get("set_headers").and_then(|x| x.as_object()) {
                let headers = req.headers_mut();
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        if let (Ok(name), Ok(hv)) = (
                            hyper::header::HeaderName::from_bytes(k.as_bytes()),
                            s.parse()
                        ) { headers.insert(name, hv); }
                    }
                }
            }
            // short_circuit: { "status": 403, "body": "..." }
            if let Some(sc) = val.get("short_circuit").and_then(|x| x.as_object()) {
                let status = sc.get("status").and_then(|x| x.as_u64()).unwrap_or(403) as u16;
                let body = sc.get("body").and_then(|x| x.as_str()).unwrap_or("");
                let resp = Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN)).body(Body::from(body.to_string())).unwrap();
                return PluginResult::ShortCircuit(resp);
            }
        }
        PluginResult::Continue
    }
}

#[cfg(feature = "cmd-plugin")]
impl ResponsePlugin for CommandPlugin {
    fn name(&self) -> &str { &self.name }
    fn on_response(&self, resp: &mut Response<Body>) {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.on_response_async(resp)))
    }
    fn last_error_and_clear(&self) -> bool { self.last_error.swap(false, std::sync::atomic::Ordering::SeqCst) }
}

#[cfg(feature = "cmd-plugin")]
impl CommandPlugin {
    async fn on_response_async(&self, resp: &mut Response<Body>) {
        let mut hdr_map = serde_json::Map::new();
        for (k, v) in resp.headers().iter() {
            if let Ok(val) = v.to_str() {
                hdr_map.insert(k.as_str().to_string(), Value::String(val.to_string()));
            }
        }
        let input = serde_json::json!({
            "stage": "response",
            "status": resp.status().as_u16(),
            "headers": Value::Object(hdr_map),
        });
        match self.run_command_async(&input.to_string(), self.timeout_ms).await {
            Ok(output) => if let Ok(val) = serde_json::from_str::<Value>(&output) {
                if let Some(obj) = val.get("set_headers").and_then(|x| x.as_object()) {
                    let headers = resp.headers_mut();
                    for (k, v) in obj { if let Some(s)=v.as_str(){ if let (Ok(name), Ok(hv))=(hyper::header::HeaderName::from_bytes(k.as_bytes()), s.parse()){ headers.insert(name, hv);} }}
                }
            },
            Err(e) => {
                metrics::counter!("dispa_plugin_errors_total", &[("plugin", self.name.clone()), ("stage", "response".to_string()), ("kind", "exec".to_string())]).increment(1);
                warn!("Command plugin '{}' failed on response: {}", self.name, e);
            }
        }
    }
}

// (last_error_and_clear implemented in the main impl blocks above)

// Shared handle container
pub type SharedPluginEngine = Arc<RwLock<Option<PluginEngine>>>;
