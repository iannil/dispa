#[cfg(feature = "wasm-plugin")]
use anyhow::Result;
#[cfg(feature = "wasm-plugin")]
use hyper::{Body, Request, Response};
#[cfg(feature = "wasm-plugin")]
use serde_json::Value;
#[cfg(feature = "wasm-plugin")]
use std::sync::Arc;
#[cfg(feature = "wasm-plugin")]
use tokio::sync::Semaphore;

#[cfg(feature = "wasm-plugin")]
use super::traits::{PluginResult, RequestPlugin, ResponsePlugin};

#[cfg(feature = "wasm-plugin")]
struct WasmState {
    // 保留结构体定义为将来实现做准备
    _reserved: (),
}

/// WASM-based plugin implementation
#[cfg(feature = "wasm-plugin")]
pub struct WasmPlugin {
    name: String,
    module_path: String,
    timeout_ms: u64,
    semaphore: Option<Arc<Semaphore>>,
    last_error: Arc<std::sync::atomic::AtomicBool>,
}

impl Clone for WasmPlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            module_path: self.module_path.clone(),
            timeout_ms: self.timeout_ms,
            semaphore: self.semaphore.clone(),
            last_error: Arc::clone(&self.last_error),
        }
    }
}

#[cfg(feature = "wasm-plugin")]
impl WasmPlugin {
    pub fn from_config(name: &str, cfg: Option<&Value>) -> Result<Self> {
        let module_path = cfg
            .and_then(|v| v.get("module_path"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        if module_path.is_empty() {
            return Err(anyhow::anyhow!("wasm plugin requires 'module_path'"));
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
            Some(Arc::new(Semaphore::new(max_conc as usize)))
        } else {
            None
        };

        Ok(Self {
            name: name.to_string(),
            module_path,
            timeout_ms,
            semaphore,
            last_error: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    fn call_guest(&self, _stage: &str, _input: &str) -> Result<Option<String>> {
        // 注意：这是一个 WASM 插件的基本实现示例
        // 实际的生产环境可能需要更复杂的绑定和安全检查
        Err(anyhow::anyhow!(
            "WASM plugin functionality is currently disabled in this build"
        ))
    }

    async fn execute_wasm(&self, stage: &str, input: &str) -> Result<Option<String>> {
        // Acquire semaphore if concurrency limiting is enabled
        let _permit = if let Some(ref sem) = self.semaphore {
            Some(sem.acquire().await?)
        } else {
            None
        };

        let timeout = std::time::Duration::from_millis(self.timeout_ms);
        let plugin = self.clone();
        let stage = stage.to_string();
        let input = input.to_string();

        let result = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || plugin.call_guest(&stage, &input)),
        )
        .await??;

        result
    }
}

#[cfg(feature = "wasm-plugin")]
impl RequestPlugin for WasmPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_request(&self, req: &mut Request<Body>) -> PluginResult {
        // Serialize request data for WASM module
        let input = serde_json::json!({
            "method": req.method().as_str(),
            "uri": req.uri().to_string(),
            "headers": req.headers().iter().map(|(k, v)| {
                (k.as_str(), v.to_str().unwrap_or(""))
            }).collect::<std::collections::HashMap<_, _>>()
        })
        .to_string();

        let rt = tokio::runtime::Handle::current();
        let plugin = self.clone();

        let result =
            std::thread::spawn(move || rt.block_on(plugin.execute_wasm("request", &input))).join();

        match result {
            Ok(Ok(Some(output))) => {
                // Parse output and modify request accordingly
                if let Ok(response_data) = serde_json::from_str::<Value>(&output) {
                    if let Some(short_circuit) =
                        response_data.get("short_circuit").and_then(|v| v.as_bool())
                    {
                        if short_circuit {
                            let status = response_data
                                .get("status")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(200) as u16;
                            let body = response_data
                                .get("body")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            return PluginResult::ShortCircuit(
                                Response::builder()
                                    .status(status)
                                    .body(Body::from(body.to_string()))
                                    .unwrap(),
                            );
                        }
                    }

                    // Apply header modifications
                    if let Some(headers) = response_data.get("headers").and_then(|v| v.as_object())
                    {
                        let req_headers = req.headers_mut();
                        for (k, v) in headers {
                            if let Some(v_str) = v.as_str() {
                                if let (Ok(name), Ok(hv)) = (
                                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                    v_str.parse(),
                                ) {
                                    req_headers.insert(name, hv);
                                }
                            }
                        }
                    }
                }

                self.last_error
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                PluginResult::Continue
            }
            _ => {
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

#[cfg(feature = "wasm-plugin")]
impl ResponsePlugin for WasmPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn on_response(&self, resp: &mut Response<Body>) {
        // Serialize response data for WASM module
        let input = serde_json::json!({
            "status": resp.status().as_u16(),
            "headers": resp.headers().iter().map(|(k, v)| {
                (k.as_str(), v.to_str().unwrap_or(""))
            }).collect::<std::collections::HashMap<_, _>>()
        })
        .to_string();

        let rt = tokio::runtime::Handle::current();
        let plugin = self.clone();

        let result =
            std::thread::spawn(move || rt.block_on(plugin.execute_wasm("response", &input))).join();

        match result {
            Ok(Ok(Some(output))) => {
                // Parse output and modify response accordingly
                if let Ok(response_data) = serde_json::from_str::<Value>(&output) {
                    // Apply header modifications
                    if let Some(headers) = response_data.get("headers").and_then(|v| v.as_object())
                    {
                        let resp_headers = resp.headers_mut();
                        for (k, v) in headers {
                            if let Some(v_str) = v.as_str() {
                                if let (Ok(name), Ok(hv)) = (
                                    hyper::header::HeaderName::from_bytes(k.as_bytes()),
                                    v_str.parse(),
                                ) {
                                    resp_headers.insert(name, hv);
                                }
                            }
                        }
                    }
                }

                self.last_error
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            _ => {
                self.last_error
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    fn last_error_and_clear(&self) -> bool {
        self.last_error
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}
