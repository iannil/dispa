use crate::config::PluginErrorStrategy;
use hyper::{Body, Request, Response};
use tracing::warn;

use super::traits::{PluginResult, RequestPlugin, ResponsePlugin};

/// 请求插件条目
pub struct PluginRequestEntry {
    pub name: String,
    pub strategy: PluginErrorStrategy,
    pub plugin: Box<dyn RequestPlugin + Send + Sync>,
}

/// 响应插件条目
pub struct PluginResponseEntry {
    pub name: String,
    pub strategy: PluginErrorStrategy,
    pub plugin: Box<dyn ResponsePlugin + Send + Sync>,
}

/// 插件执行器，负责执行插件链
pub struct PluginExecutor;

impl PluginExecutor {
    /// 执行请求插件链
    pub async fn execute_request_plugins(
        plugins: &[PluginRequestEntry],
        req: &mut Request<Body>,
    ) -> PluginResult {
        for entry in plugins {
            let result = entry.plugin.on_request(req);
            match result {
                PluginResult::Continue => {
                    if entry.plugin.last_error_and_clear() {
                        if let Err(response) =
                            Self::handle_plugin_error(&entry.name, entry.strategy)
                        {
                            return PluginResult::ShortCircuit(response);
                        }
                    }
                }
                PluginResult::ShortCircuit(resp) => return PluginResult::ShortCircuit(resp),
            }
        }
        PluginResult::Continue
    }

    /// 执行响应插件链
    pub async fn execute_response_plugins(
        plugins: &[PluginResponseEntry],
        resp: &mut Response<Body>,
    ) {
        for entry in plugins {
            entry.plugin.on_response(resp);
            if entry.plugin.last_error_and_clear() {
                Self::handle_response_plugin_error(&entry.name, entry.strategy);
            }
        }
    }

    /// 执行指定的请求插件子集
    pub async fn execute_request_plugins_subset(
        plugins: &[PluginRequestEntry],
        plugin_indices: &[usize],
        req: &mut Request<Body>,
    ) -> PluginResult {
        for &index in plugin_indices {
            if let Some(entry) = plugins.get(index) {
                let result = entry.plugin.on_request(req);
                match result {
                    PluginResult::Continue => {
                        if entry.plugin.last_error_and_clear() {
                            if let Err(response) =
                                Self::handle_plugin_error(&entry.name, entry.strategy)
                            {
                                return PluginResult::ShortCircuit(response);
                            }
                        }
                    }
                    PluginResult::ShortCircuit(resp) => return PluginResult::ShortCircuit(resp),
                }
            }
        }
        PluginResult::Continue
    }

    /// 处理插件错误
    #[allow(clippy::result_large_err)]
    fn handle_plugin_error(
        plugin_name: &str,
        strategy: PluginErrorStrategy,
    ) -> Result<(), Response<Body>> {
        match strategy {
            PluginErrorStrategy::Fail => {
                warn!(
                    "Plugin {} reported error, failing per strategy",
                    plugin_name
                );
                let response = Response::builder()
                    .status(500)
                    .body(Body::from("Plugin error"))
                    .expect("Building simple HTTP response should not fail");
                Err(response)
            }
            PluginErrorStrategy::Continue => {
                warn!(
                    "Plugin {} reported error, continuing per strategy",
                    plugin_name
                );
                Ok(())
            }
        }
    }

    /// 处理响应插件错误
    pub fn handle_response_plugin_error(plugin_name: &str, strategy: PluginErrorStrategy) -> bool {
        match strategy {
            PluginErrorStrategy::Fail => {
                warn!(
                    "Response plugin {} reported error, failing per strategy",
                    plugin_name
                );
                false // 停止执行后续插件
            }
            PluginErrorStrategy::Continue => {
                warn!(
                    "Response plugin {} reported error, continuing per strategy",
                    plugin_name
                );
                true // 继续执行后续插件
            }
        }
    }

    /// 创建请求插件条目
    pub fn create_request_entry(
        name: String,
        strategy: PluginErrorStrategy,
        plugin: Box<dyn RequestPlugin + Send + Sync>,
    ) -> PluginRequestEntry {
        PluginRequestEntry {
            name,
            strategy,
            plugin,
        }
    }

    /// 创建响应插件条目
    pub fn create_response_entry(
        name: String,
        strategy: PluginErrorStrategy,
        plugin: Box<dyn ResponsePlugin + Send + Sync>,
    ) -> PluginResponseEntry {
        PluginResponseEntry {
            name,
            strategy,
            plugin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginErrorStrategy;
    use crate::plugins::traits::{PluginResult, RequestPlugin};
    use hyper::{Body, Request};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // 模拟插件，用于测试
    struct MockRequestPlugin {
        name: String,
        should_error: bool,
        should_short_circuit: bool,
        error_flag: Arc<AtomicBool>,
    }

    impl MockRequestPlugin {
        fn new(name: &str, should_error: bool, should_short_circuit: bool) -> Self {
            Self {
                name: name.to_string(),
                should_error,
                should_short_circuit,
                error_flag: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl RequestPlugin for MockRequestPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn on_request(&self, _req: &mut Request<Body>) -> PluginResult {
            if self.should_error {
                self.error_flag.store(true, Ordering::Relaxed);
            }

            if self.should_short_circuit {
                let response = Response::builder()
                    .status(403)
                    .body(Body::from("Short circuit"))
                    .unwrap();
                PluginResult::ShortCircuit(response)
            } else {
                PluginResult::Continue
            }
        }

        fn last_error_and_clear(&self) -> bool {
            self.error_flag.swap(false, Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn test_execute_request_plugins_success() {
        let plugin1 = MockRequestPlugin::new("plugin1", false, false);
        let plugin2 = MockRequestPlugin::new("plugin2", false, false);

        let entries = vec![
            PluginExecutor::create_request_entry(
                "plugin1".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin1),
            ),
            PluginExecutor::create_request_entry(
                "plugin2".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin2),
            ),
        ];

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let result = PluginExecutor::execute_request_plugins(&entries, &mut req).await;

        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn test_execute_request_plugins_short_circuit() {
        let plugin1 = MockRequestPlugin::new("plugin1", false, false);
        let plugin2 = MockRequestPlugin::new("plugin2", false, true); // 会短路

        let entries = vec![
            PluginExecutor::create_request_entry(
                "plugin1".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin1),
            ),
            PluginExecutor::create_request_entry(
                "plugin2".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin2),
            ),
        ];

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let result = PluginExecutor::execute_request_plugins(&entries, &mut req).await;

        assert!(matches!(result, PluginResult::ShortCircuit(_)));
    }

    #[tokio::test]
    async fn test_execute_request_plugins_error_continue() {
        let plugin = MockRequestPlugin::new("plugin", true, false); // 会出错

        let entries = vec![PluginExecutor::create_request_entry(
            "plugin".to_string(),
            PluginErrorStrategy::Continue, // 继续执行
            Box::new(plugin),
        )];

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let result = PluginExecutor::execute_request_plugins(&entries, &mut req).await;

        // 应该继续，即使有错误
        assert!(matches!(result, PluginResult::Continue));
    }

    #[tokio::test]
    async fn test_execute_request_plugins_error_fail() {
        let plugin = MockRequestPlugin::new("plugin", true, false); // 会出错

        let entries = vec![PluginExecutor::create_request_entry(
            "plugin".to_string(),
            PluginErrorStrategy::Fail, // 失败时停止
            Box::new(plugin),
        )];

        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let result = PluginExecutor::execute_request_plugins(&entries, &mut req).await;

        // 应该短路，因为错误策略是Fail
        assert!(matches!(result, PluginResult::ShortCircuit(_)));
    }

    #[tokio::test]
    async fn test_execute_request_plugins_subset() {
        let plugin1 = MockRequestPlugin::new("plugin1", false, false);
        let plugin2 = MockRequestPlugin::new("plugin2", false, true); // 会短路，但不在子集中
        let plugin3 = MockRequestPlugin::new("plugin3", false, false);

        let entries = vec![
            PluginExecutor::create_request_entry(
                "plugin1".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin1),
            ),
            PluginExecutor::create_request_entry(
                "plugin2".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin2),
            ),
            PluginExecutor::create_request_entry(
                "plugin3".to_string(),
                PluginErrorStrategy::Continue,
                Box::new(plugin3),
            ),
        ];

        // 只执行plugin1和plugin3（索引0和2）
        let subset_indices = vec![0, 2];
        let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let result =
            PluginExecutor::execute_request_plugins_subset(&entries, &subset_indices, &mut req)
                .await;

        // 应该成功，因为跳过了会短路的plugin2
        assert!(matches!(result, PluginResult::Continue));
    }
}
