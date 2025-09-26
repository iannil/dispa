# Dispa 代码模板库

> 为常见开发模式提供标准化的代码模板，提高开发效率和代码一致性

## 🎯 模板分类

### 1. 结构体和构造函数模板
### 2. 异步处理模板
### 3. 配置管理模板
### 4. 错误处理模板
### 5. 测试编写模板
### 6. 状态管理模板

---

## 🏗️ 1. 结构体和构造函数模板

### 基础结构体模板
```rust
/// [结构体功能描述]
///
/// # 主要功能
/// - 功能1: 描述
/// - 功能2: 描述
///
/// # 使用示例
/// ```rust
/// let instance = MyStruct::new(config);
/// ```
#[derive(Debug, Clone)]
pub struct MyStruct {
    config: MyConfig,
    // 内部状态字段
}

impl MyStruct {
    /// 创建新实例
    pub fn new(config: MyConfig) -> Self {
        Self {
            config,
        }
    }

    /// 获取配置引用
    pub fn get_config(&self) -> &MyConfig {
        &self.config
    }

    /// 更新配置（如果支持热重载）
    pub fn update_config(&mut self, new_config: MyConfig) {
        self.config = new_config;
    }
}
```

### 异步构造函数模板
```rust
impl MyAsyncStruct {
    /// 异步创建新实例
    ///
    /// # 错误
    /// - 如果初始化资源失败
    pub async fn new(config: MyConfig) -> DispaResult<Self> {
        // 异步初始化逻辑
        let resource = Self::init_resource(&config).await?;

        Ok(Self {
            config,
            resource,
        })
    }

    /// 初始化异步资源
    async fn init_resource(config: &MyConfig) -> DispaResult<Resource> {
        // 具体初始化逻辑
        todo!()
    }
}
```

### 带状态管理的结构体模板
```rust
use std::sync::Arc;
use tokio::sync::RwLock;

/// 线程安全的共享状态结构体
#[derive(Clone)]
pub struct SharedStruct {
    inner: Arc<RwLock<SharedStructInner>>,
}

struct SharedStructInner {
    config: MyConfig,
    state: MyState,
    // 其他内部状态
}

impl SharedStruct {
    pub fn new(config: MyConfig) -> Self {
        let inner = SharedStructInner {
            config,
            state: MyState::default(),
        };

        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// 读取状态
    pub async fn get_state(&self) -> MyState {
        let inner = self.inner.read().await;
        inner.state.clone()
    }

    /// 更新状态
    pub async fn update_state(&self, new_state: MyState) {
        let mut inner = self.inner.write().await;
        inner.state = new_state;
    }
}
```

---

## ⚡ 2. 异步处理模板

### 基础异步函数模板
```rust
/// 异步处理函数模板
///
/// # 参数
/// - `input`: 输入参数描述
///
/// # 返回值
/// 返回值描述
///
/// # 错误
/// - `DispaError::Network`: 网络错误时
/// - `DispaError::Configuration`: 配置错误时
pub async fn process_async(&self, input: InputType) -> DispaResult<OutputType> {
    // 1. 参数验证
    if input.is_invalid() {
        return Err(DispaError::validation("Invalid input"));
    }

    // 2. 异步处理逻辑
    let result = self.do_async_work(input).await?;

    // 3. 结果处理
    Ok(self.transform_result(result))
}

/// 内部异步工作函数
async fn do_async_work(&self, input: InputType) -> DispaResult<WorkResult> {
    // 具体异步逻辑
    todo!()
}
```

### 超时处理模板
```rust
use tokio::time::{timeout, Duration};

/// 带超时的异步操作
pub async fn operation_with_timeout(&self, input: InputType) -> DispaResult<OutputType> {
    let timeout_duration = Duration::from_millis(self.config.timeout_ms);

    match timeout(timeout_duration, self.do_operation(input)).await {
        Ok(result) => result,
        Err(_) => Err(DispaError::timeout("Operation timed out")),
    }
}
```

### 并发处理模板
```rust
use futures::future::join_all;

/// 并发处理多个项目
pub async fn process_concurrent(&self, items: Vec<Item>) -> DispaResult<Vec<Result<Output, DispaError>>> {
    let tasks = items.into_iter().map(|item| {
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.process_single(item).await
        })
    }).collect::<Vec<_>>();

    let results = join_all(tasks).await;

    // 处理 JoinError 并收集结果
    let final_results = results.into_iter()
        .map(|join_result| match join_result {
            Ok(process_result) => process_result,
            Err(e) => Err(DispaError::runtime(format!("Task failed: {}", e))),
        })
        .collect();

    Ok(final_results)
}
```

---

## ⚙️ 3. 配置管理模板

### 配置结构体模板
```rust
use serde::{Deserialize, Serialize};

/// 模块配置结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyModuleConfig {
    /// 是否启用此功能模块
    #[serde(default)]
    pub enable_feature: bool,

    /// 连接超时时间（毫秒）
    #[serde(default = "default_timeout_ms")]
    pub connection_timeout_ms: u64,

    /// 最大连接数
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// 可选的高级配置
    pub advanced: Option<AdvancedConfig>,
}

impl Default for MyModuleConfig {
    fn default() -> Self {
        Self {
            enable_feature: false,
            connection_timeout_ms: default_timeout_ms(),
            max_connections: default_max_connections(),
            advanced: None,
        }
    }
}

impl MyModuleConfig {
    /// 验证配置的有效性
    pub fn validate(&self) -> DispaResult<()> {
        if self.connection_timeout_ms == 0 {
            return Err(DispaError::config("connection_timeout_ms must be > 0"));
        }

        if self.max_connections == 0 {
            return Err(DispaError::config("max_connections must be > 0"));
        }

        // 验证可选配置
        if let Some(ref advanced) = self.advanced {
            advanced.validate()?;
        }

        Ok(())
    }
}

// 默认值函数
fn default_timeout_ms() -> u64 { 5000 }
fn default_max_connections() -> u32 { 100 }
```

### 配置热重载模板
```rust
use notify::{Watcher, RecommendedWatcher, Event};
use tokio::sync::watch;

/// 支持热重载的配置管理器
pub struct ConfigManager<T> {
    config: Arc<RwLock<T>>,
    _watcher: Option<RecommendedWatcher>,
    reload_sender: watch::Sender<T>,
}

impl<T: Clone + Send + Sync + 'static> ConfigManager<T>
where
    T: serde::de::DeserializeOwned,
{
    /// 创建配置管理器并启动文件监控
    pub async fn new(config_path: impl AsRef<Path>, initial_config: T) -> DispaResult<Self> {
        let (reload_sender, _reload_receiver) = watch::channel(initial_config.clone());

        let mut manager = Self {
            config: Arc::new(RwLock::new(initial_config)),
            _watcher: None,
            reload_sender,
        };

        manager.start_file_watcher(config_path).await?;
        Ok(manager)
    }

    /// 获取当前配置
    pub async fn get_config(&self) -> T {
        self.config.read().await.clone()
    }

    /// 获取配置变更通知接收器
    pub fn subscribe_changes(&self) -> watch::Receiver<T> {
        self.reload_sender.subscribe()
    }

    /// 启动文件监控器
    async fn start_file_watcher(&mut self, config_path: impl AsRef<Path>) -> DispaResult<()> {
        // 文件监控实现
        todo!("实现文件监控逻辑")
    }
}
```

---

## 🚨 4. 错误处理模板

### 自定义错误类型模板
```rust
use thiserror::Error;

/// 模块专用错误类型
#[derive(Error, Debug)]
pub enum MyModuleError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    #[error("Permission denied: {action}")]
    PermissionDenied { action: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl MyModuleError {
    /// 便利构造函数
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    pub fn timeout(timeout_ms: u64) -> Self {
        Self::Timeout { timeout_ms }
    }

    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound { resource: resource.into() }
    }
}

/// 模块结果类型别名
pub type MyModuleResult<T> = Result<T, MyModuleError>;
```

### 错误处理链模板
```rust
/// 带上下文的错误处理
pub async fn operation_with_context(&self, input: InputType) -> DispaResult<OutputType> {
    self.step1(input)
        .await
        .map_err(|e| DispaError::context("Step 1 failed", e))?
        .pipe(|intermediate| self.step2(intermediate))
        .await
        .map_err(|e| DispaError::context("Step 2 failed", e))?
        .pipe(|result| self.step3(result))
        .await
        .map_err(|e| DispaError::context("Step 3 failed", e))
}

/// 管道操作扩展
trait PipelineExt<T> {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U;
}

impl<T> PipelineExt<T> for T {
    fn pipe<F, U>(self, f: F) -> U
    where
        F: FnOnce(T) -> U,
    {
        f(self)
    }
}
```

---

## 🧪 5. 测试编写模板

### 单元测试模块模板
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// 测试辅助函数：创建测试配置
    fn create_test_config() -> MyModuleConfig {
        MyModuleConfig {
            enable_feature: true,
            connection_timeout_ms: 1000,
            max_connections: 10,
            advanced: None,
        }
    }

    /// 测试辅助函数：创建测试实例
    fn create_test_instance() -> MyStruct {
        MyStruct::new(create_test_config())
    }

    #[test]
    fn test_basic_functionality() {
        let instance = create_test_instance();

        // 测试基本功能
        assert_eq!(instance.get_config().enable_feature, true);
    }

    #[tokio::test]
    async fn test_async_operation() {
        let instance = create_test_instance();
        let input = InputType::default();

        let result = instance.process_async(input).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.expected_field, "expected_value");
    }

    #[tokio::test]
    async fn test_error_handling() {
        let instance = create_test_instance();
        let invalid_input = InputType::invalid();

        let result = instance.process_async(invalid_input).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DispaError::Validation(msg) => assert!(msg.contains("Invalid")),
            _ => panic!("Expected validation error"),
        }
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let instance = create_test_instance();
        let items = vec![Item::new(1), Item::new(2), Item::new(3)];

        let results = instance.process_concurrent(items).await.unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    #[should_panic(expected = "timeout")]
    async fn test_timeout_behavior() {
        let mut config = create_test_config();
        config.connection_timeout_ms = 100; // 很短的超时
        let instance = MyStruct::new(config);

        // 这应该超时
        let slow_input = InputType::slow();
        instance.operation_with_timeout(slow_input).await.unwrap();
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    /// 集成测试：使用Mock服务器
    #[tokio::test]
    async fn test_with_mock_server() {
        // 启动Mock服务器
        let mock_server = MockServer::start().await;

        // 配置Mock响应
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                "status": "success"
            })))
            .mount(&mock_server)
            .await;

        // 使用Mock服务器URL创建测试实例
        let mut config = create_test_config();
        config.base_url = mock_server.uri();
        let instance = MyStruct::new(config);

        // 执行测试
        let result = instance.make_request("/test").await;
        assert!(result.is_ok());
    }
}
```

### 性能测试模板
```rust
#[cfg(test)]
mod bench_tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn bench_basic_operation() {
        let instance = create_test_instance();
        let iterations = 1000;

        let start = Instant::now();

        for _ in 0..iterations {
            let result = instance.fast_operation().await;
            assert!(result.is_ok());
        }

        let duration = start.elapsed();
        let avg_duration = duration / iterations;

        println!("Average operation time: {:?}", avg_duration);

        // 性能断言：单次操作应在10ms内完成
        assert!(avg_duration < Duration::from_millis(10));
    }
}
```

---

## 📊 6. 状态管理模板

### 简单状态管理
```rust
use std::sync::atomic::{AtomicU64, Ordering};

/// 原子操作的简单状态
pub struct SimpleState {
    counter: AtomicU64,
    enabled: AtomicBool,
}

impl SimpleState {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        }
    }

    pub fn increment(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}
```

### 复杂状态管理
```rust
use tokio::sync::{RwLock, Notify};
use std::collections::HashMap;

/// 复杂状态管理器
pub struct StateManager<T> {
    states: Arc<RwLock<HashMap<String, T>>>,
    notify: Arc<Notify>,
}

impl<T: Clone + Send + Sync + 'static> StateManager<T> {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            notify: Arc::new(Notify::new()),
        }
    }

    /// 设置状态
    pub async fn set(&self, key: impl Into<String>, value: T) {
        let key = key.into();
        let mut states = self.states.write().await;
        states.insert(key, value);
        drop(states);

        // 通知状态变更
        self.notify.notify_waiters();
    }

    /// 获取状态
    pub async fn get(&self, key: &str) -> Option<T> {
        let states = self.states.read().await;
        states.get(key).cloned()
    }

    /// 等待状态变更
    pub async fn wait_for_change(&self) {
        self.notify.notified().await;
    }

    /// 批量更新状态
    pub async fn batch_update(&self, updates: HashMap<String, T>) {
        let mut states = self.states.write().await;
        states.extend(updates);
        drop(states);

        self.notify.notify_waiters();
    }
}
```

---

## 🎯 使用指南

### 1. 选择合适的模板
- **简单结构体**: 使用基础结构体模板
- **异步初始化**: 使用异步构造函数模板
- **共享状态**: 使用带状态管理的结构体模板

### 2. 自定义模板
- 复制对应的模板代码
- 替换`MyStruct`, `MyConfig`等占位符
- 根据具体需求调整字段和方法

### 3. 测试驱动开发
- 先编写测试用例
- 使用测试模板确保覆盖率
- 在实现功能前确保测试能编译通过

### 4. 错误处理最佳实践
- 使用自定义错误类型
- 提供有意义的错误信息
- 保持错误处理的一致性

---

## ⚡ 快速开始清单

开发新功能时的检查清单：

- [ ] 选择合适的结构体模板
- [ ] 定义配置结构体（如果需要）
- [ ] 实现错误处理
- [ ] 编写单元测试
- [ ] 添加文档注释
- [ ] 验证异步处理正确性
- [ ] 检查状态管理线程安全性

---

*提示：这些模板是基于Dispa项目的最佳实践总结，可以根据具体需求进行调整和扩展。*