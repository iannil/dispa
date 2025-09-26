# Dispa 代码命名规范指南

## 📋 当前命名规范分析

### ✅ 已经遵循的良好模式

| 类型 | 规范 | 示例 | 状态 |
|------|------|------|------|
| 结构体 | PascalCase | `LoadBalancer`, `TrafficLogger` | ✅ 一致 |
| 枚举 | PascalCase | `LoadBalancingType`, `LoggingType` | ✅ 一致 |
| 函数 | snake_case | `get_target()`, `log_request()` | ✅ 一致 |
| 模块 | snake_case | `load_balancer`, `traffic_logger` | ✅ 一致 |
| 配置结构体 | 统一`Config`后缀 | `ServerConfig`, `LoggingConfig` | ✅ 一致 |

### 🟡 需要改进的模式

| 问题类型 | 当前状态 | 建议改进 |
|----------|----------|----------|
| 布尔配置字段 | 混合模式 | 统一使用`enable_`前缀 |
| 常量命名 | 部分不规范 | 全部使用`SCREAMING_SNAKE_CASE` |
| 超时配置 | 单位不明确 | 统一使用`_ms`, `_secs`后缀 |
| 计数配置 | 前缀不一致 | 统一使用`max_`, `min_`前缀 |

## 🎯 标准命名规范

### 1. 基础类型命名

#### 结构体 (PascalCase)
```rust
// ✅ 正确
pub struct LoadBalancer { }
pub struct TrafficLogger { }
pub struct RequestProcessor { }

// ❌ 避免
pub struct loadBalancer { }
pub struct traffic_logger { }
```

#### 枚举 (PascalCase + 描述性后缀)
```rust
// ✅ 正确
pub enum LoadBalancingType {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
}

pub enum AuthResult {
    Success,
    Failed,
    Expired,
}

// ❌ 避免
pub enum LoadBalancing { }
pub enum Auth { }
```

#### 函数和方法 (snake_case + 动词开头)
```rust
// ✅ 正确
pub fn get_target(&self) -> Option<Target>
pub async fn log_request(&self, req: &Request) -> Result<()>
pub fn update_stats(&mut self, target: &str, duration: Duration)

// ❌ 避免
pub fn target(&self) -> Option<Target>  // 缺少动词
pub fn logReq(&self, req: &Request)     // 驼峰命名
```

### 2. 配置相关命名

#### 配置结构体 (统一Config后缀)
```rust
// ✅ 正确
pub struct ServerConfig { }
pub struct LoadBalancingConfig { }
pub struct HealthCheckConfig { }

// ❌ 避免
pub struct ServerSettings { }
pub struct LoadBalancerOptions { }
```

#### 布尔配置字段 (enable_前缀)
```rust
// ✅ 推荐统一模式
pub struct Config {
    pub enable_logging: bool,
    pub enable_caching: bool,
    pub enable_compression: bool,
    pub enable_tls_verification: bool,
}

// ❌ 当前混合模式
pub struct Config {
    pub enabled: bool,           // 不明确
    pub logging: bool,           // 功能不明确
    pub use_compression: bool,   // 前缀不一致
    pub disable_tls: bool,       // 负面逻辑
}
```

#### 数量和限制配置 (明确前缀)
```rust
// ✅ 正确
pub struct Config {
    pub max_connections: u32,
    pub min_idle_connections: u32,
    pub max_retry_attempts: u32,
    pub connection_timeout_ms: u64,
    pub health_check_interval_secs: u64,
}

// ❌ 不明确
pub struct Config {
    pub connections: u32,        // 不知道是最大值还是当前值
    pub timeout: u64,            // 不知道单位
    pub retry: u32,              // 不知道是次数还是间隔
}
```

### 3. 常量和静态变量

#### 常量 (SCREAMING_SNAKE_CASE)
```rust
// ✅ 正确
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const MAX_HEADER_SIZE: usize = 8192;
const DEFAULT_WORKER_THREADS: usize = 4;

// ❌ 避免
const DEFAULT_TIMEOUT: u64 = 5000;      // 缺少单位
const maxHeaderSize: usize = 8192;      // 驼峰命名
const default_workers: usize = 4;       // snake_case
```

#### 静态变量 (SCREAMING_SNAKE_CASE)
```rust
// ✅ 正确
static SHARED_CLIENT: Lazy<Client> = Lazy::new(|| build_client());
static REQUEST_TIMEOUT_SECS: Lazy<RwLock<u64>> = Lazy::new(|| RwLock::new(5));

// 当前有改进空间的例子
static HOP_HEADERS: &[&str] = &[...];  // ✅ 已经正确
```

### 4. 错误和结果类型

#### 错误类型 (Error后缀)
```rust
// ✅ 正确
pub enum DispaError {
    ConfigurationError(String),
    NetworkError(String),
    AuthenticationError(String),
}

// 结果类型别名
pub type DispaResult<T> = Result<T, DispaError>;
```

#### 枚举变体 (描述性命名)
```rust
// ✅ 正确
pub enum AuthResult {
    Success { user_id: String },
    InvalidCredentials,
    AccountLocked,
    SessionExpired,
}

// ❌ 避免过于简洁
pub enum AuthResult {
    Ok,
    Fail,
    Lock,
}
```

## 🔧 改进建议和行动项

### 即时改进项
1. **统一布尔配置**：将`routing/config.rs`中的`enable_logging`模式应用到所有配置
2. **明确超时单位**：为所有超时配置添加`_ms`或`_secs`后缀
3. **统一计数前缀**：使用`max_`, `min_`, `default_`前缀

### 配置字段标准化
```rust
// 建议的标准配置模式
pub struct StandardConfig {
    // 功能开关 - enable_ 前缀
    pub enable_feature: bool,
    pub enable_debug_logging: bool,

    // 数量限制 - max_/min_ 前缀 + 明确含义
    pub max_connections: u32,
    pub max_request_size_bytes: usize,
    pub min_idle_connections: u32,

    // 时间配置 - 明确单位后缀
    pub connection_timeout_ms: u64,
    pub health_check_interval_secs: u32,
    pub session_lifetime_hours: u32,

    // 默认值配置 - default_ 前缀
    pub default_target: Option<String>,
    pub default_worker_threads: usize,
}
```

### 实施优先级

#### 🔴 高优先级 (影响可读性)
- [ ] 统一所有布尔配置的`enable_`前缀
- [ ] 为所有超时配置添加单位后缀
- [ ] 检查和统一常量命名

#### 🟡 中优先级 (改进一致性)
- [ ] 统一计数配置的前缀
- [ ] 检查函数命名的动词使用
- [ ] 优化错误类型的描述性

#### 🟢 低优先级 (长期维护)
- [ ] 建立命名规范的Clippy规则
- [ ] 添加命名规范的文档检查
- [ ] 在代码审查中强化命名检查

## 📚 命名规范检查工具

### 使用Clippy规则
```toml
# Cargo.toml中启用相关检查
[lints.clippy]
enum-variant-names = "warn"
struct-excessive-bools = "warn"
fn-params-excessive-bools = "warn"
```

### 自定义检查脚本
```bash
#!/bin/bash
# 检查布尔配置命名
echo "检查布尔配置命名模式..."
grep -r "pub.*: bool" src/ --include="*.rs" | grep -v "enable_" | head -5

# 检查超时配置单位
echo "检查超时配置单位..."
grep -r "timeout" src/ --include="*.rs" | grep -v "_ms\|_secs" | head -5
```

---

**注意**: 命名规范的修改应该谨慎进行，特别是公共API的变更需要考虑向后兼容性。建议优先处理内部类型和新增功能的命名规范。