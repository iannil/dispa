# Dispa 大模型理解指南

> 本文档专为大语言模型（LLM）设计，提供快速理解和开发Dispa项目所需的所有关键信息

## 🎯 快速概览

**项目性质**: 高性能HTTP代理服务器
**主要语言**: Rust (100%)
**架构模式**: 异步模块化
**核心功能**: 流量拦截、负载均衡、健康检查、日志记录

## 📁 核心架构映射

### 顶级模块结构
```text
src/
├── main.rs                 # 应用入口 (54行)
├── lib.rs                  # 库入口 (61行)
├── app_state.rs             # 应用状态管理 (398行)
├── proxy/                  # 代理服务器核心 (6个文件)
├── balancer/               # 负载均衡 (2个文件)
├── config/                 # 配置管理 (11个文件)
├── logger/                 # 日志记录 (6个文件)
├── monitoring/             # 监控指标 (8个文件)
├── cache/                  # 响应缓存 (5个文件)
├── security/               # 安全认证 (2个文件)
├── plugins/                # 插件系统 (6个文件)
├── routing/                # 路由引擎 (6个文件)
└── 单文件模块/              # 专用功能模块
```

### 关键数据流

```text
请求进入 → 域名匹配 → 路由决策 → 负载均衡 → 健康检查 → 转发 → 记录日志
    ↓         ↓         ↓         ↓         ↓       ↓        ↓
HTTP请求   Domain    Route    LoadBalancer  Target  Forward   Log
```

## 🔧 开发常用模式

### 1. 配置驱动模式
所有功能都通过`config/`模块的TOML配置控制：
```rust
// 常见模式：配置 → 构造器 → 运行时对象
let config = Config::from_file_with_env("config.toml").await?;
let component = Component::new(config.component_config);
```

### 2. 异步处理模式
项目广泛使用Tokio异步运行时：
```rust
// 常见模式：异步函数 + Result返回
async fn process_request(&self, req: Request) -> Result<Response> {
    // 异步处理逻辑
}
```

### 3. 共享状态模式
使用`Arc<RwLock<T>>`管理共享状态：
```rust
// 常见模式：线程安全的共享状态
pub struct Component {
    state: Arc<RwLock<ComponentState>>,
}
```

### 4. 错误处理模式
统一使用`anyhow::Result`和自定义错误类型：
```rust
// 统一错误处理
pub type DispaResult<T> = Result<T, DispaError>;
```

## 📝 命名约定

### 文件命名
- 模块文件: `mod.rs` (含架构图和依赖说明)
- 功能文件: `snake_case.rs`
- 测试文件: 在同文件中的`#[cfg(test)]`模块

### 类型命名
- 结构体: `PascalCase` (如`LoadBalancer`)
- 枚举: `PascalCase` (如`LoadBalancingType`)
- 函数: `snake_case` (如`get_target`)
- 常量: `SCREAMING_SNAKE_CASE`

### 配置结构命名
- 配置结构体统一后缀`Config` (如`ServerConfig`)
- 布尔配置使用`enable_/disabled_`前缀
- 数量配置使用明确单位 (如`timeout_ms`, `max_connections`)

## 🧩 核心组件速查

### ProxyServer (代理核心)
**位置**: `src/proxy/server.rs`
**作用**: HTTP服务器主循环，处理连接生命周期
**关键方法**: `new()`, `run()`, `shutdown()`

### LoadBalancer (负载均衡器)
**位置**: `src/balancer/load_balancer.rs`
**算法**: RoundRobin, WeightedRR, LeastConn, Random, IPHash
**关键方法**: `get_target()`, `update_stats()`

### TrafficLogger (流量记录)
**位置**: `src/logger/traffic_logger.rs`
**存储**: 双重存储(文件+数据库)
**关键方法**: `log_request()`, `log_response()`

### ConfigManager (配置管理)
**位置**: `src/config/manager.rs`
**功能**: 热重载、环境变量替换
**关键方法**: `load_config()`, `watch_changes()`

## 🛠️ 开发工作流模式

### 添加新功能模式
1. **配置定义**: 在`config/`下添加配置结构
2. **核心逻辑**: 在对应模块下实现核心功能
3. **集成点**: 在`app_state.rs`中注册组件
4. **测试覆盖**: 添加单元测试和集成测试
5. **文档更新**: 更新模块文档和使用示例

### 修改现有功能模式
1. **理解依赖**: 查看模块mod.rs的架构图
2. **定位代码**: 使用grep查找相关函数/结构体
3. **测试驱动**: 先运行相关测试了解行为
4. **渐进修改**: 小步修改，持续验证测试通过

### 调试问题模式
1. **日志检查**: 查看`tracing`输出定位问题
2. **配置验证**: 确认配置文件格式和数值正确
3. **健康检查**: 使用监控端点检查组件状态
4. **单元测试**: 运行特定模块测试隔离问题

## 🎮 常用开发命令

```bash
# 开发环境运行
cargo run -- -c config/config.toml -v

# 运行特定模块测试
cargo test balancer::load_balancer::tests

# 检查编译错误
cargo check

# 代码格式化和检查
cargo fmt && cargo clippy

# 生成文档
cargo doc --open
```

## 📚 重要文件快速定位

### 必读文件 (理解架构)
- `src/lib.rs` - 模块概览和重要类型导出
- `src/app_state.rs` - 应用状态管理和组件协调
- `CLAUDE.md` - 开发规范和工作流程

### 配置文件 (理解功能)
- `config/config.toml` - 主要配置示例
- `src/config/mod.rs` - 配置结构定义

### 入口文件 (理解启动过程)
- `src/main.rs` - 应用启动逻辑
- `src/proxy/server.rs` - 代理服务器主循环

## 🔍 问题定位查找表

| 问题类型 | 查看文件 | 关键函数/结构体 |
|---------|----------|----------------|
| 连接失败 | `proxy/server.rs` | `ProxyServer::handle_connection` |
| 负载均衡异常 | `balancer/load_balancer.rs` | `LoadBalancer::get_target` |
| 健康检查失败 | `balancer/health_check.rs` | `HealthChecker::check_target` |
| 配置解析错误 | `config/mod.rs` | `Config::from_file_with_env` |
| 日志记录问题 | `logger/traffic_logger.rs` | `TrafficLogger::log_*` |
| 缓存行为异常 | `cache/storage.rs` | `InMemoryCache::get/set` |
| 插件加载失败 | `plugins/engine.rs` | `PluginEngine::load_plugin` |
| 监控指标缺失 | `monitoring/metrics.rs` | `MetricsCollector::collect` |

## 🚀 性能优化要点

### 关键性能指标
- **延迟**: P99 < 10ms 代理开销
- **吞吐**: 支持100k+ RPS
- **并发**: 10k+ 连接数
- **内存**: 运行时 < 100MB

### 优化检查点
1. **连接池**: `proxy/http_client.rs` - 复用HTTP连接
2. **缓存策略**: `cache/policy.rs` - 减少上游请求
3. **异步处理**: 避免阻塞调用，使用`tokio::spawn`
4. **内存管理**: 谨慎使用`Arc<>`，避免过度克隆

## 💡 LLM开发建议

### 最佳实践
1. **始终先读取相关模块的mod.rs了解架构**
2. **查看现有测试了解预期行为**
3. **遵循项目的错误处理模式**
4. **保持异步函数的一致性**
5. **新功能配置化，避免硬编码**

### 避免的陷阱
1. **不要跳过配置验证逻辑**
2. **不要在热路径上使用阻塞调用**
3. **不要忽略错误处理**
4. **不要破坏现有的测试**
5. **不要混合同步和异步代码**

---

## 📋 快速检查清单

开发前必须确认：
- [ ] 理解要修改的模块架构图
- [ ] 运行相关测试确保环境正常
- [ ] 确认配置文件结构和依赖关系
- [ ] 了解错误处理和日志记录模式

完成开发后必须验证：
- [ ] 所有测试通过 `cargo test`
- [ ] 代码格式化 `cargo fmt`
- [ ] 无编译警告 `cargo clippy`
- [ ] 文档生成正常 `cargo doc`
- [ ] 功能符合配置预期
