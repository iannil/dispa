# Dispa 开发指南

## 架构概览

Dispa 采用模块化架构，主要包含以下组件：

```text
dispa/
├── src/
│   ├── main.rs              # 应用入口点
│   ├── config/              # 配置管理
│   │   └── mod.rs
│   ├── proxy/               # 代理服务器
│   │   ├── mod.rs
│   │   ├── server.rs        # HTTP 服务器
│   │   └── handler.rs       # 请求处理器
│   ├── logger/              # 流量记录
│   │   ├── mod.rs
│   │   └── traffic_logger.rs
│   ├── balancer/            # 负载均衡
│   │   ├── mod.rs
│   │   ├── load_balancer.rs
│   │   └── health_check.rs
│   └── monitoring/          # 监控指标
│       ├── mod.rs
│       ├── metrics.rs
│       └── health.rs
├── config/
│   └── config.toml          # 配置文件
└── README.md
```

## 核心模块说明

### 1. 配置管理 (`config`)

负责解析和验证配置文件，支持：

- TOML 格式配置文件
- 配置验证和默认值
- 运行时配置重载（计划中）

### 2. 代理服务器 (`proxy`)

HTTP/HTTPS 代理服务器实现：

- 基于 Hyper 的异步 HTTP 服务器
- 域名匹配和流量拦截
- 请求/响应转发
- 连接池管理

### 3. 负载均衡器 (`balancer`)

实现多种负载均衡算法：

- 轮询 (Round Robin)
- 加权轮询 (Weighted Round Robin)
- 随机选择 (Random)
- 最少连接 (Least Connections)

健康检查功能：

- 定期检查后端服务状态
- 自动故障转移
- 可配置的健康阈值

### 4. 流量记录器 (`logger`)

支持多种存储方式：

- SQLite 数据库存储
- 文件日志存储
- 结构化日志格式
- 自动日志轮转和清理

### 5. 监控系统 (`monitoring`)

集成监控和指标：

- Prometheus 指标导出
- 健康检查端点
- 系统状态监控
- 性能指标收集

## 技术栈详解

### 异步运行时

- **Tokio**: 提供异步 I/O、任务调度、定时器等核心功能
- **Futures**: 异步编程抽象和组合器

### HTTP 处理

- **Hyper**: 低级 HTTP 库，提供客户端和服务器实现
- **Reqwest**: 高级 HTTP 客户端，用于转发请求
- **Tower**: 服务抽象层，提供中间件支持

### 数据处理

- **Serde**: 序列化/反序列化框架
- **SQLx**: 异步数据库访问库
- **Chrono**: 日期时间处理

### 配置和CLI

- **Config**: 分层配置管理
- **Clap**: 命令行参数解析
- **TOML**: 配置文件格式

### 监控和日志

- **Tracing**: 结构化日志和追踪
- **Metrics**: 指标收集框架
- **Prometheus**: 指标导出器

## 数据流

```text
客户端请求
    ↓
域名匹配检查
    ↓
负载均衡器选择目标
    ↓
转发请求到目标服务器
    ↓
记录流量日志
    ↓
返回响应给客户端
```

## 错误处理

采用 `anyhow` 和 `thiserror` 进行错误处理：

```rust
use anyhow::{Result, Context};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Target not available")]
    TargetUnavailable,

    #[error("Domain not allowed: {domain}")]
    DomainNotAllowed { domain: String },

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
}
```

## 性能考虑

### 内存管理

- 使用 `Arc` 和 `RwLock` 进行线程安全的共享状态
- 避免不必要的内存分配和复制
- 合理使用连接池减少资源消耗

### 并发模型

- 基于 Tokio 的任务并发
- 每个连接独立处理，避免阻塞
- 共享状态使用读写锁优化性能

### 网络优化

- 复用 HTTP 连接
- 合理设置超时时间
- 支持 HTTP/2（计划中）

## 扩展点

### 新增负载均衡算法

1. 在 `LoadBalancingType` 枚举中添加新类型
2. 在 `LoadBalancer::get_target()` 中实现选择逻辑
3. 更新配置验证

### 新增存储后端

1. 在 `LoggingType` 枚举中添加新类型
2. 实现相应的存储接口
3. 更新 `TrafficLogger` 实现

### 新增监控指标

1. 在 `register_metrics()` 中注册新指标
2. 在相应模块中更新指标值
3. 更新 Prometheus 查询示例

## 测试策略

### 单元测试

- 每个模块的核心逻辑测试
- 配置解析和验证测试
- 负载均衡算法测试

### 集成测试

- 端到端代理功能测试
- 健康检查和故障转移测试
- 监控指标准确性测试

### 压力测试

- 高并发连接测试
- 长时间运行稳定性测试
- 内存泄漏检测

## 部署最佳实践

### 容器化部署

- 使用多阶段构建减小镜像体积
- 合理设置资源限制
- 健康检查配置

### 生产环境配置

- 启用 TLS 终止
- 配置适当的超时时间
- 设置日志轮转和清理

### 监控和告警

- 设置关键指标告警
- 日志聚合和分析
- 性能监控仪表板

## 安全考虑

### 网络安全

- 输入验证和过滤
- 防止 SSRF 攻击
- 安全的错误处理

### 访问控制

- 域名白名单机制
- 可选的身份验证
- 请求速率限制（计划中）

## 贡献指南

### 代码风格

- 遵循 Rust 官方风格指南
- 使用 `cargo fmt` 格式化代码
- 通过 `cargo clippy` 检查

### 提交规范

- 清晰的提交信息
- 一个提交解决一个问题
- 包含必要的测试用例

### 文档更新

- API 变更需要更新文档
- 新功能需要添加使用示例
- 重要变更需要更新 CHANGELOG
