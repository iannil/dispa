# Dispa 功能清单

> 高性能 HTTP/HTTPS 流量拦截与转发代理
>
> 版本: v0.1.0 | 更新日期: 2026年1月6日

---

## 目录

1. [核心架构](#1-核心架构)
2. [负载均衡](#2-负载均衡)
3. [熔断器](#3-熔断器)
4. [重试机制](#4-重试机制)
5. [缓存系统](#5-缓存系统)
6. [TLS/SSL 支持](#6-tlsssl-支持)
7. [安全模块](#7-安全模块)
8. [路由引擎](#8-路由引擎)
9. [插件系统](#9-插件系统)
10. [协议支持](#10-协议支持)
11. [服务发现](#11-服务发现)
12. [日志与流量记录](#12-日志与流量记录)
13. [监控与指标](#13-监控与指标)
14. [配置管理](#14-配置管理)
15. [优雅关闭](#15-优雅关闭)
16. [性能优化](#16-性能优化)
17. [管理接口](#17-管理接口)

---

## 1. 核心架构

| 项目 | 说明 |
|------|------|
| 语言 | Rust 2021 Edition |
| 异步运行时 | Tokio (全功能) |
| HTTP 框架 | Hyper 0.14 |
| 序列化 | Serde / Serde JSON |
| 日志追踪 | Tracing |
| 加密 | Ring (可选) |
| 数据库 | SQLx (PostgreSQL, SQLite) |

### 核心模块

```
src/
├── proxy/           # 代理核心
├── balancer/        # 负载均衡
├── cache/           # 缓存系统
├── config/          # 配置管理
├── logger/          # 日志记录
├── monitoring/      # 监控指标
├── plugins/         # 插件系统
├── protocol/        # 协议处理
├── routing/         # 路由引擎
├── security/        # 安全模块
└── service_discovery/ # 服务发现
```

---

## 2. 负载均衡

**模块**: `src/balancer/`

### 负载均衡算法

| 算法 | 说明 | 配置项 |
|------|------|--------|
| Round Robin | 轮询分发 | 默认算法 |
| Weighted Round Robin | 加权轮询，平滑权重分发 | `weight` |
| Least Connections | 最少连接优先 | - |
| Random | 随机选择 | - |
| Consistent Hashing | 一致性哈希，会话保持 | `virtual_nodes`, `hash_function` |
| Geographic | 地理位置感知路由 | `region`, `fallback_strategy` |
| Session Sticky | 会话粘滞 | `session_timeout` |
| Adaptive Weighted | 自适应权重，基于响应时间 | `health_metrics` |
| Priority Based | 优先级路由，多层故障转移 | `priority`, `failover_threshold` |

### 健康检查

| 功能 | 默认值 | 说明 |
|------|--------|------|
| 检查间隔 | 30秒 | 健康检查周期 |
| 超时时间 | 5秒 | 单次检查超时 |
| 失败阈值 | 连续失败次数触发不健康 | 可配置 |
| 成功阈值 | 连续成功次数触发恢复 | 可配置 |
| HTTP 状态验证 | 2xx/3xx 为健康 | 可配置 |

### 目标服务器配置

```toml
[[targets.servers]]
address = "http://backend1:8080"
weight = 1.0
timeout = "30s"
```

---

## 3. 熔断器

**模块**: `src/circuit_breaker.rs`

### 熔断状态

| 状态 | 说明 |
|------|------|
| Closed | 正常运行，请求正常流转 |
| Open | 服务异常，请求被阻断 |
| Half-Open | 恢复探测，测试服务是否恢复 |

### 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| failure_threshold | 5 | 连续失败次数触发熔断 |
| success_threshold | 3 | 连续成功次数恢复服务 |
| timeout | 60秒 | 熔断后等待恢复时间 |
| time_window | 60秒 | 失败计数时间窗口 |
| min_request_count | 10 | 最小请求数触发判断 |

---

## 4. 重试机制

**模块**: `src/retry.rs`

### 退避策略

| 策略 | 公式 | 说明 |
|------|------|------|
| Fixed | `delay = base_delay` | 固定延迟 |
| Linear | `delay = base_delay × attempt` | 线性增长 |
| Exponential | `delay = base_delay × multiplier^(attempt-1)` | 指数增长 |

### 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| max_attempts | 3 | 最大重试次数 |
| base_delay | 100ms | 基础延迟 |
| max_delay | 30秒 | 最大延迟 |
| jitter | 支持 | 分布式重试抖动 |

### 可重试错误

- ✅ 网络错误
- ✅ 目标服务器错误
- ✅ 超时错误
- ✅ 服务不可用
- ❌ 配置错误 (不重试)
- ❌ 严重错误 (不重试)

---

## 5. 缓存系统

**模块**: `src/cache/`

### 核心功能

| 功能 | 说明 |
|------|------|
| 内存缓存 | HTTP 响应内存缓存 |
| ETag 验证 | 条件请求支持 |
| TTL 过期 | 基于时间的缓存失效 |
| 状态码过滤 | 可配置缓存状态码 |

### 缓存策略

| 匹配方式 | 说明 |
|----------|------|
| 路径前缀 | 基于 URL 路径匹配 |
| Content-Type | 基于响应类型匹配 |
| 状态码 | 仅缓存指定状态码 |
| Vary Header | 差异化缓存 |

### 缓存指标

- 命中率 (Hit Ratio)
- 每策略统计
- 缓存大小跟踪
- 内存使用监控

---

## 6. TLS/SSL 支持

**模块**: `src/tls.rs`

### 功能特性

| 功能 | 说明 |
|------|------|
| Rustls | 纯 Rust TLS 实现 |
| TLS 1.2/1.3 | 支持现代 TLS 版本 |
| SNI | 多证书虚拟主机 |
| 客户端认证 | 可选双向认证 |
| 通配符证书 | 支持 *.domain.com |

### 配置示例

```toml
[tls]
enabled = true
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
https_port = 8443
min_version = "1.2"
```

---

## 7. 安全模块

**模块**: `src/security/`

### 认证方式

| 方式 | 说明 | Feature Flag |
|------|------|--------------|
| Basic Auth | 用户名/密码认证 | 内置 |
| JWT | 无状态令牌认证 | 内置 |
| JWT RS256 | RSA 签名 + JWKS | `jwt-rs256` |

### DDoS 防护

| 防护项 | 说明 |
|--------|------|
| 最大头数量 | 限制 HTTP 头数量 |
| 最大头大小 | 限制单个头大小 |
| 最大 Body 大小 | 限制请求体大小 |
| Content-Length 强制 | 必须包含长度头 |

### 速率限制

| 功能 | 说明 |
|------|------|
| 令牌桶算法 | 基于 IP 的限流 |
| 突发支持 | 允许突发请求 |
| 白名单 | IP 白名单放行 |
| 黑名单 | IP 黑名单阻断 |

### 访问控制

- IP 访问控制
- 路径访问控制
- 方法访问控制
- 模式匹配规则

---

## 8. 路由引擎

**模块**: `src/routing/`

### 路由条件

| 条件类型 | 说明 |
|----------|------|
| 路径匹配 | URL 路径规则 |
| 方法过滤 | HTTP 方法过滤 |
| 头匹配 | 请求头条件 |
| 正则表达式 | 高级模式匹配 |

### 路由动作

| 动作 | 说明 |
|------|------|
| 头注入/移除 | 请求头操作 |
| 路径重写 | URL 重写 |
| 响应头操作 | 响应头修改 |
| 自定义响应 | 直接返回响应 |
| 目标覆盖 | 指定转发目标 |

### 配置示例

```toml
[[routing.rules]]
priority = 1
conditions = [
    { type = "path", pattern = "/api/v1/*" },
    { type = "method", methods = ["GET", "POST"] }
]
actions = [
    { type = "rewrite_path", from = "/api/v1", to = "/v1" },
    { type = "add_header", name = "X-Routed", value = "true" }
]
```

---

## 9. 插件系统

**模块**: `src/plugins/`

### 内置插件

| 插件 | 说明 | Feature Flag |
|------|------|--------------|
| Header Injector | 请求/响应头操作 | 内置 |
| Blocklist | 主机/路径阻断 | 内置 |
| Command Plugin | 外部命令执行 | `cmd-plugin` |
| WASM Plugin | WebAssembly 插件 | `wasm-plugin` |

### 执行阶段

| 阶段 | 说明 |
|------|------|
| Request | 转发前预处理 |
| Response | 响应后处理 |
| Both | 双向处理 |

### 插件结果

| 结果 | 说明 |
|------|------|
| Continue | 继续执行 |
| ShortCircuit | 短路返回 |
| Error | 错误处理 |

### 错误策略

- Continue: 忽略错误继续
- Abort: 终止请求
- Custom: 自定义处理

---

## 10. 协议支持

**模块**: `src/protocol/`

### 支持的协议

| 协议 | 说明 | 状态 |
|------|------|------|
| HTTP/1.1 | 完整实现 | ✅ |
| HTTP/2 | 完整实现 | ✅ |
| WebSocket | 双向通信 | ✅ |
| gRPC | HTTP/2 RPC | ✅ |
| TCP | 四层透明代理 | ✅ |
| UDP | 四层透明代理 | ✅ |

### 协议特性

- 协议自动检测
- 协议升级支持
- 连接上下文跟踪
- 协议版本协商

---

## 11. 服务发现

**模块**: `src/service_discovery/`

### 支持的后端

| 后端 | 说明 | Feature Flag |
|------|------|--------------|
| Consul | 服务注册与发现 | `consul-discovery` |
| DNS | 传统 DNS 发现 | 内置 |
| etcd | 分布式配置存储 | `etcd-discovery` |
| Kubernetes | K8s API 集成 | `kubernetes-discovery` |

### Consul 功能

- 服务注册/注销
- 健康检查集成
- 服务实例发现
- Token 认证
- 连接池

### Kubernetes 功能

- K8s API Server 集成
- Service 对象发现
- Pod Endpoint 跟踪
- Namespace 支持

### 健康状态

| 状态 | 说明 |
|------|------|
| Healthy | 健康 |
| Unhealthy | 不健康 |
| Unknown | 未知 |
| Critical | 严重 |
| Warning | 警告 |

---

## 12. 日志与流量记录

**模块**: `src/logger/`

### 日志类型

| 类型 | 说明 |
|------|------|
| File | 文件轮转日志 |
| Database | 持久化存储 |
| Both | 双重记录 |

### 流量日志字段

| 字段 | 说明 |
|------|------|
| 时间戳 | 请求时间 |
| 持续时间 | 请求耗时 |
| 状态码 | HTTP 状态 |
| 请求头 | 完整请求头 |
| 响应头 | 完整响应头 |
| Body | 可选，有大小限制 |
| 客户端 IP | 来源地址 |
| User-Agent | 客户端标识 |

### 文件日志配置

| 配置 | 说明 |
|------|------|
| log_directory | 日志目录 |
| max_file_size | 单文件大小限制 |
| retention_days | 保留天数 |

### 数据库支持

- PostgreSQL
- SQLite
- 连接池配置
- 批量写入
- 自动清理

---

## 13. 监控与指标

**模块**: `src/monitoring/`

### Prometheus 指标

| 类型 | 说明 |
|------|------|
| Counter | 请求计数、错误计数 |
| Histogram | 响应时间、负载大小 |
| Gauge | 活跃连接、内存使用 |
| Summary | 命中率、错误率 |

### 健康检查端点

| 端点 | 说明 |
|------|------|
| /health | 健康状态 |
| /metrics | Prometheus 指标 |

### 容量监控

| 指标 | 说明 |
|------|------|
| 内存使用 | 内存占用跟踪 |
| 连接数 | 活跃连接监控 |
| 请求率 | 请求速率统计 |
| 警告阈值 | 可配置告警 |

### 实时告警

| 功能 | 说明 |
|------|------|
| 阈值告警 | 超限触发 |
| 邮件通知 | Email 告警 |
| Webhook | HTTP 回调 |
| 告警聚合 | 历史告警管理 |

---

## 14. 配置管理

**模块**: `src/config/`

### 配置格式

- TOML 格式
- 环境变量替换
- 热重载支持

### 配置段落

| 段落 | 说明 |
|------|------|
| server | 服务器配置 |
| domains | 域名拦截 |
| targets | 目标服务器 |
| logging | 日志配置 |
| monitoring | 监控配置 |
| tls | TLS 配置 |
| cache | 缓存配置 |
| plugins | 插件配置 |
| security | 安全配置 |
| routing | 路由配置 |
| http_client | HTTP 客户端 |
| service_discovery | 服务发现 |

### 热重载

- 文件变更监控
- 配置验证
- 无需重启生效

---

## 15. 优雅关闭

**模块**: `src/graceful_shutdown.rs`

### 关闭信号

| 信号 | 说明 |
|------|------|
| SIGTERM | 优雅关闭 |
| SIGINT | 立即关闭 |
| 强制关闭 | 超时后强制退出 |

### 关闭流程

1. 停止接受新连接
2. 等待活跃请求完成
3. 清理资源
4. 退出进程

### 配置

- 关闭超时时间
- 清理回调注册
- 任务句柄管理

---

## 16. 性能优化

**模块**: `src/performance.rs`

### CPU 优化

| 功能 | 说明 |
|------|------|
| Worker 线程池 | 可配置线程数 |
| 任务队列 | 队列大小配置 |
| CPU 亲和性 | 核心绑定 |
| 优先级调度 | 任务优先级 |

### 内存优化

| 功能 | 说明 |
|------|------|
| 对象池 | 对象复用 |
| 内存池 | 内存池管理 |
| GC 调优 | 垃圾回收优化 |
| 内存限制 | 使用上限 |

### I/O 优化

| 功能 | 说明 |
|------|------|
| 缓冲区大小 | 可配置缓冲 |
| Vectored I/O | 批量 I/O |
| Zero-Copy | 零拷贝优化 |
| I/O 批处理 | 批量操作 |

### 压测框架

- 内置压测场景
- 并发连接模拟
- 可配置测试时长
- 性能基准测试

---

## 17. 管理接口

**模块**: `src/monitoring/admin.rs`

### API 端点

| 端点 | 说明 |
|------|------|
| 配置查询 | 运行时配置 |
| 指标查询 | 实时指标 |
| 负载均衡状态 | LB 状态 |
| 域名配置 | 拦截域名 |
| 流量日志 | 日志查询 |
| 健康状态 | 服务健康 |

---

## 功能统计

| 类别 | 数量 |
|------|------|
| 核心模块 | 13+ |
| 配置项 | 100+ |
| 支持协议 | 6 |
| 负载均衡算法 | 9 |
| 服务发现后端 | 4 |
| 认证方式 | 3 |
| 日志后端 | 3 |
| 插件类型 | 4 |
| 错误类型 | 15+ |
| 指标类型 | 4 |

---

## Feature Flags

| Flag | 说明 |
|------|------|
| `cmd-plugin` | 外部命令插件 |
| `wasm-plugin` | WASM 插件支持 |
| `jwt-rs256` | JWT RS256 验证 |
| `jwt-rs256-net` | JWKS 网络获取 |
| `consul-discovery` | Consul 服务发现 |
| `etcd-discovery` | etcd 服务发现 |
| `kubernetes-discovery` | K8s 服务发现 |
| `service-discovery-all` | 全部服务发现 |

---

## 更新记录

- 2026-01-06: 初始功能清单整理
