<p align="center">
  <h1 align="center">Dispa</h1>
  <p align="center">
    <strong>高性能 HTTP/HTTPS 流量拦截与转发代理</strong>
  </p>
  <p align="center">
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.90+-orange.svg" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
    <a href="#"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status"></a>
    <a href="#"><img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version"></a>
  </p>
  <p align="center">
    <a href="docs/README.md">文档</a> •
    <a href="docs/QUICKSTART.md">快速开始</a> •
    <a href="docs/USER_MANUAL.md">用户手册</a> •
    <a href="docs/USER_MANUAL_EN.md">English</a> •
    <a href="docs/FEATURE_LIST.md">功能清单</a>
  </p>
</p>

---

Dispa 是一个用 Rust 编写的高性能流量拦截和转发代理服务器。它能够拦截指定域名的流量，支持多种负载均衡算法、服务发现、安全认证、插件扩展等企业级特性。

## 特性亮点

| 特性 | 说明 |
|------|------|
| **高性能异步架构** | 基于 Tokio + Hyper，支持数万并发连接 |
| **多协议支持** | HTTP/1.1、HTTP/2、WebSocket、gRPC、TCP、UDP |
| **智能负载均衡** | 9种算法：轮询、加权、最少连接、一致性哈希、地理位置等 |
| **服务发现** | Consul、etcd、Kubernetes、DNS 多后端支持 |
| **安全防护** | JWT/Basic 认证、速率限制、DDoS 防护、IP 黑白名单 |
| **插件系统** | 内置插件 + 外部命令 + WASM 扩展 |
| **可观测性** | Prometheus 指标、流量日志、健康检查、实时告警 |
| **热重载** | 配置变更无需重启 |

## 快速开始

### 安装

```bash
# 克隆项目
git clone https://github.com/iannil/dispa.git
cd dispa

# 编译 (基础功能)
cargo build --release

# 编译 (全部功能)
cargo build --release --features "consul-discovery,kubernetes-discovery,jwt-rs256,wasm-plugin"
```

### 最小配置

创建 `config.toml`:

```toml
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = ["api.example.com", "*.test.com"]

[[targets.servers]]
name = "backend1"
url = "http://127.0.0.1:3000"
weight = 1
```

### 运行

```bash
# 启动代理
./target/release/dispa -c config.toml

# 测试
curl -H "Host: api.example.com" http://localhost:8080/

# 健康检查
curl http://localhost:8081/health

# Prometheus 指标
curl http://localhost:9090/metrics
```

## 核心功能

### 负载均衡

支持 9 种负载均衡算法：

| 算法 | 说明 |
|------|------|
| `round_robin` | 轮询分发 |
| `weighted` | 加权轮询 |
| `least_connections` | 最少连接优先 |
| `random` | 随机选择 |
| `consistent_hash` | 一致性哈希 (会话保持) |
| `geographic` | 地理位置感知 |
| `session_sticky` | 会话粘滞 |
| `adaptive` | 自适应权重 |
| `priority` | 优先级路由 |

```toml
[[targets.servers]]
name = "backend1"
url = "http://10.0.1.10:8080"
weight = 3

[[targets.servers]]
name = "backend2"
url = "http://10.0.1.11:8080"
weight = 2

[targets.load_balancing]
type = "weighted"

[targets.health_check]
enabled = true
interval = 30
timeout = 5
```

### 服务发现

支持多种服务发现后端 (需启用对应 feature):

```toml
# Consul
[service_discovery]
backend = "consul"
consul_addr = "http://consul:8500"
service_name = "my-service"

# Kubernetes
[service_discovery]
backend = "kubernetes"
namespace = "default"
service_name = "my-service"

# etcd
[service_discovery]
backend = "etcd"
endpoints = ["http://etcd1:2379", "http://etcd2:2379"]
service_prefix = "/services/"
```

### 安全配置

```toml
[security]
enabled = true

# 认证方式: basic, jwt, jwt-rs256
auth_mode = "jwt"
jwt_secret = "your-secret-key"

# 速率限制
rate_limit_enabled = true
rate_limit_requests = 100
rate_limit_window_secs = 60

# DDoS 防护
ddos_protection = true
max_header_size = 8192
max_body_size = 10485760

# IP 访问控制
ip_whitelist = ["10.0.0.0/8", "192.168.0.0/16"]
ip_blacklist = ["1.2.3.4"]
```

### 插件系统

内置插件：

```toml
[plugins]
enabled = true

# 请求头注入
[[plugins.plugins]]
name = "header-inject"
type = "headerinjector"
stage = "both"
config = {
  request_headers = { "X-Request-Id" = "generated" },
  response_headers = { "X-Powered-By" = "Dispa" }
}

# 路径重写
[[plugins.plugins]]
name = "path-rewrite"
type = "pathrewrite"
stage = "request"
config = { from_prefix = "/api/v1", to_prefix = "/v1" }

# 速率限制
[[plugins.plugins]]
name = "rate-limiter"
type = "ratelimiter"
stage = "request"
config = { rate_per_sec = 100.0, burst = 200.0 }

# 黑名单
[[plugins.plugins]]
name = "blocklist"
type = "blocklist"
stage = "request"
config = { hosts = ["blocked.com"], paths = ["/admin"] }
```

外部插件 (需启用 feature):

```toml
# 命令插件 (cargo build --features cmd-plugin)
[[plugins.plugins]]
name = "custom-cmd"
type = "command"
config = { exec = "/usr/local/bin/my-filter", timeout_ms = 100 }

# WASM 插件 (cargo build --features wasm-plugin)
[[plugins.plugins]]
name = "wasm-filter"
type = "wasm"
config = { module_path = "./plugins/filter.wasm" }
```

### 缓存

```toml
[cache]
enabled = true
max_size = 104857600  # 100MB
default_ttl = 300

[[cache.policies]]
path_prefix = "/static"
ttl = 3600
cacheable_status = [200, 301, 302]
```

### 路由规则

```toml
[[routing.rules]]
priority = 1
conditions = [
  { type = "path", pattern = "/api/*" },
  { type = "method", methods = ["GET", "POST"] }
]
actions = [
  { type = "rewrite_path", from = "/api", to = "/v2/api" },
  { type = "add_header", name = "X-Routed", value = "true" }
]
target = "api-backend"
```

### TLS/HTTPS

```toml
[tls]
enabled = true
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
https_port = 8443
```

## 架构

```
                                    ┌─────────────────────────────────────────┐
                                    │              Dispa Proxy                │
┌──────────┐                        │  ┌─────────┐  ┌─────────┐  ┌─────────┐  │                        ┌──────────┐
│  Client  │──▶ TLS Termination ──▶ │  │ Plugins │─▶│ Router  │─▶│  Cache  │  │──▶ Load Balancer ──▶  │ Backend1 │
└──────────┘                        │  └─────────┘  └─────────┘  └─────────┘  │                        └──────────┘
                                    │       │            │            │       │                        ┌──────────┐
                                    │       ▼            ▼            ▼       │                    ──▶ │ Backend2 │
                                    │  ┌─────────────────────────────────┐    │                        └──────────┘
                                    │  │     Security (Auth/RateLimit)   │    │                        ┌──────────┐
                                    │  └─────────────────────────────────┘    │                    ──▶ │ Backend3 │
                                    │       │                                 │                        └──────────┘
                                    │       ▼                                 │
                                    │  ┌─────────────────────────────────┐    │
                                    │  │  Logging / Metrics / Monitoring │    │
                                    │  └─────────────────────────────────┘    │
                                    └─────────────────────────────────────────┘
```

**请求处理流程:**

1. TLS 终止 (可选)
2. 插件预处理 (可选)
3. 域名匹配检查
4. 路由规则匹配
5. 安全检查 (认证、限流、DDoS)
6. 缓存查询
7. 负载均衡选择目标
8. 请求转发
9. 响应缓存 (可选)
10. 插件后处理
11. 流量日志记录
12. 返回响应

## Feature Flags

| Feature | 说明 | 编译命令 |
|---------|------|----------|
| `cmd-plugin` | 外部命令插件 | `--features cmd-plugin` |
| `wasm-plugin` | WASM 插件支持 | `--features wasm-plugin` |
| `jwt-rs256` | JWT RS256 验证 | `--features jwt-rs256` |
| `consul-discovery` | Consul 服务发现 | `--features consul-discovery` |
| `etcd-discovery` | etcd 服务发现 | `--features etcd-discovery` |
| `kubernetes-discovery` | K8s 服务发现 | `--features kubernetes-discovery` |
| `service-discovery-all` | 全部服务发现 | `--features service-discovery-all` |

**启用全部功能:**

```bash
cargo build --release --features "service-discovery-all,jwt-rs256,wasm-plugin,cmd-plugin"
```

## Docker 部署

```bash
# 构建镜像
docker build -t dispa .

# 运行
docker run -d \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  dispa

# 或使用 docker-compose
docker-compose up -d
```

## 监控

### 端口说明

| 端口 | 服务 | 说明 |
|------|------|------|
| 8080 | 代理服务 | HTTP/HTTPS 流量入口 |
| 8443 | HTTPS 服务 | TLS 加密入口 (可选) |
| 8081 | 健康检查 | /health, /ready |
| 9090 | Prometheus | /metrics |

### 核心指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `dispa_requests_total` | Counter | 总请求数 |
| `dispa_request_duration_seconds` | Histogram | 请求延迟 |
| `dispa_active_connections` | Gauge | 活跃连接数 |
| `dispa_target_healthy` | Gauge | 后端健康状态 |
| `dispa_cache_hits_total` | Counter | 缓存命中数 |
| `dispa_plugin_duration_ms` | Histogram | 插件执行耗时 |

### Grafana Dashboard

```bash
# 导入预配置面板
curl -X POST http://grafana:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @grafana/dispa-dashboard.json
```

## 性能

在 4 核 8GB 环境下的基准测试：

| 指标 | 数值 |
|------|------|
| 并发连接 | 10,000+ |
| 吞吐量 | 50,000+ RPS |
| 代理延迟 | < 1ms (本地网络) |
| 内存占用 | < 50MB (基础运行) |

## 文档

| 文档 | 说明 |
|------|------|
| [文档总览](docs/README.md) | 完整文档导航 |
| [快速开始](docs/QUICKSTART.md) | 5分钟上手教程 |
| [用户手册](docs/USER_MANUAL.md) | 详细使用指南 |
| [English Manual](docs/USER_MANUAL_EN.md) | Full user manual |
| [功能清单](docs/FEATURE_LIST.md) | 完整功能列表 |
| [配置文档](docs/CONFIG.md) | 全部配置选项 |
| [安全配置](docs/SECURITY.md) | 安全相关配置 |
| [插件开发](docs/PLUGINS.md) | 插件开发指南 |
| [开发指南](docs/DEVELOPMENT.md) | 架构与开发 |
| [API 文档](docs/API.md) | REST API 接口 |

## 贡献

欢迎贡献代码！请阅读 [贡献指南](docs/AGENTS.md) 了解详情。

```bash
# 开发环境设置
git clone https://github.com/iannil/dispa.git
cd dispa
cargo build
cargo test

# 提交 PR
git checkout -b feature/your-feature
# ... 开发 ...
cargo fmt && cargo clippy
git commit -m "feat: your feature"
git push origin feature/your-feature
```

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 致谢

感谢以下开源项目：

- [Tokio](https://tokio.rs/) - 异步运行时
- [Hyper](https://hyper.rs/) - HTTP 实现
- [Rustls](https://github.com/rustls/rustls) - TLS 实现
- [SQLx](https://github.com/launchbadge/sqlx) - 数据库
- [Wasmtime](https://wasmtime.dev/) - WASM 运行时

---

<p align="center">
  <sub>Made with ❤️ in Rust</sub>
</p>
