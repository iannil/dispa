# Dispa - 高性能流量拦截转发代理

[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)

Dispa 是一个用 Rust 实现的高性能流量拦截和转发代理服务器，能够拦截指定域名的所有流量，记录流量数据，并转发到多个目标地址。

## ✨ 特性

- 🚀 **高性能异步架构** - 基于 Tokio，支持高并发连接
- 🎯 **智能域名匹配** - 支持精确匹配和通配符（`*.example.com`）
- ⚖️ **多种负载均衡** - 轮询、加权、随机、最少连接
- 🔍 **自动健康检查** - 实时监控后端服务，自动故障转移
- 📊 **完整流量记录** - 文件和数据库双重存储，支持日志轮转
- 📈 **Prometheus 监控** - 内置指标导出，Grafana 可视化
- 🔧 **灵活配置** - TOML 配置文件，支持热重载

## 🚀 快速开始

### 安装

```bash
# 克隆项目
git clone <repository-url>
cd dispa

# 编译
cargo build --release
```

### 配置

编辑 `config/config.toml`：

```toml
[domains]
intercept_domains = ["example.com", "*.test.com"]

[[targets.targets]]
name = "backend1"
url = "http://192.168.1.100:3000"
weight = 3

[[targets.targets]]
name = "backend2"
url = "http://192.168.1.101:3000"
weight = 2

[targets.load_balancing]
type = "weighted"

[targets.health_check]
enabled = true
interval = 30

# 可选：上游 HTTP 客户端连接池（性能优化）
[http_client]
# 每个主机的最大空闲连接数（默认 32）
pool_max_idle_per_host = 32
# 空闲连接回收超时秒数（默认 90）
pool_idle_timeout_secs = 90
# 健康检查等简单 GET 的请求超时（秒，默认 5）
connect_timeout_secs = 5

# 也可通过环境变量覆盖：
# DISPA_HTTP_POOL_MAX_IDLE_PER_HOST, DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS, DISPA_HTTP_CONNECT_TIMEOUT_SECS
```

#### 自定义 Prometheus 直方图桶（buckets）

可为关键直方图指标配置自定义 buckets（单位统一为毫秒，`*_seconds` 指标会自动换算为秒）。

```toml
[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081

# 直方图桶（按指标名精确匹配）
[[monitoring.histogram_buckets]]
metric = "dispa_log_write_duration_ms"           # 日志写入耗时（ms）
buckets_ms = [0.5, 1, 2, 5, 10, 20, 50, 100, 200]

[[monitoring.histogram_buckets]]
metric = "dispa_target_health_check_duration_ms" # 健康检查耗时（ms）
buckets_ms = [5, 10, 25, 50, 100, 250, 500, 1000]

[[monitoring.histogram_buckets]]
metric = "dispa_request_duration_seconds"        # 请求耗时（秒）
# 这里单位仍写毫秒，系统会自动除以 1000 以适配 *_seconds
buckets_ms = [1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000]
```

内置默认 buckets：

- `dispa_log_write_duration_ms`：`[0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]`
- `dispa_target_health_check_duration_ms`：`[1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]`
- `dispa_request_duration_seconds`：`[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]`

#### 插件系统（实验特性）

配置示例：

```toml
[plugins]
enabled = true
# 控制请求阶段插件的执行时机：
# true = 在域名拦截检查之前执行（默认，兼容现有行为）
# false = 在域名拦截检查通过后再执行（避免非拦截域名上的开销）
apply_before_domain_match = true

[[plugins.plugins]]
name = "inject"
type = "headerinjector"
enabled = true
stage = "both"
error_strategy = "continue"   # continue | fail（插件内部错误时，是否短路为 500）
config = { request_headers = { "x-request-id" = "generated" }, response_headers = { "x-power" = "dispa" } }

[[plugins.plugins]]
name = "block"
type = "blocklist"
enabled = true
stage = "request"
error_strategy = "continue"
config = { hosts = ["internal.example.com"], paths = ["/admin", "/private"] }

[[plugins.plugins]]
name = "rewrite-path"
type = "pathrewrite"
enabled = true
stage = "request"
error_strategy = "continue"
config = { from_prefix = "/old", to_prefix = "/new" }

[[plugins.plugins]]
name = "limit-global"
type = "ratelimiter"
enabled = true
stage = "request"
error_strategy = "continue"
config = { rate_per_sec = 100.0, burst = 200.0 }

# 外部命令插件（可选构建特性：`cmd-plugin`；同步执行，适合低 QPS）
# 构建开启示例：`cargo build --features cmd-plugin`
[[plugins.plugins]]
name = "cmd"
type = "command"
enabled = true
stage = "request"
error_strategy = "continue"
config = { 
  exec = "/usr/local/bin/myplugin",            # 必填：可执行文件路径（建议搭配 allowlist）
  args = ["--opt"],                             # 可选：参数
  timeout_ms = 200,                              # 可选：超时（默认 100ms）
  max_concurrency = 8,                           # 可选：最大并发（默认不限）
  exec_allowlist = ["/usr/local/bin/myplugin"], # 可选：允许的可执行文件白名单
  cwd = "/var/run",                             # 可选：工作目录
  env = { RUST_LOG = "info" }                   # 可选：环境变量（注意：目前 spawn 前设置环境更安全）
}

# WASM 插件（PoC，需启用 `wasm-plugin` 特性，并提供符合约定的导出函数）
# 构建开启示例：`cargo build --features wasm-plugin`
[[plugins.plugins]]
name = "wasm-filter"
type = "wasm"
enabled = true
stage = "request"
error_strategy = "continue"
config = { module_path = "./plugins/filter.wasm", timeout_ms = 200, max_concurrency = 16 }
```

外部命令插件协议：
- 输入（stdin）：JSON，如 `{ "stage": "request", "method": "GET", "path": "/api", "headers": {"host": "..."} }`
- 输出（stdout）：JSON，如 `{ "set_headers": {"x-added": "1"} }` 或 `{ "short_circuit": {"status": 403, "body": "blocked"} }`

WASM 插件约定（PoC）：
- 导出函数：`alloc(i32)->i32`, `dealloc(i32,i32)`, `dispa_on_request(i32,i32)->i32`, `dispa_on_response(i32,i32)->i32`, `dispa_get_result_len()->i32`
- 内存交换：传入 JSON 字符串，返回 JSON 字符串；JSON 含义与命令插件一致

插件指标：
- `dispa_plugin_invocations_total{plugin,stage}`、`dispa_plugin_short_circuits_total{plugin,stage}`、`dispa_plugin_duration_ms{plugin,stage}`
- `dispa_plugin_errors_total{plugin,stage,kind}`（panic/exec/io/timeout 等）

每路由（per-route）插件链（与 routing 集成）
- 在路由规则中添加：
  - `plugins_request = ["plugin-a", "plugin-b"]`
  - `plugins_response = ["plugin-c"]`
- 行为与全局插件链一致，按数组顺序执行；响应阶段在全局插件之前执行
- 示例：`config/routing-plugins-example.toml`（包含 `routing` 与 `plugins`）

错误策略说明：
- `continue`：插件内部错误（panic/命令执行失败/超时）被记录并忽略，继续下游处理
- `fail`：遇到错误立即短路返回 500（请求阶段）或将响应改为 500（响应阶段）

### 运行

```bash
# 启动代理服务
./target/release/dispa -c config/config.toml -v

# 测试代理功能
curl -H "Host: example.com" http://localhost:8080/

# 检查健康状态
curl http://localhost:8081/health

# 查看监控指标
curl http://localhost:9090/metrics
```

## 📖 文档

- **[文档总览](docs/README.md)** - 完整文档目录导航
- **[快速开始指南](docs/QUICKSTART.md)** - 5分钟上手教程
- **[完整用户手册](docs/USER_MANUAL.md)** - 详细配置和使用说明
- **[项目状态](docs/PROJECT_STATUS.md)** - 当前功能实现状态和发展规划
- **[配置文档](docs/CONFIG.md)** - 完整配置选项说明（包含数据库配置）
- **[开发指南](docs/DEVELOPMENT.md)** - 架构设计和扩展开发
- **[贡献者指南](docs/AGENTS.md)** - 开发者与代理协作者（LLM/工具）规范
- **[安全配置示例](docs/SECURITY.md)** - 访问控制 / 认证 / 全局限流 / DDoS 保护
- **[管理界面](docs/ADMIN.md)** - Web 管理控制台 / 实时监控 / 配置管理
- **[English Manual](docs/USER_MANUAL_EN.md)** - Full user manual in English
- **[插件开发指南](docs/PLUGINS.md)** - 插件系统 / 每路由插件 / 命令与 WASM 插件

## 🏗️ 架构

```
客户端请求
    ↓
域名匹配检查 (*.example.com)
    ↓
负载均衡器选择健康目标
    ↓
转发请求到后端服务器
    ↓
记录流量日志 (文件/数据库)
    ↓
返回响应给客户端
```

## 🐳 Docker 部署

```bash
# 构建镜像
docker build -t dispa .

# 启动服务
docker-compose up -d

# 查看状态
docker-compose ps
```

## 📊 监控面板

| 服务   | 端口   | 说明              |
|------|------|-----------------|
| 代理服务 | 8080 | HTTP/HTTPS 流量代理 |
| 健康检查 | 8081 | 系统状态 API        |
| 监控指标 | 9090 | Prometheus 指标   |

### 主要指标

- `dispa_requests_total` - 总请求数
- `dispa_request_duration_seconds` - 请求处理时间
- `dispa_target_healthy` - 后端服务健康状态
- `dispa_active_connections` - 活跃连接数

## ⚙️ 配置示例

### 开发环境

```toml
[domains]
intercept_domains = ["*.local.dev"]

[[targets.targets]]
name = "dev-server"
url = "http://localhost:3000"
```

### 生产环境

```toml
[domains]
intercept_domains = ["api.myapp.com"]

[[targets.targets]]
name = "prod-server-1"
url = "http://10.0.1.10:8080"
weight = 3

[[targets.targets]]
name = "prod-server-2"
url = "http://10.0.1.11:8080"
weight = 2

[targets.health_check]
enabled = true
interval = 10
```

## 🛠️ 故障排除

| 问题    | 解决方案                      |
|-------|---------------------------|
| 端口被占用 | 修改配置文件中的 `bind_address`   |
| 后端不可用 | 检查 `targets` 配置和网络连通性     |
| 域名未匹配 | 验证 `intercept_domains` 设置 |
| 数据库错误 | 确保数据目录存在或使用文件日志           |

## 🚀 性能

- **并发连接**: 支持数万并发连接
- **吞吐量**: 在 4 核 8GB 环境下可达 50k+ RPS
- **延迟**: 代理延迟 < 1ms（本地网络）
- **内存**: 运行时内存占用 < 50MB

## 📝 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 📞 支持

- **GitHub Issues**: [报告问题](https://github.com/iannil/dispa/issues)
- **讨论区**: [功能讨论](https://github.com/iannil/dispa/discussions)

## 🌟 致谢

感谢以下开源项目：

- [Tokio](https://tokio.rs/) - 异步运行时
- [Hyper](https://hyper.rs/) - HTTP 库
- [SQLx](https://github.com/launchbadge/sqlx) - 数据库访问
- [Tracing](https://tracing.rs/) - 结构化日志

---

<div align="center">

**[文档总览](./docs/README.md)** • **[快速开始](./docs/QUICKSTART.md)** • **[用户手册](./docs/USER_MANUAL.md)** • **[English Manual](./docs/USER_MANUAL_EN.md)** • **[插件开发](./docs/PLUGINS.md)** • **[开发指南](./docs/DEVELOPMENT.md)**

Made with ❤️ in Rust

</div>
