# Dispa 插件开发指南（实验特性）

本指南介绍 Dispa 的插件系统：如何启用、如何按路由使用、以及如何开发外部命令插件和 WASM 插件。

- 全局插件链：在配置的 `plugins.plugins` 列表中注册的插件，按声明顺序执行。
- 阶段（stage）：`request` / `response` / `both`。请求阶段可短路（直接返回响应），响应阶段可修改响应头/体。
- 执行时机：`apply_before_domain_match` 控制请求阶段插件在域名拦截检查之前（true，默认）或之后（false）执行。
- 错误策略：`error_strategy` = `continue`（记录并忽略）或 `fail`（短路 500）。

参考示例配置：`config/plugins-example.toml`、`config/routing-plugins-example.toml`。

## 启用与基础配置

```toml
[plugins]
enabled = true
apply_before_domain_match = true  # 请求阶段插件在域名检查前执行

[[plugins.plugins]]
name = "inject"
type = "headerinjector"
enabled = true
stage = "both"
error_strategy = "continue"
config = { request_headers = { "x-request-id" = "abc" }, response_headers = { "x-power" = "dispa" } }
```

内置插件类型（`type` 值，均为小写）：
- `headerinjector` / `headeroverride`：设置请求/响应头（常量值）。
- `blocklist`：按 host 精确匹配 或 path 前缀匹配拦截请求，返回 403。
- `pathrewrite`：按前缀改写路径（from_prefix -> to_prefix）。
- `hostrewrite`：重写 Host 头。
- `ratelimiter`：简单令牌桶限流（按 `method:host:path` 维度）。
- `command`：外部命令插件（需 `--features cmd-plugin` 编译）。
- `wasm`：WASM 插件（需 `--features wasm-plugin` 编译）。

各插件 `config` 示例：

```toml
# headerinjector / headeroverride
config = { request_headers = { "k1" = "v1" }, response_headers = { "k2" = "v2" } }

# blocklist
config = { hosts = ["internal.example.com"], paths = ["/admin", "/private"] }

# pathrewrite
config = { from_prefix = "/old", to_prefix = "/new" }

# hostrewrite
config = { host = "api.internal" }

# ratelimiter
config = { rate_per_sec = 100.0, burst = 200.0 }
```

## 每路由插件链（与 routing 集成）

在路由规则中引用已注册的插件名，仅对命中该规则的请求/响应生效，并且在全局响应插件之前执行：

```toml
[routing]
enable_logging = true
default_target = "backend"

[[routing.rules]]
name = "api-rule"
priority = 100
enabled = true
target = "backend"

[routing.rules.conditions]
[routing.rules.conditions.path]
prefix = "/api"

# 按名称引用
routing.rules.plugins_request = ["route-tag"]
routing.rules.plugins_response = ["route-tag"]
# 可选：排序与去重
# routing.rules.plugins_order = "as_listed|name_asc|name_desc"
# routing.rules.plugins_dedup = true
```

完整例子见 `config/routing-plugins-example.toml`。

## 外部命令插件（Command）

- 需启用构建特性：`cmd-plugin`
- 适用场景：低 QPS 的同步外部检查/变更（例如黑白名单、轻量鉴权）。
- 构建/运行：

```bash
cargo run --features cmd-plugin -- -c config/plugins-example.toml -v
```

协议：
- 输入（stdin）：JSON，例如 `{ "stage": "request", "method": "GET", "path": "/api", "headers": {"host":"..."} }`
- 输出（stdout）：JSON，支持两种指令：
  - `{"set_headers": {"Header":"Value"}}` 设置（或覆盖）头
  - `{"short_circuit": {"status": 403, "body": "blocked"}}` 短路返回

安全与性能建议：
- 配置 `exec_allowlist = ["/path/to/your-plugin"]`，仅允许白名单可执行文件。
- 设置 `timeout_ms`，并通过 `max_concurrency` 限制并发。
- 为插件程序预先置好权限与工作目录；避免在高频路径里进行复杂 I/O。

示例（Bash）：

- 追加请求头：`examples/plugins/cmd_headers.sh`
- 短路返回：`examples/plugins/cmd_block.sh`

配置示例：

```toml
[[plugins.plugins]]
name = "cmd-headers"
type = "command"
enabled = true
stage = "request"
error_strategy = "continue"
config = {
  exec = "./examples/plugins/cmd_headers.sh",
  timeout_ms = 200,
  max_concurrency = 8,
  exec_allowlist = ["./examples/plugins/cmd_headers.sh"],
}
```

## WASM 插件（PoC）

- 需启用构建特性：`wasm-plugin`
- 运行时约定：导出函数
  - `alloc(i32)->i32`, `dealloc(i32,i32)`
  - `dispa_on_request(i32,i32)->i32`, `dispa_on_response(i32,i32)->i32`
  - `dispa_get_result_len()->i32`
- 主机与插件通过线性内存交换 JSON 字符串；返回 JSON 语义与命令插件一致（支持 `set_headers` 与 `short_circuit`）。

构建/运行：

```bash
# WAT -> WASM
wat2wasm examples/wasm/filter.wat -o examples/wasm/filter.wasm

# Rust -> WASI WASM（示例工程）
cargo build -p dispa-wasm-plugin --target wasm32-wasi --release

# 运行 Dispa（启用 wasm 插件）
cargo run --features wasm-plugin -- -c config/plugins-example.toml -v
```

配置示例：

```toml
[[plugins.plugins]]
name = "wasm-filter"
type = "wasm"
enabled = true
stage = "request"
error_strategy = "continue"
config = { module_path = "./examples/wasm/filter.wasm", timeout_ms = 200, max_concurrency = 16 }
```

注意事项：
- WASM 插件当前为 PoC，适合原型与隔离执行；生产化前需完善沙箱和接口稳定性。
- 复杂场景推荐将业务逻辑迁移至路由/安全模块或服务内实现。

## 插件指标

- `dispa_plugin_invocations_total{plugin,stage}`
- `dispa_plugin_short_circuits_total{plugin,stage}`
- `dispa_plugin_duration_ms{plugin,stage}`
- `dispa_plugin_errors_total{plugin,stage,kind}`（panic/exec/io/timeout 等）
- 命令插件特有：
  - `dispa_plugin_cmd_exec_duration_ms{plugin}`
  - `dispa_plugin_cmd_errors_total{plugin,kind}`（status/io/exec）
  - `dispa_plugin_cmd_timeouts_total{plugin}`

## 调试与排查

- 启用调试日志：`RUST_LOG=debug` 或启动参数 `-v`。
- 在 `/metrics` 观察插件指标；配合自定义直方图 buckets 观测延时分布。
- 命令插件：重点核查可执行文件路径、权限、工作目录、超时与并发配置。

---

更多：
- 全量用户手册：`docs/USER_MANUAL.md`
- 插件示例：`config/plugins-example.toml`、`config/routing-plugins-example.toml`、`examples/plugins/`、`examples/wasm/`
