# Dispa 流量拦截转发代理 - 完整使用手册

## 概述

Dispa 是一个用 Rust 实现的高性能流量拦截和转发代理服务器。它能够拦截指定域名的所有流量，记录流量数据，并将请求转发到多个后端服务器，支持负载均衡和健康检查。

### 核心特性

- 🚀 **高性能异步架构**：基于 Tokio 运行时，支持高并发连接
- 🎯 **智能域名匹配**：支持精确匹配和通配符匹配（如 `*.example.com`）
- ⚖️ **多种负载均衡算法**：轮询、加权轮询、随机选择、最少连接
- 🔍 **自动健康检查**：定期检测后端服务状态，自动故障转移
- 📊 **完整流量记录**：支持文件和数据库存储，可配置日志轮转
- 📈 **Prometheus 监控**：内置指标导出，支持 Grafana 可视化
- 🔧 **灵活配置管理**：TOML 配置文件，支持热重载

## 快速开始

### 系统要求

- **操作系统**：Linux、macOS、Windows
- **内存**：最少 256MB RAM
- **存储**：至少 100MB 可用空间
- **网络**：需要的端口默认为 8080（代理）、8081（健康检查）、9090（监控）

### 安装和编译

#### 方法 1：源码编译

```bash
# 1. 克隆项目
git clone <repository-url>
cd dispa

# 2. 安装 Rust（如果未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 3. 编译项目
cargo build --release

# 4. 验证安装
./target/release/dispa --help
```

#### 方法 2：Docker 部署

```bash
# 构建 Docker 镜像
docker build -t dispa .

# 运行容器
docker run -d \
  --name dispa \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/logs:/app/logs \
  dispa
```

## 配置指南

### 配置文件结构

配置文件使用 TOML 格式，包含以下主要部分：

```toml
# config/config.toml

[server]              # 服务器基础配置
[domains]            # 域名拦截规则
[[targets.targets]]  # 后端目标服务器
[targets.load_balancing]  # 负载均衡配置
[targets.health_check]    # 健康检查配置
[logging]            # 日志记录配置
[monitoring]         # 监控配置
```

### 详细配置说明

#### 1. 服务器配置

```toml
[server]
bind_address = "0.0.0.0:8080"  # 代理服务监听地址
workers = 4                     # 工作线程数（建议设为 CPU 核心数）
keep_alive_timeout = 60         # HTTP 连接保持时间（秒）
request_timeout = 30            # 单个请求超时时间（秒）
```

#### 2. 域名拦截配置

```toml
[domains]
# 需要拦截的域名列表（支持通配符）
intercept_domains = [
    "example.com",      # 精确匹配
    "api.example.com",  # 子域名匹配
    "*.test.com"        # 通配符匹配
]

# 排除的域名列表（优先级高于拦截列表）
exclude_domains = ["admin.example.com", "internal.test.com"]

# 是否启用通配符支持
wildcard_support = true
```

#### 3. 后端目标服务器配置

```toml
# 定义多个后端服务器
[[targets.targets]]
name = "backend1"                    # 服务器名称
url = "http://192.168.1.100:3000"   # 后端服务器地址
weight = 3                          # 权重（用于加权负载均衡）
timeout = 30                        # 请求超时时间

[[targets.targets]]
name = "backend2"
url = "http://192.168.1.101:3000"
weight = 2
timeout = 30

[[targets.targets]]
name = "backend3"
url = "http://192.168.1.102:3000"
weight = 1
timeout = 30
```

#### 4. 负载均衡配置

```toml
[targets.load_balancing]
type = "weighted"              # 负载均衡算法
# 可选值：
# - "roundrobin"    # 轮询
# - "weighted"      # 加权轮询
# - "random"        # 随机选择
# - "leastconnections"  # 最少连接（实验性）

sticky_sessions = false       # 会话粘性（暂未实现）
```

#### 5. 健康检查配置

```toml
[targets.health_check]
enabled = true              # 是否启用健康检查
interval = 30              # 检查间隔（秒）
timeout = 10               # 单次检查超时时间（秒）
healthy_threshold = 2      # 连续成功次数阈值（标记为健康）
unhealthy_threshold = 3    # 连续失败次数阈值（标记为不健康）
```

#### 6. 日志记录配置

```toml
[logging]
enabled = true           # 是否启用日志记录
type = "both"           # 日志类型：file、database、both
retention_days = 30     # 日志保留天数

# 数据库存储配置
[logging.database]
url = "sqlite://./data/traffic.db"  # 数据库连接字符串
max_connections = 10                # 最大连接数
connection_timeout = 30             # 连接超时时间

# 文件存储配置
[logging.file]
directory = "./logs"               # 日志文件目录
max_file_size = 104857600         # 单个文件最大大小（100MB）
rotation = true                   # 是否启用日志轮转
```

#### 7. 监控配置

```toml
[monitoring]
enabled = true              # 是否启用监控
metrics_port = 9090        # Prometheus 指标端口
health_check_port = 8081   # 健康检查 API 端口
```

## 运行和管理

### 基本运行命令

```bash
# 使用默认配置启动
./target/release/dispa

# 指定配置文件
./target/release/dispa -c /path/to/config.toml

# 指定监听地址
./target/release/dispa -b 0.0.0.0:9000

# 启用详细日志
./target/release/dispa -v

# 查看帮助信息
./target/release/dispa --help
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config` | 配置文件路径 | `config/config.toml` |
| `-b, --bind` | 代理服务监听地址 | `0.0.0.0:8080` |
| `-v, --verbose` | 启用详细日志输出 | - |
| `-h, --help` | 显示帮助信息 | - |

### 服务管理

#### 作为系统服务运行

1. **创建服务文件** `/etc/systemd/system/dispa.service`：

```ini
[Unit]
Description=Dispa Traffic Proxy
After=network.target

[Service]
Type=simple
User=dispa
Group=dispa
WorkingDirectory=/opt/dispa
ExecStart=/opt/dispa/dispa -c /opt/dispa/config/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/dispa/logs /opt/dispa/data

[Install]
WantedBy=multi-user.target
```

2. **启用和启动服务**：

```bash
# 创建用户和目录
sudo useradd -r -s /bin/false dispa
sudo mkdir -p /opt/dispa/{config,logs,data}
sudo chown -R dispa:dispa /opt/dispa

# 复制文件
sudo cp target/release/dispa /opt/dispa/
sudo cp config/config.toml /opt/dispa/config/

# 启用服务
sudo systemctl daemon-reload
sudo systemctl enable dispa
sudo systemctl start dispa

# 检查状态
sudo systemctl status dispa
```

#### Docker Compose 部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  dispa:
    build: .
    container_name: dispa
    restart: unless-stopped
    ports:
      - "8080:8080"    # 代理端口
      - "8081:8081"    # 健康检查端口
      - "9090:9090"    # 监控端口
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - RUST_LOG=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 监控和维护

### API 端点

#### 健康检查 API（端口 8081）

```bash
# 基础健康检查
curl http://localhost:8081/health

# 响应示例
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "0.1.0",
  "uptime": 3600,
  "components": {
    "proxy_server": "healthy",
    "load_balancer": "healthy",
    "traffic_logger": "healthy",
    "metrics_collector": "healthy"
  }
}
```

#### Prometheus 指标（端口 9090）

```bash
# 获取所有指标
curl http://localhost:9090/metrics

# 主要指标说明
# dispa_requests_total - 总请求数
# dispa_requests_errors_total - 错误请求数
# dispa_request_duration_seconds - 请求处理时间
# dispa_target_healthy - 目标服务器健康状态
# dispa_target_requests_total - 转发到各目标的请求数
# dispa_active_connections - 活跃连接数
```

### 日志分析

#### 应用程序日志

Dispa 使用结构化日志记录，主要日志级别：

- **INFO**：正常操作信息
- **WARN**：警告信息（如后端服务不可用）
- **ERROR**：错误信息
- **DEBUG**：详细调试信息（使用 `-v` 参数启用）

#### 流量日志

当启用文件日志时，流量记录保存在配置的日志目录中：

```bash
# 查看今天的流量日志
tail -f logs/traffic-$(date +%Y-%m-%d).log

# 日志格式（JSON）
{
  "id": "uuid",
  "timestamp": "2024-01-01T12:00:00Z",
  "client_ip": "192.168.1.10",
  "host": "example.com",
  "target": "backend1",
  "status_code": 200,
  "duration_ms": 45
}
```

### 性能调优

#### 系统级优化

```bash
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 调整网络参数
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

#### 应用配置优化

```toml
[server]
workers = 8                # 根据 CPU 核心数调整
keep_alive_timeout = 120   # 根据业务需求调整
request_timeout = 60       # 根据后端响应时间调整

[targets.health_check]
interval = 15             # 缩短检查间隔以快速发现故障
timeout = 5               # 降低超时时间以快速切换
```

## 故障排除

### 常见问题

#### 1. 端口被占用

**症状**：启动时报错 "Address already in use"

**解决方案**：

```bash
# 检查端口使用情况
sudo netstat -tlnp | grep :8080

# 修改配置文件中的端口
# 或者停止占用端口的进程
sudo kill -9 <PID>
```

#### 2. 后端服务不可用

**症状**：所有请求返回 "Service unavailable"

**解决方案**：

```bash
# 检查后端服务状态
curl -I http://backend-server:3000/

# 查看健康检查日志
journalctl -u dispa -f | grep "health check"

# 验证网络连通性
ping backend-server
telnet backend-server 3000
```

#### 3. 域名匹配问题

**症状**：应该被拦截的请求返回 "Domain not found"

**解决方案**：

```bash
# 检查配置文件中的域名设置
grep -A 5 "intercept_domains" config/config.toml

# 验证请求的 Host 头
curl -H "Host: example.com" http://localhost:8080/ -v

# 检查通配符配置
# 确保 wildcard_support = true
```

#### 4. 数据库连接失败

**症状**：启动时报错 "unable to open database file"

**解决方案**：

```bash
# 确保数据目录存在
mkdir -p data

# 检查权限
chmod 755 data/
chown dispa:dispa data/

# 简化配置为文件日志
[logging]
type = "file"  # 而不是 "database" 或 "both"
```

#### 5. 内存使用过高

**症状**：系统内存不足，Dispa 进程被 OOM killer 终止

**解决方案**：

```toml
# 调整连接池大小
[logging.database]
max_connections = 5  # 降低数据库连接数

# 启用日志轮转
[logging.file]
max_file_size = 50000000  # 降低单文件大小到 50MB
rotation = true

# 减少健康检查频率
[targets.health_check]
interval = 60  # 增加到 60 秒
```

### 调试技巧

#### 启用详细日志

```bash
# 启动时添加 -v 参数
./target/release/dispa -c config/config.toml -v

# 或设置环境变量
RUST_LOG=debug ./target/release/dispa
```

#### 网络抓包分析

```bash
# 抓取代理端口的流量
sudo tcpdump -i any -w dispa.pcap port 8080

# 使用 wireshark 分析
wireshark dispa.pcap
```

#### 性能分析

```bash
# 使用 strace 跟踪系统调用
strace -p <dispa-pid> -e network

# 使用 htop 监控资源使用
htop -p <dispa-pid>
```

## 最佳实践

### 安全配置

1. **网络安全**：
   - 在防火墙中只开放必要端口
   - 使用 TLS 终止负载均衡器
   - 配置适当的超时时间防止慢速攻击

2. **访问控制**：
   - 限制管理端口（8081、9090）的访问
   - 使用 nginx 等反向代理添加认证
   - 定期轮换监控凭据

3. **日志安全**：
   - 避免记录敏感信息（如 Authorization 头）
   - 定期清理旧日志文件
   - 确保日志文件权限正确

### 高可用部署

1. **多实例部署**：

```bash
# 使用不同端口运行多个实例
./dispa -c config/config1.toml -b 0.0.0.0:8080 &
./dispa -c config/config2.toml -b 0.0.0.0:8081 &

# 前置负载均衡器（如 nginx）
upstream dispa_backend {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
}
```

2. **健康检查集成**：

```bash
# 配置外部健康检查
while true; do
    if ! curl -f http://localhost:8081/health; then
        systemctl restart dispa
    fi
    sleep 30
done
```

### 监控告警

1. **Prometheus 告警规则**：

```yaml
groups:
- name: dispa
  rules:
  - alert: DispaDown
    expr: up{job="dispa"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Dispa instance is down"

  - alert: DispaHighErrorRate
    expr: rate(dispa_requests_errors_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate in Dispa"
```

2. **Grafana 仪表板**：
   - 请求率和错误率趋势
   - 响应时间分布
   - 后端服务健康状态
   - 系统资源使用情况

## 附录

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `RUST_LOG` | 日志级别 | `info` |
| `DISPA_CONFIG` | 配置文件路径 | `config/config.toml` |
| `DISPA_BIND` | 监听地址 | `0.0.0.0:8080` |

### 退出码

| 码值 | 说明 |
|------|------|
| 0 | 正常退出 |
| 1 | 配置文件错误 |
| 2 | 网络绑定失败 |
| 3 | 数据库连接失败 |

### 信号处理

| 信号 | 行为 |
|------|------|
| SIGTERM | 优雅关闭 |
| SIGINT (Ctrl+C) | 优雅关闭 |
| SIGUSR1 | 重新加载配置（计划中） |

---

## 支持和贡献

- **项目主页**：[GitHub Repository]
- **问题报告**：[Issues]
- **功能请求**：[Feature Requests]
- **文档改进**：[Documentation]

如有问题或建议，欢迎提交 Issue 或 Pull Request！

---

## 配置补充：HTTP 客户端连接池与自定义直方图

### 上游 HTTP 客户端连接池（性能优化）

用于控制转发到后端时的连接复用与超时，减少建连开销、提高吞吐。

```toml
[http_client]
# 每个主机的最大空闲连接数（默认 32）
pool_max_idle_per_host = 32
# 空闲连接回收超时秒数（默认 90）
pool_idle_timeout_secs = 90
# 健康检查等简单 GET 的请求超时（秒，默认 5）
connect_timeout_secs = 5

# 环境变量覆盖：
# DISPA_HTTP_POOL_MAX_IDLE_PER_HOST, DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS, DISPA_HTTP_CONNECT_TIMEOUT_SECS
```

### Prometheus 直方图桶（可选）

对关键耗时指标自定义直方图 buckets，便于更精细的 Pxx 观测。注意 buckets 配置统一使用毫秒，若指标名以 `_seconds` 结尾会自动换算为秒。

```toml
[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081

[[monitoring.histogram_buckets]]
metric = "dispa_log_write_duration_ms"
buckets_ms = [0.5, 1, 2, 5, 10, 20, 50, 100, 200]

[[monitoring.histogram_buckets]]
metric = "dispa_target_health_check_duration_ms"
buckets_ms = [5, 10, 25, 50, 100, 250, 500, 1000]

[[monitoring.histogram_buckets]]
metric = "dispa_request_duration_seconds"   # 注意：仍以毫秒填写，系统会自动 /1000
buckets_ms = [1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000]
```

内置默认 buckets：

- dispa_log_write_duration_ms: [0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
- dispa_target_health_check_duration_ms: [1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
- dispa_request_duration_seconds: [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

---

## 插件系统与开发（实验特性）

完整、持续更新的插件文档已拆分至：`docs/PLUGINS.md`。以下为概要；如需开发与高级用法，请参考该文件。

本节介绍如何启用与配置插件链、每路由（per-route）插件、以及如何开发外部命令插件和 WASM 插件。

### 1. 启用与基础概念

- 全局插件链：在配置的 `plugins.plugins` 列表中注册的插件，按声明顺序执行。
- 阶段（stage）：`request`、`response`、`both`。请求阶段可短路（直接返回响应），响应阶段可修改响应头/体。
- 执行时机：`apply_before_domain_match` 控制请求阶段插件在域名拦截检查之前（true，默认）或之后（false）执行。
- 错误策略：`error_strategy` = `continue`（记录并忽略）或 `fail`（短路 500）。

最小示例（也可参考 `config/plugins-example.toml`）：

```toml
[plugins]
enabled = true
apply_before_domain_match = true

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
- `command`：外部命令插件（需 `--features cmd-plugin`）。
- `wasm`：WASM 插件（需 `--features wasm-plugin`）。

各插件 `config` 字段示例：

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

### 2. 每路由插件链（与 routing 集成）

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

### 3. 外部命令插件开发（Command，需 `cmd-plugin` 特性）

构建运行：

```bash
cargo run --features cmd-plugin -- -c config/plugins-example.toml -v
```

协议：
- 输入（stdin）：JSON，例如 `{ "stage": "request", "method": "GET", "path": "/api", "headers": {"host":"..."} }`
- 输出（stdout）：JSON，支持两种指令：
  - `{"set_headers": {"Header":"Value"}}` 设置（或覆盖）头
  - `{"short_circuit": {"status": 403, "body": "blocked"}}` 短路返回

安全建议：
- 强烈建议配置 `exec_allowlist = ["/path/to/your-plugin"]` 仅允许白名单可执行文件。
- 使用 `max_concurrency` 限制并发执行，`timeout_ms` 设置超时。

示例（Bash）：`examples/plugins/cmd_headers.sh`

```bash
#!/usr/bin/env bash
read -r _INPUT
echo '{ "set_headers": { "x-cmd-plugin": "1" } }'
```

示例（Bash，短路）：`examples/plugins/cmd_block.sh`

```bash
#!/usr/bin/env bash
read -r _INPUT
echo '{ "short_circuit": { "status": 418, "body": "blocked by cmd plugin" } }'
```

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

可观测性：
- `dispa_plugin_cmd_exec_duration_ms{plugin}`
- `dispa_plugin_cmd_errors_total{plugin,kind}`（status/io/exec）
- `dispa_plugin_cmd_timeouts_total{plugin}`

### 4. WASM 插件开发（PoC，需 `wasm-plugin` 特性）

运行时约定：导出函数 `alloc(i32)->i32`, `dealloc(i32,i32)`, `dispa_on_request(i32,i32)->i32`, `dispa_on_response(i32,i32)->i32`, `dispa_get_result_len()->i32`；内存中交换 JSON 字符串，返回 JSON 的语义与命令插件一致（支持 `set_headers` 与 `short_circuit`）。

构建运行：

```bash
cargo run --features wasm-plugin -- -c config/plugins-example.toml -v
```

示例 1（WAT -> WASM）：`examples/wasm/filter.wat`

```bash
wat2wasm examples/wasm/filter.wat -o examples/wasm/filter.wasm
```

示例 2（Rust -> WASI WASM）：`examples/wasm/rust-plugin`

```bash
cargo build -p dispa-wasm-plugin --target wasm32-wasi --release
# 生成：target/wasm32-wasi/release/dispa_wasm_plugin.wasm
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

### 5. 插件指标与错误策略

- `dispa_plugin_invocations_total{plugin,stage}`
- `dispa_plugin_short_circuits_total{plugin,stage}`
- `dispa_plugin_duration_ms{plugin,stage}`
- `dispa_plugin_errors_total{plugin,stage,kind}`（panic/exec/io/timeout 等）

错误策略说明：
- `continue`：插件内部错误被记录并忽略，继续下游处理。
- `fail`：请求阶段遇到错误立即短路 500；响应阶段则将响应改为 500。

### 6. 调试与排查

- 启用调试日志：`RUST_LOG=debug` 或启动参数 `-v`。
- 在 `/metrics` 中观察上述插件指标；结合直方图 buckets 配置观测延时分布。
- 若使用命令插件，优先从系统日志中确认可执行文件权限、工作目录、超时等问题。

注意：当前 `headerinjector/headeroverride` 仅支持常量值注入，不支持内置“动态值”生成。

---

## 附录补充：更多环境变量覆盖

| 变量名 | 说明 |
|--------|------|
| `DISPA_BIND_ADDRESS` | 覆盖配置中的监听地址 |
| `DISPA_WORKERS` | 覆盖工作线程数 |
| `DISPA_REQUEST_TIMEOUT` | 覆盖请求超时秒数 |
| `DISPA_METRICS_PORT` | 覆盖监控端口 |
| `DISPA_HEALTH_CHECK_PORT` | 覆盖健康检查端口 |
| `DISPA_LOGGING_ENABLED` | 覆盖日志开关 |
| `DISPA_LOGGING_TYPE` | 覆盖日志类型 `database|file|both` |
| `DISPA_LOG_DIRECTORY` | 覆盖文件日志目录 |
| `DISPA_HTTP_POOL_MAX_IDLE_PER_HOST` | 上游连接池最大空闲连接数（默认 32） |
| `DISPA_HTTP_POOL_IDLE_TIMEOUT_SECS` | 上游连接池空闲回收秒数（默认 90） |
| `DISPA_HTTP_CONNECT_TIMEOUT_SECS` | 健康检查/简单 GET 超时秒数（默认 5） |
