# Dispa 配置文档

## 概述

Dispa 使用 TOML 格式的配置文件，支持热重载功能。本文档详细描述了所有可用的配置选项。

## 配置文件结构

```toml
[server]          # 服务器基础配置
[domains]         # 域名拦截配置
[targets]         # 后端目标配置
[logging]         # 日志配置
[monitoring]      # 监控配置
[tls]            # TLS/SSL 配置 (可选)
[routing]        # 高级路由配置 (可选)
[cache]          # 缓存配置 (可选)
[http_client]    # HTTP 客户端配置 (可选)
[plugins]        # 插件配置 (可选)
[security]       # 安全配置 (可选)
```

## 服务器配置 [server]

```toml
[server]
# 代理服务绑定地址和端口
bind_address = "0.0.0.0:8080"

# 工作线程数量，默认为 CPU 核心数
workers = 4

# Keep-alive 超时时间（秒）
keep_alive_timeout = 60

# 请求超时时间（秒）
request_timeout = 30
```

**配置项说明**:
- `bind_address`: 代理服务监听的地址和端口
- `workers`: Tokio 运行时的工作线程数量
- `keep_alive_timeout`: HTTP keep-alive 连接的超时时间
- `request_timeout`: 单个请求的超时时间

## 域名配置 [domains]

```toml
[domains]
# 要拦截的域名列表，支持通配符
intercept_domains = ["example.com", "api.example.com", "*.test.com"]

# 排除的域名列表，即使匹配 intercept_domains 也不拦截
exclude_domains = ["admin.example.com"]

# 是否启用通配符支持
wildcard_support = true
```

**通配符规则**:
- `*.example.com`: 匹配所有 example.com 的子域名
- `example.*`: 匹配所有以 example 开头的域名
- 通配符只能在域名的开头或结尾使用

## 目标配置 [targets]

### 后端服务器配置

```toml
[[targets.targets]]
name = "backend1"
url = "http://192.168.1.100:3000"
weight = 3
timeout = 30

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

**配置项说明**:
- `name`: 后端服务器的唯一名称
- `url`: 后端服务器的 URL
- `weight`: 负载均衡权重（仅对加权算法有效）
- `timeout`: 请求超时时间（秒）

### 负载均衡配置

```toml
[targets.load_balancing]
# 负载均衡算法: "round_robin", "weighted", "random", "least_connections"
type = "weighted"

# 是否启用会话保持（基于 IP）
sticky_sessions = false
```

**负载均衡算法**:
- `round_robin`: 轮询算法
- `weighted`: 加权轮询算法
- `random`: 随机选择算法
- `least_connections`: 最少连接算法

### 健康检查配置

```toml
[targets.health_check]
# 是否启用健康检查
enabled = true

# 检查间隔（秒）
interval = 30

# 单次检查超时时间（秒）
timeout = 10

# 健康阈值：连续成功次数
healthy_threshold = 2

# 不健康阈值：连续失败次数
unhealthy_threshold = 3
```

## 日志配置 [logging]

```toml
[logging]
# 是否启用日志记录
enabled = true

# 日志类型: "file", "database", "both"
type = "file"

# 日志保留天数
retention_days = 30

# 数据库日志配置（当 type 为 "database" 或 "both" 时）
[logging.database]
url = "sqlite://./data/traffic.db"
max_connections = 10
connection_timeout = 30

# 文件日志配置
[logging.file]
directory = "./logs"
max_file_size = 104857600  # 100MB
rotation = true
```

**日志类型说明**:
- `file`: 只记录到文件
- `database`: 只记录到数据库
- `both`: 同时记录到文件和数据库

## 监控配置 [monitoring]

```toml
[monitoring]
# 是否启用监控
enabled = true

# Prometheus 指标端口
metrics_port = 9090

# 健康检查端口
health_check_port = 8081
```

## TLS 配置 [tls] (可选)

```toml
[tls]
# 是否启用 TLS
enabled = true

# 证书文件路径
cert_file = "/path/to/cert.pem"

# 私钥文件路径
key_file = "/path/to/key.pem"

# TLS 版本，支持: "1.2", "1.3"
min_version = "1.2"

# 支持的密码套件（可选）
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256"
]
```

## 路由配置 [routing] (可选)

```toml
[routing]
# 是否启用请求/响应日志记录
enable_logging = false

# 默认目标（当没有规则匹配时）
default_target = "backend1"

# 路由规则
[[routing.rules]]
name = "api_routes"
priority = 100
target = "api_backend"

# 匹配条件
[routing.rules.match]
path_prefix = "/api/"
method = ["GET", "POST"]
headers = { "X-API-Version" = "v1" }

# 请求转换（可选）
[routing.rules.transform]
add_headers = { "X-Route" = "api" }
remove_headers = ["X-Internal"]
```

**路由匹配条件**:
- `path_prefix`: 路径前缀匹配
- `path_regex`: 路径正则表达式匹配
- `method`: HTTP 方法匹配
- `headers`: 请求头匹配
- `query_params`: 查询参数匹配

## 缓存配置 [cache] (可选)

```toml
[cache]
# 是否启用缓存
enabled = true

# 最大缓存大小（字节）
max_size = 1073741824  # 1GB

# 默认 TTL（秒）
default_ttl = 3600

# 是否启用 ETag 支持
etag_enabled = true

# 缓存键前缀
key_prefix = "dispa"

# 是否启用缓存指标
metrics_enabled = true

# 缓存策略
[[cache.policies]]
name = "images"
pattern = { content_type = "image/*" }
ttl = 86400  # 24小时
max_size = 10485760  # 10MB
enabled = true

[[cache.policies]]
name = "api"
pattern = { path_prefix = "/api/" }
ttl = 300  # 5分钟
enabled = true
```

**缓存策略模式**:
- `content_type`: 按 Content-Type 匹配
- `path_prefix`: 按路径前缀匹配
- `path_regex`: 按路径正则表达式匹配
- `status_code`: 按响应状态码匹配

## HTTP 客户端配置 [http_client] (可选)

```toml
[http_client]
# 连接池大小
pool_size = 50

# 连接超时时间（秒）
connect_timeout = 10

# 请求超时时间（秒）
request_timeout = 30

# 是否启用 HTTP/2
http2_enabled = true

# 最大空闲连接数
max_idle_connections = 20

# 空闲连接超时时间（秒）
idle_timeout = 60

# 用户代理字符串
user_agent = "dispa/0.1.0"
```

## 插件配置 [plugins] (可选)

```toml
[plugins]
# 是否启用插件系统
enabled = true

# 请求阶段插件是否在域名匹配前执行
apply_before_domain_match = true

# 全局插件列表
[[plugins.plugins]]
name = "request_id"
type = "headerinjector"
enabled = true
stage = "request"
error_strategy = "continue"

[plugins.plugins.config]
request_headers = { "X-Request-ID" = "{{uuid}}" }

[[plugins.plugins]]
name = "cors"
type = "headeroverride"
enabled = true
stage = "response"
error_strategy = "continue"

[plugins.plugins.config]
response_headers = {
    "Access-Control-Allow-Origin" = "*",
    "Access-Control-Allow-Methods" = "GET, POST, PUT, DELETE",
    "Access-Control-Allow-Headers" = "Content-Type, Authorization"
}

# 外部命令插件（需要启用 cmd-plugin 特性）
[[plugins.plugins]]
name = "auth_checker"
type = "command"
enabled = true
stage = "request"
error_strategy = "fail"

[plugins.plugins.config]
command = "/usr/local/bin/auth-check"
args = ["--request"]
timeout = 5
env = { "AUTH_URL" = "http://auth.internal" }
```

**内置插件类型**:
- `headerinjector`: 注入请求/响应头
- `headeroverride`: 覆盖请求/响应头
- `blocklist`: 按域名或路径阻止请求
- `command`: 外部命令插件（实验性）
- `wasm`: WASM 插件（实验性）

**插件阶段**:
- `request`: 请求阶段
- `response`: 响应阶段
- `both`: 请求和响应阶段

**错误策略**:
- `continue`: 记录错误但继续处理
- `fail`: 出错时返回 500 错误

## 安全配置 [security] (可选)

```toml
[security]
# 是否启用安全模块
enabled = true

# 访问控制配置
[security.access_control]
# 允许的 IP 地址列表（支持 CIDR 和通配符）
allowed_ips = ["192.168.1.0/24", "10.0.0.*"]

# 拒绝的 IP 地址列表
denied_ips = ["203.0.113.0/24"]

# 是否信任代理头部（X-Forwarded-For 等）
trust_proxy_headers = false

# 认证配置
[security.auth]
# 认证模式: "apikey", "bearer"
mode = "apikey"

# API Key 配置
header_name = "X-API-Key"
valid_keys = ["your-secret-api-key"]

# Bearer Token 配置（当 mode = "bearer" 时）
# valid_tokens = ["your-bearer-token"]

# 全局速率限制
[security.rate_limit]
# 是否启用速率限制
enabled = true

# 每秒请求数限制
requests_per_second = 100

# 突发请求数
burst_size = 200

# 限制窗口大小（秒）
window_size = 60

# DDoS 防护
[security.ddos]
# 是否启用 DDoS 防护
enabled = true

# 每个 IP 的最大连接数
max_connections_per_ip = 50

# 连接频率限制（每秒）
connection_rate_limit = 10

# 检测窗口（秒）
detection_window = 60

# JWT 配置
[security.jwt]
# 是否启用 JWT 验证
enabled = false

# JWT 密钥
secret = "your-jwt-secret"

# 算法: "HS256", "HS384", "HS512", "RS256"
algorithm = "HS256"

# 是否验证过期时间
verify_exp = true

# 是否验证签发时间
verify_iat = true

# JWT 头部名称
header_name = "Authorization"

# JWT 前缀（如 "Bearer "）
prefix = "Bearer "

# JWKS URL（用于 RS256 算法，需要启用 jwt-rs256-net 特性）
# jwks_url = "https://example.com/.well-known/jwks.json"
```

## 配置验证

### 语法检查

可以使用以下方法验证配置文件语法：

```bash
# 使用 Dispa 自带的配置验证
./dispa -c config.toml --validate

# 使用 TOML 语法检查工具
toml-sort config.toml --check
```

### 常见配置错误

1. **端口冲突**：
   ```
   Error: Address already in use (os error 98)
   ```
   检查 `bind_address`、`metrics_port`、`health_check_port` 是否冲突。

2. **无效的 URL**：
   ```
   Error: Invalid target URL: http://[invalid]
   ```
   检查 `targets.targets.url` 格式是否正确。

3. **权重配置错误**：
   ```
   Error: All target weights are zero
   ```
   确保至少有一个目标的 `weight` 大于 0。

4. **文件路径不存在**：
   ```
   Error: No such file or directory
   ```
   检查 TLS 证书路径、日志目录等是否存在。

## 配置示例

### 基础配置示例

```toml
# 最小化配置示例
[server]
bind_address = "0.0.0.0:8080"

[domains]
intercept_domains = ["example.com"]

[[targets.targets]]
name = "backend"
url = "http://localhost:3000"
weight = 1

[targets.load_balancing]
type = "round_robin"

[targets.health_check]
enabled = true
interval = 30

[logging]
enabled = true
type = "file"

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081
```

### 生产环境配置示例

```toml
[server]
bind_address = "0.0.0.0:8080"
workers = 8
keep_alive_timeout = 75
request_timeout = 30

[domains]
intercept_domains = ["api.example.com", "*.service.example.com"]
exclude_domains = ["admin.example.com", "internal.example.com"]
wildcard_support = true

[[targets.targets]]
name = "backend1"
url = "http://10.0.1.10:8080"
weight = 3
timeout = 15

[[targets.targets]]
name = "backend2"
url = "http://10.0.1.11:8080"
weight = 3
timeout = 15

[[targets.targets]]
name = "backend3"
url = "http://10.0.1.12:8080"
weight = 2
timeout = 15

[targets.load_balancing]
type = "least_connections"
sticky_sessions = true

[targets.health_check]
enabled = true
interval = 10
timeout = 5
healthy_threshold = 2
unhealthy_threshold = 3

[logging]
enabled = true
type = "both"
retention_days = 7

[logging.database]
url = "postgresql://user:pass@db.example.com/dispa"
max_connections = 20
connection_timeout = 30

[logging.file]
directory = "/var/log/dispa"
max_file_size = 536870912  # 512MB
rotation = true

[monitoring]
enabled = true
metrics_port = 9090
health_check_port = 8081

[tls]
enabled = true
cert_file = "/etc/ssl/certs/dispa.pem"
key_file = "/etc/ssl/private/dispa.key"
min_version = "1.2"

[cache]
enabled = true
max_size = 2147483648  # 2GB
default_ttl = 1800
etag_enabled = true
metrics_enabled = true

[[cache.policies]]
name = "static_assets"
pattern = { path_regex = "\\.(css|js|png|jpg|gif|svg)$" }
ttl = 86400
enabled = true

[http_client]
pool_size = 100
connect_timeout = 5
request_timeout = 30
http2_enabled = true
max_idle_connections = 50

[security]
enabled = true

[security.access_control]
allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
trust_proxy_headers = true

[security.rate_limit]
enabled = true
requests_per_second = 1000
burst_size = 2000

[security.ddos]
enabled = true
max_connections_per_ip = 100
connection_rate_limit = 50

[plugins]
enabled = true
apply_before_domain_match = false

[[plugins.plugins]]
name = "security_headers"
type = "headeroverride"
enabled = true
stage = "response"
error_strategy = "continue"

[plugins.plugins.config]
response_headers = {
    "X-Content-Type-Options" = "nosniff",
    "X-Frame-Options" = "DENY",
    "X-XSS-Protection" = "1; mode=block",
    "Strict-Transport-Security" = "max-age=31536000; includeSubDomains"
}
```

## 热重载

Dispa 支持配置文件热重载，当配置文件发生变化时会自动重新加载：

1. **监控机制**：使用文件系统监控检测配置文件变化
2. **重载过程**：新配置会替换旧配置，无需重启服务
3. **错误处理**：如果新配置无效，会保留旧配置并记录错误日志

**注意事项**：
- 某些配置项（如端口绑定）的更改可能需要重启服务
- 热重载可能会有短暂的服务中断
- 建议在测试环境验证配置后再在生产环境应用

## 环境变量覆盖

部分配置可以通过环境变量覆盖：

```bash
export DISPA_BIND_ADDRESS="0.0.0.0:9000"
export DISPA_LOG_LEVEL="debug"
export DISPA_CONFIG_FILE="/etc/dispa/config.toml"

./dispa
```

支持的环境变量：
- `DISPA_BIND_ADDRESS`: 覆盖 `server.bind_address`
- `DISPA_LOG_LEVEL`: 设置日志级别
- `DISPA_CONFIG_FILE`: 指定配置文件路径