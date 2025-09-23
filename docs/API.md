# Dispa API 文档

## 概述

Dispa 提供了多个 HTTP API 端点用于监控、管理和健康检查。本文档详细描述了所有可用的 API 接口。

## 端点概览

| 服务类型  | 默认端口 | 端点            | 描述              |
|-------|------|---------------|-----------------|
| 代理服务  | 8080 | /             | 主要的流量代理服务       |
| 健康检查  | 8081 | /health       | 服务健康状态检查        |
| 监控服务  | 9090 | /metrics      | Prometheus 指标导出 |
| 监控服务  | 9090 | /metrics/json | JSON 格式指标       |
| 管理界面  | 9090 | /admin        | Web 管理界面        |
| 管理API | 9090 | /admin/*      | 管理API接口         |

## 健康检查 API

### GET /health

检查服务健康状态。

**端口**: 8081 (默认，可通过 `monitoring.health_check_port` 配置)

**响应格式**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "uptime": 3600,
  "version": "0.1.0",
  "targets": [
    {
      "name": "backend1",
      "url": "http://192.168.1.100:3000",
      "status": "healthy",
      "last_check": "2024-01-01T12:00:00Z"
    }
  ]
}
```

**状态码**:
- `200 OK`: 服务健康
- `503 Service Unavailable`: 服务不健康

## 监控 API

### GET /metrics

Prometheus 格式的指标数据。

**端口**: 9090 (默认，可通过 `monitoring.metrics_port` 配置)

**响应格式**: Prometheus 文本格式

**指标示例**:
```
# HELP dispa_requests_total Total number of requests processed
# TYPE dispa_requests_total counter
dispa_requests_total{domain="example.com",method="GET",status="200"} 1234

# HELP dispa_request_duration_seconds Request duration in seconds
# TYPE dispa_request_duration_seconds histogram
dispa_request_duration_seconds_bucket{le="0.1"} 100
dispa_request_duration_seconds_bucket{le="1.0"} 200
dispa_request_duration_seconds_sum 45.67
dispa_request_duration_seconds_count 200

# HELP dispa_target_health Target health status (1=healthy, 0=unhealthy)
# TYPE dispa_target_health gauge
dispa_target_health{target="backend1",url="http://192.168.1.100:3000"} 1
```

### GET /metrics/json

JSON 格式的指标数据，便于程序化访问。

**端口**: 9090

**响应格式**:
```json
{
  "requests": {
    "total": 1234,
    "success": 1200,
    "errors": 34,
    "rate_per_second": 15.5
  },
  "targets": [
    {
      "name": "backend1",
      "url": "http://192.168.1.100:3000",
      "healthy": true,
      "response_time_ms": 45,
      "success_rate": 0.98
    }
  ],
  "load_balancer": {
    "algorithm": "weighted",
    "total_requests": 1234,
    "distribution": {
      "backend1": 740,
      "backend2": 494
    }
  },
  "cache": {
    "enabled": true,
    "hit_rate": 0.65,
    "total_entries": 1500,
    "size_bytes": 52428800
  }
}
```

## 管理 API

管理 API 提供了配置查看、修改和系统状态监控功能。

### GET /admin

Web 管理界面首页。返回 HTML 页面。

**端口**: 9090

### GET /admin/status

获取系统详细状态信息。

**端口**: 9090

**响应格式**:
```json
{
  "service": {
    "name": "dispa",
    "version": "0.1.0",
    "uptime_seconds": 3600,
    "start_time": "2024-01-01T08:00:00Z"
  },
  "configuration": {
    "config_file": "/path/to/config.toml",
    "last_reload": "2024-01-01T08:00:00Z",
    "hot_reload_enabled": true
  },
  "proxy": {
    "bind_address": "0.0.0.0:8080",
    "worker_threads": 4,
    "total_requests": 1234,
    "active_connections": 45
  },
  "targets": [
    {
      "name": "backend1",
      "url": "http://192.168.1.100:3000",
      "weight": 3,
      "healthy": true,
      "response_time_ms": 45,
      "total_requests": 740,
      "error_rate": 0.02
    }
  ],
  "domains": {
    "intercept_domains": ["example.com", "*.test.com"],
    "exclude_domains": ["admin.example.com"],
    "wildcard_support": true
  },
  "features": {
    "caching": true,
    "security": true,
    "plugins": true,
    "routing": false,
    "tls": false
  }
}
```

### GET /admin/config

获取当前配置文件内容（TOML 格式）。

**端口**: 9090

**响应格式**: TOML 文本，敏感信息已脱敏

**示例**:
```toml
[server]
bind_address = "0.0.0.0:8080"
workers = 4

[security.jwt]
secret = "***"  # 敏感信息已脱敏
```

### POST /admin/config
### PUT /admin/config

更新配置文件。配置会写入文件，然后由热重载机制自动应用。

**端口**: 9090

**请求格式**: TOML 文本

**请求头**:
```
Content-Type: text/plain
```

**响应格式**:
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "reload_time": "2024-01-01T12:30:00Z"
}
```

**错误响应**:
```json
{
  "success": false,
  "error": "Invalid TOML format: missing closing bracket at line 15",
  "details": "Configuration validation failed"
}
```

## 代理 API

代理服务本身不提供管理 API，但它会处理所有被拦截的 HTTP 请求。

### 请求头处理

代理会保留大部分原始请求头，但会添加一些额外的头部信息：

**添加的请求头**:
- `X-Forwarded-For`: 客户端真实 IP
- `X-Forwarded-Proto`: 原始协议 (http/https)
- `X-Forwarded-Host`: 原始主机名
- `X-Request-ID`: 唯一请求标识符（如果启用了相关插件）

**添加的响应头**:
- `X-Proxy-By`: "dispa" （如果启用了相关插件）
- `X-Response-Time`: 请求处理时间（毫秒）

### 错误响应

当代理遇到错误时，会返回相应的 HTTP 状态码：

- `502 Bad Gateway`: 后端服务不可达
- `503 Service Unavailable`: 所有后端服务都不健康
- `504 Gateway Timeout`: 后端服务响应超时
- `403 Forbidden`: 被安全规则或插件阻止
- `429 Too Many Requests`: 触发速率限制

## 安全考虑

### 访问控制

建议在生产环境中：

1. **限制管理端口访问**：
   - 使用防火墙或安全组限制访问
   - 配置反向代理进行身份验证
   - 启用 IP 白名单

2. **启用安全模块**：
   ```toml
   [security]
   enabled = true

   [security.access_control]
   allowed_ips = ["192.168.1.0/24", "10.0.0.0/8"]
   ```

3. **使用 HTTPS**：
   ```toml
   [tls]
   cert_file = "/path/to/cert.pem"
   key_file = "/path/to/key.pem"
   ```

### 认证

支持多种认证方式：

1. **API Key 认证**：
   ```toml
   [security.auth]
   mode = "apikey"
   header_name = "X-API-Key"
   valid_keys = ["your-secret-key"]
   ```

2. **Bearer Token 认证**：
   ```toml
   [security.auth]
   mode = "bearer"
   valid_tokens = ["your-bearer-token"]
   ```

3. **JWT 认证**：
   ```toml
   [security.jwt]
   enabled = true
   secret = "your-jwt-secret"
   algorithm = "HS256"
   ```

## API 客户端示例

### Python 示例

```python
import requests
import json

# 健康检查
response = requests.get("http://localhost:8081/health")
health = response.json()
print(f"Service status: {health['status']}")

# 获取指标
response = requests.get("http://localhost:9090/metrics/json")
metrics = response.json()
print(f"Total requests: {metrics['requests']['total']}")

# 获取配置
response = requests.get("http://localhost:9090/admin/config")
config = response.text
print("Current configuration:")
print(config)

# 更新配置
new_config = """
[server]
bind_address = "0.0.0.0:8080"
workers = 8
"""

response = requests.post(
    "http://localhost:9090/admin/config",
    data=new_config,
    headers={"Content-Type": "text/plain"}
)
result = response.json()
print(f"Config update: {result['message']}")
```

### curl 示例

```bash
# 健康检查
curl http://localhost:8081/health

# 获取 Prometheus 指标
curl http://localhost:9090/metrics

# 获取 JSON 指标
curl http://localhost:9090/metrics/json

# 获取系统状态
curl http://localhost:9090/admin/status

# 获取配置
curl http://localhost:9090/admin/config

# 更新配置
curl -X POST http://localhost:9090/admin/config \
  -H "Content-Type: text/plain" \
  -d @new-config.toml
```

## 故障排除

### 常见问题

1. **端口被占用**：
   - 检查配置文件中的端口设置
   - 使用 `netstat` 或 `ss` 检查端口占用情况

2. **配置更新失败**：
   - 检查 TOML 语法是否正确
   - 验证配置项是否有效
   - 查看应用日志获取详细错误信息

3. **健康检查失败**：
   - 检查后端服务是否运行
   - 验证网络连接
   - 查看健康检查配置

### 日志级别

使用 `-v` 参数启用详细日志：

```bash
./dispa -c config.toml -v
```

这将启用 debug 级别的日志，帮助诊断问题。