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
