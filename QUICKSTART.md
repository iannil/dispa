# Dispa 快速开始指南

## 5分钟快速上手

### 1. 编译和安装

```bash
# 克隆项目
git clone <repository-url>
cd dispa

# 编译
cargo build --release

# 验证安装
./target/release/dispa --help
```

### 2. 基础配置

编辑 `config/config.toml`，设置你的域名和后端服务器：

```toml
[domains]
intercept_domains = ["yourdomain.com"]  # 替换为你的域名

[[targets.targets]]
name = "backend1"
url = "http://your-backend-server:3000"  # 替换为你的后端地址
weight = 1
```

### 3. 启动服务

```bash
# 创建必要目录
mkdir -p logs data

# 启动代理服务
./target/release/dispa -c config/config.toml -v
```

### 4. 测试验证

在另一个终端中测试：

```bash
# 测试健康检查
curl http://localhost:8081/health

# 测试代理功能
curl -H "Host: yourdomain.com" http://localhost:8080/

# 查看监控指标
curl http://localhost:9090/metrics
```

## 核心功能演示

### 域名拦截

```bash
# 拦截的域名 - 转发到后端
curl -H "Host: yourdomain.com" http://localhost:8080/
# → 转发到配置的后端服务器

# 未配置的域名 - 返回 404
curl -H "Host: unknown.com" http://localhost:8080/
# → "Domain not found"
```

### 负载均衡

当配置多个后端时，请求会按照配置的算法分发：

```bash
# 连续发送多个请求观察负载分发
for i in {1..10}; do
  curl -H "Host: yourdomain.com" http://localhost:8080/ &
done
```

### 监控数据

```bash
# Prometheus 格式的指标
curl http://localhost:9090/metrics | grep dispa

# JSON 格式的健康状态
curl http://localhost:8081/health | jq
```

## 常用场景配置

### 场景 1：开发环境代理

```toml
[domains]
intercept_domains = ["*.local.dev"]

[[targets.targets]]
name = "local-server"
url = "http://localhost:3000"
```

### 场景 2：生产环境负载均衡

```toml
[domains]
intercept_domains = ["api.myapp.com", "www.myapp.com"]

[[targets.targets]]
name = "server1"
url = "http://10.0.1.10:8080"
weight = 3

[[targets.targets]]
name = "server2"
url = "http://10.0.1.11:8080"
weight = 2

[targets.load_balancing]
type = "weighted"

[targets.health_check]
enabled = true
interval = 10
```

### 场景 3：API 网关

```toml
[domains]
intercept_domains = ["api.company.com"]
exclude_domains = ["admin.api.company.com"]

[logging]
enabled = true
type = "both"

[monitoring]
enabled = true
```

## 故障排除速查

| 问题 | 可能原因 | 解决方案 |
|------|----------|----------|
| `Address already in use` | 端口被占用 | 更改配置中的端口或停止占用进程 |
| `Service unavailable` | 后端服务不可用 | 检查后端服务状态和网络连通性 |
| `Domain not found` | 域名未在拦截列表中 | 检查 `intercept_domains` 配置 |
| `database error` | 数据库连接失败 | 确保数据目录存在，或改用文件日志 |

## 下一步

- 查看 [完整用户手册](USER_MANUAL.md) 了解详细配置
- 查看 [开发指南](DEVELOPMENT.md) 了解架构细节
- 配置监控和告警系统
- 设置生产环境部署
