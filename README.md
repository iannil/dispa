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
```

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

- **[快速开始指南](QUICKSTART.md)** - 5分钟上手教程
- **[完整用户手册](USER_MANUAL.md)** - 详细配置和使用说明
- **[开发指南](DEVELOPMENT.md)** - 架构设计和扩展开发
- **[数据库指南](docs/DATABASE.md)** - SQLite / PostgreSQL 连接与迁移

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

| 服务 | 端口 | 说明 |
|------|------|------|
| 代理服务 | 8080 | HTTP/HTTPS 流量代理 |
| 健康检查 | 8081 | 系统状态 API |
| 监控指标 | 9090 | Prometheus 指标 |

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

| 问题 | 解决方案 |
|------|----------|
| 端口被占用 | 修改配置文件中的 `bind_address` |
| 后端不可用 | 检查 `targets` 配置和网络连通性 |
| 域名未匹配 | 验证 `intercept_domains` 设置 |
| 数据库错误 | 确保数据目录存在或使用文件日志 |

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
- **文档**: [在线文档](https://your-docs-site.com)

## 🌟 致谢

感谢以下开源项目：

- [Tokio](https://tokio.rs/) - 异步运行时
- [Hyper](https://hyper.rs/) - HTTP 库
- [SQLx](https://github.com/launchbadge/sqlx) - 数据库访问
- [Tracing](https://tracing.rs/) - 结构化日志

---

<div align="center">

**[快速开始](./docs/QUICKSTART.md)** • **[用户手册](./docs/USER_MANUAL.md)** • **[开发指南](./docs/DEVELOPMENT.md)**

Made with ❤️ in Rust

</div>
