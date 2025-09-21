# 管理界面（4.2）

本实现提供一个内置的 Web 管理页面与简单的配置管理 API（复用监控服务）。

访问入口
- 管理首页（HTML）：`/admin`
- 系统状态（JSON）：`/admin/status`
- 读取配置（TOML 文本）：`/admin/config`（GET）
- 写入配置（TOML 文本）：`/admin/config`（POST/PUT）
- 指标 JSON：`/metrics/json`（已存在）
- Prometheus：`/metrics`（已存在）

说明
- 管理/监控与健康检查共用同一监控服务监听端口（`monitoring.metrics_port`）
- 配置写入采用“写文件 -> 由热重载监视器接管”的策略，不直接在进程内切换配置结构
- 简单的敏感信息脱敏：读取配置时会对 `security.jwt.secret` 进行粗略遮蔽（`***`）
- 页面提供基础实时信息（请求总数、错误总数、目标健康）与配置浏览/编辑区

安全建议
- 建议通过前置反向代理或安全组限制管理端口访问
- 在生产环境开启全局安全模块（`[security]`）并限制来源 IP 或要求认证
- 如需多租户/更细粒度 RBAC，可在此基础上扩展鉴权逻辑

开发说明
- 代码位置：
  - 管理路由：`src/monitoring/admin.rs`（OnceCell 注入运行态句柄）
  - 监控/路由集成：`src/monitoring/metrics.rs`（在 `handle_metrics` 中分派 `/admin` 前缀）
  - 启动注入：`src/main.rs`（将 config_path、负载均衡/路由/插件/安全等句柄注入）
