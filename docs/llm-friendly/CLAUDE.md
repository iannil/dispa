# CLAUDE.md

本文档为Claude Code (claude.ai/code) 提供在此代码库中处理代码时的指导。

## Dispa

### 项目概述

Dispa 是一个用 Rust 编写的高性能流量拦截和转发代理服务器。它拦截指定域名的流量，记录流量数据，并使用多种负载均衡算法将请求转发到多个目标地址。

### 重要规则

- 总是测试先行，遵循测试驱动开发
- 始终用中文回复
- 生成的代码始终使用英文
- 生成的文档始终使用中文

## 技术标准

### 架构原则

- 组合优于继承：使用依赖注入
- 接口优于单例：支持测试和灵活性
- 显式优于隐式：清晰的数据流和依赖关系
- 尽可能测试驱动：永不禁用测试，修复它们

### 代码质量

- 每次提交必须：
  - 成功编译
  - 通过所有现有测试
  - 包含新功能测试
  - 遵循项目格式化/规范

- 提交前必须：
  - 运行格式化工具/检查器
  - 自我审查变更
  - 确保提交信息说明"为什么"

### 错误处理

- 快速失败并提供描述性信息
- 包含调试上下文
- 在适当层级处理错误
- 绝不静默吞异常

## 开发指南

### 核心信念

- 渐进式改进优于大爆炸式变革：小而可编译通过测试的变更
- 从现有代码中学习：实施前先研究规划
- 务实优于教条：适应项目实际情况
- 意图清晰优于代码巧妙：保持平庸和显而易见

### 简洁性意味着

- 函数/类单一职责
- 避免过早抽象
- 不耍小聪明，选择平庸的解决方案
- 如果需要解释，说明过于复杂

## 流程规范

### 1. 规划与分期

将复杂工作拆分为3-5个阶段。在`IMPLEMENTATION_PLAN.md`中记录：

```markdown
## 阶段N：[名称]
**目标**：[具体交付物]
**成功标准**：[可测试的结果]
**测试用例**：[具体测试场景]
**状态**：[未开始|进行中|已完成]
```

- 随进度更新状态
- 所有阶段完成后删除文件

### 2. 实施流程

1. 理解：研究代码库现有模式
2. 测试：先写测试（红）
3. 实现：最简代码通过测试（绿）
4. 重构：保持测试通过的情况下清理代码
5. 提交：附带清晰消息关联实施计划

### 3. 遇到阻碍时（3次尝试后）

关键原则：每个问题最多尝试3次，然后立即停止

1. 记录失败原因：
   - 尝试过的方法
   - 具体错误信息
   - 失败原因分析

2. 研究替代方案：
   - 寻找2-3个类似实现
   - 记录使用的不同方法

3. 质疑根本前提：
   - 抽象层级是否合适？
   - 能否拆分为更小问题？
   - 是否存在更简单的整体方案？

4. 尝试不同角度：
   - 不同的库/框架特性？
   - 不同的架构模式？
   - 减少而非增加抽象？

## 决策框架

存在多个有效方案时，基于以下标准选择：

1. 可测试性：是否易于测试？
2. 可读性：半年后他人能否理解？
3. 一致性：是否符合项目模式？
4. 简洁性：是否是最简单的可行方案？
5. 可逆性：后续修改难度如何？

## 项目集成

### 代码库学习

- 找到3个类似功能/组件
- 识别通用模式和约定
- 尽可能使用相同库/工具
- 遵循现有测试模式

### 工具使用

- 使用项目现有构建系统
- 使用项目测试框架
- 使用项目格式化/检查设置
- 无充分理由不引入新工具

## 质量门禁

### 完成定义

- [ ] 测试编写并通过
- [ ] 代码遵循项目规范
- [ ] 无检查器/格式化警告
- [ ] 提交信息清晰
- [ ] 实施符合计划
- [ ] 无未关联问题的TODO项

### 测试指南

- 测试行为而非实现
- 尽可能每个测试一个断言
- 测试名称清晰描述场景
- 使用现有测试工具/辅助函数
- 测试应具有确定性

## 重要提醒

严禁：

- 使用`--no-verify`绕过提交钩子
- 禁用测试而非修复
- 提交无法编译的代码
- 凭假设行事 - 通过现有代码验证

必须：

- 增量提交可工作代码
- 随时更新计划文档
- 从现有实现中学习
- 3次失败后停止并重新评估

## 架构概述

### 核心模块

1. **`config/`** - 使用 TOML 文件的配置管理
   - 支持服务器、域名、目标、日志和监控配置
   - 配置验证和类型安全解析
   - 支持配置热重载功能

2. **`proxy/`** - HTTP 代理服务器实现
   - `server.rs` - 基于 Hyper 的 HTTP 服务器
   - `handler.rs` - 请求处理和转发逻辑
   - `cached_handler.rs` - 带缓存功能的请求处理器
   - `http_client.rs` - HTTP 客户端连接池管理
   - 支持通配符的域名匹配 (`*.example.com`)

3. **`balancer/`** - 负载均衡和健康检查
   - `load_balancer.rs` - 多种算法：轮询、加权、最少连接、随机
   - `health_check.rs` - 并发健康监控，可配置阈值

4. **`logger/`** - 流量记录和持久化
   - `traffic_logger.rs` - 双重存储：SQLite 数据库和文件日志
   - 自动日志轮转和清理
   - 结构化日志记录，包含请求/响应元数据

5. **`monitoring/`** - 指标和健康端点
   - `metrics.rs` - Prometheus 指标导出
   - `enhanced_metrics.rs` - 增强性能监控
   - `health.rs` - 健康检查端点
   - `admin.rs` - 管理API接口
   - 独立端口的健康检查 API（默认：8081）
   - 性能和系统指标收集

6. **`cache/`** - 响应缓存系统 ⭐ 新增
   - `storage.rs` - 内存缓存存储实现
   - `policy.rs` - 缓存策略引擎
   - `etag.rs` - ETag 条件请求处理
   - 支持TTL、缓存策略和指标收集

7. **`security/`** - 安全认证和访问控制 ⭐ 新增
   - `enhanced_auth.rs` - 增强认证系统
   - 基础认证、令牌验证
   - 访问控制和速率限制
   - 安全审计日志

8. **`plugins/`** - 插件系统 ⭐ 新增
   - WASM 插件运行时（可选）
   - 插件生命周期管理
   - 请求/响应处理钩子
   - 错误处理策略

9. **`app_state.rs`** - 应用状态管理 ⭐ 新增
   - 集中式状态管理
   - 配置热重载逻辑
   - 应用初始化流程
   - 减少 Arc 克隆调用

10. **`routing.rs`** - 路由引擎 ⭐ 新增
    - 基于路径的路由规则
    - 支持正则表达式匹配
    - 路由优先级管理

11. **`circuit_breaker.rs`** - 熔断器模式 ⭐ 新增
    - 故障检测和自动熔断
    - 半开状态恢复机制
    - 可配置的失败阈值

12. **`retry.rs`** - 重试机制 ⭐ 新增
    - 指数退避重试策略
    - 可配置重试次数和间隔
    - 支持条件重试

### 关键设计模式

- **Async/Await**：基于 Tokio 的异步运行时
- **`Arc<RwLock<T>>`**：线程安全访问的共享状态管理
- **建造者模式**：具有可选字段的配置结构体
- **错误处理**：Anyhow 用于错误传播，自定义 DispaError 类型用于业务逻辑
- **模块化架构**：清晰的模块边界和依赖注入
- **集中式状态管理**：通过 AppState 减少状态分散和 Arc 克隆

## 配置结构

主配置文件 (`config/config.toml`) 包含以下部分：

- `[server]` - 绑定地址、工作线程数、超时设置
- `[domains]` - 域名拦截规则，支持通配符
- `[[targets.targets]]` - 后端服务器，包含权重和超时设置
- `[targets.load_balancing]` - 算法选择和会话亲和性
- `[targets.health_check]` - 健康监控间隔和阈值
- `[logging]` - 流量记录选项（文件/数据库/两者）
- `[monitoring]` - 指标和健康检查端口配置
- `[cache]` - 缓存配置（可选）⭐ 新增
- `[security]` - 安全认证配置（可选）⭐ 新增
- `[plugins]` - 插件系统配置（可选）⭐ 新增
- `[routing]` - 路由规则配置（可选）⭐ 新增
- `[tls]` - TLS/SSL 证书配置（可选）⭐ 新增

## 服务端口

| 服务 | 默认端口 | 用途 |
|------|----------|------|
| 代理服务器 | 8080 | HTTP 流量拦截 |
| 健康检查 | 8081 | 系统状态 API |
| 指标 | 9090 | Prometheus 指标导出 |

## 测试架构

项目包含全面的单元测试，涵盖：

- **负载均衡器测试**：所有算法、边界情况、并发访问
- **健康检查测试**：端点回退、阈值管理、错误处理
- **缓存系统测试**：存储、策略、ETag处理 ⭐ 新增
- **安全模块测试**：认证、授权、速率限制 ⭐ 新增
- **插件系统测试**：插件加载、执行、错误处理 ⭐ 新增
- **应用状态测试**：状态管理、配置重载 ⭐ 新增
- **模拟基础设施**：wiremock 用于 HTTP 模拟，tokio-test 用于异步测试

测试组织：

- 每个模块都有 `#[cfg(test)]` 部分和辅助函数
- 集成测试使用 `MockServer` 的真实 HTTP 服务器
- 基于属性的测试确保算法正确性

## 常见开发工作流

### 添加新的负载均衡算法

1. 在 `config/mod.rs` 的 `LoadBalancingType` 中添加算法枚举变体
2. 在 `load_balancer.rs` 中实现选择逻辑
3. 在测试模块中添加全面的测试
4. 更新配置文档

### 扩展健康检查逻辑

1. 修改 `health_check.rs` 中的 `HealthChecker` 结构体
2. 更新 `perform_health_check` 方法以支持新的端点逻辑
3. 添加相应的测试用例
4. 如果需要，考虑配置选项

### 添加新指标

1. 在 `register_metrics()` 函数中注册指标
2. 在 `MetricsCollector` 中实现收集逻辑
3. 如果需要，添加 JSON 端点支持
4. 记录指标含义和用法

## 重要实现说明

- **纯 Rust TLS**：使用 `rustls` 而非 OpenSSL，以获得更好的跨编译支持
- **连接池**：reqwest 客户端处理 HTTP 连接复用
- **优雅关闭**：Tokio 信号处理实现服务干净终止
- **内存管理**：谨慎使用 Arc/Rc 处理共享数据结构
- **错误恢复**：通过健康检查实现断路器模式，防止级联故障

## 性能考虑

- 目标：标准硬件上支持 10,000+ 并发连接，100k+ RPS
- 内存效率：运行时使用 <100MB
- 低延迟：P99 代理开销 <10ms
- 数据库操作是异步的且使用连接池
- 健康检查并发运行，避免阻塞请求处理

## 开发命令

### 构建和运行

```bash
# 构建项目
cargo build --release

# 开发模式运行
cargo run -- -c config/config.toml -v

# 使用自定义配置和绑定运行
cargo run -- -c config/custom.toml -b 0.0.0.0:9000 -v
```

### 测试

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test balancer::load_balancer::tests
cargo test balancer::health_check::tests

# 运行带输出的测试
cargo test -- --nocapture

# 运行单个测试
cargo test test_round_robin_selection -- --exact
```

### 开发工具

```bash
# 检查编译错误
cargo check

# 格式化代码
cargo fmt

# 运行代码检查
cargo clippy

# 生成文档
cargo doc --open
```

## Git Hooks 和质量保证

本项目配置了Git hooks来确保代码质量和CI/CD的一致性。

### Pre-commit Hook

每次提交时自动运行以下检查：

- **代码格式化检查**: `cargo fmt --all -- --check`
- **Clippy 代码检查**: `cargo clippy --all-targets --all-features -- -D warnings`
- **编译检查**: `cargo check --verbose`
- **单元测试**: `cargo test --verbose`
- **发布构建**: `cargo build --verbose --release`
- **代码质量检查**: 检查调试语句、TODO注释等

如果任何检查失败，提交将被拒绝。可以使用 `git commit --no-verify` 跳过检查（不推荐）。

### Pre-push Hook

推送到主分支时运行额外检查：

- **主分支保护**: 对 main/master 分支进行严格检查
- **发布版本检查**: 自动检测版本发布提交
- **功能分支**: 对功能分支进行基础编译检查

### 手动质量检查

运行完整的质量保证检查：

```bash
# 运行所有质量检查
./scripts/qa.sh

# 包含的检查项目：
# - 代码格式化
# - Clippy 检查
# - 编译检查
# - 单元测试
# - 文档测试
# - 发布构建
# - 安全审计 (如果安装了 cargo-audit)
# - 依赖更新检查 (如果安装了 cargo-outdated)
# - 许可证兼容性 (如果安装了 cargo-license)
# - 未使用依赖检查 (如果安装了 cargo-udeps)
```

### 推荐的开发流程

1. **开发前**:

   ```bash
   git pull origin main
   cargo update
   ```

2. **开发过程中**:

   ```bash
   # 定期运行检查
   cargo check
   cargo test
   cargo fmt
   ```

3. **提交前**:

   ```bash
   # 运行完整检查（可选，pre-commit hook会自动运行）
   ./scripts/qa.sh

   # 提交（会自动触发pre-commit检查）
   git add .
   git commit -m "feat: your changes"
   ```

4. **推送前**:

   ```bash
   # 推送（会自动触发pre-push检查）
   git push origin feature-branch
   ```

### 质量工具安装

建议安装以下工具以获得完整的代码质量检查：

```bash
# 安全审计
cargo install cargo-audit

# 依赖更新检查
cargo install cargo-outdated

# 许可证检查
cargo install cargo-license

# 未使用依赖检查
cargo install cargo-udeps

# 代码覆盖率（可选）
cargo install cargo-tarpaulin
```

### 便捷命令

项目提供了 Makefile 来简化常用操作：

```bash
# 查看所有可用命令
make help

# 开发常用命令
make check      # 快速编译检查
make test       # 运行测试
make fmt        # 格式化代码
make clippy     # 运行代码检查

# 质量保证
make qa         # 运行完整质量检查
make pre-commit # 手动运行pre-commit检查
make ci         # 模拟CI环境

# 维护命令
make clean      # 清理构建文件
make update     # 更新依赖
make install-tools # 安装推荐的开发工具
```

### 团队协作

1. **Clone项目后的设置**：
   ```bash
   git clone <repository>
   cd dispa
   make dev-setup  # 安装工具并验证环境
   ```

2. **日常开发**：
   ```bash
   make quick      # 快速开发循环检查
   git commit -m "your changes"  # 自动触发质量检查
   ```

3. **发布前**：
   ```bash
   make qa         # 运行完整质量检查
   ```

## 相关文档

- [Git Hooks 详细说明](../git-hooks.md)
- [CI 工作流说明](../CI.md)
- [开发工具和脚本](../../scripts/)
