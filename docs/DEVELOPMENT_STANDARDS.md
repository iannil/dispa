# Dispa 开发规范和代码审查标准

**版本**: v1.0
**生效日期**: 2024-09-25
**适用范围**: Dispa 项目所有开发者和贡献者

---

## 概述

本文档定义了 Dispa 项目的开发规范、代码质量标准和审查流程，旨在确保代码质量、可维护性和团队协作效率。

---

## 代码规范

### Rust 代码风格

#### 基础规范
- **格式化**: 使用 `cargo fmt` 自动格式化，基于官方 `rustfmt` 配置
- **Linting**: 使用 `cargo clippy` 进行代码检查，所有警告必须修复
- **命名约定**: 遵循 Rust 官方命名约定 (RFC 430)

#### 具体规范

##### 1. 命名规范
```rust
// ✅ 正确: 结构体使用 PascalCase
pub struct ServiceDiscovery {
    client: ConsulClient,
}

// ✅ 正确: 函数和变量使用 snake_case
pub async fn discover_services(&self, service_name: &str) -> Result<Vec<ServiceInstance>> {
    let service_instances = self.fetch_from_consul().await?;
    Ok(service_instances)
}

// ✅ 正确: 常量使用 SCREAMING_SNAKE_CASE
const MAX_RETRY_ATTEMPTS: u32 = 3;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

// ✅ 正确: 枚举和变体使用 PascalCase
#[derive(Debug, Clone, PartialEq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    WeightedRoundRobin,
    ConsistentHash { virtual_nodes: u32 },
}

// ❌ 错误示例
pub struct serviceDiscovery {} // 应该是 ServiceDiscovery
pub fn discoverServices() {}   // 应该是 discover_services
const maxRetries: u32 = 3;     // 应该是 MAX_RETRIES
```

##### 2. 代码组织
```rust
// ✅ 正确: 模块组织结构
pub mod service_discovery {
    pub mod consul;
    pub mod etcd;
    pub mod kubernetes;

    mod traits;
    mod error;

    pub use traits::{ServiceDiscovery, ServiceInstance};
    pub use error::{ServiceDiscoveryError, Result};
}

// ✅ 正确: 导入顺序
use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::config::ConsulConfig;
use crate::error::DispaError;
```

##### 3. 错误处理
```rust
// ✅ 正确: 使用 Result 类型和 ? 操作符
pub async fn register_service(&self, service: &ServiceInstance) -> Result<()> {
    let response = self.client
        .register_service(service)
        .await
        .map_err(|e| DispaError::ServiceRegistrationFailed(e.to_string()))?;

    if !response.success {
        return Err(DispaError::ServiceRegistrationFailed(response.message));
    }

    Ok(())
}

// ✅ 正确: 自定义错误类型
#[derive(Debug, thiserror::Error)]
pub enum ServiceDiscoveryError {
    #[error("Service registration failed: {0}")]
    RegistrationFailed(String),

    #[error("Service not found: {service_name}")]
    ServiceNotFound { service_name: String },

    #[error("Connection failed: {0}")]
    ConnectionFailed(#[from] std::io::Error),
}

// ❌ 错误示例: 使用 unwrap() 或 expect() (除非在测试中)
let result = risky_operation().unwrap(); // 不推荐在生产代码中使用
```

##### 4. 异步编程
```rust
// ✅ 正确: 异步函数设计
#[async_trait]
pub trait ServiceDiscovery: Send + Sync {
    async fn discover_services(&self, service_name: &str) -> Result<Vec<ServiceInstance>>;
    async fn health_check(&self, service_id: &str) -> Result<HealthStatus>;
}

// ✅ 正确: 使用 tokio 工具
pub struct ConsulServiceDiscovery {
    client: consul::Client,
    health_check_interval: Duration,
    _health_check_task: tokio::task::JoinHandle<()>,
}

impl ConsulServiceDiscovery {
    pub async fn new(config: ConsulConfig) -> Result<Self> {
        let client = consul::Client::new(config.address)?;

        // 启动后台健康检查任务
        let health_check_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                // 健康检查逻辑
            }
        });

        Ok(Self {
            client,
            health_check_interval: config.health_check_interval,
            _health_check_task: health_check_task,
        })
    }
}
```

##### 5. 文档注释
```rust
/// Consul-based service discovery implementation.
///
/// This implementation provides service registration, discovery, and health checking
/// capabilities using HashiCorp Consul as the backend.
///
/// # Examples
///
/// ```rust
/// use dispa::service_discovery::{ConsulServiceDiscovery, ConsulConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = ConsulConfig {
///         address: "http://localhost:8500".to_string(),
///         health_check_interval: Duration::from_secs(30),
///     };
///
///     let discovery = ConsulServiceDiscovery::new(config).await?;
///     let services = discovery.discover_services("api-service").await?;
///
///     println!("Found {} service instances", services.len());
///     Ok(())
/// }
/// ```
pub struct ConsulServiceDiscovery {
    /// Consul HTTP client instance
    client: consul::Client,
    /// Health check interval configuration
    health_check_interval: Duration,
}

impl ConsulServiceDiscovery {
    /// Creates a new Consul service discovery instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Consul configuration including server address and options
    ///
    /// # Returns
    ///
    /// A new `ConsulServiceDiscovery` instance or an error if connection fails.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The Consul server is unreachable
    /// - The provided configuration is invalid
    pub async fn new(config: ConsulConfig) -> Result<Self> {
        // Implementation...
    }
}
```

### 配置和常量管理

#### 配置结构设计
```rust
// ✅ 正确: 配置结构设计
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceDiscoveryConfig {
    /// Enable service discovery functionality
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Service discovery provider type
    pub provider: ServiceDiscoveryProvider,

    /// Consul-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consul: Option<ConsulConfig>,

    /// Service refresh interval in seconds
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ServiceDiscoveryProvider::Consul,
            consul: None,
            refresh_interval: 30,
        }
    }
}

fn default_enabled() -> bool { false }
fn default_refresh_interval() -> u64 { 30 }

// ✅ 正确: 配置验证
impl ServiceDiscoveryConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.enabled && self.consul.is_none() && self.provider == ServiceDiscoveryProvider::Consul {
            return Err(ValidationError::new("Consul config required when provider is Consul"));
        }

        if self.refresh_interval < 5 || self.refresh_interval > 3600 {
            return Err(ValidationError::new("Refresh interval must be between 5 and 3600 seconds"));
        }

        Ok(())
    }
}
```

---

## 测试规范

### 测试策略

#### 测试分层
1. **单元测试**: 测试单个函数或方法
2. **集成测试**: 测试模块间交互
3. **端到端测试**: 测试完整功能流程
4. **性能测试**: 测试性能和资源使用

#### 测试覆盖率要求
- **单元测试覆盖率**: ≥ 85%
- **集成测试覆盖**: 主要功能路径 100%
- **错误路径测试**: 重要错误场景 100%

### 单元测试规范

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use tokio_test;

    /// Test service registration with valid configuration
    #[tokio::test]
    async fn test_register_service_success() {
        // Arrange
        let mut mock_client = MockConsulClient::new();
        mock_client
            .expect_register_service()
            .with(eq(expected_service))
            .times(1)
            .returning(|_| Ok(RegistrationResponse { success: true, message: "".to_string() }));

        let discovery = ConsulServiceDiscovery::new_with_client(mock_client);

        let service = ServiceInstance {
            id: "test-service-1".to_string(),
            name: "test-service".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8080,
            tags: vec!["api".to_string()],
            metadata: HashMap::new(),
            health_check: None,
        };

        // Act
        let result = discovery.register_service(&service).await;

        // Assert
        assert!(result.is_ok(), "Service registration should succeed");
    }

    /// Test service registration failure handling
    #[tokio::test]
    async fn test_register_service_failure() {
        // Arrange
        let mut mock_client = MockConsulClient::new();
        mock_client
            .expect_register_service()
            .returning(|_| Err(ConsulError::ConnectionFailed("Network error".to_string())));

        let discovery = ConsulServiceDiscovery::new_with_client(mock_client);
        let service = create_test_service();

        // Act
        let result = discovery.register_service(&service).await;

        // Assert
        assert!(result.is_err(), "Service registration should fail");
        match result.unwrap_err() {
            DispaError::ServiceRegistrationFailed(msg) => {
                assert!(msg.contains("Network error"), "Error message should contain network error details");
            }
            _ => panic!("Expected ServiceRegistrationFailed error"),
        }
    }

    // Helper function for test data
    fn create_test_service() -> ServiceInstance {
        ServiceInstance {
            id: "test-service-1".to_string(),
            name: "test-service".to_string(),
            address: "127.0.0.1".to_string(),
            port: 8080,
            tags: vec!["api".to_string()],
            metadata: HashMap::new(),
            health_check: Some(HealthCheckConfig {
                interval: Duration::from_secs(10),
                timeout: Duration::from_secs(5),
                endpoint: "/health".to_string(),
            }),
        }
    }
}
```

### 集成测试规范

```rust
// tests/service_discovery_integration_tests.rs
use dispa::service_discovery::{ConsulServiceDiscovery, ConsulConfig};
use testcontainers::{clients::Cli, images::consul::Consul, Container};

/// Integration test with real Consul instance
#[tokio::test]
async fn test_consul_service_discovery_integration() {
    // Setup test environment
    let docker = Cli::default();
    let consul_container: Container<'_, Consul> = docker.run(Consul::default());
    let consul_port = consul_container.get_host_port_ipv4(8500);

    let config = ConsulConfig {
        address: format!("http://localhost:{}", consul_port),
        health_check_interval: Duration::from_secs(10),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
    };

    // Test service discovery lifecycle
    let discovery = ConsulServiceDiscovery::new(config).await.unwrap();

    // Register a test service
    let service = ServiceInstance {
        id: "integration-test-service-1".to_string(),
        name: "integration-test-service".to_string(),
        address: "127.0.0.1".to_string(),
        port: 8080,
        tags: vec!["test".to_string()],
        metadata: HashMap::new(),
        health_check: Some(HealthCheckConfig {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            endpoint: "/health".to_string(),
        }),
    };

    // Test registration
    discovery.register_service(&service).await.unwrap();

    // Test discovery
    let discovered_services = discovery
        .discover_services("integration-test-service")
        .await
        .unwrap();

    assert_eq!(discovered_services.len(), 1);
    assert_eq!(discovered_services[0].id, "integration-test-service-1");

    // Test deregistration
    discovery.deregister_service("integration-test-service-1").await.unwrap();

    // Verify service is removed
    let services_after_removal = discovery
        .discover_services("integration-test-service")
        .await
        .unwrap();

    assert_eq!(services_after_removal.len(), 0);
}
```

### 性能测试规范

```rust
// benches/service_discovery_benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dispa::service_discovery::ConsulServiceDiscovery;

fn benchmark_service_discovery(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("consul_service_discovery_register", |b| {
        b.to_async(&runtime).iter(|| async {
            let discovery = create_test_discovery().await;
            let service = create_test_service();

            black_box(discovery.register_service(&service).await.unwrap());
        });
    });

    let mut group = c.benchmark_group("service_discovery_scale");
    for service_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("discover_services", service_count),
            service_count,
            |b, &service_count| {
                b.to_async(&runtime).iter(|| async {
                    let discovery = create_test_discovery_with_services(service_count).await;

                    black_box(discovery.discover_services("test-service").await.unwrap());
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, benchmark_service_discovery);
criterion_main!(benches);
```

---

## Git 工作流程

### 分支模型

#### 主要分支
- **main**: 主分支，包含稳定的生产代码
- **develop**: 开发分支，集成最新的开发功能

#### 辅助分支
- **feature/**: 功能分支，从 develop 分出，完成后合并回 develop
- **release/**: 发布分支，准备新版本发布
- **hotfix/**: 热修复分支，修复生产环境紧急问题

#### 分支命名规范
```bash
# 功能分支
feature/sprint-1.1-consul-integration
feature/phase2-oauth2-integration

# 发布分支
release/v0.2.0
release/v0.3.0

# 热修复分支
hotfix/v0.2.1-security-fix
hotfix/v0.3.1-performance-fix

# 个人开发分支 (可选)
dev/username/feature-name
```

### 提交规范

#### 提交消息格式
```
<type>(<scope>): <subject>

<body>

<footer>
```

#### 提交类型
- **feat**: 新功能
- **fix**: 错误修复
- **docs**: 文档更新
- **style**: 代码格式修改 (不影响功能)
- **refactor**: 代码重构
- **perf**: 性能优化
- **test**: 测试相关
- **chore**: 构建和工具相关

#### 提交示例
```bash
feat(service-discovery): add Consul service registration support

- Implement ConsulServiceDiscovery struct
- Add service registration and deregistration methods
- Include health check integration
- Add comprehensive error handling

Closes #123
```

```bash
fix(load-balancer): resolve consistent hash ring node removal issue

The consistent hash balancer was not properly removing virtual nodes
when a backend server was marked as unhealthy, causing requests to
be routed to unavailable servers.

- Fix virtual node cleanup in remove_node method
- Add unit tests for node removal scenarios
- Update documentation for hash ring management

Fixes #456
```

### Pull Request 流程

#### PR 标题格式
```
[Sprint X.Y] Brief description of changes
```

#### PR 模板
```markdown
## 描述
简要描述此 PR 的主要变更内容。

## 变更类型
- [ ] Bug 修复
- [ ] 新功能
- [ ] 破坏性变更
- [ ] 文档更新
- [ ] 性能优化
- [ ] 重构

## 测试
- [ ] 单元测试已添加/更新
- [ ] 集成测试已添加/更新
- [ ] 手动测试已完成
- [ ] 性能测试已完成 (如适用)

## 检查清单
- [ ] 代码遵循项目编码规范
- [ ] 自我代码审查已完成
- [ ] 代码已添加必要注释
- [ ] 相关文档已更新
- [ ] 没有引入新的编译警告
- [ ] 所有测试均已通过

## 关联问题
Closes #issue_number

## 截图 (如适用)
添加截图以帮助解释您的更改。

## 额外说明
任何审查者应该知道的额外信息。
```

---

## 代码审查标准

### 审查角色

#### 审查者职责
1. **代码质量检查**: 确保代码符合项目标准
2. **逻辑正确性验证**: 验证实现逻辑是否正确
3. **性能影响评估**: 评估变更对性能的影响
4. **安全性检查**: 识别潜在的安全风险
5. **可维护性评估**: 评估代码的可读性和可维护性

#### 作者职责
1. **自我审查**: 提交前进行充分的自我审查
2. **测试完整性**: 确保测试覆盖率和质量
3. **文档更新**: 同步更新相关文档
4. **响应反馈**: 及时响应审查意见并修改

### 审查检查清单

#### 代码质量检查
- [ ] 代码符合 Rust 编码规范
- [ ] 变量和函数命名清晰有意义
- [ ] 代码结构合理，模块划分清晰
- [ ] 没有代码重复 (DRY 原则)
- [ ] 错误处理完整且合理
- [ ] 没有使用 `unwrap()` 或 `expect()` (除非在测试中)
- [ ] 所有公共 API 都有文档注释

#### 功能正确性检查
- [ ] 实现逻辑符合需求
- [ ] 边界条件处理正确
- [ ] 错误场景处理完整
- [ ] 并发安全性考虑充分
- [ ] 资源管理 (内存、文件句柄等) 正确

#### 性能检查
- [ ] 没有不必要的性能开销
- [ ] 算法复杂度合理
- [ ] 内存使用效率
- [ ] 避免不必要的内存分配
- [ ] 异步操作使用得当

#### 安全性检查
- [ ] 输入验证充分
- [ ] 没有 SQL 注入或其他注入风险
- [ ] 敏感信息不会泄露
- [ ] 认证和授权检查正确
- [ ] 依赖库安全性

#### 测试检查
- [ ] 单元测试覆盖率充足
- [ ] 测试用例覆盖主要场景
- [ ] 错误路径测试完整
- [ ] 测试数据和 mock 合理
- [ ] 性能测试 (如需要)

### 审查流程

#### 审查请求
```bash
# 创建 PR
git checkout -b feature/consul-integration
# ... 开发工作 ...
git push origin feature/consul-integration
# 在 GitHub 创建 Pull Request
```

#### 审查过程
1. **自动检查**: CI 管道运行自动化检查
   - 编译检查
   - 格式化检查 (`cargo fmt --check`)
   - Lint 检查 (`cargo clippy`)
   - 测试运行 (`cargo test`)
   - 安全扫描 (`cargo audit`)

2. **人工审查**: 指定审查者进行代码审查
   - 至少 1 个审查者批准 (简单修改)
   - 至少 2 个审查者批准 (重要功能)
   - 架构变更需要主开发者批准

3. **反馈处理**: 作者根据反馈修改代码
   - 及时响应审查意见
   - 逐项处理反馈问题
   - 必要时进行讨论澄清

4. **最终批准**: 所有检查通过，获得批准
   - 所有 CI 检查通过
   - 所有审查者批准
   - 没有未解决的讨论

#### 合并策略
- **Squash and merge**: 功能分支合并到 develop
- **Create merge commit**: 发布分支合并到 main
- **Rebase and merge**: 热修复合并到 main

### 审查意见分类

#### 意见严重程度
1. **Must Fix** 🚨: 必须修复才能合并
   - 功能错误
   - 安全问题
   - 性能严重问题
   - 编码规范严重违反

2. **Should Fix** ⚠️: 建议修复
   - 代码可读性问题
   - 轻微性能问题
   - 文档不完整
   - 测试覆盖不足

3. **Consider** 💭: 考虑改进
   - 代码结构优化建议
   - 替代实现方案
   - 未来改进建议

#### 意见表达示例
```markdown
🚨 **Must Fix**: 这里存在潜在的空指针解引用风险
建议添加 null 检查或使用 Option 类型。

⚠️ **Should Fix**: 函数名 `do_stuff` 不够描述性
建议改为更具描述性的名称，如 `process_service_request`。

💭 **Consider**: 考虑使用 HashMap 替代 Vec 来提高查找性能
当服务实例数量较大时，这可能会有显著的性能提升。
```

---

## 质量保证

### 自动化检查

#### Pre-commit Hook
```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "Running pre-commit checks..."

# Format check
echo "Checking code format..."
cargo fmt -- --check
if [ $? -ne 0 ]; then
    echo "❌ Code format check failed. Please run 'cargo fmt'"
    exit 1
fi

# Clippy check
echo "Running clippy..."
cargo clippy -- -D warnings
if [ $? -ne 0 ]; then
    echo "❌ Clippy check failed. Please fix warnings"
    exit 1
fi

# Test check
echo "Running tests..."
cargo test
if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Please fix failing tests"
    exit 1
fi

echo "✅ All pre-commit checks passed"
```

#### CI 管道检查
```yaml
# .github/workflows/quality.yml
name: Quality Checks

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy

    - name: Format Check
      run: cargo fmt -- --check

    - name: Clippy Check
      run: cargo clippy -- -D warnings

    - name: Test
      run: cargo test --verbose

    - name: Test Coverage
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out xml --output-dir coverage/

    - name: Security Audit
      run: |
        cargo install cargo-audit
        cargo audit

    - name: Dependency Check
      run: cargo outdated --exit-code 1
```

### 质量指标监控

#### 代码质量指标
- **圈复杂度**: 单个函数不超过 10
- **函数长度**: 单个函数不超过 50 行
- **文件长度**: 单个文件不超过 1000 行
- **参数数量**: 函数参数不超过 7 个

#### 测试质量指标
- **单元测试覆盖率**: ≥ 85%
- **分支覆盖率**: ≥ 80%
- **测试执行时间**: 完整测试套件 < 5 分钟
- **测试稳定性**: 99% 通过率 (非随机失败)

#### 性能指标
- **编译时间**: 完整编译 < 2 分钟
- **二进制大小**: Release 版本 < 50MB
- **启动时间**: < 1 秒
- **内存使用**: 空载 < 20MB

---

## 文档规范

### 文档分类
1. **API 文档**: Rust doc 生成的 API 文档
2. **用户文档**: 使用指南和配置说明
3. **开发者文档**: 架构设计和贡献指南
4. **运维文档**: 部署和维护指南

### 文档更新要求
- **API 变更**: 必须更新相关文档
- **配置变更**: 必须更新配置文档和示例
- **新功能**: 必须添加使用文档和示例
- **破坏性变更**: 必须更新迁移指南

### 文档质量标准
- **准确性**: 文档与代码实现一致
- **完整性**: 覆盖所有公共 API 和功能
- **可读性**: 清晰的结构和表达
- **示例**: 包含实际可运行的代码示例

---

## 安全规范

### 代码安全
1. **输入验证**: 所有外部输入必须验证
2. **错误处理**: 不泄露敏感信息
3. **依赖管理**: 定期更新和审计依赖
4. **秘密管理**: 不在代码中硬编码秘密

### 安全审查
1. **依赖审计**: 每周运行 `cargo audit`
2. **代码扫描**: 使用静态分析工具
3. **安全测试**: 针对安全功能的专项测试
4. **漏洞响应**: 24 小时内响应安全问题

---

## 工具配置

### 开发环境配置

#### VS Code 配置 (`.vscode/settings.json`)
```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.checkOnSave.allTargets": false,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll": true
    },
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer",
        "editor.rulers": [100]
    }
}
```

#### Rustfmt 配置 (`rustfmt.toml`)
```toml
edition = "2021"
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Default"
reorder_imports = true
reorder_modules = true
remove_nested_parens = true
merge_derives = true
use_try_shorthand = true
use_field_init_shorthand = true
force_explicit_abi = true
empty_item_single_line = true
struct_lit_single_line = true
fn_single_line = false
where_single_line = false
imports_layout = "Vertical"
merge_imports = false
```

#### Clippy 配置 (`clippy.toml`)
```toml
msrv = "1.70.0"
avoid-breaking-exported-api = true
disallowed-methods = [
    "std::env::set_var",
    "std::process::exit",
]
```

---

## 执行和监督

### 规范执行
1. **自动化检查**: CI 管道强制执行基本规范
2. **代码审查**: 人工审查确保规范遵守
3. **定期审计**: 月度代码质量审计
4. **培训更新**: 定期团队培训和规范更新

### 违规处理
1. **轻微违规**: 代码审查阶段纠正
2. **重复违规**: 团队讨论和额外培训
3. **严重违规**: 拒绝合并，要求重新开发

### 规范更新
1. **社区反馈**: 收集团队和社区意见
2. **定期评审**: 季度规范评审和更新
3. **版本控制**: 规范文档版本化管理
4. **变更通知**: 规范变更及时通知团队

---

**文档状态**: 🟢 正式生效
**最后更新**: 2024-09-25
**下次评审**: 2024-12-25
**维护责任**: 技术负责人和开发团队