# Git Hooks for Dispa

这个目录包含了为 Dispa 项目配置的 Git hooks，用于确保代码质量和一致性。

## 安装的 Hooks

### Pre-commit Hook

- **文件**: `.git/hooks/pre-commit`
- **触发时机**: 每次运行 `git commit` 时
- **检查内容**:
  - 代码格式化检查 (`cargo fmt --all -- --check`)
  - Clippy 代码检查 (`cargo clippy --all-targets --all-features -- -D warnings`)
  - 编译检查 (`cargo check --verbose`)
  - 单元测试 (`cargo test --verbose`)
  - 发布构建 (`cargo build --verbose --release`)
  - 代码质量检查（调试语句、TODO注释等）

### Pre-push Hook

- **文件**: `.git/hooks/pre-push`
- **触发时机**: 每次运行 `git push` 时
- **检查内容**:
  - 主分支保护：对 main/master 分支进行严格检查
  - 功能分支：对其他分支进行基础编译检查
  - 版本发布检测：自动检测版本发布相关的提交

## 使用方式

### 正常开发流程

1. **代码开发**

   ```bash
   # 修改代码
   vim src/lib.rs

   # 定期运行检查（可选）
   cargo check
   cargo test
   ```

2. **提交代码**

   ```bash
   git add .
   git commit -m "feat: add new feature"
   # 这会自动触发 pre-commit hook
   ```

3. **推送代码**

   ```bash
   git push origin feature-branch
   # 这会自动触发 pre-push hook
   ```

### 如果 Hook 失败

当 Git hook 失败时，你会看到详细的错误信息。根据错误类型进行修复：

#### 格式化错误

```bash
# 自动修复格式化问题
cargo fmt --all

# 重新提交
git commit -m "your message"
```

#### Clippy 警告

```bash
# 查看并修复 Clippy 警告
cargo clippy --all-targets --all-features

# 某些情况下可以自动修复
cargo clippy --all-targets --all-features --fix

# 重新提交
git commit -m "your message"
```

#### 编译错误

```bash
# 查看编译错误详情
cargo check --verbose

# 修复错误后重新提交
git commit -m "your message"
```

#### 测试失败

```bash
# 运行测试查看失败详情
cargo test --verbose

# 修复测试后重新提交
git commit -m "your message"
```

### 跳过 Hook（紧急情况）

⚠️ **不推荐**，但在紧急情况下可以跳过 hook：

```bash
# 跳过 pre-commit hook
git commit --no-verify -m "emergency fix"

# 跳过 pre-push hook
git push --no-verify origin branch-name
```

## 手动运行检查

你可以手动运行与 hook 相同的检查：

### 运行 Pre-commit 检查

```bash
./.git/hooks/pre-commit
```

### 运行完整的质量检查

```bash
./scripts/qa.sh
```

### 使用 Makefile 命令

```bash
# 快速开发循环
make quick

# 完整质量检查
make qa

# 模拟 CI 环境
make ci
```

## Hook 配置文件

- **Pre-commit hook**: `.git/hooks/pre-commit`
- **Pre-push hook**: `.git/hooks/pre-push`
- **QA 脚本**: `scripts/qa.sh`
- **Makefile**: `Makefile`

## 常见问题

### Q: Hook 运行很慢怎么办？

A: Hook 会运行完整的构建和测试，这是确保代码质量的必要步骤。你可以：

- 在开发过程中更频繁地运行 `cargo check` 和 `cargo test`
- 使用 `make quick` 进行快速检查

### Q: 可以修改 Hook 的检查项目吗？

A: 可以编辑 `.git/hooks/pre-commit` 和 `.git/hooks/pre-push` 文件。但建议保持严格的质量标准。

### Q: 在 CI/CD 中如何处理？

A: GitHub Actions 工作流 (`.github/workflows/`) 会运行相同的检查，确保 CI 和本地环境的一致性。

### Q: 如何在团队中共享这些 Hook？

A: Git hooks 不会自动同步。团队成员需要：

1. 拉取最新代码
2. 运行安装脚本（如果有的话）
3. 或者手动复制 hook 文件

## 推荐工具

安装这些工具可以获得更完整的代码质量检查：

```bash
# 安全审计
cargo install cargo-audit

# 依赖更新检查
cargo install cargo-outdated

# 许可证检查
cargo install cargo-license

# 未使用依赖检查
cargo install cargo-udeps

# 代码覆盖率
cargo install cargo-tarpaulin
```

## 相关文档

- [CLAUDE.md](../CLAUDE.md) - 项目开发指南
- [Makefile](../Makefile) - 便捷开发命令
- [GitHub Actions](.github/workflows/) - CI/CD 配置
