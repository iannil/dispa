# GitHub Actions 配置说明

本项目包含两个 GitHub Actions 工作流：

## 1. CI 工作流 (`.github/workflows/ci.yml`)

### 触发条件

- 推送到 `master`、`main`、`develop` 分支
- 向 `master`、`main` 分支提交 Pull Request

### 执行任务

- **测试**: 运行所有单元测试和集成测试
- **代码格式检查**: 使用 `rustfmt` 检查代码格式
- **代码质量检查**: 使用 `clippy` 检查代码质量
- **多平台构建**: 在 Linux、Windows、macOS 上构建项目

## 2. Release 工作流 (`.github/workflows/release.yml`)

### 触发条件

- 推送以 `v` 开头的标签 (如 `v1.0.0`, `v1.2.3`)

### 执行任务

#### 创建 Release

- 自动创建 GitHub Release
- 生成发布说明模板

#### 多平台构建

构建以下平台的二进制文件：

- **Linux x86_64**: `dispa-linux-x86_64.tar.gz`
- **Linux ARM64**: `dispa-linux-aarch64.tar.gz`
- **macOS x86_64**: `dispa-macos-x86_64.tar.gz`
- **macOS ARM64**: `dispa-macos-aarch64.tar.gz`
- **Windows x86_64**: `dispa-windows-x86_64.zip`

#### 发布资产上传

- 自动上传所有平台的二进制文件到 Release
- 包含配置示例和文档文件

## 使用方法

### 发布新版本

1. **更新版本号**

   ```bash
   # 编辑 Cargo.toml 中的版本号
   version = "1.0.0"
   ```

2. **提交更改**

   ```bash
   git add Cargo.toml
   git commit -m "bump version to 1.0.0"
   git push origin master
   ```

3. **创建并推送标签**

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

4. **自动发布**
   - GitHub Actions 会自动触发
   - 构建所有平台的二进制文件
   - 创建 Release 并上传资产

### 监控构建状态

- 在 GitHub 仓库的 **Actions** 标签页查看构建状态
- CI 工作流确保代码质量
- Release 工作流自动化发布流程

## 发布包内容

每个发布包包含：

- `dispa` 可执行文件
- `README.md` 项目说明
- `USER_MANUAL.md` 用户手册
- `QUICKSTART.md` 快速开始指南
- `config.example.toml` 配置示例

这个自动化流程确保每次发布都包含完整的多平台支持，提升用户体验。
