# Dispa 文档目录

欢迎来到 Dispa 项目文档！本页面包含所有相关文档的导航链接。

> **当前版本**: v0.1.0 | **最后更新**: 2026年1月6日

## 📚 用户文档

### 快速开始
- **[快速开始指南](QUICKSTART.md)** - 5分钟快速上手 Dispa
- **[完整用户手册](USER_MANUAL.md)** - 详细的安装、配置和使用指南
- **[English User Manual](USER_MANUAL_EN.md)** - Complete user manual in English

### 配置和部署
- **[配置文档](CONFIG.md)** - 完整的配置选项说明，包括数据库配置
- **[安全配置](SECURITY.md)** - 访问控制、认证、限流和 DDoS 防护
- **[插件开发指南](PLUGINS.md)** - 插件系统和扩展开发
- **[API 文档](API.md)** - REST API 接口说明

### 监控和管理
- **[管理界面](ADMIN.md)** - Web 管理控制台使用指南
- **[项目状态](PROJECT_STATUS.md)** - 当前功能实现状态和发展规划

## 🛠️ 开发者文档

### 开发指南
- **[开发指南](DEVELOPMENT.md)** - 架构设计和本地开发环境搭建
- **[开发规范](DEVELOPMENT_STANDARDS.md)** - 代码规范、审查标准和最佳实践
- **[贡献者指南](AGENTS.md)** - 开发者与 LLM 代理协作规范

### 工程和运维
- **[CI/CD 配置](CI.md)** - 持续集成和部署流程
- **[Git Hooks](git-hooks.md)** - 代码提交前的自动检查配置

## 📊 项目报告

- **[功能清单](FEATURE_LIST.md)** - 完整的功能特性清单
- **[项目状态](PROJECT_STATUS.md)** - 当前功能实现状态和发展规划
- **[项目梳理报告 2026Q1](PROJECT_REVIEW_2026Q1.md)** - 完整的项目分析和评估报告

## 📁 文档组织结构

```
docs/
├── README.md                    # 本文档索引
├── 用户文档/
│   ├── QUICKSTART.md           # 快速开始
│   ├── USER_MANUAL.md          # 中文用户手册
│   ├── USER_MANUAL_EN.md       # 英文用户手册
│   ├── CONFIG.md               # 配置文档
│   ├── SECURITY.md             # 安全配置
│   ├── PLUGINS.md              # 插件开发
│   ├── API.md                  # API 文档
│   └── ADMIN.md                # 管理界面
├── 开发者文档/
│   ├── DEVELOPMENT.md          # 开发指南
│   ├── DEVELOPMENT_STANDARDS.md # 开发规范
│   ├── AGENTS.md               # 贡献者指南
│   ├── CI.md                   # CI/CD 配置
│   └── git-hooks.md            # Git 钩子配置
├── 项目信息/
│   ├── FEATURE_LIST.md         # 功能清单
│   ├── PROJECT_STATUS.md       # 项目状态和规划
│   └── PROJECT_REVIEW_2026Q1.md # 项目梳理报告
├── archived/                   # 已归档的历史文档
│   ├── ROADMAP.md              # 旧版路线图
│   ├── DEVELOPMENT_PLAN.md     # 历史开发计划
│   ├── MILESTONES.md           # 历史里程碑
│   └── PHASE1_TASKS.md         # 历史任务清单
└── internal/                   # 内部开发文档
    └── llm-friendly/           # LLM 开发辅助文档
        ├── CLAUDE.md           # Claude AI 协作指南
        ├── LLM_GUIDE.md        # LLM 使用指南
        ├── CODE_TEMPLATES.md   # 代码模板
        ├── NAMING_CONVENTIONS.md # 命名规范
        ├── REFACTORING_PLAN.md # 重构计划
        ├── LLM_PLAN.md         # LLM 开发计划
        └── LLM_IMPROVEMENT_REPORT.md # 改进报告
```

## 🔍 如何查找文档

- **新用户**：从 [快速开始指南](QUICKSTART.md) 开始
- **配置问题**：查看 [配置文档](CONFIG.md) 和 [安全配置](SECURITY.md)
- **API 集成**：参考 [API 文档](API.md) 和 [用户手册](USER_MANUAL.md)
- **插件开发**：阅读 [插件开发指南](PLUGINS.md)
- **贡献代码**：查看 [开发指南](DEVELOPMENT.md) 和 [开发规范](DEVELOPMENT_STANDARDS.md)
- **了解进展**：查看 [功能清单](FEATURE_LIST.md)、[项目状态](PROJECT_STATUS.md) 和 [项目梳理报告](PROJECT_REVIEW_2026Q1.md)

## 📝 文档维护

- 所有用户文档应保持最新，与项目实际实现一致
- 已过时的文档移至 `archived/` 目录保存
- 内部开发文档放在 `internal/` 目录
- 文档间的相互引用使用相对路径
- 定期检查链接的有效性

## ❓ 获取帮助

如果文档中没有找到您需要的信息：

1. 查看 [GitHub Issues](https://github.com/iannil/dispa/issues) 中是否有相关讨论
2. 在 [GitHub Discussions](https://github.com/iannil/dispa/discussions) 提出问题
3. 参考项目 [README.md](../README.md) 中的支持信息

---

*最后更新：2026年1月6日*