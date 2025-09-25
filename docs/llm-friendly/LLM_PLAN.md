# LLM 友好化改造规划

以下是一份面向“让大模型读得懂、改得动”的 LLM 友好化改造计划，兼顾你仓库现状与落地可操作性。

  现状亮点

- 文档体系完整：README、用户/开发手册、API、安全、插件、ROADMAP；已有专门的 LLM 指南与模板 docs/llm-
  friendly/*（如 docs/llm-friendly/LLM_GUIDE.md、CODE_TEMPLATES.md）
- 代码结构清晰：模块化良好，crate 级文档已补全（src/lib.rs），入口简洁（src/main.rs、src/
  app_state.rs）
- 质量基线扎实：CI/QA、clippy、fmt、测试用例与分离的 examples/*、scripts/qa.sh

  主要短板（LLM视角）

- 上下文裁剪工具缺失：LLM很难快速聚焦“只与任务相关的子集代码/文档”
- 符号/接口索引不足：缺少一份“公开符号/边界/不变量/并发约束”的机器/人两用概览
- 文档→测试→代码的“任务模板/流水线”不成套：有 LLM 文档，但缺“任务输入/接受标准/验证命令”的结构化模板
  +脚本
- 规范“落地到CI”的力度稍弱：缺 missing_docs、unwrap_used 等逐步硬化策略及白名单化出路
- 配置的机器可读规范缺少：TOML 很好，但缺 JSON Schema/Schema 测试，LLM易误配

  目标

- 让模型“读得快”：最小上下文包+架构/符号索引+关键不变量
- 让模型“改得对”：任务模板+接受标准+一键验证脚本
- 让模型“出错早”：规则硬化到CI，错误信息有上下文且定位友好
- 让模型“可复用”：示例/模板/脚手架统一可复用

  分阶段实施计划

  Phase 1（本周）：上下文打包与符号索引

- LLM 上下文打包器
  - 新增 scripts/llm-pack.sh：基于 ripgrep/fd 生成“任务最小上下文包”，按模块/话题打包 src/*、相关文
  档、配置片段；默认排除 target、logs、tests 大文件夹，支持 include/exclude globs
  - 产出 `artifacts/llm-context/<topic>/{files.txt,summary.md,pack.zip}`
  - summary.md 自动汇总：模块说明、关键类型/函数签名、入口文件、相关配置项
- 符号/接口索引
  - 新增 scripts/gen-symbols-index.sh：提取 pub struct|enum|trait|fn、特性开关、cfg gate，生成
  docs/SYMBOLS.md
  - 输出每个公开符号所在文件、简述（从 rustdoc 第一行抽取）、相关 feature、常见调用点（rg 反向索引
  Top-N）
- 模块级 LLM 前言块
  - 在每个模块 mod.rs 顶部补充“LLM 前言块”，包含：职责、输入输出、并发与锁策略、不变量、边界条件、
  易错点、相关配置/Feature
  - 目标文件夹：src/proxy, src/balancer, src/monitoring, src/plugins, src/security, src/cache,
  src/routing

  可验证交付

- 运行 bash scripts/llm-pack.sh topic=plugins 生成最小包
- 生成 docs/SYMBOLS.md 并在 README 中链接

  Phase 2（下周）：任务模板与验证流水线

- 任务/PR 模板
  - .github/ISSUE_TEMPLATE/llm_task.md：问题背景、修改范围、相关模块、验收标准、风险、回滚
  - .github/PULL_REQUEST_TEMPLATE.md：变更概览、对照验收标准、影响面、验证命令、文档更新勾选项
- 一键验证脚本（面向 LLM）
  - 新增 scripts/verify.sh：统一调用 cargo check/test/fmt/clippy/doc、文档死链检查、示例构建；接
  受 --fast/--full
  - 在 scripts/qa.sh 基础上简化输出结构/失败重试提示，面向 LLM 更友好
- docs/llm-friendly/TASK_GUIDE.md
  - 定义“如何提交一个 LLM 任务”：输入格式（上下文包+变更意图+验收标准）、输出格式（变更清单+文件清
  单+验证命令+失败处理）

  可验证交付

- 新增 issue/pr 模板生效；本地 bash scripts/verify.sh --fast 通过

  Phase 3（2-3周）：文档硬化与配置 Schema

- 渐进式文档硬化
  - 在 src/lib.rs 开启 #![warn(missing_docs)]（先 warn 不阻断）
  - 在 CI 中新增“文档覆盖率报告”（统计 pub 符号 rustdoc 覆盖率），阈值逐步提升（例如 60%→80%）
- unwrap/panic 守卫
  - 在 CI clippy 增加 unwrap_used 警告（生产代码），保留 tests/ 目录白名单
  - docs/llm-friendly/ERROR_HANDLING.md：提供错误处理模板/统一分类（已使用 thiserror，可沉淀错误分
  类表）
- 配置 Schema + 校验
  - 新增 config/schema/dispa.schema.json（覆盖 config/config.toml 的结构）与脚本 scripts/validate-
  config.sh（用 djv 或 ajv 等本地工具；若无网络，使用 pure Rust 或最简 Python 校验）
  - CI 增加“示例配置”校验：config/*.toml 均需通过 Schema 校验；docs/CONFIG.md 链接 Schema

  可验证交付

- CI 出具缺文档/unwrap 使用统计；bash scripts/validate-config.sh config/config.toml 通过

  Phase 4（3-4周）：开发者/模型协同与可演练用例

- 可演练 E2E 用例
  - tests/spec/* 增加 BDD/Golden 测试（给定配置+请求→期望响应/指标），覆盖拦截/路由/均衡/插件/安全/
  缓存关键路径
  - examples/ 下补充“最小可运行场景”，与 docs/QUICKSTART.md 双向指向
- 变更影响半自动评估
  - scripts/impact-map.sh：根据改动文件列出“潜在影响模块+应运行的测试套件+文档需更新列表”，用于 PR
  机器人消息模板
- 设计决策沉淀
  - docs/adr/ADR-XXXX-*.md 记录关键取舍（并发模型、插件短路策略、TLS 边界、鉴权模式），LLM 变更前可
  参考

  可验证交付

- 新增 spec 测试可本地一键跑通，PR 机器人输出影响面提示

  跨阶段的微改动（建议立即开始）

- 文件头统一“LLM提示区块”模版（已在 Phase 1 列出）；先从 src/proxy、src/plugins 两个最常改动模块开始
- 统一命名与单位
  - 对配置类字段补齐单位后缀（如 ms），布尔开关统一 enable，与 docs/llm-friendly/
  NAMING_CONVENTIONS.md 对齐
  - 在 docs/CONFIG.md 中维护“字段→单位/默认值/范围→示例”表，配合 Schema 校验
- Intra-doc 链接与示例
  - 在 rustdoc 中使用 intra-doc links（[crate::module::Type]），给关键 pub API 补简短可运行 doctest

  拟新增文件/修改点

- scripts/llm-pack.sh（新增）
- scripts/gen-symbols-index.sh（新增）
- scripts/verify.sh（新增）
- docs/SYMBOLS.md（生成）
- docs/llm-friendly/TASK_GUIDE.md（新增）
- config/schema/dispa.schema.json（新增）
- .github/ISSUE_TEMPLATE/llm_task.md（新增）
- .github/PULL_REQUEST_TEMPLATE.md（新增）
- src/*/mod.rs 顶部补 LLM 前言块（逐步推进）
- src/lib.rs：启用 #![warn(missing_docs)]（先警告）

  验收标准（样例）

- 输入最小化：给定 “plugins: 新增 header 修改” 任务，scripts/llm-pack.sh topic=plugins 打包输出小于
  1MB，且包含 src/plugins/* + docs/PLUGINS.md 及相关配置片段
- 文档覆盖率：公开符号 rustdoc 覆盖率首月 ≥60%，两个月内 ≥80%
- 配置健壮性：所有示例配置通过 Schema 校验；CI 对新增/变更配置项要求同步更新 Schema 与文档
- 一键验证：bash scripts/verify.sh --fast ≤60s 返回，失败时输出“修复指引+相关测试建议”

  可选增强

- 语义提交/变更日志：conventional commits + auto-changelog，LLM 输出 PR 时直接复用
- 本地 call graph/依赖图：生成 docs/dep-graph.svg（cargo-deps/cargo-modules），帮助 LLM 识别边界
- mdBook 文档站：将 docs/* 汇编为 mdBook，统一导航与搜索（离线亦可）

  需要你确认

  1. 是否同意我先落地 Phase 1 的两个脚本（llm-pack 与符号索引）和 docs/SYMBOLS.md 的初版？
  2. 命名规范与配置字段单位后缀，是否希望一次性改动（可能带来破坏性变更），还是采用“新增同义字段+旧字段
  deprecated”的平滑迁移策略？
