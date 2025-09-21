WASM 插件示例（PoC）

文件：filter.wat（文本格式）
- 导出函数满足运行时约定：alloc、dealloc、dispa_on_request、dispa_on_response、dispa_get_result_len
- 固定返回 JSON：{"set_headers":{"x-wasm":"1"}}

构建 .wasm
1) 安装 wabt（含 wat2wasm）
2) 转换：
   wat2wasm filter.wat -o filter.wasm

使用（需开启 wasm-plugin 特性）：
1) 在配置中加入：
   [plugins]
   enabled = true
   
   [[plugins.plugins]]
   name = "wasm-filter"
   type = "wasm"
   enabled = true
   stage = "request"
   error_strategy = "continue"
   config = { module_path = "./examples/wasm/filter.wasm", timeout_ms = 200, max_concurrency = 4 }

2) 构建运行：
   cargo run --features wasm-plugin -- -c config/plugins-example.toml -v

Rust 版本 WASM 插件（更易扩展）
- 示例工程：examples/wasm/rust-plugin
- 构建（需要 nightly/稳定 Rust 均可）：
  cargo build -p dispa-wasm-plugin --target wasm32-wasi --release
- 生成的 wasm 路径：`target/wasm32-wasi/release/dispa_wasm_plugin.wasm`
- 配置使用：将 `module_path` 指向该 .wasm 文件
