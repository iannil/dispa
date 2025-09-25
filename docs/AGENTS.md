# Repository Guidelines

## Project Structure & Module Organization
- src/: core crate. Key modules: balancer/, proxy/, routing/, cache/, security/, logger/, monitoring/, plugins/, tls/, config/
- tests/: integration/E2E with tokio + wiremock; files end with `_tests.rs`.
- config/: TOML samples (config.toml, plugins-example.toml, routing-plugins-example.toml).
- docs/: user/dev manuals (docs/DEVELOPMENT.md, docs/PLUGINS.md); LLM helpers in docs/llm-friendly/ and LLM.md.
- scripts/: QA helpers (scripts/qa.sh, scripts/test_with_timeout.py). CI in .github/workflows/.

## Environment & Toolchain
- Rust 1.90+; install rustfmt and clippy components.
- First-time setup: `make dev-setup` or `make install-tools` (installs cargo-audit/outdated/license/udeps and verifies build/tests).

## Build, Test, and Development Commands
- `make help` shows all. Common loop: `make quick`.
- Build: `make build` (debug) / `make release` (optimized).
- Tests: `make test` (unit+integration), `make test-doc` (doctests), `make test-all`.
- Quality: `make fmt` (rustfmt), `make clippy` (lint, `-D warnings`), `make qa` (full suite).
- Run locally: `cargo run -- -c config/config.toml -v`.
- Features: `cargo build --features cmd-plugin,wasm-plugin` (see docs/PLUGINS.md).

## Coding Style & Naming Conventions
- rustfmt enforced; clippy must be clean (`-D warnings`).
- Naming: snake_case (fns/vars), CamelCase (types), SCREAMING_SNAKE_CASE (consts); modules lowercased.
- Errors: anyhow/thiserror; avoid `unwrap()` in production paths; prefer small, testable functions.

## Testing Guidelines
- `cargo test`; async via `#[tokio::test]`. Integration lives in `tests/` and commonly uses wiremock.
- Name tests descriptively (e.g., `test_cache_expiration_edge_cases`). Add doctests where useful.
- Optional coverage: cargo tarpaulin (if installed). New logic must include tests.

## Commit & Pull Request Guidelines
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `chore:` (see history).
- Examples: `refactor: complete enhanced_auth.rs modularization`, `chore: 20250924`.
- Hooks: pre-commit runs fmt, clippy, check, tests, release build—keep green. Run `scripts/qa.sh` before PRs.
- PRs: clear description, linked issues, rationale, test evidence, and doc/config updates. CI mirrors local checks (see `.github/workflows/ci.yml`, `qa.yml`).

## Security & Configuration Tips
- Main config: `config/config.toml`; keep secrets out of VCS.
- Prefer rustls; validate external command paths/timeouts for command plugins.
- Optional features: `cmd-plugin`, `wasm-plugin`, `jwt-rs256`, `jwt-rs256-net` (enable only if needed).

## Agent-Specific Notes
- Use ripgrep (`rg`) for navigation; follow patterns in src/ and tests/.
- Keep changes minimal and verifiable; run `make quick` often and `make qa` before committing; see `LLM.md`.
