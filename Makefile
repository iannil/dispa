# Makefile for dispa project
# Provides convenient commands for development and quality assurance

.PHONY: help build test test-doc test-all check fmt clippy clean qa install-tools pre-commit release

# Default target
help:
	@echo "Dispa Development Commands"
	@echo "=========================="
	@echo ""
	@echo "Development:"
	@echo "  build      - Build the project in debug mode"
	@echo "  release    - Build the project in release mode"
	@echo "  test       - Run unit and integration tests"
	@echo "  test-doc   - Run documentation tests"
	@echo "  test-all   - Run all tests (unit, integration, doc)"
	@echo "  check      - Quick compilation check"
	@echo "  run        - Run the project with default config"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt        - Format all code"
	@echo "  clippy     - Run clippy linter"
	@echo "  qa         - Run comprehensive quality checks"
	@echo "  pre-commit - Run pre-commit checks manually"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean      - Clean build artifacts"
	@echo "  install-tools - Install recommended development tools"
	@echo "  update     - Update dependencies"
	@echo ""
	@echo "Git Hooks:"
	@echo "  install-hooks - Install git hooks (already done)"
	@echo ""

# Build commands
build:
	@echo "🔨 Building dispa (debug mode)..."
	cargo build

release:
	@echo "🔨 Building dispa (release mode)..."
	cargo build --release

# Test commands
test:
	@echo "🧪 Running unit and integration tests..."
	cargo test --workspace --all-targets --verbose

test-doc:
	@echo "📚 Running documentation tests..."
	cargo test --doc --verbose

test-all: test test-doc
	@echo "✅ All tests completed!"

# Development commands
check:
	@echo "✅ Running quick check..."
	cargo check

run:
	@echo "🚀 Running dispa with example config..."
	cargo run -- --help

# Code quality commands
fmt:
	@echo "🎨 Formatting code..."
	cargo fmt --all

clippy:
	@echo "📎 Running clippy..."
	cargo clippy --all-targets --all-features -- -D warnings

qa:
	@echo "🔍 Running comprehensive quality assurance..."
	@./scripts/qa.sh

pre-commit:
	@echo "🎯 Running pre-commit checks..."
	@./.git/hooks/pre-commit

# Maintenance commands
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean

update:
	@echo "📦 Updating dependencies..."
	cargo update

install-tools:
	@echo "🛠️  Installing recommended development tools..."
	@echo "Installing cargo-audit for security auditing..."
	-cargo install cargo-audit
	@echo "Installing cargo-outdated for dependency checking..."
	-cargo install cargo-outdated
	@echo "Installing cargo-license for license checking..."
	-cargo install cargo-license
	@echo "Installing cargo-udeps for unused dependency detection..."
	-cargo install cargo-udeps
	@echo "Installing cargo-tarpaulin for code coverage..."
	-cargo install cargo-tarpaulin
	@echo "✅ Tool installation complete!"

install-hooks:
	@echo "🎣 Git hooks are already installed!"
	@echo "Pre-commit hook: .git/hooks/pre-commit"
	@echo "Pre-push hook: .git/hooks/pre-push"

# Specific development tasks
dev-setup: install-tools
	@echo "🎯 Setting up development environment..."
	@echo "Updating dependencies..."
	cargo update
	@echo "Running initial build..."
	cargo build
	@echo "Running tests to verify setup..."
	cargo test
	@echo "✅ Development environment ready!"

# CI simulation
ci:
	@echo "🤖 Simulating CI environment..."
	make clean
	make fmt
	make clippy
	make test
	make build
	make release
	@echo "✅ CI simulation complete!"

# Documentation
docs:
	@echo "📖 Generating documentation..."
	cargo doc --open

# Performance testing
bench:
	@echo "🏃‍♂️ Running benchmarks..."
	cargo bench

# Security audit
audit:
	@echo "🔒 Running security audit..."
	cargo audit

# Check for outdated dependencies
outdated:
	@echo "📅 Checking for outdated dependencies..."
	cargo outdated

# Generate license report
license:
	@echo "📄 Generating license report..."
	cargo license

# All quality checks (comprehensive)
all-checks: fmt clippy test audit outdated
	@echo "✅ All quality checks completed!"

# Quick development cycle
quick: fmt check test
	@echo "⚡ Quick development cycle complete!"
