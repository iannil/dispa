#!/bin/bash

# Quality assurance script for dispa project
# Runs all quality checks that are also performed by the git pre-commit hook

echo "🔍 Running full quality assurance checks for dispa..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in a Rust project
if [ ! -f "Cargo.toml" ]; then
    print_error "Cargo.toml not found. This script is designed for Rust projects."
    exit 1
fi

# Initialize counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to run a check
run_check() {
    local name="$1"
    local cmd="$2"
    local required="${3:-true}"

    echo ""
    print_status "Running $name..."

    if eval "$cmd"; then
        print_success "$name passed"
        PASSED=$((PASSED + 1))
        return 0
    else
        if [ "$required" = "true" ]; then
            print_error "$name failed"
            FAILED=$((FAILED + 1))
        else
            print_warning "$name had issues (non-critical)"
            WARNINGS=$((WARNINGS + 1))
        fi
        return 1
    fi
}

echo "Starting comprehensive quality checks..."
echo "======================================"

# 1. Clean previous builds
print_status "Cleaning previous builds..."
cargo clean
print_success "Cleaned previous builds"

# 2. Format check
run_check "Code formatting check" "cargo fmt --all -- --check"

# 3. Clippy linting
run_check "Clippy linting (all warnings as errors)" "cargo clippy --all-targets --all-features -- -D warnings"

# 4. Basic cargo check
run_check "Cargo check (debug)" "cargo check --verbose"

# 5. Run tests
run_check "Unit and integration tests" "cargo test --verbose"

# 6. Documentation tests
run_check "Documentation tests" "cargo test --doc --verbose" "false"

# 7. Release build
run_check "Release build" "cargo build --verbose --release"

# 8. Check for security vulnerabilities (if cargo-audit is installed)
if command -v cargo-audit &> /dev/null; then
    run_check "Security audit" "cargo audit" "false"
else
    print_warning "cargo-audit not installed. Run 'cargo install cargo-audit' to enable security checks"
    WARNINGS=$((WARNINGS + 1))
fi

# 9. Check for outdated dependencies (if cargo-outdated is installed)
if command -v cargo-outdated &> /dev/null; then
    run_check "Outdated dependencies check" "cargo outdated" "false"
else
    print_warning "cargo-outdated not installed. Run 'cargo install cargo-outdated' to enable dependency checks"
    WARNINGS=$((WARNINGS + 1))
fi

# 10. License check (if cargo-license is installed)
if command -v cargo-license &> /dev/null; then
    run_check "License compatibility check" "cargo license" "false"
else
    print_warning "cargo-license not installed. Run 'cargo install cargo-license' to enable license checks"
    WARNINGS=$((WARNINGS + 1))
fi

# 11. Check for unused dependencies (if cargo-udeps is installed)
if command -v cargo-udeps &> /dev/null; then
    run_check "Unused dependencies check" "cargo +nightly udeps" "false"
else
    print_warning "cargo-udeps not installed. Run 'cargo install cargo-udeps' to enable unused dependency checks"
    WARNINGS=$((WARNINGS + 1))
fi

# Additional checks
echo ""
print_status "Running additional code quality checks..."

# Check for common issues in Rust code
print_status "Checking for debugging statements..."
if find src -name "*.rs" -exec grep -l "println!\|dbg!\|eprintln!" {} \; | head -5; then
    print_warning "Found debugging print statements. Consider removing them."
    WARNINGS=$((WARNINGS + 1))
else
    print_success "No debugging statements found"
fi

print_status "Checking for TODO/FIXME comments..."
if find src -name "*.rs" -exec grep -l "TODO\|FIXME" {} \; | head -5; then
    print_warning "Found TODO/FIXME comments. Consider addressing them."
    WARNINGS=$((WARNINGS + 1))
else
    print_success "No TODO/FIXME comments found"
fi

# Check Cargo.toml for basic best practices
print_status "Checking Cargo.toml configuration..."
if grep -q "edition.*2021" Cargo.toml; then
    print_success "Using Rust 2021 edition"
else
    print_warning "Consider upgrading to Rust 2021 edition"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
echo ""
echo "======================================"
echo "Quality Assurance Summary"
echo "======================================"

if [ $FAILED -eq 0 ]; then
    print_success "🎉 All critical checks passed! ($PASSED passed)"
    if [ $WARNINGS -gt 0 ]; then
        print_warning "⚠️  $WARNINGS warning(s) found - consider addressing them"
    fi
    echo ""
    print_success "✅ Code is ready for commit!"
    exit 0
else
    print_error "❌ $FAILED critical check(s) failed, $PASSED passed"
    if [ $WARNINGS -gt 0 ]; then
        print_warning "⚠️  $WARNINGS warning(s) found"
    fi
    echo ""
    print_error "🚫 Please fix the issues before committing"
    echo ""
    echo "Quick fixes:"
    echo "  - Format: cargo fmt --all"
    echo "  - Linting: cargo clippy --all-targets --all-features --fix"
    echo "  - Check: cargo check"
    echo "  - Test: cargo test"
    exit 1
fi