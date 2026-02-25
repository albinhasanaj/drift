#!/usr/bin/env bash
#
# Cortex TypeScript Quality Gate — mirrors the Rust quality-gate.sh
# Usage: ./scripts/quality-gate.sh
#
# Runs: Prettier (fmt), TypeScript (check), ESLint (clippy), Vitest (test)
# Exit code 0 = gate passed. Non-zero = gate failed.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILURES=0

echo -e "${YELLOW}=== TypeScript Quality Gate: packages/cortex ===${NC}"

run_check() {
    local name="$1"
    shift
    echo -e "\n${YELLOW}[$name]${NC} $*"
    if "$@"; then
        echo -e "${GREEN}  ✓ $name passed${NC}"
    else
        echo -e "${RED}  ✗ $name FAILED${NC}"
        FAILURES=$((FAILURES + 1))
    fi
}

# ─── 1. Formatting (Prettier) ───────────────────────────────
# Zero tolerance. Matches Rust `cargo fmt --check`.
run_check "prettier" npx prettier --check "src/**/*.ts"

# ─── 2. Type Checking (tsc) ─────────────────────────────────
# Must compile with zero errors. Matches Rust `cargo check`.
run_check "typecheck" npx tsc --noEmit

# ─── 3. Linting (ESLint strict) ─────────────────────────────
# Warnings are errors. Matches Rust `cargo clippy -D warnings`.
# Catches: unused vars, unsafe any, floating promises, type safety.
run_check "eslint" npx eslint src/

# ─── 4. Tests (Vitest) ──────────────────────────────────────
# All tests must pass. Matches Rust `cargo test`.
run_check "test" npx vitest run

# ─── Summary ─────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}  ✓ TS QUALITY GATE PASSED — all checks clean${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
else
    echo -e "${RED}  ✗ TS QUALITY GATE FAILED — $FAILURES check(s) failed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
