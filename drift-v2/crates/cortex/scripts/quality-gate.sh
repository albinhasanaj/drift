#!/usr/bin/env bash
#
# Cortex Quality Gate — runs at the end of every phase.
# Usage: ./scripts/quality-gate.sh [crate-name]
#
# If a crate name is provided, only that crate is checked.
# If omitted, the entire workspace is checked.
#
# Exit code 0 = gate passed. Non-zero = gate failed.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CRATE="${1:-}"
FAILURES=0

if [ -n "$CRATE" ]; then
    TARGET="-p $CRATE"
    echo -e "${YELLOW}=== Quality Gate: $CRATE ===${NC}"
else
    TARGET="--workspace"
    echo -e "${YELLOW}=== Quality Gate: Full Workspace ===${NC}"
fi

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

# ─── 1. Formatting ───────────────────────────────────────────
# Zero tolerance. No formatting debates.
run_check "fmt" cargo fmt --all -- --check

# ─── 2. Compilation ─────────────────────────────────────────
# Must compile with zero errors.
run_check "check" cargo check $TARGET

# ─── 3. Clippy (strict) ─────────────────────────────────────
# Warnings are errors. Catches:
#   - unused variables, imports, mut
#   - redundant clones
#   - suspicious arithmetic
#   - missing error handling
#   - inefficient patterns (e.g. .clone() where borrow works)
run_check "clippy" cargo clippy $TARGET -- \
    -D warnings \
    -D clippy::all \
    -D clippy::pedantic \
    -D clippy::nursery \
    -A clippy::module_name_repetitions \
    -A clippy::must_use_candidate \
    -A clippy::missing_errors_doc \
    -A clippy::missing_panics_doc \
    -A clippy::future_not_send

# ─── 4. Tests ────────────────────────────────────────────────
# All tests must pass. Fail fast on first failure.
run_check "test" cargo test $TARGET

# ─── 5. Doc generation ──────────────────────────────────────
# Catches broken intra-doc links, missing docs on public items,
# and invalid code examples in doc comments.
RUSTDOCFLAGS="-D warnings" run_check "doc" cargo doc $TARGET --no-deps

# ─── 6. License & advisory audit ────────────────────────────
# No unapproved licenses, no known vulnerabilities.
run_check "deny-advisories" cargo deny check advisories
run_check "deny-licenses" cargo deny check licenses
run_check "deny-sources" cargo deny check sources

# ─── 7. Unused dependencies ─────────────────────────────────
# Dead deps slow compilation and bloat binaries.
# Note: machete may false-positive on stub crates with no code yet.
# Use --with-metadata for better accuracy once crates have real code.
if command -v cargo-machete &> /dev/null; then
    echo -e "\n${YELLOW}[machete]${NC} cargo machete --with-metadata"
    if cargo machete --with-metadata; then
        echo -e "${GREEN}  ✓ machete passed${NC}"
    else
        echo -e "${YELLOW}  ⚠ machete found unused deps (warning only — verify manually)${NC}"
        # Not counted as a failure — stub crates legitimately declare deps
        # they haven't imported yet. Promote to hard failure once crates
        # have real implementations.
    fi
else
    echo -e "${YELLOW}  ⚠ cargo-machete not installed, skipping unused dep check${NC}"
    echo "    Install: cargo install cargo-machete"
fi

# ─── Summary ─────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}  ✓ QUALITY GATE PASSED — all checks clean${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
else
    echo -e "${RED}  ✗ QUALITY GATE FAILED — $FAILURES check(s) failed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
