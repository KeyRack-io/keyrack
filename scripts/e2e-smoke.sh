#!/usr/bin/env bash
# KeyRack E2E smoke test runner.
#
# Validates the full stack from attribute input to usable output.
# Designed to grow with W1 — add sections as deliverables land.
#
# Usage:
#   ./scripts/e2e-smoke.sh          # run all E2E checks
#   ./scripts/e2e-smoke.sh --quick  # skip property tests (faster CI)
#
# Exit code 0 = all green; nonzero = something broke.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${YELLOW}…${NC} $1"; }

FAILURES=0
QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

echo ""
echo "KeyRack E2E Smoke Test"
echo "======================"
echo ""

# --------------------------------------------------------------------------
# 1. Workspace compiles
# --------------------------------------------------------------------------
echo "Stage 1: Workspace build"
if cargo build --workspace --quiet 2>&1; then
    pass "cargo build --workspace"
else
    fail "cargo build --workspace"
    FAILURES=$((FAILURES + 1))
fi

# --------------------------------------------------------------------------
# 2. Unit tests pass
# --------------------------------------------------------------------------
echo ""
echo "Stage 2: Unit tests"
if cargo test --workspace --lib --quiet 2>&1; then
    pass "unit tests (all crates)"
else
    fail "unit tests"
    FAILURES=$((FAILURES + 1))
fi

# --------------------------------------------------------------------------
# 3. E2E integration tests (identity pipeline)
# --------------------------------------------------------------------------
echo ""
echo "Stage 3: E2E integration tests"
if cargo test -p keyrack-core --test e2e_smoke --quiet 2>&1; then
    pass "identity pipeline (canon → LID → round-trip)"
else
    fail "identity pipeline"
    FAILURES=$((FAILURES + 1))
fi

# --------------------------------------------------------------------------
# 4. Property tests (skip with --quick)
# --------------------------------------------------------------------------
echo ""
echo "Stage 4: Property tests"
if [[ $QUICK -eq 1 ]]; then
    info "skipped (--quick)"
else
    if cargo test -p keyrack-core --test property_tests --quiet 2>&1; then
        pass "proptest: canonicalization + LID determinism (500 cases each)"
    else
        fail "property tests"
        FAILURES=$((FAILURES + 1))
    fi
fi

# --------------------------------------------------------------------------
# 5. Doc tests
# --------------------------------------------------------------------------
echo ""
echo "Stage 5: Doc tests"
if cargo test --workspace --doc --quiet 2>&1; then
    pass "doc tests"
else
    fail "doc tests"
    FAILURES=$((FAILURES + 1))
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All checks passed.${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}${FAILURES} check(s) failed.${NC}"
    echo ""
    exit 1
fi
