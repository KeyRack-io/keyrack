#!/usr/bin/env bash
# Run the FOSS demo compose stacks end-to-end and aggregate pass/fail.
#
# Each demo ships a `demo` service that runs its run-demo.sh and exits 0 on
# success / non-zero on failure. This script builds + starts each stack, waits
# on that container, captures its exit code, prints logs, tears down, and exits
# non-zero if any demo failed. Intended for the release-gated CI lane.
#
# Usage:
#   ./scripts/run-demos-ci.sh                 # all FOSS demos
#   ./scripts/run-demos-ci.sh 01-foss-vault   # a subset

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMOS_DIR="$REPO_ROOT/demos"

ALL_DEMOS=(01-foss-vault 02-foss-softhsm 04-hyok-full-stack 06-provider-routing 08-cascade-rotation 09-audit-tamper-evidence 10-mtls-identity 11-multi-tenant-hyok)
DEMOS=("$@")
if [ "${#DEMOS[@]}" -eq 0 ]; then
  DEMOS=("${ALL_DEMOS[@]}")
fi

RESULTS=()
overall=0

run_demo() {
  local demo="$1"
  local dir="$DEMOS_DIR/$demo"

  if [ ! -f "$dir/docker-compose.yml" ]; then
    echo "::error::no docker-compose.yml for demo '$demo'"
    RESULTS+=("$demo|FAIL (missing)")
    overall=1
    return
  fi

  echo "::group::demo $demo"
  ( cd "$dir" && docker compose down -v >/dev/null 2>&1 || true )

  local exit_code=1
  if ( cd "$dir" && docker compose up -d --build ); then
    local cid
    cid="$( cd "$dir" && docker compose ps -aq demo )"
    if [ -n "$cid" ]; then
      exit_code="$(docker wait "$cid" 2>/dev/null || echo 1)"
      echo "---- demo output ($demo) ----"
      docker logs "$cid" 2>&1 || true
      echo "---- end demo output ----"
    else
      echo "::error::demo service container not found for '$demo'"
    fi
  else
    echo "::error::compose up failed for '$demo'"
  fi

  ( cd "$dir" && docker compose down -v >/dev/null 2>&1 || true )
  echo "::endgroup::"

  if [ "$exit_code" = "0" ]; then
    echo "✓ $demo: PASS"
    RESULTS+=("$demo|PASS")
  else
    echo "✗ $demo: FAIL (exit $exit_code)"
    RESULTS+=("$demo|FAIL (exit $exit_code)")
    overall=1
  fi
}

for demo in "${DEMOS[@]}"; do
  run_demo "$demo"
done

echo ""
echo "===== demo E2E summary ====="
for r in "${RESULTS[@]}"; do
  echo "  ${r%%|*} — ${r#*|}"
done

exit "$overall"
