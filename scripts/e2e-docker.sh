#!/usr/bin/env bash
# Run E2E tests inside Docker with SoftHSM available.
#
# Usage:
#   ./scripts/e2e-docker.sh          # full suite
#   ./scripts/e2e-docker.sh --quick  # skip property tests
#   ./scripts/e2e-docker.sh --clippy # lint only
#
# The container includes SoftHSM2 with a pre-initialized token.
# No host-side SoftHSM installation required.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SERVICE="e2e"

case "${1:-}" in
    --quick)  SERVICE="e2e-quick" ;;
    --clippy) SERVICE="clippy" ;;
esac

echo "Building and running: $SERVICE"
echo ""

docker compose up --build --abort-on-container-exit --exit-code-from "$SERVICE" "$SERVICE"
