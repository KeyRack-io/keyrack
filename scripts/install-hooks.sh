#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "Git hooks installed — using .githooks/ (pre-commit partner-name guard active)."
