#!/usr/bin/env bash
set -euo pipefail

# Build keyrack-wasm for npm distribution.
# Requires: wasm-pack (cargo install wasm-pack)
#
# Outputs:
#   pkg/         — npm-ready package (browser + Node.js targets)
#   pkg-node/    — Node.js-only target (for server-side usage)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building browser target..."
wasm-pack build --target bundler --out-dir pkg --scope keyrack

echo "Building Node.js target..."
wasm-pack build --target nodejs --out-dir pkg-node --scope keyrack

echo "Done. Publish with: cd pkg && npm publish --access public"
