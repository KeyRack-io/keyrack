#!/usr/bin/env bash
# Build and run the PKCS#11 custody-recovery proof.
#
#   ./conformance/pkcs11-custody/run-proof.sh
#
# Everything runs in one Linux container, because the proof needs the real
# service binary and the real PKCS#11 module loaded into the same process.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="keyrack-pkcs11-custody-proof"

cd "$REPO_ROOT"

echo "Building the proof image (this compiles keyrack-service)..."
docker build -f conformance/pkcs11-custody/Dockerfile -t "$IMAGE" .

echo
echo "Running the proof..."
docker run --rm "$IMAGE"
