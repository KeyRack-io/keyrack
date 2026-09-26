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
container="keyrack-custody-proof-$(date +%s)-$$"
mkdir -p conformance/pkcs11-custody/run
cleanup() {
    result=$?
    trap - EXIT
    docker cp "$container:/tmp/evidence/." conformance/pkcs11-custody/run/ || result=1
    docker rm -f "$container" >/dev/null || result=1
    exit "$result"
}
trap cleanup EXIT
docker run --name "$container" "$IMAGE"
