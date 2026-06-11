#!/usr/bin/env bash
# Self-contained k8s "sidecar in a pod" demo on a local kind cluster.
#
# Spins up kind, builds + loads the keyrack image, applies the manifests
# (Postgres + Cedar PDP as services; app + keyrack as a sidecar pair in one
# pod), waits for the app pod to complete, and asserts the verification passed.
#
# Requires: kind, kubectl, docker.
# Env:  KEEP_UP=1  leave the cluster running for inspection.

set -uo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
CLUSTER="keyrack-demo"
IMAGE="keyrack-service:demo"
NS="keyrack-demo"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' is required but not installed."; exit 2; }; }
need kind; need kubectl; need docker

cleanup() {
  if [ "${KEEP_UP:-0}" = "1" ]; then
    echo "→ KEEP_UP=1; leaving cluster '$CLUSTER' running. Delete with: kind delete cluster --name $CLUSTER"
  else
    echo "→ tearing down kind cluster '$CLUSTER'..."
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== creating kind cluster '$CLUSTER' =="
kind create cluster --name "$CLUSTER" --wait 120s

echo "== building keyrack image =="
docker build -f "$REPO_ROOT/docker/Dockerfile.service" -t "$IMAGE" "$REPO_ROOT"

echo "== loading image into kind =="
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "== applying manifests =="
kubectl apply -f "$DEMO_DIR/manifests/"

echo "== waiting for dependencies =="
kubectl -n "$NS" rollout status deploy/postgres --timeout=120s
kubectl -n "$NS" rollout status deploy/cedar-pdp --timeout=120s

echo "== waiting for the app pod to complete (sidecar serves it over localhost) =="
# Wait for the pod to reach a terminal phase.
deadline=$(( $(date +%s) + 240 ))
phase=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  phase="$(kubectl -n "$NS" get pod keyrack-sidecar-demo -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "$phase" in
    Succeeded|Failed) break ;;
  esac
  sleep 3
done

echo ""
echo "---- app container logs ----"
kubectl -n "$NS" logs keyrack-sidecar-demo -c app 2>&1 || true
echo "---- keyrack sidecar logs (tail) ----"
kubectl -n "$NS" logs keyrack-sidecar-demo -c keyrack 2>&1 | tail -15 || true
echo "----------------------------"

if kubectl -n "$NS" logs keyrack-sidecar-demo -c app 2>/dev/null | grep -q "ALL CHECKS PASSED"; then
  echo "✓ DEMO 07-k8s-sidecar: PASS (pod phase: ${phase:-unknown})"
  exit 0
else
  echo "✗ DEMO 07-k8s-sidecar: FAIL (pod phase: ${phase:-unknown})"
  exit 1
fi
