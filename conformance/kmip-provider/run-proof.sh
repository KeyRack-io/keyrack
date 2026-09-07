#!/usr/bin/env bash
# Boot keyrack-service against a third-party KMIP server and exercise the
# documented operations through the service's own REST surface.
#
# The server is PyKMIP, not keyrack-kmip-server, on purpose: a client checked
# only against our own server proves that the two agree, which is precisely how
# a shared misreading of the specification survives. Four wrong wire constants
# and an unusable protocol version did survive that way.
set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
IMAGE="kr-pykmip:proof"
CONTAINER="kr-pykmip-proof"
REST="http://127.0.0.1:8080"  # pinned in the proof configs
SERVICE_PID=""

PYTHON="${PYTHON:-python3}"

cleanup() {
  [ -n "$SERVICE_PID" ] && kill "$SERVICE_PID" 2>/dev/null || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== certificates"
[ -f certs/client.crt ] || ./gen-certs.sh
echo "   ok"

echo "== neutral KMIP server (PyKMIP)"
docker build -q --load -f Dockerfile.pykmip -t "$IMAGE" . >/dev/null
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
mkdir -p run
sed "s|CERT_DIR|/etc/pykmip/certs|g" pykmip-server.conf > run/pykmip-server.conf
docker run -d --name "$CONTAINER" -p 5696:5696 \
  -v "$HERE/run/pykmip-server.conf:/etc/pykmip/pykmip-server.conf:ro" \
  -v "$HERE/certs:/etc/pykmip/certs:ro" "$IMAGE" >/dev/null

# Readiness has to be proved by a KMIP exchange, not by the port answering:
# Docker's port proxy accepts connections while the server behind it is dead,
# so a TCP check reports a healthy fixture when there is none.
echo -n "   waiting for a KMIP response"
ready=""
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" python -c "
import sys
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
try:
    with ProxyKmipClient(hostname='127.0.0.1', port=5696,
                         cert='/etc/pykmip/certs/client.crt',
                         key='/etc/pykmip/certs/client.key',
                         ca='/etc/pykmip/certs/ca.crt',
                         kmip_version=enums.KMIPVersion.KMIP_1_4) as c:
        c.create(enums.CryptographicAlgorithm.AES, 256)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; then
    ready="yes"
    break
  fi
  echo -n "."
  sleep 1
done
echo
if [ -z "$ready" ]; then
  echo "   FAIL: the KMIP server never served a request"
  docker logs "$CONTAINER" 2>&1 | tail -20
  exit 1
fi
echo "   serving KMIP 1.4"

echo "== constants cross-check against the neutral implementation"
docker run --rm -v "$HERE/../..:/src:ro" --entrypoint python "$IMAGE" \
  /src/conformance/kmip-provider/check-constants.py
echo

echo "== keyrack-service, from the documented configuration"
BIN="$(cargo metadata --format-version 1 --no-deps --manifest-path ../../Cargo.toml \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/keyrack-service"
# Always build. Skipping this when the binary merely exists is how a proof
# ends up describing a previous build of the code.
echo "   building"
(cd ../.. && cargo build -q -p keyrack-service --bin keyrack-service)

sed "s|CERT_DIR|$HERE/certs|g" keyrack.yaml > run/keyrack.yaml
RUST_LOG="${RUST_LOG:-info}" KEYRACK_CONFIG=run/keyrack.yaml "$BIN" > run/keyrack-service.log 2>&1 &
SERVICE_PID=$!

echo -n "   waiting for readiness"
for _ in $(seq 1 40); do
  if curl -fsS "$REST/readyz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
    echo
    echo "   FAIL: the service exited during startup"
    tail -20 run/keyrack-service.log
    exit 1
  fi
  echo -n "."
  sleep 0.5
done
echo
grep -q "kmip" run/keyrack-service.log && echo "   provider: kmip"

echo
echo "== documented operations, over REST, against the neutral server"
KEYRACK_REST="$REST" "$PYTHON" proof.py
STATUS=$?

echo
echo "== service log (KMIP lines)"
grep -i "kmip" run/keyrack-service.log | tail -12 || true

kill "$SERVICE_PID" 2>/dev/null || true
SERVICE_PID=""

# Properties that the REST surface cannot reach, because the service derives
# the encryption context itself: whether the server binds it, and whether a
# key comes back usable rather than Pre-Active.
echo
echo "== server-side guarantees (provider level, against the same server)"
export KEYRACK_KMIP_PROOF_ENDPOINT="kmip://127.0.0.1:5696"
export KEYRACK_KMIP_PROOF_CLIENT_CERT="$HERE/certs/client.crt"
export KEYRACK_KMIP_PROOF_CLIENT_KEY="$HERE/certs/client.key"
export KEYRACK_KMIP_PROOF_CA_CERT="$HERE/certs/ca.crt"
if ! (cd ../.. && cargo test -q -p keyrack-kmip --test neutral_server -- --ignored --nocapture 2>&1 | tail -12); then
  STATUS=1
fi

# The other documented way to configure a KMIP backend. Same construction
# path, and equally unreachable before, so it gets the same treatment.
echo
echo "== the documented multi-provider routing shape"
sed "s|CERT_DIR|$HERE/certs|g" keyrack-routing.yaml > run/keyrack-routing.yaml
RUST_LOG="${RUST_LOG:-info}" KEYRACK_CONFIG=run/keyrack-routing.yaml "$BIN" \
  > run/keyrack-routing.log 2>&1 &
SERVICE_PID=$!
for _ in $(seq 1 40); do
  curl -fsS "$REST/readyz" >/dev/null 2>&1 && break
  sleep 0.5
done
routed=$(curl -fsS "$REST/v1/keys" -X POST -H 'Content-Type: application/json' \
  -d '{"key_spec":"AES_256","attributes":{"tenant":"acme"}}' 2>/dev/null || true)
if echo "$routed" | grep -q '"lid"'; then
  echo "[PASS]          key routed to the kmip provider by tenant tag"
  grep -i "kmip key created" run/keyrack-routing.log | tail -1 || true
else
  echo "[FAIL]          routing a key to the kmip provider: $routed"
  tail -5 run/keyrack-routing.log
  STATUS=1
fi

exit $STATUS
