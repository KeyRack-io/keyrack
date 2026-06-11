#!/usr/bin/env bash
# Prove that keys + metadata survive a KeyRack service restart when backed by
# Postgres (vs the old in-memory storage, which lost everything on restart).
#
# Runs on the HOST (needs docker + curl) — the in-container demo runner cannot
# restart the service itself. It brings the stack up, creates + encrypts a key,
# restarts ONLY the keyrack service (Postgres keeps its data, the HSM token lives
# in a named volume), then proves the key still resolves and the pre-restart
# ciphertext still decrypts.
#
# Usage:  ./scripts/restart-survival.sh

set -uo pipefail

DEMO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEMO_DIR"

KEYRACK="http://localhost:8080"
JWT_ISSUER="http://localhost:9000"

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ✓ $1"; }
bad()  { fail=$((fail+1)); echo "  ✗ $1"; }

wait_healthy() {
  local i=0
  while [ "$i" -lt 60 ]; do
    if curl -sf "$KEYRACK/healthz" >/dev/null 2>&1; then return 0; fi
    i=$((i+1)); sleep 1
  done
  return 1
}

echo "== bringing up demo 04 stack (Postgres-backed) =="
docker compose up -d --build

echo "== waiting for KeyRack =="
wait_healthy || { bad "KeyRack never became healthy"; exit 1; }
ok "KeyRack healthy"

echo "== create key + encrypt (pre-restart) =="
TOKEN=$(curl -sf -X POST "$JWT_ISSUER/token" -H "Content-Type: application/json" \
  -d '{"sub":"tenant-a-admin","tenant_id":"tenant-a"}' \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { bad "no JWT"; exit 1; }

KEY_ID=$(curl -sf -X POST "$KEYRACK/v1/keys" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"restart-survival key"}' \
  | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
[ -n "$KEY_ID" ] || { bad "key creation failed"; exit 1; }
ok "created key $KEY_ID"

PT_B64=$(printf "survives-a-restart" | base64)
CT=$(curl -sf -X POST "$KEYRACK/v1/keys/$KEY_ID/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$PT_B64\"}" \
  | sed -n 's/.*"ciphertext_blob":"\([^"]*\)".*/\1/p')
[ -n "$CT" ] || { bad "encrypt failed"; exit 1; }
ok "encrypted (ciphertext recorded)"

echo "== restarting ONLY the keyrack service =="
docker compose restart keyrack
wait_healthy || { bad "KeyRack did not come back after restart"; exit 1; }
ok "KeyRack healthy again after restart"

echo "== verify survival (post-restart) =="
TOKEN=$(curl -sf -X POST "$JWT_ISSUER/token" -H "Content-Type: application/json" \
  -d '{"sub":"tenant-a-admin","tenant_id":"tenant-a"}' \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

GET_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$KEYRACK/v1/keys/$KEY_ID" \
  -H "Authorization: Bearer $TOKEN")
if [ "$GET_CODE" = "200" ]; then ok "key metadata survived restart (GET 200)"; else bad "key gone after restart (GET $GET_CODE)"; fi

DEC=$(curl -sf -X POST "$KEYRACK/v1/keys/$KEY_ID/actions-decrypt" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"$CT\"}" \
  | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
DECODED=$(printf "%s" "$DEC" | base64 -d 2>/dev/null || true)
if [ "$DECODED" = "survives-a-restart" ]; then
  ok "pre-restart ciphertext still decrypts correctly"
else
  bad "pre-restart ciphertext failed to decrypt after restart"
fi

echo ""
echo "===== restart-survival: $pass passed, $fail failed ====="
[ "$fail" -eq 0 ] || exit 1
echo "Postgres-backed metadata + persistent HSM token survived the restart."
