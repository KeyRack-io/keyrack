#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Demo 11: Multi-Tenant HYOK — scope_owner isolation + backend_id routing
#
# Showcases KeyRack 0.3.0 differentiators:
#   (a) scope_owner tenant isolation — PermissionDenied on cross-tenant access
#   (b) backend_id selector — callers name their crypto backend
#   (c) route pin (operator-authoritative) and delegate_any (caller selects)
#   (d) NATS audit: scope_owner_check events with result=success AND denied
#
# Every positive AND deny path is ASSERTED — a single unexpected result
# fails the demo. The audit assertions subscribe to NATS and verify
# specific scope_owner_check event payloads (not just message counts).
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

KEYRACK_REST="http://keyrack:8080"
KEYRACK_GRPC="keyrack:50051"
JWT_ISSUER="http://jwt-issuer:9000"
PROTO_DIR="/proto"
AUDIT_LOG="/tmp/audit-events.log"

PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────────────

banner() {
  echo ""
  echo "================================================================"
  echo "  $1"
  echo "================================================================"
  echo ""
}

step() { echo "--- $1"; }
ok()   { PASS=$((PASS + 1)); echo "  ✓ $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }

assert_eq() {
  if [ "$1" = "$2" ]; then
    ok "$3"
  else
    bad "$3 (expected '$2', got '$1')"
  fi
}

assert_http() {
  local actual="$1" expected="$2" label="$3"
  if [ "$actual" = "$expected" ]; then
    ok "$label (HTTP $actual)"
  else
    bad "$label (expected HTTP $expected, got HTTP $actual)"
  fi
}

json_field() {
  echo "$1" | tr ',' '\n' | tr '{' '\n' | tr '}' '\n' \
    | grep "\"$2\"" | head -1 \
    | sed 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}//; s/"\{0,1\}[[:space:]]*$//'
}

get_token() {
  local sub="$1" scope="$2"
  local resp
  resp=$(curl -sf -X POST "$JWT_ISSUER/token" \
    -H "Content-Type: application/json" \
    -d "{\"sub\": \"$sub\", \"scope\": \"$scope\"}")
  echo "$resp" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

grpc_call() {
  local method="$1"; shift
  grpcurl -plaintext -import-path "$PROTO_DIR" -proto keyrack/v1/key_service.proto \
    "$@" "$KEYRACK_GRPC" "keyrack.v1.KeyService/$method"
}

# ══════════════════════════════════════════════════════════════════════
#  PART 0 — Wait for KeyRack + start NATS audit subscription
# ══════════════════════════════════════════════════════════════════════

banner "Demo 11: Multi-Tenant HYOK (scope_owner + backend_id)"

step "Waiting for KeyRack REST API..."
attempts=0
while [ $attempts -lt 30 ]; do
  if curl -sf "${KEYRACK_REST}/healthz" >/dev/null 2>&1; then
    ok "KeyRack is healthy"
    break
  fi
  attempts=$((attempts + 1))
  sleep 1
done
if [ $attempts -ge 30 ]; then
  bad "KeyRack did not become healthy in time"
  exit 1
fi

step "Starting NATS audit subscription (captures events for later assertion)..."
: > "$AUDIT_LOG"
nats sub "kms.audit.>" -s nats://nats:4222 > "$AUDIT_LOG" 2>&1 &
NATS_SUB_PID=$!
sleep 2
if kill -0 "$NATS_SUB_PID" 2>/dev/null; then
  ok "NATS subscriber active (PID $NATS_SUB_PID)"
else
  bad "NATS subscriber failed to start — check nats CLI installation"
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 1 — Register two HSM connections with scope_owner via gRPC
# ══════════════════════════════════════════════════════════════════════

banner "Part 1: Register tenant HSM connections (gRPC, scope_owner isolation)"

step "Getting admin token for HSM connection registration..."
ADMIN_TOKEN=$(get_token "platform-admin" "admin")
if [ -n "$ADMIN_TOKEN" ]; then
  ok "Got admin JWT for HSM registration"
else
  bad "Failed to get admin token"
  exit 1
fi

step "Registering conn-tenant-a (scope_owner=tenant:a) via gRPC..."
REG_A=$(grpc_call CreateHsmConnection \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "providerType": "HSM",
    "connectionId": "conn-tenant-a",
    "pkcs11": {
      "libPath": "/usr/lib/softhsm/libsofthsm2.so",
      "tokenLabel": "tenant-a",
      "pinRef": "file:/etc/keyrack/secrets/pin-tenant-a"
    },
    "scopeOwner": "tenant:a"
  }' 2>&1)
echo "  Response: $REG_A"
if echo "$REG_A" | grep -q '"connectionId"'; then
  ok "conn-tenant-a registered with scope_owner=tenant:a"
else
  bad "gRPC CreateHsmConnection failed for conn-tenant-a"
  echo "  ↑ registration must succeed — cannot continue"
  exit 1
fi

step "Registering conn-tenant-b (scope_owner=tenant:b) via gRPC..."
REG_B=$(grpc_call CreateHsmConnection \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "providerType": "HSM",
    "connectionId": "conn-tenant-b",
    "pkcs11": {
      "libPath": "/usr/lib/softhsm/libsofthsm2.so",
      "tokenLabel": "tenant-b",
      "pinRef": "file:/etc/keyrack/secrets/pin-tenant-b"
    },
    "scopeOwner": "tenant:b"
  }' 2>&1)
echo "  Response: $REG_B"
if echo "$REG_B" | grep -q '"connectionId"'; then
  ok "conn-tenant-b registered with scope_owner=tenant:b"
else
  bad "gRPC CreateHsmConnection failed for conn-tenant-b"
  echo "  ↑ registration must succeed — cannot continue"
  exit 1
fi

step "Listing HSM connections via gRPC..."
LIST_ALL=$(grpc_call ListHsmConnections \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{}' 2>&1)
CONN_COUNT=$(echo "$LIST_ALL" | grep -c '"connectionId"' || true)
if [ "$CONN_COUNT" -ge 2 ]; then
  ok "Both connections visible ($CONN_COUNT connections)"
else
  bad "Expected at least 2 connections, got $CONN_COUNT"
fi

step "Listing connections filtered by scope_owner=tenant:a..."
LIST_A=$(grpc_call ListHsmConnections \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"scopeOwner":"tenant:a"}' 2>&1)
FILTERED_COUNT=$(echo "$LIST_A" | grep -c '"connectionId"' || true)
assert_eq "$FILTERED_COUNT" "1" "scope_owner filter returns exactly tenant-a's connection"

# ══════════════════════════════════════════════════════════════════════
#  PART 2 — Positive path: tenant-a creates + uses a key on its own HSM
# ══════════════════════════════════════════════════════════════════════

banner "Part 2: Positive path — tenant-a on its own connection"

TOKEN_A=$(get_token "tenant-a-admin" "tenant:a")
if [ -n "$TOKEN_A" ]; then
  ok "Got JWT for tenant-a-admin (scope=tenant:a)"
else
  bad "Failed to get token for tenant-a-admin"
  exit 1
fi

step "tenant-a creates an AES-256 key on conn-tenant-a (via backend_id)..."
CREATE_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "tenant-a key", "backend_id": "conn-tenant-a"}')
KEY_A=$(json_field "$CREATE_RESP" lid)
BACKEND_A=$(json_field "$CREATE_RESP" backend_id)
if [ -n "$KEY_A" ]; then
  ok "Created key: $KEY_A"
else
  bad "Failed to create key for tenant-a"
  echo "  Response: $CREATE_RESP"
fi
assert_eq "$BACKEND_A" "conn-tenant-a" "Key bound to conn-tenant-a (backend_id echoed)"

step "tenant-a encrypts data..."
PLAINTEXT="multi-tenant HYOK: tenant-a owns this data"
PLAINTEXT_B64=$(printf "%s" "$PLAINTEXT" | base64)
ENC_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys/$KEY_A/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\": \"$PLAINTEXT_B64\"}")
CIPHERTEXT=$(json_field "$ENC_RESP" ciphertext_blob)
if [ -n "$CIPHERTEXT" ]; then
  ok "Encrypted successfully"
else
  bad "Encryption failed"
  echo "  Response: $ENC_RESP"
fi

step "tenant-a decrypts data (exact plaintext assertion)..."
DEC_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys/$KEY_A/actions-decrypt" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\": \"$CIPHERTEXT\"}")
DEC_PT=$(json_field "$DEC_RESP" plaintext)
DECODED=$(echo "$DEC_PT" | base64 -d 2>/dev/null || true)
assert_eq "$DECODED" "$PLAINTEXT" "Decrypted plaintext matches original exactly"

# ══════════════════════════════════════════════════════════════════════
#  PART 3 — DENY PATH: tenant-a CANNOT use tenant-b's connection (REST)
# ══════════════════════════════════════════════════════════════════════

banner "Part 3: DENY PATH — cross-tenant scope_owner isolation (REST)"

step "tenant-a attempts to create a key on conn-tenant-b (REST)..."
echo "  → scope_owner=tenant:b but principal scope=tenant:a → must be DENIED"
DENY_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "should fail", "backend_id": "conn-tenant-b"}')
assert_http "$DENY_CODE" "403" "REST CreateKey on cross-tenant connection → PermissionDenied"

step "tenant-b creates a key on conn-tenant-b (for cross-tenant encrypt test)..."
TOKEN_B=$(get_token "tenant-b-admin" "tenant:b")
if [ -z "$TOKEN_B" ]; then
  bad "Failed to get token for tenant-b-admin"
  exit 1
fi
ok "Got JWT for tenant-b-admin (scope=tenant:b)"

CREATE_B_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "tenant-b key", "backend_id": "conn-tenant-b"}')
KEY_B=$(json_field "$CREATE_B_RESP" lid)
BACKEND_B=$(json_field "$CREATE_B_RESP" backend_id)
if [ -n "$KEY_B" ]; then
  ok "Created tenant-b key: $KEY_B"
else
  bad "Failed to create key for tenant-b"
  echo "  Response: $CREATE_B_RESP"
fi
assert_eq "$BACKEND_B" "conn-tenant-b" "tenant-b key bound to conn-tenant-b"

step "tenant-a attempts to encrypt using tenant-b's key (REST)..."
echo "  → key is on conn-tenant-b (scope_owner=tenant:b), principal scope=tenant:a → DENIED"
CROSS_ENC_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$KEYRACK_REST/v1/keys/$KEY_B/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\": \"$PLAINTEXT_B64\"}")
assert_http "$CROSS_ENC_CODE" "403" "REST Encrypt on cross-tenant key → PermissionDenied"

step "tenant-a attempts to decrypt using tenant-b's key (REST)..."
ENC_B_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys/$KEY_B/actions-encrypt" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\": \"$PLAINTEXT_B64\"}")
CT_B=$(json_field "$ENC_B_RESP" ciphertext_blob)
if [ -z "$CT_B" ]; then
  bad "tenant-b encrypt failed (needed for cross-tenant decrypt test)"
fi

CROSS_DEC_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$KEYRACK_REST/v1/keys/$KEY_B/actions-decrypt" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\": \"$CT_B\"}")
assert_http "$CROSS_DEC_CODE" "403" "REST Decrypt on cross-tenant key → PermissionDenied"

# ══════════════════════════════════════════════════════════════════════
#  PART 3b — DENY PATH: gRPC cross-tenant Encrypt → PermissionDenied
# ══════════════════════════════════════════════════════════════════════

banner "Part 3b: DENY PATH — gRPC cross-tenant Encrypt"

step "tenant-a attempts to encrypt using tenant-b's key via gRPC..."
echo "  → same scope_owner check, gRPC surface"
GRPC_DENY_OUT=$(grpc_call Encrypt \
  -H "authorization: Bearer $TOKEN_A" \
  -d "{\"keyId\": \"$KEY_B\", \"plaintext\": \"$PLAINTEXT_B64\"}" 2>&1) || true
if echo "$GRPC_DENY_OUT" | grep -qi "PermissionDenied"; then
  ok "gRPC Encrypt on cross-tenant key → PermissionDenied"
else
  bad "gRPC Encrypt should have returned PermissionDenied (got: $GRPC_DENY_OUT)"
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 4 — DENY PATH: no-scope principal cannot use scoped connections
# ══════════════════════════════════════════════════════════════════════

banner "Part 4: DENY PATH — absent scope claim on scoped connection"

step "Getting JWT with NO scope claim..."
TOKEN_NO_SCOPE=$(get_token "no-scope-user" "")
if [ -n "$TOKEN_NO_SCOPE" ]; then
  ok "Got JWT for no-scope-user (no scope claim)"
else
  bad "Failed to get token for no-scope-user"
fi

step "no-scope-user attempts to create a key on conn-tenant-a..."
NO_SCOPE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_NO_SCOPE" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "should fail", "backend_id": "conn-tenant-a"}')
assert_http "$NO_SCOPE_CODE" "403" "CreateKey with no scope on scoped connection → PermissionDenied"

# ══════════════════════════════════════════════════════════════════════
#  PART 5 — Route (operator pin) + delegate_any (caller selects)
# ══════════════════════════════════════════════════════════════════════

banner "Part 5: Route pin + delegate_any routing"

step "Creating key with regulated=true tag → route pins to default (software)..."
echo "  → config: regulated=true → route to 'default'; operator-authoritative pin"
ROUTE_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "regulated key", "attributes": {"regulated": "true"}}')
ROUTE_KEY=$(json_field "$ROUTE_RESP" lid)
ROUTE_BACKEND=$(json_field "$ROUTE_RESP" backend_id)
if [ -n "$ROUTE_KEY" ]; then
  ok "Created regulated key: $ROUTE_KEY"
else
  bad "Failed to create regulated key"
  echo "  Response: $ROUTE_RESP"
fi
assert_eq "$ROUTE_BACKEND" "default" "Route pin: regulated=true → default software provider"

step "Attempting regulated key with conflicting backend_id..."
echo "  → route pins to 'default', but caller asks for conn-tenant-a → route overrides"
CONFLICT_RESP=$(curl -s -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "conflict test", "attributes": {"regulated": "true"}, "backend_id": "conn-tenant-a"}')
if echo "$CONFLICT_RESP" | grep -q '"lid"'; then
  CONFLICT_BACKEND=$(json_field "$CONFLICT_RESP" backend_id)
  assert_eq "$CONFLICT_BACKEND" "default" "Route pin overrides caller backend_id (operator-authoritative)"
else
  ok "Route-pin conflict rejected — operator pin is authoritative"
fi

step "Creating key WITHOUT tags + backend_id → delegate_any lets caller select..."
echo "  → no tag match → delegate_any catch-all → tenant-b picks conn-tenant-b"
DELEG_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "delegated key", "backend_id": "conn-tenant-b"}')
DELEG_KEY=$(json_field "$DELEG_RESP" lid)
DELEG_BACKEND=$(json_field "$DELEG_RESP" backend_id)
if [ -n "$DELEG_KEY" ]; then
  ok "Created delegated key: $DELEG_KEY"
else
  bad "Failed to create delegated key"
  echo "  Response: $DELEG_RESP"
fi
assert_eq "$DELEG_BACKEND" "conn-tenant-b" "delegate_any: caller selected conn-tenant-b"

step "Creating key WITHOUT backend_id → falls to default software provider..."
DEFAULT_RESP=$(curl -sf -X POST "$KEYRACK_REST/v1/keys" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "default-backend key"}')
DEFAULT_BACKEND=$(json_field "$DEFAULT_RESP" backend_id)
assert_eq "$DEFAULT_BACKEND" "default" "No backend_id → default software provider"

# ══════════════════════════════════════════════════════════════════════
#  PART 6 — Audit: assert scope_owner_check events in NATS (REAL)
# ══════════════════════════════════════════════════════════════════════

banner "Part 6: Audit — scope_owner_check events from NATS (content assertion)"

step "Stopping NATS subscription and analysing captured events..."
sleep 2
kill "$NATS_SUB_PID" 2>/dev/null || true
wait "$NATS_SUB_PID" 2>/dev/null || true

CAPTURED=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
step "Captured $CAPTURED lines of NATS output"

SCOPE_EVENTS=$(grep -c "scope_owner_check" "$AUDIT_LOG" || true)
if [ "$SCOPE_EVENTS" -gt 0 ]; then
  ok "Found $SCOPE_EVENTS scope_owner_check audit events in NATS stream"
else
  bad "NO scope_owner_check events found in NATS — audit pipeline broken"
fi

step "Asserting scope_owner_check with result=success (allowed operation)..."
SUCCESS_COUNT=$(grep "scope_owner_check" "$AUDIT_LOG" | grep -c '"success"' || true)
if [ "$SUCCESS_COUNT" -gt 0 ]; then
  ok "scope_owner_check result=success events present ($SUCCESS_COUNT hits)"
else
  bad "scope_owner_check result=success event MISSING — allowed ops must emit success"
  echo "  Dumping scope_owner_check lines for debugging:"
  grep "scope_owner_check" "$AUDIT_LOG" | head -3
fi

step "Asserting scope_owner_check with result=denied (cross-tenant block)..."
DENIED_COUNT=$(grep "scope_owner_check" "$AUDIT_LOG" | grep -c '"denied"' || true)
if [ "$DENIED_COUNT" -gt 0 ]; then
  ok "scope_owner_check result=denied events present ($DENIED_COUNT hits)"
else
  bad "scope_owner_check result=denied event MISSING — deny path must emit denied"
  echo "  Dumping scope_owner_check lines for debugging:"
  grep "scope_owner_check" "$AUDIT_LOG" | head -3
fi

# ══════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════

banner "Demo Complete"

TOTAL=$((PASS + FAIL))
echo "  Results: ${PASS}/${TOTAL} checks passed"
echo ""
echo "  Demonstrated:"
echo "    • scope_owner tenant isolation (conn-level, fail-closed)"
echo "    • backend_id selector (callers name their crypto backend)"
echo "    • Route pin (regulated → default) + delegate_any (caller picks)"
echo "    • Cross-tenant deny: REST CreateKey/Encrypt/Decrypt + gRPC Encrypt"
echo "    • Absent-scope deny: no scope claim → PermissionDenied"
echo "    • gRPC CreateHsmConnection + ListHsmConnections scope_owner filter"
echo "    • NATS audit: scope_owner_check events (success + denied) verified"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  ⚠ ${FAIL} check(s) FAILED — review output above."
  exit 1
else
  echo "  ALL CHECKS PASSED!"
  exit 0
fi
