#!/bin/sh
set -e

BASE="http://keyrack:8080"
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

step() {
  echo "--- $1"
}

ok() {
  PASS=$((PASS + 1))
  echo "  ✓ $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "  ✗ $1"
}

assert_eq() {
  if [ "$1" = "$2" ]; then
    ok "$3"
  else
    fail "$3 (expected '$2', got '$1')"
  fi
}

# Extract a JSON string field from a flat response (no jq available).
# Usage: json_field '{"lid":"abc","state":"Enabled"}' lid  →  abc
json_field() {
  echo "$1" | tr ',' '\n' | tr '{' '\n' | tr '}' '\n' \
    | grep "\"$2\"" | head -1 \
    | sed 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}//; s/"\{0,1\}[[:space:]]*$//'
}

# ── Wait for KeyRack ─────────────────────────────────────────────────

banner "Demo 1: KeyRack FOSS + HashiCorp Vault Transit"

step "Waiting for KeyRack REST API..."
attempts=0
while [ $attempts -lt 30 ]; do
  if curl -sf "${BASE}/healthz" >/dev/null 2>&1; then
    ok "KeyRack is healthy"
    break
  fi
  attempts=$((attempts + 1))
  sleep 1
done
if [ $attempts -ge 30 ]; then
  fail "KeyRack did not become healthy in time"
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 1 — Key creation with hierarchy
# ══════════════════════════════════════════════════════════════════════

banner "Part 1: Key Creation with Hierarchy"

step "Creating tenant root key (AES-256)..."
ROOT_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"demo tenant root key"}')
echo "  Response: ${ROOT_RESP}"
ROOT_LID=$(json_field "$ROOT_RESP" lid)

if [ -n "$ROOT_LID" ]; then
  ok "Root key created — LID: ${ROOT_LID}"
else
  fail "Root key creation failed"
  exit 1
fi

step "Creating child data-encryption key under the root..."
CHILD_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"key_spec\":\"AES_256\",\"description\":\"child data-encryption key\",\"parent_key_id\":\"${ROOT_LID}\"}")
echo "  Response: ${CHILD_RESP}"
CHILD_LID=$(json_field "$CHILD_RESP" lid)

if [ -n "$CHILD_LID" ]; then
  ok "Child key created — LID: ${CHILD_LID}"
else
  fail "Child key creation failed"
  exit 1
fi

step "Verifying parent relationship..."
CHILD_GET=$(curl -sf "${BASE}/v1/keys/${CHILD_LID}")
CHILD_PARENT=$(json_field "$CHILD_GET" parent_lid)
assert_eq "$CHILD_PARENT" "$ROOT_LID" "Child's parent_lid matches root key"

# ══════════════════════════════════════════════════════════════════════
#  PART 2 — Key lifecycle: encrypt / decrypt
# ══════════════════════════════════════════════════════════════════════

banner "Part 2: Encrypt & Decrypt"

PLAINTEXT="Hello from KeyRack demo!"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

step "Encrypting: '${PLAINTEXT}'"
ENC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT_B64}\"}")
echo "  Response: ${ENC_RESP}"
CIPHERTEXT_BLOB=$(json_field "$ENC_RESP" ciphertext_blob)

if [ -n "$CIPHERTEXT_BLOB" ]; then
  ok "Encryption succeeded — ciphertext_blob length: $(echo -n "$CIPHERTEXT_BLOB" | wc -c | tr -d ' ') chars"
else
  fail "Encryption failed"
  exit 1
fi

step "Decrypting ciphertext..."
DEC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"${CIPHERTEXT_BLOB}\"}")
echo "  Response: ${DEC_RESP}"
DEC_PT_B64=$(json_field "$DEC_RESP" plaintext)

RECOVERED=$(echo "$DEC_PT_B64" | base64 -d 2>/dev/null || echo "$DEC_PT_B64" | base64 -D 2>/dev/null || echo "DECODE_FAILED")
assert_eq "$RECOVERED" "$PLAINTEXT" "Decrypted plaintext matches original"

# ══════════════════════════════════════════════════════════════════════
#  PART 3 — Key rotation with zero downtime
# ══════════════════════════════════════════════════════════════════════

banner "Part 3: Key Rotation with Zero Downtime"

step "Starting background encrypt/decrypt loop..."

BG_LOG="/tmp/bg-ops.log"
: > "$BG_LOG"
BG_RUNNING="/tmp/bg-running"
echo "1" > "$BG_RUNNING"

(
  seq_num=0
  while [ "$(cat "$BG_RUNNING" 2>/dev/null)" = "1" ]; do
    seq_num=$((seq_num + 1))
    MSG="bg-operation-${seq_num}"
    MSG_B64=$(echo -n "$MSG" | base64)

    enc_out=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-encrypt" \
      -H "Content-Type: application/json" \
      -d "{\"plaintext\":\"${MSG_B64}\"}" 2>&1) || {
        echo "[${seq_num}] ENCRYPT FAILED: ${enc_out}" >> "$BG_LOG"
        sleep 1
        continue
      }
    ct=$(json_field "$enc_out" ciphertext_blob)

    dec_out=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-decrypt" \
      -H "Content-Type: application/json" \
      -d "{\"ciphertext_blob\":\"${ct}\"}" 2>&1) || {
        echo "[${seq_num}] DECRYPT FAILED: ${dec_out}" >> "$BG_LOG"
        sleep 1
        continue
      }
    pt_b64=$(json_field "$dec_out" plaintext)
    recovered=$(echo "$pt_b64" | base64 -d 2>/dev/null || echo "$pt_b64" | base64 -D 2>/dev/null)

    if [ "$recovered" = "$MSG" ]; then
      echo "[${seq_num}] OK" >> "$BG_LOG"
    else
      echo "[${seq_num}] MISMATCH: expected '${MSG}', got '${recovered}'" >> "$BG_LOG"
    fi
    sleep 1
  done
) &
BG_PID=$!
echo "  Background loop PID: ${BG_PID}"

sleep 3
step "Background operations before rotation:"
cat "$BG_LOG"

step "Checking current key version..."
KEY_BEFORE=$(curl -sf "${BASE}/v1/keys/${CHILD_LID}")
VER_BEFORE=$(json_field "$KEY_BEFORE" current_key_version)
echo "  Current version: ${VER_BEFORE}"

step "Rotating the child key..."
ROT_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-rotate" \
  -H "Content-Type: application/json")
echo "  Response: ${ROT_RESP}"

KEY_AFTER=$(curl -sf "${BASE}/v1/keys/${CHILD_LID}")
VER_AFTER=$(json_field "$KEY_AFTER" current_key_version)
echo "  New version: ${VER_AFTER}"

if [ "$VER_AFTER" -gt "$VER_BEFORE" ] 2>/dev/null; then
  ok "Key rotated: version ${VER_BEFORE} → ${VER_AFTER}"
else
  fail "Key rotation did not increment version (before=${VER_BEFORE}, after=${VER_AFTER})"
fi

step "Letting background loop run post-rotation..."
sleep 4

step "Stopping background loop..."
echo "0" > "$BG_RUNNING"
wait "$BG_PID" 2>/dev/null || true

step "Background operation log (post-rotation):"
cat "$BG_LOG"

BG_ERRORS=$(grep -c "FAILED\|MISMATCH" "$BG_LOG" 2>/dev/null || echo "0")
if [ "$BG_ERRORS" = "0" ]; then
  ok "Zero errors during rotation — zero downtime confirmed"
else
  fail "${BG_ERRORS} error(s) during background operations"
fi

step "Verifying old ciphertext still decrypts after rotation..."
OLD_DEC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"${CIPHERTEXT_BLOB}\"}")
OLD_DEC_PT_B64=$(json_field "$OLD_DEC_RESP" plaintext)
OLD_RECOVERED=$(echo "$OLD_DEC_PT_B64" | base64 -d 2>/dev/null || echo "$OLD_DEC_PT_B64" | base64 -D 2>/dev/null || echo "DECODE_FAILED")
assert_eq "$OLD_RECOVERED" "$PLAINTEXT" "Pre-rotation ciphertext still decrypts correctly"

# ══════════════════════════════════════════════════════════════════════
#  PART 4 — Key state transitions
# ══════════════════════════════════════════════════════════════════════

banner "Part 4: Key State Transitions"

step "Current key state:"
STATE_BEFORE=$(json_field "$(curl -sf "${BASE}/v1/keys/${CHILD_LID}")" state)
echo "  State: ${STATE_BEFORE}"
assert_eq "$STATE_BEFORE" "enabled" "Key starts in Enabled state"

step "Disabling the key..."
DIS_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-disable" \
  -H "Content-Type: application/json")
DIS_STATE=$(json_field "$DIS_RESP" state)
echo "  State after disable: ${DIS_STATE}"
assert_eq "$DIS_STATE" "disabled" "Key is now Disabled"

step "Attempting encrypt on disabled key (should fail)..."
DIS_ENC_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT_B64}\"}")
echo "  HTTP status: ${DIS_ENC_RESP}"
if [ "$DIS_ENC_RESP" != "200" ] && [ "$DIS_ENC_RESP" != "201" ]; then
  ok "Encrypt correctly rejected on disabled key (HTTP ${DIS_ENC_RESP})"
else
  fail "Encrypt should have been rejected on disabled key"
fi

step "Re-enabling the key..."
EN_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-enable" \
  -H "Content-Type: application/json")
EN_STATE=$(json_field "$EN_RESP" state)
echo "  State after enable: ${EN_STATE}"
assert_eq "$EN_STATE" "enabled" "Key is re-enabled"

step "Verifying encrypt works again after re-enable..."
RE_ENC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${CHILD_LID}/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT_B64}\"}")
RE_CT=$(json_field "$RE_ENC_RESP" ciphertext_blob)
if [ -n "$RE_CT" ]; then
  ok "Encrypt works after re-enable"
else
  fail "Encrypt failed after re-enable"
fi

# ══════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════

banner "Demo Complete"

TOTAL=$((PASS + FAIL))
echo "  Results: ${PASS}/${TOTAL} checks passed"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  ⚠ ${FAIL} check(s) failed — review output above."
  exit 1
else
  echo "  All checks passed!"
  exit 0
fi
