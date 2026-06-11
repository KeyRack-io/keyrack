#!/bin/sh
# Demo 09: Audit Tamper-Evidence
#
# Proves that the signed + hash-chained audit log detects:
#   (a) field-level tampering (invalid Ed25519 signature)
#   (b) line deletion / reordering (broken BLAKE3 hash chain)
set -e

BASE="http://keyrack:8080"
AUDIT_LOG="/data/audit.log"
SIGNING_KEY="/data/audit-signing.key"

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
fail() { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }

json_field() {
  echo "$1" | tr ',' '\n' | tr '{' '\n' | tr '}' '\n' \
    | grep "\"$2\"" | head -1 \
    | sed 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}//; s/"\{0,1\}[[:space:]]*$//'
}

# ── Wait for KeyRack ─────────────────────────────────────────────────

banner "Demo 09: Audit Tamper-Evidence"

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
#  PART 1 — Populate the audit log with real operations
# ══════════════════════════════════════════════════════════════════════

banner "Part 1: Generate audit events (create, encrypt, decrypt)"

step "Creating a key..."
CREATE_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"tamper-evidence demo key"}')
echo "  Response: ${CREATE_RESP}"
KEY_LID=$(json_field "$CREATE_RESP" lid)
if [ -n "$KEY_LID" ]; then
  ok "Key created — LID: ${KEY_LID}"
else
  fail "Key creation failed"
  exit 1
fi

PLAINTEXT_B64=$(printf "audit tamper demo payload" | base64)

step "Encrypting data..."
ENC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${KEY_LID}/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"${PLAINTEXT_B64}\"}")
echo "  Response: ${ENC_RESP}"
CIPHERTEXT=$(json_field "$ENC_RESP" ciphertext_blob)
if [ -n "$CIPHERTEXT" ]; then
  ok "Encryption succeeded"
else
  fail "Encryption failed"
  exit 1
fi

step "Decrypting data..."
DEC_RESP=$(curl -sf -X POST "${BASE}/v1/keys/${KEY_LID}/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"${CIPHERTEXT}\"}")
echo "  Response: ${DEC_RESP}"
DEC_PT=$(json_field "$DEC_RESP" plaintext)
if [ -n "$DEC_PT" ]; then
  ok "Decryption succeeded"
else
  fail "Decryption failed"
  exit 1
fi

# Small pause to ensure all events are flushed to the file
sleep 1

step "Checking audit log line count..."
LINE_COUNT=$(wc -l < "${AUDIT_LOG}" | tr -d ' ')
echo "  Audit log has ${LINE_COUNT} events"
if [ "${LINE_COUNT}" -lt 3 ]; then
  fail "Expected at least 3 audit events, got ${LINE_COUNT}"
  exit 1
else
  ok "Audit log has ${LINE_COUNT} events (>= 3)"
fi

step "Verifying signing key exists..."
if [ -f "${SIGNING_KEY}" ]; then
  KEY_SIZE=$(wc -c < "${SIGNING_KEY}" | tr -d ' ')
  echo "  Signing key: ${KEY_SIZE} bytes"
  ok "Signing key found (${KEY_SIZE} bytes)"
else
  fail "Signing key file not found at ${SIGNING_KEY}"
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 2 — Clean log: all events must pass
# ══════════════════════════════════════════════════════════════════════

banner "Part 2: Verify clean audit log (expect ALL PASS)"

step "Running: keyrack audit verify ${AUDIT_LOG} --key ${SIGNING_KEY}"
VERIFY_OUT=$(keyrack audit verify "${AUDIT_LOG}" --key "${SIGNING_KEY}" 2>&1)
VERIFY_RC=$?
echo "${VERIFY_OUT}"
if [ "${VERIFY_RC}" -eq 0 ]; then
  ok "Clean log verified successfully (exit 0)"
else
  fail "Clean log verification FAILED unexpectedly (exit ${VERIFY_RC})"
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 3 — Field tampering: modify an action value
# ══════════════════════════════════════════════════════════════════════

banner "Part 3: Tamper — falsify recorded outcome (expect signature FAIL)"

TAMPERED_LOG="/tmp/audit-tampered.jsonl"
cp "${AUDIT_LOG}" "${TAMPERED_LOG}"

# Falsify the recorded outcome of the first event (success -> denied).
# The JSON still parses, but the Ed25519 signature no longer matches.
sed -i '1s/"result":"success"/"result":"denied"/' "${TAMPERED_LOG}"

step "Running: keyrack audit verify ${TAMPERED_LOG} --key ${SIGNING_KEY}"
TAMPER_OUT=$(keyrack audit verify "${TAMPERED_LOG}" --key "${SIGNING_KEY}" 2>&1) && TAMPER_RC=0 || TAMPER_RC=$?
echo "${TAMPER_OUT}"
if [ "${TAMPER_RC}" -ne 0 ]; then
  ok "Tampered log correctly rejected (exit ${TAMPER_RC} — signature failure detected)"
else
  fail "Tampered log was NOT rejected — verification should have failed"
  exit 1
fi

# Confirm the output mentions signature failure
if echo "${TAMPER_OUT}" | grep -q "invalid signature"; then
  ok "Output correctly reports 'invalid signature'"
else
  fail "Output did not report 'invalid signature'"
fi

# ══════════════════════════════════════════════════════════════════════
#  PART 4 — Line deletion: breaks the BLAKE3 hash chain
# ══════════════════════════════════════════════════════════════════════

banner "Part 4: Delete a line — breaks hash chain (expect chain FAIL)"

DELETED_LOG="/tmp/audit-deleted.jsonl"
# Remove the second event; this breaks the chain at the third event whose
# previous_hash was computed from the deleted event's signature.
sed -n '1p;3,$p' "${AUDIT_LOG}" > "${DELETED_LOG}"

DEL_LINES=$(wc -l < "${DELETED_LOG}" | tr -d ' ')
echo "  Remaining events after deletion: ${DEL_LINES}"

step "Running: keyrack audit verify ${DELETED_LOG} --key ${SIGNING_KEY}"
DEL_OUT=$(keyrack audit verify "${DELETED_LOG}" --key "${SIGNING_KEY}" 2>&1) && DEL_RC=0 || DEL_RC=$?
echo "${DEL_OUT}"
if [ "${DEL_RC}" -ne 0 ]; then
  ok "Deletion-tampered log correctly rejected (exit ${DEL_RC} — chain break detected)"
else
  fail "Deletion-tampered log was NOT rejected — verification should have failed"
  exit 1
fi

# Confirm the output mentions hash chain failure
if echo "${DEL_OUT}" | grep -q "hash chain"; then
  ok "Output correctly reports 'hash chain break'"
else
  fail "Output did not report 'hash chain break'"
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
