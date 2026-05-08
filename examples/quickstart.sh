#!/usr/bin/env bash
# KeyRack Quickstart — end-to-end encrypt/decrypt via the REST API.
#
# Prerequisites:
#   docker compose up -d keyrack-service
#
# This script creates a key, encrypts data, decrypts it back, and
# verifies the round-trip.

set -euo pipefail

BASE_URL="${KEYRACK_REST_URL:-http://localhost:8080}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

step() { echo -e "\n${CYAN}▸ $1${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo ""
echo "KeyRack Quickstart"
echo "=================="

# ── Wait for service ──────────────────────────────────────────────
step "Waiting for KeyRack to be ready..."
for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/healthz" > /dev/null 2>&1; then
        ok "Service is healthy"
        break
    fi
    if [ "$i" -eq 30 ]; then
        fail "Service not ready after 30s. Is 'docker compose up -d keyrack-service' running?"
    fi
    sleep 1
done

# ── Create a key ──────────────────────────────────────────────────
step "Creating an AES-256 key..."
CREATE_RESPONSE=$(curl -sf "$BASE_URL/v1/keys" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"key_spec": "AES_256", "description": "quickstart demo key"}')

KEY_ID=$(echo "$CREATE_RESPONSE" | jq -r '.lid')
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = "null" ]; then
    fail "Failed to create key. Response: $CREATE_RESPONSE"
fi
ok "Key created: $KEY_ID"

# ── Encrypt ───────────────────────────────────────────────────────
step "Encrypting 'hello keyrack'..."
PLAINTEXT_B64=$(echo -n "hello keyrack" | base64)

ENCRYPT_RESPONSE=$(curl -sf "$BASE_URL/v1/keys/$KEY_ID/actions-encrypt" -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"plaintext\": \"$PLAINTEXT_B64\"}")

CIPHERTEXT=$(echo "$ENCRYPT_RESPONSE" | jq -r '.ciphertext_blob')
if [ -z "$CIPHERTEXT" ] || [ "$CIPHERTEXT" = "null" ]; then
    fail "Encryption failed. Response: $ENCRYPT_RESPONSE"
fi
ok "Encrypted (${#CIPHERTEXT} chars of base64 ciphertext)"

# ── Decrypt ───────────────────────────────────────────────────────
step "Decrypting..."
DECRYPT_RESPONSE=$(curl -sf "$BASE_URL/v1/keys/$KEY_ID/actions-decrypt" -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"ciphertext_blob\": \"$CIPHERTEXT\"}")

DECRYPTED_B64=$(echo "$DECRYPT_RESPONSE" | jq -r '.plaintext')
DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d 2>/dev/null || echo "$DECRYPTED_B64" | base64 -D 2>/dev/null)

if [ "$DECRYPTED" = "hello keyrack" ]; then
    ok "Decrypted: '$DECRYPTED'"
else
    fail "Round-trip failed. Expected 'hello keyrack', got '$DECRYPTED'"
fi

# ── List keys ─────────────────────────────────────────────────────
step "Listing keys..."
KEY_COUNT=$(curl -sf "$BASE_URL/v1/keys" | jq '.keys | length')
ok "$KEY_COUNT key(s) in the system"

# ── Describe key ──────────────────────────────────────────────────
step "Describing key..."
DESCRIBE=$(curl -sf "$BASE_URL/v1/keys/$KEY_ID/describe")
STATE=$(echo "$DESCRIBE" | jq -r '.state')
SPEC=$(echo "$DESCRIBE" | jq -r '.key_spec')
ok "State: $STATE, Spec: $SPEC"

# ── Sign / Verify (Ed25519) ──────────────────────────────────────
step "Creating an Ed25519 signing key..."
SIGN_KEY_ID=$(curl -sf "$BASE_URL/v1/keys" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"key_spec": "ED25519", "description": "quickstart signing key"}' \
    | jq -r '.lid')
ok "Signing key: $SIGN_KEY_ID"

step "Signing a message..."
MSG_B64=$(echo -n "sign this document" | base64)
SIG_RESPONSE=$(curl -sf "$BASE_URL/v1/keys/$SIGN_KEY_ID/actions-sign" -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"message\": \"$MSG_B64\", \"algorithm\": \"ED25519\"}")
SIGNATURE=$(echo "$SIG_RESPONSE" | jq -r '.signature')
ok "Signature: ${SIGNATURE:0:40}..."

step "Verifying signature..."
VERIFY_RESPONSE=$(curl -sf "$BASE_URL/v1/keys/$SIGN_KEY_ID/actions-verify" -X POST \
    -H 'Content-Type: application/json' \
    -d "{\"message\": \"$MSG_B64\", \"signature\": \"$SIGNATURE\", \"algorithm\": \"ED25519\"}")
VALID=$(echo "$VERIFY_RESPONSE" | jq -r '.valid')
if [ "$VALID" = "true" ]; then
    ok "Signature valid"
else
    fail "Signature verification failed"
fi

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}All checks passed.${NC} KeyRack is working."
echo ""
echo "Next steps:"
echo "  - Try encryption context (AAD): add '\"encryption_context\": {\"purpose\": \"demo\"}' to encrypt/decrypt"
echo "  - Connect to the gRPC API on port 50051"
echo "  - See docs/OPERATOR.md for production configuration"
echo ""
