#!/bin/sh
set -e

BASE="http://keyrack:8080"

header() { printf "\n\033[1;36m══════════════════════════════════════════\033[0m\n"; printf "\033[1;36m  %s\033[0m\n" "$1"; printf "\033[1;36m══════════════════════════════════════════\033[0m\n\n"; }
step()   { printf "\033[1;33m→ %s\033[0m\n" "$1"; }
ok()     { printf "\033[1;32m✓ %s\033[0m\n\n" "$1"; }
fail()   { printf "\033[1;31m✗ %s\033[0m\n" "$1"; exit 1; }
request() {
  if request_response=$(curl -sS --fail-with-body "$@"); then
    printf '%s\n' "$request_response"
  else
    printf '%s\n' "$request_response" >&2
    return 1
  fi
}

header "Demo 2: KeyRack FOSS + SoftHSM2 (PKCS#11)"
echo "Key generation and cryptographic operations use SoftHSM2 through PKCS#11."
echo "SoftHSM2 is a software token loaded into the service process."
echo "This ordinary-key demo does not enable experimental native wrapping."
echo ""

# ─── Step 1: Create a tenant key (AES-256, PKCS#11 backed) ─────────
step "Creating tenant key (AES-256-GCM via PKCS#11/SoftHSM2)..."

TENANT_KEY=$(request "$BASE/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"tenant key (SoftHSM2)"}')

TENANT_KEY_ID=$(echo "$TENANT_KEY" | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
PROVIDER=$(echo "$TENANT_KEY" | sed -n 's/.*"provider_class":"\([^"]*\)".*/\1/p')
[ -n "$TENANT_KEY_ID" ] || fail "Tenant key ID is missing"
[ "$PROVIDER" = "pkcs11" ] || fail "Tenant key is not backed by PKCS#11"

echo "  Key ID:         $TENANT_KEY_ID"
echo "  Provider class: $PROVIDER"
ok "Tenant key created through PKCS#11"

# ─── Step 2: Create an independent data key ───────────────────────
# parent_key_id requests wrapped material. This ordinary SoftHSM provider has
# no wrapping opt-in, so both keys are independent resident token objects.
step "Creating an independent data key through PKCS#11..."

DATA_KEY=$(request "$BASE/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"data key (SoftHSM2)"}')

DATA_KEY_ID=$(echo "$DATA_KEY" | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
DATA_PROVIDER=$(echo "$DATA_KEY" | sed -n 's/.*"provider_class":"\([^"]*\)".*/\1/p')
INITIAL_VERSION=$(echo "$DATA_KEY" | sed -n 's/.*"current_key_version":\([0-9]*\).*/\1/p')
[ -n "$DATA_KEY_ID" ] || fail "Data key ID is missing"
[ "$DATA_KEY_ID" != "$TENANT_KEY_ID" ] || fail "Independent keys must have distinct IDs"
[ "$DATA_PROVIDER" = "pkcs11" ] || fail "Data key is not backed by PKCS#11"
[ "$INITIAL_VERSION" = "1" ] || fail "Data key must start at version 1"
echo "  Key ID:  $DATA_KEY_ID"
ok "Independent data key created through PKCS#11"

# ─── Step 3: Encrypt ──────────────────────────────────────────────
step "Encrypting data with the data key (SoftHSM2 performs AES-GCM)..."

PLAINTEXT="SoftHSM2 PKCS#11 demo payload"
PLAINTEXT_B64=$(printf '%s' "$PLAINTEXT" | base64 | tr -d '\n')

ENC_RESP=$(request "$BASE/v1/keys/$DATA_KEY_ID/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$PLAINTEXT_B64\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

CIPHERTEXT=$(echo "$ENC_RESP" | sed -n 's/.*"ciphertext_blob":"\([^"]*\)".*/\1/p')
[ -n "$CIPHERTEXT" ] || fail "Encryption returned no ciphertext"
echo "  Plaintext:  $PLAINTEXT"
printf '  Ciphertext: %.48s...\n' "$CIPHERTEXT"
ok "Encryption performed inside SoftHSM2"

# ─── Step 4: Decrypt ──────────────────────────────────────────────
step "Decrypting ciphertext (SoftHSM2 performs AES-GCM decrypt)..."

DEC_RESP=$(request "$BASE/v1/keys/$DATA_KEY_ID/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"$CIPHERTEXT\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

DECRYPTED_B64=$(echo "$DEC_RESP" | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d)
echo "  Decrypted: $DECRYPTED"

if [ "$DECRYPTED" = "$PLAINTEXT" ]; then
  ok "Decryption successful — round-trip verified"
else
  printf "\033[1;31m✗ Decryption mismatch!\033[0m\n"
  exit 1
fi

# ─── Step 5: Key rotation ────────────────────────────────────────
step "Rotating data key (new version generated in SoftHSM2)..."

ROT_RESP=$(request -X POST "$BASE/v1/keys/$DATA_KEY_ID/actions-rotate")
NEW_VERSION=$(echo "$ROT_RESP" | sed -n 's/.*"current_key_version":\([0-9]*\).*/\1/p')
[ "$NEW_VERSION" = "2" ] || fail "Rotation must advance the data key to version 2"
echo "  New key version: $NEW_VERSION"
ok "Key rotated — new material generated in SoftHSM2"

# ─── Step 6: Decrypt old ciphertext with rotated key ──────────────
step "Decrypting old ciphertext after rotation (version header routes to v1)..."

DEC_RESP2=$(request "$BASE/v1/keys/$DATA_KEY_ID/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"$CIPHERTEXT\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

DECRYPTED2_B64=$(echo "$DEC_RESP2" | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
DECRYPTED2=$(echo "$DECRYPTED2_B64" | base64 -d)

if [ "$DECRYPTED2" = "$PLAINTEXT" ]; then
  ok "Old ciphertext remains decryptable after rotation"
else
  printf "\033[1;31m✗ Failed to decrypt after rotation!\033[0m\n"
  exit 1
fi

# ─── Step 7: Encrypt with new version ─────────────────────────────
step "Encrypting new data with rotated key (uses version $NEW_VERSION)..."

NEW_PLAIN="Post-rotation payload with SoftHSM2 key v${NEW_VERSION}"
NEW_PLAIN_B64=$(printf '%s' "$NEW_PLAIN" | base64 | tr -d '\n')

ENC_RESP2=$(request "$BASE/v1/keys/$DATA_KEY_ID/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$NEW_PLAIN_B64\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

CIPHERTEXT2=$(echo "$ENC_RESP2" | sed -n 's/.*"ciphertext_blob":"\([^"]*\)".*/\1/p')
[ -n "$CIPHERTEXT2" ] || fail "Post-rotation encryption returned no ciphertext"
printf '  New ciphertext: %.48s...\n' "$CIPHERTEXT2"
DEC_RESP3=$(request "$BASE/v1/keys/$DATA_KEY_ID/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"$CIPHERTEXT2\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")
DECRYPTED3_B64=$(echo "$DEC_RESP3" | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
DECRYPTED3=$(printf '%s' "$DECRYPTED3_B64" | base64 -d)
[ "$DECRYPTED3" = "$NEW_PLAIN" ] || fail "Post-rotation decrypt mismatch"
ok "New data round-trip verified after rotation"

# ─── Step 8: Describe key (show PKCS#11 metadata) ─────────────────
step "Describing data key (shows PKCS#11 provider metadata)..."

DESC=$(request "$BASE/v1/keys/$DATA_KEY_ID/describe")
DESC_PROVIDER=$(echo "$DESC" | sed -n 's/.*"provider_class":"\([^"]*\)".*/\1/p')
DESC_VERSION=$(echo "$DESC" | sed -n 's/.*"current_key_version":\([0-9]*\).*/\1/p')
[ "$DESC_PROVIDER" = "pkcs11" ] || fail "Describe must report the PKCS#11 provider"
[ "$DESC_VERSION" = "2" ] || fail "Describe must report version 2 after rotation"
echo "$DESC" | sed 's/,/,\n  /g; s/{/{\n  /; s/}/\n}/'
echo ""
ok "Key metadata retrieved"

# ─── Summary ──────────────────────────────────────────────────────
header "Demo Complete"
echo "What was demonstrated:"
echo "  • Independent tenant and data keys using the PKCS#11 provider"
echo "  • AES-256-GCM encrypt/decrypt through SoftHSM2"
echo "  • Rotation to version 2 with old and new ciphertext round-trips"
echo "  • PKCS#11 provider and current version verified in metadata"
echo ""
echo "SoftHSM2 runs in process; this demo establishes no hardware custody"
echo "or qualification of the experimental native child-wrapping profile."
echo "ALL CHECKS PASSED"
echo ""
