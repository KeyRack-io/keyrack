#!/bin/sh
set -e

BASE="http://keyrack:8080"

header() { printf "\n\033[1;36m══════════════════════════════════════════\033[0m\n"; printf "\033[1;36m  %s\033[0m\n" "$1"; printf "\033[1;36m══════════════════════════════════════════\033[0m\n\n"; }
step()   { printf "\033[1;33m→ %s\033[0m\n" "$1"; }
ok()     { printf "\033[1;32m✓ %s\033[0m\n\n" "$1"; }

header "Demo 2: KeyRack FOSS + SoftHSM2 (PKCS#11)"
echo "All cryptographic operations are backed by a PKCS#11 HSM (SoftHSM2)."
echo "No key material ever exists in application memory — the HSM handles"
echo "key generation, encryption, and decryption internally."
echo ""

# ─── Step 1: Create a root key (AES-256, PKCS#11 backed) ──────────
step "Creating tenant root key (AES-256-GCM via PKCS#11/SoftHSM2)..."

ROOT_KEY=$(curl -sf "$BASE/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"tenant-root-key (HSM-backed)"}')

ROOT_KEY_ID=$(echo "$ROOT_KEY" | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
PROVIDER=$(echo "$ROOT_KEY" | sed -n 's/.*"provider_class":"\([^"]*\)".*/\1/p')

echo "  Key ID:         $ROOT_KEY_ID"
echo "  Provider class: $PROVIDER"
ok "Root key created in HSM"

# ─── Step 2: Create a child key ───────────────────────────────────
step "Creating child key (derived from root, also HSM-backed)..."

CHILD_KEY=$(curl -sf "$BASE/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"key_spec\":\"AES_256\",\"parent_key_id\":\"$ROOT_KEY_ID\",\"description\":\"child-data-key (HSM-backed)\"}")

CHILD_KEY_ID=$(echo "$CHILD_KEY" | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
echo "  Key ID:  $CHILD_KEY_ID"
echo "  Parent:  $ROOT_KEY_ID"
ok "Child key created in HSM"

# ─── Step 3: Encrypt ──────────────────────────────────────────────
step "Encrypting sensitive data with child key (HSM performs AES-GCM)..."

PLAINTEXT="SoftHSM2 PKCS#11 demo — all crypto in the HSM!"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

ENC_RESP=$(curl -sf "$BASE/v1/keys/$CHILD_KEY_ID/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$PLAINTEXT_B64\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

CIPHERTEXT=$(echo "$ENC_RESP" | sed -n 's/.*"ciphertext_blob":"\([^"]*\)".*/\1/p')
echo "  Plaintext:  $PLAINTEXT"
echo "  Ciphertext: ${CIPHERTEXT:0:48}..."
ok "Encryption performed inside SoftHSM2"

# ─── Step 4: Decrypt ──────────────────────────────────────────────
step "Decrypting ciphertext (HSM performs AES-GCM decrypt)..."

DEC_RESP=$(curl -sf "$BASE/v1/keys/$CHILD_KEY_ID/actions-decrypt" \
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

# ─── Step 5: Key rotation (zero-downtime) ─────────────────────────
step "Rotating child key (new version generated in HSM)..."

ROT_RESP=$(curl -sf -X POST "$BASE/v1/keys/$CHILD_KEY_ID/actions-rotate")
NEW_VERSION=$(echo "$ROT_RESP" | sed -n 's/.*"current_key_version":\([0-9]*\).*/\1/p')
echo "  New key version: $NEW_VERSION"
ok "Key rotated — new material generated in SoftHSM2"

# ─── Step 6: Decrypt old ciphertext with rotated key ──────────────
step "Decrypting old ciphertext after rotation (version header routes to v1)..."

DEC_RESP2=$(curl -sf "$BASE/v1/keys/$CHILD_KEY_ID/actions-decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"ciphertext_blob\":\"$CIPHERTEXT\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

DECRYPTED2_B64=$(echo "$DEC_RESP2" | sed -n 's/.*"plaintext":"\([^"]*\)".*/\1/p')
DECRYPTED2=$(echo "$DECRYPTED2_B64" | base64 -d)

if [ "$DECRYPTED2" = "$PLAINTEXT" ]; then
  ok "Old ciphertext still decryptable — zero-downtime rotation confirmed"
else
  printf "\033[1;31m✗ Failed to decrypt after rotation!\033[0m\n"
  exit 1
fi

# ─── Step 7: Encrypt with new version ─────────────────────────────
step "Encrypting new data with rotated key (uses version $NEW_VERSION)..."

NEW_PLAIN="Post-rotation payload — encrypted with HSM key v${NEW_VERSION}"
NEW_PLAIN_B64=$(echo -n "$NEW_PLAIN" | base64)

ENC_RESP2=$(curl -sf "$BASE/v1/keys/$CHILD_KEY_ID/actions-encrypt" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$NEW_PLAIN_B64\",\"encryption_context\":{\"tenant\":\"acme\",\"env\":\"demo\"}}")

CIPHERTEXT2=$(echo "$ENC_RESP2" | sed -n 's/.*"ciphertext_blob":"\([^"]*\)".*/\1/p')
echo "  New ciphertext: ${CIPHERTEXT2:0:48}..."
ok "New data encrypted with latest key version in HSM"

# ─── Step 8: Describe key (show HSM metadata) ─────────────────────
step "Describing child key (shows PKCS#11 provider metadata)..."

DESC=$(curl -sf "$BASE/v1/keys/$CHILD_KEY_ID/describe")
echo "$DESC" | sed 's/,/,\n  /g; s/{/{\n  /; s/}/\n}/'
echo ""
ok "Key metadata retrieved"

# ─── Summary ──────────────────────────────────────────────────────
header "Demo Complete"
echo "What was demonstrated:"
echo "  • Key creation via PKCS#11 (SoftHSM2) — no raw key material in app"
echo "  • Hierarchical key structure (root → child)"
echo "  • AES-256-GCM encrypt/decrypt performed entirely inside the HSM"
echo "  • Key rotation with zero downtime (old ciphertexts still decryptable)"
echo "  • All operations audited with signed events"
echo ""
echo "In production, replace SoftHSM2 with a real PKCS#11 HSM"
echo "(e.g., Thales Luna, Utimaco, YubiHSM2, or a cloud HSM via PKCS#11)."
echo ""
