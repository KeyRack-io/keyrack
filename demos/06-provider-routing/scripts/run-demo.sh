#!/bin/sh
set -e

BASE="http://keyrack:8080"

header() { printf "\n\033[1;36m══════════════════════════════════════════════════════════\033[0m\n"; printf "\033[1;36m  %s\033[0m\n" "$1"; printf "\033[1;36m══════════════════════════════════════════════════════════\033[0m\n\n"; }
step()   { printf "\033[1;33m→ %s\033[0m\n" "$1"; }
ok()     { printf "\033[1;32m  ✓ %s\033[0m\n" "$1"; }
fail()   { printf "\033[1;31m  ✗ %s\033[0m\n" "$1"; exit 1; }

# create_key <json-body> → echoes the response body
create_key() {
  curl -sf "$BASE/v1/keys" -H "Content-Type: application/json" -d "$1"
}
field() { echo "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

# round_trip <key_id> <label> — encrypt then decrypt, assert match
round_trip() {
  kid="$1"; label="$2"
  pt="routing demo payload for $label"
  ptb64=$(printf "%s" "$pt" | base64)
  enc=$(curl -sf "$BASE/v1/keys/$kid/actions-encrypt" -H "Content-Type: application/json" -d "{\"plaintext\":\"$ptb64\"}")
  ct=$(field "$enc" ciphertext_blob)
  [ -n "$ct" ] || fail "$label: encrypt returned no ciphertext"
  dec=$(curl -sf "$BASE/v1/keys/$kid/actions-decrypt" -H "Content-Type: application/json" -d "{\"ciphertext_blob\":\"$ct\"}")
  back=$(field "$dec" plaintext | base64 -d 2>/dev/null || true)
  [ "$back" = "$pt" ] || fail "$label: round-trip mismatch (got '$back')"
  ok "$label: encrypt/decrypt round-trip OK (crypto executed in its HSM token)"
}

header "Demo 06: Provider Routing across two SoftHSM tokens"
echo "One KeyRack service, one libsofthsm2.so, TWO tokens (tenant-a, tenant-b)."
echo "Keys are routed to a tenant's HSM partition by their identity tags."
echo ""

# ─── 1: tenant-a key routes to hsm-tenant-a ───────────────────────────────
step "Create a key tagged tenant=tenant-a"
RESP=$(create_key '{"key_spec":"AES_256","description":"acme key","attributes":{"tenant":"tenant-a"}}')
KID_A=$(field "$RESP" lid)
PREF_A=$(field "$RESP" provider_ref)
echo "  key_id:       $KID_A"
echo "  provider_ref: $PREF_A"
[ "$PREF_A" = "hsm-tenant-a" ] || fail "expected hsm-tenant-a, got '$PREF_A'"
ok "Routed to hsm-tenant-a"
round_trip "$KID_A" "tenant-a"
echo ""

# ─── 2: tenant-b key routes to hsm-tenant-b ───────────────────────────────
step "Create a key tagged tenant=tenant-b"
RESP=$(create_key '{"key_spec":"AES_256","description":"beta key","attributes":{"tenant":"tenant-b"}}')
KID_B=$(field "$RESP" lid)
PREF_B=$(field "$RESP" provider_ref)
echo "  key_id:       $KID_B"
echo "  provider_ref: $PREF_B"
[ "$PREF_B" = "hsm-tenant-b" ] || fail "expected hsm-tenant-b, got '$PREF_B'"
ok "Routed to hsm-tenant-b — a DIFFERENT token than tenant-a's key"
round_trip "$KID_B" "tenant-b"
echo ""

# ─── 3: no tags → default provider ────────────────────────────────────────
step "Create a key with no tenant tag (should fall back to default_provider)"
RESP=$(create_key '{"key_spec":"AES_256","description":"untagged key"}')
PREF_D=$(field "$RESP" provider_ref)
echo "  provider_ref: $PREF_D"
[ "$PREF_D" = "hsm-tenant-a" ] || fail "expected default hsm-tenant-a, got '$PREF_D'"
ok "Fell back to default_provider (hsm-tenant-a)"
echo ""

# ─── 4: fail-closed provider assertion ────────────────────────────────────
step "Assert keyrack.provider=hsm-tenant-b on an UNtagged key (policy selects default)"
echo "  → routing selects hsm-tenant-a, assertion demands hsm-tenant-b ⇒ must be rejected"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","attributes":{"keyrack.provider":"hsm-tenant-b"}}')
[ "$CODE" = "409" ] || fail "expected HTTP 409 (ProviderMismatch), got $CODE"
ok "Rejected with HTTP 409 — assertion is fail-closed, never overrides policy"
echo ""

# ─── 5: matching assertion is accepted ────────────────────────────────────
step "Assert keyrack.provider=hsm-tenant-b on a tenant-b key (policy agrees)"
RESP=$(create_key '{"key_spec":"AES_256","attributes":{"tenant":"tenant-b","keyrack.provider":"hsm-tenant-b"}}')
PREF_OK=$(field "$RESP" provider_ref)
[ "$PREF_OK" = "hsm-tenant-b" ] || fail "expected hsm-tenant-b, got '$PREF_OK'"
ok "Accepted — assertion matched the routed provider"
echo ""

header "Demo Complete"
echo "Demonstrated:"
echo "  • Two PKCS#11 providers on ONE library (shared module, separate tokens)"
echo "  • Tag-driven routing: tenant-a → hsm-tenant-a, tenant-b → hsm-tenant-b"
echo "  • Default fallback for untagged keys"
echo "  • Fail-closed keyrack.provider assertion (reject on mismatch)"
echo ""
echo "Peek inside each token (run on the host):"
echo "  docker compose exec keyrack pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \\"
echo "    --token-label tenant-a --login --pin 1234 --list-objects"
echo "  docker compose exec keyrack pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \\"
echo "    --token-label tenant-b --login --pin 5678 --list-objects"
echo ""
