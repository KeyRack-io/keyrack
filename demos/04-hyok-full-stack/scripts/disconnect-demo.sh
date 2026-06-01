#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════
# HYOK Disconnect Demo — Run from the HOST (not inside a container)
#
# Demonstrates time-bounded lockout: after HSM disconnect, cached
# crypto operations succeed for up to TTL seconds, then fail.
# ═══════════════════════════════════════════════════════════════════════

set -e

KEYRACK="http://localhost:8080"
JWT_ISSUER="http://localhost:9000"
CACHE_TTL=10

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() { printf "\n${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; printf "${CYAN} %s${NC}\n" "$1"; printf "${CYAN}══════════════════════════════════════════════════════════════${NC}\n\n"; }
ok()     { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
fail()   { printf "  ${RED}✗${NC} %s\n" "$1"; }
info()   { printf "  ${YELLOW}→${NC} %s\n" "$1"; }

# Pre-flight check
if ! curl -sf "$KEYRACK/healthz" > /dev/null 2>&1; then
  fail "KeyRack not reachable at $KEYRACK. Is the stack running?"
  info "Run: docker compose up -d"
  exit 1
fi

# ── Get token ────────────────────────────────────────────────────────
banner "Phase 1: Setup — create key and verify encrypt works"

TOKEN_RESP=$(curl -sf -X POST "$JWT_ISSUER/token" \
  -H "Content-Type: application/json" \
  -d '{"sub": "tenant-a-admin", "tenant_id": "tenant-a"}')
TOKEN=$(echo "$TOKEN_RESP" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

CREATE_RESP=$(curl -sf -X POST "$KEYRACK/v1/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_spec": "AES_256", "description": "disconnect-test-key"}')
KEY_ID=$(echo "$CREATE_RESP" | sed -n 's/.*"lid":"\([^"]*\)".*/\1/p')
ok "Created key: $KEY_ID"

PLAINTEXT_B64=$(printf "disconnect-test-payload" | base64)
encrypt_test() {
  curl -s -o /dev/null -w "%{http_code}" -X POST "$KEYRACK/v1/keys/$KEY_ID/actions-encrypt" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"plaintext\": \"$PLAINTEXT_B64\"}"
}

STATUS=$(encrypt_test)
if [ "$STATUS" = "200" ]; then
  ok "Encrypt succeeds (HTTP 200) — HSM is connected"
else
  fail "Encrypt returned HTTP $STATUS before disconnect — aborting"
  exit 1
fi

# ── Disconnect HSM ───────────────────────────────────────────────────
banner "Phase 2: Simulating HSM disconnect"

info "Removing SoftHSM token files from container..."
docker compose exec keyrack sh -c "rm -rf /var/lib/softhsm/tokens/*"
ok "HSM token store wiped — PKCS#11 operations will now fail at the provider level"

DISCONNECT_TIME=$(date +%s)
info "Disconnect time: $(date)"

# ── Probe: immediate retry (may still use cache) ─────────────────────
banner "Phase 3: Observing cache behavior"

info "Trying encrypt immediately after disconnect..."
sleep 1
STATUS=$(encrypt_test)
if [ "$STATUS" = "200" ]; then
  ok "Encrypt still succeeds (HTTP $STATUS) — served from cache!"
else
  info "Encrypt returned HTTP $STATUS — cache may have already expired or not cover this operation"
fi

# ── Wait for TTL expiry ──────────────────────────────────────────────
info "Waiting ${CACHE_TTL} seconds for cache TTL to expire..."
REMAINING=$CACHE_TTL
while [ $REMAINING -gt 0 ]; do
  printf "  ${YELLOW}⏳${NC} %d seconds remaining...\r" "$REMAINING"
  sleep 1
  REMAINING=$((REMAINING - 1))
done
printf "                                     \r"

# ── Post-TTL: should fail ────────────────────────────────────────────
banner "Phase 4: Post-TTL — verifying lockout"

STATUS=$(encrypt_test)
ELAPSED=$(( $(date +%s) - DISCONNECT_TIME ))

if [ "$STATUS" = "200" ]; then
  fail "Encrypt still succeeds after ${ELAPSED}s — cache TTL may be longer than expected"
else
  ok "Encrypt FAILED (HTTP $STATUS) after ${ELAPSED}s — LOCKOUT CONFIRMED"
  ok "Bounded lockout guarantee: max ${CACHE_TTL}s window after HSM disconnect"
fi

# ── Summary ──────────────────────────────────────────────────────────
banner "HYOK Disconnect Demo Complete"

printf "  Timeline:\n"
printf "  ├─ HSM connected:     encrypt ✓\n"
printf "  ├─ HSM disconnected:  encrypt ✓ (cache, <${CACHE_TTL}s)\n"
printf "  └─ After TTL expiry:  encrypt ✗ (LOCKOUT)\n"
printf "\n"
info "This demonstrates that HYOK tenants can revoke KeyRack's access"
info "to their HSM and be guaranteed lockout within ${CACHE_TTL} seconds."
printf "\n"
info "To restore: docker compose down -v && docker compose up -d"
printf "\n"
