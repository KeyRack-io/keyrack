#!/usr/bin/env bash
# Runs inside the proof container. Drives the real keyrack-service binary
# through losing custody of a PKCS#11 token and getting it back, and asserts
# that service returns without the process being restarted.
#
# Every assertion is counted. The suite refuses to report success unless it
# ran the number of checks it was written to run, so a step that silently
# stops executing reads as a failure rather than as a pass.

set -uo pipefail

BASE="http://127.0.0.1:8080"
TOKENS=/var/lib/softhsm/tokens
AWAY=/var/lib/softhsm/away
LOG=/tmp/keyrack-service.log
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# Number of assertions below. Raising or lowering it is a deliberate edit and
# the CI job checks this value, so a quiet suite cannot pass.
MIN_EXPECTED_PASSES=13

# How long service may take to come back after custody returns. Recovery is
# attempted at most once every MIN_REINIT_INTERVAL (2s in the provider), and
# a caller retry is what triggers it, so this allows several attempts.
RECOVERY_BUDGET_SECS=30

passes=0
failures=0

pass() { printf '  PASS  %s\n' "$1"; passes=$((passes + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
step() { printf '\n== %s\n' "$1"; }

cleanup() {
    if [[ -n "${SVC_PID:-}" ]] && kill -0 "$SVC_PID" 2>/dev/null; then
        kill "$SVC_PID" 2>/dev/null
        wait "$SVC_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── tokens ───────────────────────────────────────────────────────────────
step "Two SoftHSM tokens on one library"
mkdir -p "$TOKENS" "$AWAY"
softhsm2-util --init-token --free --label custody --pin 1234 --so-pin 0000 >/dev/null
# Exactly one token directory exists at this point, so it is the custody one.
CUSTODY_DIR=$(ls "$TOKENS")
softhsm2-util --init-token --free --label sibling --pin 5678 --so-pin 0000 >/dev/null
echo "  custody token directory: $CUSTODY_DIR"
if [[ $(ls "$TOKENS" | wc -l) -eq 2 ]]; then
    pass "two tokens initialized on one library"
else
    fail "expected two token directories, found: $(ls "$TOKENS" | tr '\n' ' ')"
fi

# ── the real binary ──────────────────────────────────────────────────────
step "Start the real keyrack-service binary"
RUST_LOG=info KEYRACK_CONFIG=/config/keyrack.yaml keyrack-service >"$LOG" 2>&1 &
SVC_PID=$!

for _ in $(seq 1 60); do
    if curl -sf "$BASE/healthz" >/dev/null 2>&1; then break; fi
    sleep 1
done
if curl -sf "$BASE/healthz" >/dev/null 2>&1; then
    pass "service is up (pid $SVC_PID)"
else
    fail "service never became healthy; log follows"
    tail -30 "$LOG"
    exit 1
fi

# ── helpers ──────────────────────────────────────────────────────────────
create_key() {
    curl -s "$BASE/v1/keys" -H 'Content-Type: application/json' \
        -d "{\"key_spec\":\"AES_256\",\"description\":\"custody proof\",\"attributes\":{\"token\":\"$1\"}}"
}

# encrypt_code <key_id> → HTTP status of an encrypt call
encrypt_code() {
    curl -s -o /tmp/enc-body -w '%{http_code}' \
        "$BASE/v1/keys/$1/actions-encrypt" -H 'Content-Type: application/json' \
        -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}'
}

step "A key in each token"
custody_resp=$(create_key custody)
sibling_resp=$(create_key sibling)
CUSTODY_KEY=$(jq -r '.lid' <<<"$custody_resp")
SIBLING_KEY=$(jq -r '.lid' <<<"$sibling_resp")
CUSTODY_PROVIDER=$(jq -r '.provider_ref' <<<"$custody_resp")
SIBLING_PROVIDER=$(jq -r '.provider_ref' <<<"$sibling_resp")
echo "  custody key $CUSTODY_KEY on $CUSTODY_PROVIDER"
echo "  sibling key $SIBLING_KEY on $SIBLING_PROVIDER"
if [[ "$CUSTODY_PROVIDER" == "hsm-custody" && "$SIBLING_PROVIDER" == "hsm-sibling" ]]; then
    pass "the two keys live in different tokens"
else
    fail "keys did not route to separate providers ($CUSTODY_PROVIDER / $SIBLING_PROVIDER)"
fi

step "Baseline: both tokens serve"
code=$(encrypt_code "$CUSTODY_KEY")
[[ "$code" == "200" ]] && pass "custody token encrypts (200)" || fail "custody baseline returned $code"
code=$(encrypt_code "$SIBLING_KEY")
[[ "$code" == "200" ]] && pass "sibling token encrypts (200)" || fail "sibling baseline returned $code"

# ── custody loss ─────────────────────────────────────────────────────────
# The sibling shares the initialized module with the token that is about to
# vanish, and recovery reinitializes that module. Calling the sibling before
# and after would miss exactly the window that matters, so hammer it without
# a break from here until after the recovery and count every non-200.
HAMMER_LOG=/tmp/sibling-requests
: >"$HAMMER_LOG"
hammer_sibling() {
    while true; do
        code=$(curl -s -o /dev/null -w '%{http_code}' \
            "$BASE/v1/keys/$SIBLING_KEY/actions-encrypt" \
            -H 'Content-Type: application/json' \
            -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}')
        echo "$code" >>"$HAMMER_LOG"
    done
}
# Every request is recorded, not just the failures, so that a hammer that
# never ran reads as an unproven claim rather than as zero failures.
MIN_SIBLING_REQUESTS=20
hammer_sibling &
HAMMER_PID=$!

step "Custody lost: the token is taken away from the running process"
mv "$TOKENS/$CUSTODY_DIR" "$AWAY/"

code=$(encrypt_code "$CUSTODY_KEY")
if [[ "$code" == "503" ]]; then
    pass "custody token fails closed as unavailable (503)"
else
    fail "expected 503 while custody is absent, got $code: $(cat /tmp/enc-body)"
fi

# The sibling shares the initialized module with the token that just vanished.
sibling_ok=true
for _ in 1 2 3; do
    code=$(encrypt_code "$SIBLING_KEY")
    [[ "$code" == "200" ]] || { sibling_ok=false; echo "  sibling returned $code during the outage"; }
    sleep 1
done
$sibling_ok && pass "sibling token keeps serving throughout the outage" \
             || fail "the outage took the sibling token down with it"

# ── custody restored, no restart ─────────────────────────────────────────
step "Custody restored — the process is NOT restarted"
mv "$AWAY/$CUSTODY_DIR" "$TOKENS/"

started=$(date +%s)
recovered=false
while (( $(date +%s) - started < RECOVERY_BUDGET_SECS )); do
    if [[ "$(encrypt_code "$CUSTODY_KEY")" == "200" ]]; then
        recovered=true
        break
    fi
    sleep 1
done
elapsed=$(( $(date +%s) - started ))

if $recovered; then
    pass "custody token serves again ${elapsed}s after restoration"
else
    fail "custody token still refusing ${elapsed}s after restoration (this is the defect)"
fi

if kill -0 "$SVC_PID" 2>/dev/null; then
    pass "recovery happened in the original process (pid $SVC_PID, never restarted)"
else
    fail "the service process died; this proof only means anything without a restart"
fi

kill "$HAMMER_PID" 2>/dev/null
wait "$HAMMER_PID" 2>/dev/null
sibling_total=$(wc -l <"$HAMMER_LOG" | tr -d ' ')
sibling_bad=$(grep -cv '^200$' "$HAMMER_LOG")
if (( sibling_total < MIN_SIBLING_REQUESTS )); then
    fail "only $sibling_total sibling requests were made; too few to claim anything"
elif (( sibling_bad == 0 )); then
    pass "sibling served all $sibling_total requests across the outage and the recovery"
else
    fail "sibling failed $sibling_bad of $sibling_total requests: $(sort -u "$HAMMER_LOG" | tr '\n' ' ')"
fi

code=$(encrypt_code "$SIBLING_KEY")
[[ "$code" == "200" ]] && pass "sibling token still serving after the recovery" \
                       || fail "recovery disturbed the sibling token ($code)"

step "The recovered token does real crypto, not just a 200"
ct=$(curl -s "$BASE/v1/keys/$CUSTODY_KEY/actions-encrypt" \
    -H 'Content-Type: application/json' \
    -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}' | jq -r '.ciphertext_blob')
pt=$(curl -s "$BASE/v1/keys/$CUSTODY_KEY/actions-decrypt" \
    -H 'Content-Type: application/json' \
    -d "{\"ciphertext_blob\":\"$ct\"}" | jq -r '.plaintext')
if [[ "$pt" == "Y3VzdG9keSBwcm9vZg==" ]]; then
    pass "encrypt/decrypt round-trip through the recovered token"
else
    fail "round-trip through the recovered token failed (got '$pt')"
fi

step "Recovery is what fixed it, and it was the module reinitialization"
if grep -q "PKCS#11 module reinitialized" "$LOG"; then
    pass "service log records the module reinitialization"
else
    fail "no reinitialization in the log — the token came back some other way"
    grep -i "pkcs" "$LOG" | tail -10
fi

# ── verdict ──────────────────────────────────────────────────────────────
printf '\n== Result\n'
printf '  %d passed, %d failed (suite expects at least %d passes)\n' \
    "$passes" "$failures" "$MIN_EXPECTED_PASSES"

if (( failures > 0 )); then
    printf '\nService log tail:\n'
    tail -40 "$LOG"
    exit 1
fi
if (( passes < MIN_EXPECTED_PASSES )); then
    printf '  refusing to report success: only %d checks ran\n' "$passes"
    exit 1
fi
printf '  PKCS#11 custody recovery proof PASSED\n'
