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
MIN_EXPECTED_PASSES=27

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
    [[ -n "${HAMMER_STOP:-}" ]] && : >"$HAMMER_STOP"
    [[ -f "$LOG" ]] && cp "$LOG" /tmp/evidence/service.log
    if [[ -n "${SVC_PID:-}" ]] && kill -0 "$SVC_PID" 2>/dev/null; then
        kill "$SVC_PID" 2>/dev/null
        wait "$SVC_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ── tokens ───────────────────────────────────────────────────────────────
step "Start with only the sibling token"
mkdir -p "$TOKENS" "$AWAY" /tmp/evidence
softhsm2-util --init-token --free --label sibling --pin 5678 --so-pin 0000 >/dev/null
SIBLING_DIR=$(ls "$TOKENS")

# ── the real binary ──────────────────────────────────────────────────────
step "Start the real keyrack-service binary"
RUST_LOG=info KEYRACK_CONFIG=/config/keyrack.yaml keyrack-service >"$LOG" 2>&1 &
SVC_PID=$!

for _ in $(seq 1 60); do
    if curl -sf --connect-timeout 2 --max-time 15 "$BASE/healthz" >/dev/null 2>&1; then break; fi
    sleep 1
done
if curl -sf --connect-timeout 2 --max-time 15 "$BASE/healthz" >/dev/null 2>&1; then
    pass "service is up (pid $SVC_PID)"
else
    fail "service never became healthy; log follows"
    tail -30 "$LOG"
    exit 1
fi

# ── helpers ──────────────────────────────────────────────────────────────
create_key() {
    curl -s --connect-timeout 2 --max-time 15 "$BASE/v1/keys" -H 'Content-Type: application/json' \
        -d "{\"key_spec\":\"AES_256\",\"description\":\"custody proof\",\"attributes\":{\"token\":\"$1\"}}"
}

# encrypt_code <key_id> → HTTP status of an encrypt call
encrypt_code() {
    curl -s --connect-timeout 2 --max-time 15 -o /tmp/enc-body -w '%{http_code}' \
        "$BASE/v1/keys/$1/actions-encrypt" -H 'Content-Type: application/json' \
        -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}'
}

# ── custody loss ─────────────────────────────────────────────────────────
# The sibling shares the initialized module with the token that is about to
# vanish, and recovery reinitializes that module. Calling the sibling before
# and after would miss exactly the window that matters, so load it without a
# break from here until after the recovery and count every non-200.
#
# The load is CONCURRENT, and that is the point. An earlier version of this
# harness ran one request at a time, which meant the module was almost always
# idle: recovery waits for in-flight calls to drain, so a serial load made
# draining instant and the harness could not observe what happens to callers
# that arrive while the library is being reinitialized. Several workers keep
# calls in flight across the whole window, which is what a deployment does.
SIBLING_WORKERS=8
HAMMER_DIR=/tmp/sibling-requests.d
HAMMER_STOP=/tmp/sibling-stop
HAMMER_PIDS=()

hammer_worker() {
    local id="$1"
    while [[ ! -e "$HAMMER_STOP" ]]; do
        code=$(curl -s --connect-timeout 2 --max-time 15 -o /dev/null -w '%{http_code} %{time_total}' \
            "$BASE/v1/keys/$SIBLING_KEY/actions-encrypt" \
            -H 'Content-Type: application/json' \
            -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}')
        printf '%s %s\n' "$(cut -d ' ' -f1 /proc/uptime)" "$code" >>"$HAMMER_DIR/$id"
    done
}

start_hammer() {
    rm -rf "$HAMMER_DIR" "$HAMMER_STOP"
    mkdir -p "$HAMMER_DIR"
    HAMMER_PIDS=()
    for id in $(seq 1 "$SIBLING_WORKERS"); do
        hammer_worker "$id" &
        HAMMER_PIDS+=("$!")
    done
}

# Stopped with a file rather than a signal, so no worker is killed midway
# through a request and every answer it received is in the tally.
stop_hammer() {
    : >"$HAMMER_STOP"
    local pid
    for pid in "${HAMMER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null
    done
}

# Every request is recorded, not just the failures, so that a load generator
# that never ran reads as an unproven claim rather than as zero failures.
MIN_SIBLING_REQUESTS=40
step "An absent optional token does not prevent startup"
code=$(curl -s --connect-timeout 2 --max-time 15 -o /tmp/evidence/startup-readiness.json -w '%{http_code}' "$BASE/readyz")
if [[ "$code" == 200 ]] && jq -e '.status == "ready" and .provider_states["hsm-custody"] == {custody:"customer",status:"unavailable"} and .provider_states["hsm-sibling"].status == "available"' /tmp/evidence/startup-readiness.json >/dev/null; then
    pass "absent optional token is unavailable while readiness stays ready"
else
    fail "absent optional token blocked readiness or was not reported"
fi
code=$(curl -s --connect-timeout 2 --max-time 15 -o /tmp/startup-create -w '%{http_code}' "$BASE/v1/keys" -H 'Content-Type: application/json' -d '{"key_spec":"AES_256","attributes":{"token":"custody"}}')
[[ "$code" == 503 ]] && pass "absent token refuses creation with 503" || fail "absent token creation returned $code"
sibling_resp=$(create_key sibling)
SIBLING_KEY=$(jq -r '.lid' <<<"$sibling_resp")
start_hammer
sleep 1
softhsm2-util --init-token --free --label custody --pin 1234 --so-pin 0000 >/dev/null
CUSTODY_DIR=$(ls "$TOKENS" | grep -Fxv "$SIBLING_DIR")
[[ $(ls "$TOKENS" | wc -l) -eq 2 ]] && pass "two tokens initialized on one library" || fail "token initialization failed"
started=$SECONDS
custody_resp='{}'
while (( SECONDS - started < 180 )); do
    custody_resp=$(create_key custody)
    if jq -e '.lid != null' <<<"$custody_resp" >/dev/null; then break; fi
    sleep 1
done
if jq -e '.lid != null' <<<"$custody_resp" >/dev/null && kill -0 "$SVC_PID"; then
    pass "late token initialization recovered in the original process"
else
    fail "late token initialization did not recover without restart"
fi
stop_hammer
cp -R "$HAMMER_DIR" /tmp/evidence/startup-requests
startup_total=$(cat "$HAMMER_DIR"/* | wc -l)
startup_bad=$(cat "$HAMMER_DIR"/* | awk '$2 != 200 {n++} END {print n+0}')
if (( startup_total >= MIN_SIBLING_REQUESTS && startup_bad == 0 )) && [[ $(ls "$HAMMER_DIR" | wc -l) -eq $SIBLING_WORKERS ]]; then
    pass "startup sibling served all $startup_total requests with zero failures"
else
    fail "startup sibling failed $startup_bad of $startup_total requests"
fi

step "A key in each token"
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


start_hammer

step "Custody lost: the token is taken away from the running process"
mv "$TOKENS/$CUSTODY_DIR" "$AWAY/"

code=$(encrypt_code "$CUSTODY_KEY")
if [[ "$code" == "503" ]]; then
    pass "custody token fails closed as unavailable (503)"
else
    fail "expected 503 while custody is absent, got $code: $(cat /tmp/enc-body)"
fi

# Steady unavailable-token traffic for at least 60 monotonic seconds while
# all eight sibling workers remain active. Keep raw samples for the report.
outage_start=$(cut -d ' ' -f1 /proc/uptime)
outage_calls=0
outage_bad=0
while awk -v start="$outage_start" '{exit !(($1-start)<60)}' /proc/uptime; do
    code=$(encrypt_code "$CUSTODY_KEY")
    outage_calls=$((outage_calls + 1))
    [[ "$code" == 503 ]] || outage_bad=$((outage_bad + 1))
    sleep 0.1
done
outage_end=$(cut -d ' ' -f1 /proc/uptime)
if (( outage_calls >= 40 && outage_bad == 0 )); then
    pass "sustained outage issued $outage_calls custody requests, all unavailable"
else
    fail "sustained outage traffic: $outage_bad unexpected responses in $outage_calls requests"
fi
code=$(curl -s --connect-timeout 2 --max-time 15 -o /tmp/evidence/outage-readiness.json -w '%{http_code}' "$BASE/readyz")
if [[ "$code" == 200 ]] && jq -e '.status == "ready" and .provider_states["hsm-custody"].status == "unavailable"' /tmp/evidence/outage-readiness.json >/dev/null; then
    pass "readiness stays ready during sustained optional-token outage"
else
    fail "sustained optional-token outage blocked readiness"
fi

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

stop_hammer
cp -R "$HAMMER_DIR" /tmp/evidence/outage-requests
python3 /usr/local/bin/latency.py "$HAMMER_DIR" "$outage_start" "$outage_end" > /tmp/evidence/latency.json
if [[ $? == 0 ]]; then
    pass "sustained outage sibling latency: $(cat /tmp/evidence/latency.json)"
else
    fail "latency evidence is incomplete or contains sibling failures"
fi
sibling_total=$(cat "$HAMMER_DIR"/* 2>/dev/null | wc -l | tr -d ' ')
sibling_bad=$(cat "$HAMMER_DIR"/* 2>/dev/null | awk '$2 != 200 {n++} END {print n+0}')
sibling_active=$(ls "$HAMMER_DIR" | wc -l | tr -d ' ')

# A load that collapsed to one worker would drain instantly and prove nothing
# about the reinitialization window, so the concurrency itself is asserted.
if (( sibling_active == SIBLING_WORKERS )); then
    pass "all $SIBLING_WORKERS concurrent workers issued requests across the window"
else
    fail "only $sibling_active of $SIBLING_WORKERS workers ran; the load was not concurrent"
fi

if (( sibling_total < MIN_SIBLING_REQUESTS )); then
    fail "only $sibling_total sibling requests were made; too few to claim anything"
elif (( sibling_bad == 0 )); then
    pass "sibling served all $sibling_total requests across the outage and the recovery"
else
    fail "sibling failed $sibling_bad of $sibling_total requests: $(cat "$HAMMER_DIR"/* | sort | uniq -c | tr '\n' ' ')"
fi

code=$(encrypt_code "$SIBLING_KEY")
[[ "$code" == "200" ]] && pass "sibling token still serving after the recovery" \
                       || fail "recovery disturbed the sibling token ($code)"

step "The recovered token does real crypto, not just a 200"
ct=$(curl -s --connect-timeout 2 --max-time 15 "$BASE/v1/keys/$CUSTODY_KEY/actions-encrypt" \
    -H 'Content-Type: application/json' \
    -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}' | jq -r '.ciphertext_blob')
pt=$(curl -s --connect-timeout 2 --max-time 15 "$BASE/v1/keys/$CUSTODY_KEY/actions-decrypt" \
    -H 'Content-Type: application/json' \
    -d "{\"ciphertext_blob\":\"$ct\"}" | jq -r '.plaintext')
if [[ "$pt" == "Y3VzdG9keSBwcm9vZg==" ]]; then
    pass "encrypt/decrypt round-trip through the recovered token"
else
    fail "round-trip through the recovered token failed (got '$pt')"
fi

# ── rotation as the first operation after custody returns ────────────────
# A second cycle, because which operation runs first after restoration is not
# a detail: recovery is driven by a request failing, so the first request
# decides whether it happens at all. Rotation writes new key material, and it
# was left untested by the first version of this proof, which only ever
# encrypted and decrypted.
step "Custody lost again, and rotation is the FIRST call after it returns"
PRE_ROTATION_CT=$(curl -s --connect-timeout 2 --max-time 15 "$BASE/v1/keys/$CUSTODY_KEY/actions-encrypt" \
    -H 'Content-Type: application/json' \
    -d '{"plaintext":"Y3VzdG9keSBwcm9vZg=="}' | jq -r '.ciphertext_blob // empty')
start_hammer
mv "$TOKENS/$CUSTODY_DIR" "$AWAY/"

code=$(encrypt_code "$CUSTODY_KEY")
if [[ "$code" == "503" ]]; then
    pass "custody token is unavailable again (503)"
else
    fail "expected 503 while custody is absent the second time, got $code"
fi



mv "$AWAY/$CUSTODY_DIR" "$TOKENS/"

# Nothing may touch this token before the rotation does.
rotate_code() {
    curl -s --connect-timeout 2 --max-time 15 -o /tmp/rot-body -w '%{http_code}' \
        "$BASE/v1/keys/$1/actions-rotate" -H 'Content-Type: application/json' -d '{}'
}

ROTATE_CODES=/tmp/rotate-codes
: >"$ROTATE_CODES"
started=$(date +%s)
rotated=false
while (( $(date +%s) - started < RECOVERY_BUDGET_SECS )); do
    code=$(rotate_code "$CUSTODY_KEY")
    printf '%s\n' "$code" >>"$ROTATE_CODES"
    if [[ "$code" == "200" ]]; then
        rotated=true
        break
    fi
    sleep 1
done
elapsed=$(( $(date +%s) - started ))

if $rotated; then
    pass "rotation succeeded ${elapsed}s after restoration, with no restart"
else
    fail "rotation still refusing ${elapsed}s after restoration: $(sort "$ROTATE_CODES" | uniq -c | tr '\n' ' ')"
fi

# 503 says "unavailable, retry" and a retry is what triggers recovery. 500
# says the failure is permanent, which stops a well-behaved client retrying
# and means recovery was never attempted for it. That distinction is the
# whole mechanism, so a permanent answer here is a failure even if a later
# attempt succeeds.
if grep -qv '^\(200\|503\)$' "$ROTATE_CODES"; then
    fail "rotation answered a non-retryable status: $(sort "$ROTATE_CODES" | uniq -c | tr '\n' ' ')"
else
    pass "every rotation answer was 200 or retryable 503, never a permanent error"
fi

step "The rotated token is usable, and the old version still is"
code=$(encrypt_code "$CUSTODY_KEY")
[[ "$code" == "200" ]] && pass "encrypt under the new primary version (200)" \
                       || fail "encrypt after rotation returned $code"

if [[ -n "$PRE_ROTATION_CT" ]]; then
    pt=$(curl -s --connect-timeout 2 --max-time 15 "$BASE/v1/keys/$CUSTODY_KEY/actions-decrypt" \
        -H 'Content-Type: application/json' \
        -d "{\"ciphertext_blob\":\"$PRE_ROTATION_CT\"}" | jq -r '.plaintext // empty')
    [[ "$pt" == "Y3VzdG9keSBwcm9vZg==" ]] \
        && pass "ciphertext from before the rotation still decrypts" \
        || fail "rotation cost us the retained version (got '$pt')"
else
    fail "pre-rotation ciphertext missing; retained-version check did not run"
fi

if kill -0 "$SVC_PID" 2>/dev/null; then
    pass "both recovery cycles happened in the original process (pid $SVC_PID)"
else
    fail "the service process died during the second cycle"
fi

stop_hammer
cp -R "$HAMMER_DIR" /tmp/evidence/rotation-requests
cycle2_total=$(cat "$HAMMER_DIR"/* 2>/dev/null | wc -l | tr -d ' ')
cycle2_bad=$(cat "$HAMMER_DIR"/* 2>/dev/null | awk '$2 != 200 {n++} END {print n+0}')
if (( cycle2_total < MIN_SIBLING_REQUESTS )); then
    fail "only $cycle2_total sibling requests during the second cycle"
elif (( cycle2_bad == 0 )); then
    pass "sibling served all $cycle2_total requests across the second cycle"
else
    fail "sibling failed $cycle2_bad of $cycle2_total requests in the second cycle: $(cat "$HAMMER_DIR"/* | sort | uniq -c | tr '\n' ' ')"
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
