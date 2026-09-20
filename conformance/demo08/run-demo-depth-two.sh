#!/bin/sh
# Demo 08: Hierarchical Cascade Rotation
#
# Shows that rotating a root key cascades rotation jobs through a multi-level
# hierarchy (root → child → grandchild) and demonstrates the cooperative
# acknowledge/complete protocol over gRPC.
set -e

BASE="http://keyrack:8080"
GRPC="keyrack:50051"
PROTO_IMPORT="/proto"
PROTO_FILE="keyrack/v1/key_service.proto"
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

step()       { echo "--- $1"; }
ok()         { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail()       { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }
assert_eq()  {
  if [ "$1" = "$2" ]; then ok "$3"
  else fail "$3 (expected '$2', got '$1')"; fi
}

json_field() {
  echo "$1" | tr ',' '\n' | tr '{' '\n' | tr '}' '\n' \
    | grep "\"$2\"" | head -1 \
    | sed 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\{0,1\}//; s/"\{0,1\}[[:space:]]*$//'
}

grpc_call() {
  # grpc_call <method> <json-data>
  grpcurl -plaintext \
    -import-path "${PROTO_IMPORT}" \
    -proto "${PROTO_FILE}" \
    -d "$2" \
    "${GRPC}" "keyrack.v1.KeyService/$1"
}

# ── Wait for KeyRack ─────────────────────────────────────────────────

banner "Demo 08: Hierarchical Cascade Rotation"

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
#  PART 1 — Build a 3-level key hierarchy via REST
# ══════════════════════════════════════════════════════════════════════

banner "Part 1: Build Root → Child → Grandchild hierarchy"

step "Creating root key..."
ROOT_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d '{"key_spec":"AES_256","description":"demo root key"}')
echo "  Response: ${ROOT_RESP}"
ROOT_LID=$(json_field "$ROOT_RESP" lid)
if [ -n "$ROOT_LID" ]; then
  ok "Root key created — LID: ${ROOT_LID}"
else
  fail "Root key creation failed"
  exit 1
fi

step "Creating child key under root..."
CHILD_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"key_spec\":\"AES_256\",\"description\":\"child key\",\"parent_key_id\":\"${ROOT_LID}\"}")
echo "  Response: ${CHILD_RESP}"
CHILD_LID=$(json_field "$CHILD_RESP" lid)
if [ -n "$CHILD_LID" ]; then
  ok "Child key created — LID: ${CHILD_LID}"
else
  fail "Child key creation failed"
  exit 1
fi

step "Creating grandchild key under child..."
GC_RESP=$(curl -sf -X POST "${BASE}/v1/keys" \
  -H "Content-Type: application/json" \
  -d "{\"key_spec\":\"AES_256\",\"description\":\"grandchild key\",\"parent_key_id\":\"${CHILD_LID}\"}")
echo "  Response: ${GC_RESP}"
GC_LID=$(json_field "$GC_RESP" lid)
if [ -n "$GC_LID" ]; then
  ok "Grandchild key created — LID: ${GC_LID}"
else
  fail "Grandchild key creation failed"
  exit 1
fi

step "Verifying parent relationships via /describe..."
CHILD_DESC=$(curl -sf "${BASE}/v1/keys/${CHILD_LID}/describe")
CHILD_PARENT=$(json_field "$CHILD_DESC" parent_lid)
assert_eq "$CHILD_PARENT" "$ROOT_LID" "Child's parent_lid matches root"

GC_DESC=$(curl -sf "${BASE}/v1/keys/${GC_LID}/describe")
GC_PARENT=$(json_field "$GC_DESC" parent_lid)
assert_eq "$GC_PARENT" "$CHILD_LID" "Grandchild's parent_lid matches child"

# ══════════════════════════════════════════════════════════════════════
#  PART 2 — Inspect the hierarchy via gRPC GetKeyDependents
# ══════════════════════════════════════════════════════════════════════

banner "Part 2: Inspect hierarchy via gRPC"

step "GetKeyDependents(root, recursive=true)..."
DEPS_JSON=$(grpc_call "GetKeyDependents" \
  "{\"keyId\": \"${ROOT_LID}\", \"recursive\": true}")
echo "  Response: ${DEPS_JSON}"

DEPS_COUNT=$(echo "$DEPS_JSON" | jq 'if .dependents then (.dependents | length) else 0 end')
echo "  Dependent count: ${DEPS_COUNT}"
assert_eq "$DEPS_COUNT" "2" "Root has exactly 2 recursive dependents (child + grandchild)"

# ══════════════════════════════════════════════════════════════════════
#  PART 3 — Rotate the root key and observe cascaded rotation jobs
# ══════════════════════════════════════════════════════════════════════

banner "Part 3: Rotate root key via gRPC — cascade to descendants"

step "Rotating the root key via gRPC RotateKey (creates descendant rotation jobs)..."
ROT_JSON=$(grpc_call "RotateKey" "{\"keyId\": \"${ROOT_LID}\"}")
echo "  Response: ${ROT_JSON}"
NEW_VER=$(echo "$ROT_JSON" | jq -r '.newVersion // empty')
if [ -n "$NEW_VER" ]; then
  ok "Root key rotated — new version: ${NEW_VER}"
else
  fail "Root key rotation failed"
  exit 1
fi

# Small pause to let the server record all rotation jobs
sleep 1

step "ListRotationJobs (all) — should show pending jobs for child + grandchild..."
JOBS_JSON=$(grpc_call "ListRotationJobs" '{}')
echo "  Response: ${JOBS_JSON}"

PENDING_COUNT=$(echo "$JOBS_JSON" | jq '[.jobs[]? | select(.state == "PENDING")] | length')
echo "  Pending rotation job count: ${PENDING_COUNT}"
assert_eq "$PENDING_COUNT" "2" "Exactly 2 pending rotation jobs created (child + grandchild)"

# The jobs must target the two DISTINCT descendants, not just any 2 keys.
# Each job carries dependent_key_id = the key that must re-wrap.
DEP_IDS=$(echo "$JOBS_JSON" | jq -r '[.jobs[]? | select(.state == "PENDING") | .dependentKeyId] | sort | join(",")')
EXPECTED_DEPS=$(printf '%s\n%s\n' "$CHILD_LID" "$GC_LID" | sort | tr '\n' ',' | sed 's/,$//')
echo "  Dependent keys with jobs: ${DEP_IDS}"
assert_eq "$DEP_IDS" "$EXPECTED_DEPS" "Jobs target the distinct child + grandchild dependents"

# ══════════════════════════════════════════════════════════════════════
#  PART 4 — Cooperative ack/complete protocol
# ══════════════════════════════════════════════════════════════════════

banner "Part 4: Cooperative ack/complete for each rotation job"

JOB_IDS=$(echo "$JOBS_JSON" | jq -r '.jobs[]? | select(.state == "PENDING") | .jobId')

step "Processing rotation jobs..."
JOBS_PROCESSED=0
for JOB_ID in $JOB_IDS; do
  step "  AcknowledgeRotationJob: ${JOB_ID}"
  ACK_JSON=$(grpc_call "AcknowledgeRotationJob" "{\"jobId\": \"${JOB_ID}\"}")
  ACK_STATE=$(echo "$ACK_JSON" | jq -r '.job.state // empty')
  echo "    State after ack: ${ACK_STATE}"
  assert_eq "$ACK_STATE" "ACKNOWLEDGED" "Job ${JOB_ID} moved to ACKNOWLEDGED"

  step "  CompleteRotationJob: ${JOB_ID}"
  COMP_JSON=$(grpc_call "CompleteRotationJob" "{\"jobId\": \"${JOB_ID}\"}")
  COMP_STATE=$(echo "$COMP_JSON" | jq -r '.job.state // empty')
  echo "    State after complete: ${COMP_STATE}"
  assert_eq "$COMP_STATE" "COMPLETED" "Job ${JOB_ID} moved to COMPLETED"

  JOBS_PROCESSED=$((JOBS_PROCESSED + 1))
done

assert_eq "$JOBS_PROCESSED" "2" "Processed exactly 2 rotation jobs"

step "ListRotationJobs — verify all are now COMPLETED..."
JOBS_AFTER=$(grpc_call "ListRotationJobs" '{}')
echo "  Response: ${JOBS_AFTER}"

COMPLETED_COUNT=$(echo "$JOBS_AFTER" | jq '[.jobs[]? | select(.state == "COMPLETED")] | length')
STILL_PENDING=$(echo "$JOBS_AFTER" | jq '[.jobs[]? | select(.state == "PENDING")] | length')
echo "  Completed: ${COMPLETED_COUNT}, Still pending: ${STILL_PENDING}"
assert_eq "$COMPLETED_COUNT" "2" "Both rotation jobs are COMPLETED"
assert_eq "$STILL_PENDING" "0" "Zero pending rotation jobs remain"

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
