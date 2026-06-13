#!/bin/sh
# Demo 10: mTLS identity -> authorization, end to end.
#
# Proves that the client TLS certificate's identity (CN) is extracted by
# KeyRack, propagated to the Cedar PDP, and enforced — at both the transport
# and the application layer:
#
#   1. alice  (valid cert, permitted by policy)   -> CreateKey SUCCEEDS
#   2. bob    (valid cert, denied by policy)       -> CreateKey -> PermissionDenied
#   3. no client certificate                       -> rejected at the TLS layer
#   4. "alice" forged by an untrusted CA           -> rejected at the TLS layer
#
# (1) vs (2) differ only by which client certificate is presented, so a
# different authorization outcome proves the identity genuinely flows from the
# certificate through authn into the PDP. (3) and (4) prove the identity cannot
# be omitted or forged.
set -u

GRPC="keyrack:50051"
CERTS=/certs
PROTO_IMPORT=/proto
PROTO_FILE="keyrack/v1/key_service.proto"
PASS=0
FAIL=0

banner() {
  echo
  echo "============================================================"
  echo "  $1"
  echo "============================================================"
  echo
}
ok()   { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }

# call_as <cert-basename | "none"> <json> -> echoes combined stdout+stderr,
# returns grpcurl's exit code.
call_as() {
  who=$1; data=$2
  if [ "$who" = "none" ]; then
    grpcurl -cacert "$CERTS/ca.pem" \
      -import-path "$PROTO_IMPORT" -proto "$PROTO_FILE" \
      -d "$data" "$GRPC" keyrack.v1.KeyService/CreateKey 2>&1
  else
    grpcurl -cacert "$CERTS/ca.pem" \
      -cert "$CERTS/${who}.pem" -key "$CERTS/${who}-key.pem" \
      -import-path "$PROTO_IMPORT" -proto "$PROTO_FILE" \
      -d "$data" "$GRPC" keyrack.v1.KeyService/CreateKey 2>&1
  fi
}

banner "Demo 10: mTLS identity -> authorization"

echo "--- waiting for KeyRack (REST /healthz is plain HTTP; gRPC is mTLS-only) ..."
i=0
while [ $i -lt 30 ]; do
  if curl -sf "http://keyrack:8080/healthz" >/dev/null 2>&1; then ok "KeyRack healthy"; break; fi
  i=$((i + 1)); sleep 1
done
if [ $i -ge 30 ]; then fail "KeyRack did not become healthy in time"; exit 1; fi

REQ='{"keySpec":"AES_256","description":"demo-10 key"}'

# 1) alice — permitted by the Cedar policy.
banner "1) alice presents a valid cert and IS permitted by policy"
OUT=$(call_as alice "$REQ"); RC=$?
echo "$OUT" | sed 's/^/    /'
LID=$(echo "$OUT" | jq -r '.metadata.keyId // empty' 2>/dev/null)
if [ $RC -eq 0 ] && [ -n "$LID" ]; then
  ok "alice CreateKey SUCCEEDED (keyId=$LID)"
else
  fail "alice CreateKey should have succeeded (rc=$RC)"
fi

# 2) bob — authenticated via mTLS, but denied by policy (application layer).
banner "2) bob presents a valid cert but is DENIED by policy"
OUT=$(call_as bob "$REQ"); RC=$?
echo "$OUT" | sed 's/^/    /'
if [ $RC -ne 0 ] && echo "$OUT" | grep -qi "PermissionDenied"; then
  ok "bob CreateKey DENIED with PermissionDenied (identity reached the PDP)"
else
  fail "bob should have been denied with PermissionDenied (rc=$RC)"
fi

# 3) no client certificate — rejected at the TLS layer (mTLS is mandatory).
banner "3) no client certificate — rejected before the application"
OUT=$(call_as none "$REQ"); RC=$?
echo "$OUT" | sed 's/^/    /'
if [ $RC -ne 0 ] && ! echo "$OUT" | grep -qi "PermissionDenied"; then
  ok "anonymous (no cert) was rejected before reaching the application"
else
  fail "anonymous request should have been rejected (rc=$RC)"
fi

# 4) forged "alice" from an untrusted CA — rejected at the TLS layer.
banner "4) forged 'alice' signed by an untrusted CA — rejected at the TLS layer"
OUT=$(call_as rogue "$REQ"); RC=$?
echo "$OUT" | sed 's/^/    /'
if [ $RC -ne 0 ] && ! echo "$OUT" | grep -qi "PermissionDenied"; then
  ok "forged identity (untrusted CA) was rejected at the TLS layer"
else
  fail "forged identity should have been rejected at the TLS layer (rc=$RC)"
fi

banner "Summary"
TOTAL=$((PASS + FAIL))
echo "  Results: ${PASS}/${TOTAL} checks passed"
echo
if [ "$FAIL" -gt 0 ]; then
  echo "  ⚠ ${FAIL} check(s) failed — review output above."
  exit 1
else
  echo "  All checks passed!"
  exit 0
fi
