#!/usr/bin/env bash
# Generate a throwaway CA, server certificate and client certificate for the
# KMIP provider proof. Everything lands in ./certs, which is gitignored.
#
# The client certificate's CN matters: PyKMIP derives the client identity from
# it and its default policy grants a client access to the objects it owns, so
# the CN here is the identity that owns every key the proof creates.
#
# Keys are ECDSA P-256, not RSA, and that is load-bearing. keyrack-kmip uses
# rustls, which implements only AEAD cipher suites; the only AEAD suites
# PyKMIP offers are ECDHE-ECDSA-AES-GCM, which require an ECDSA server
# certificate. With RSA certificates the two share no cipher suite and the
# handshake fails with an opaque alert.
set -euo pipefail

cd "$(dirname "$0")"
OUT="certs"
CLIENT_CN="${CLIENT_CN:-keyrack-kmip-provider}"

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 3 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=keyrack-kmip-proof-ca" 2>/dev/null

# Server certificate. localhost + 127.0.0.1 so the provider can be pointed at
# either without a hostname-verification failure.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
cat > server.ext <<'EXT'
subjectAltName = DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 3 -extfile server.ext -out server.crt 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
  -keyout client.key -out client.csr -subj "/CN=${CLIENT_CN}" 2>/dev/null
cat > client.ext <<'EXT'
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 3 -extfile client.ext -out client.crt 2>/dev/null

rm -f server.csr client.csr server.ext client.ext ca.srl
chmod 600 ./*.key

echo "certs written to $(pwd) (client CN=${CLIENT_CN})"
