#!/bin/sh
# Generate a self-contained demo PKI:
#   - a trusted CA (the server's client_ca_root)
#   - a server cert (CN=keyrack, SANs for hostname verification)
#   - two client certs: alice and bob (CN becomes the KeyRack principal id)
#   - a forged "alice" signed by an UNTRUSTED rogue CA
#
# busybox/ash compatible. Idempotent: re-running is a no-op once generated.
set -eu

CERTS=/certs
DAYS=825
cd "$CERTS"

if [ -f alice.pem ]; then
  echo "certs already present in $CERTS — skipping generation"
  exit 0
fi

echo "generating demo PKI in $CERTS ..."

# --- Trusted CA (server validates client certs against this) ---
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca-key.pem -out ca.pem -days "$DAYS" \
  -subj "/CN=KeyRack Demo CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Rogue (untrusted) CA, used to forge an "alice" identity ---
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout rogue-ca-key.pem -out rogue-ca.pem -days "$DAYS" \
  -subj "/CN=Rogue CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# issue <name> <CN> <ca-cert> <ca-key> <ext-lines>
issue() {
  name=$1; cn=$2; ca=$3; cakey=$4; ext=$5
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${name}-key.pem" -out "${name}.csr" -subj "/CN=${cn}"
  printf '%b\n' "$ext" > "${name}.ext"
  openssl x509 -req -in "${name}.csr" \
    -CA "$ca" -CAkey "$cakey" -CAcreateserial \
    -out "${name}.pem" -days "$DAYS" -extfile "${name}.ext"
  rm -f "${name}.csr" "${name}.ext"
}

# Server: serverAuth + SANs so the client can verify the hostname "keyrack".
issue server keyrack ca.pem ca-key.pem \
  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:keyrack,DNS:localhost"

# Clients: clientAuth. The CN is what MtlsAuthenticator uses as the principal id.
issue alice alice ca.pem ca-key.pem \
  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth"
issue bob bob ca.pem ca-key.pem \
  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth"

# Forged "alice" signed by the rogue CA (NOT trusted by the server).
issue rogue alice rogue-ca.pem rogue-ca-key.pem \
  "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth"

chmod 644 ./*.pem
echo "done:"
ls -1 "$CERTS"
