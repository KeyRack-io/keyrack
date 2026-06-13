# Demo 10 — mTLS identity → authorization

This demo proves that a client's **mutual-TLS certificate identity** is
extracted by KeyRack, carried through authentication, and **enforced by the
Cedar PDP** — not just validated at the transport layer and then dropped.

| Layer | What it does |
|-------|--------------|
| **Transport** | Mandatory mTLS on the gRPC server (`tls.ca_cert` set). Clients without a trusted client certificate cannot connect. |
| **AuthN** | `MtlsAuthenticator` derives the principal id from the client cert's CN (or SPIFFE SAN). |
| **AuthZ** | Cedar PDP, deny-by-default. Only `alice` is permitted. |

## What it shows

```
┌──────────┐   client cert    ┌───────────────────────────┐     authorize    ┌────────────┐
│ grpcurl  │─────────────────▶│  KeyRack (mTLS gRPC)       │─────────────────▶│  Cedar PDP │
│ as alice │   CN = alice     │  CN → principal id         │  principal=alice │  permit    │
│ / bob    │                  │  fail-closed authn         │                  │  alice     │
└──────────┘                  └───────────────────────────┘                  └────────────┘
```

Four cases, run with the same request but different (or no) certificates:

1. **alice** — valid cert, permitted by policy → `CreateKey` **succeeds**.
2. **bob** — valid cert, no matching policy → `CreateKey` → **`PermissionDenied`**.
3. **no certificate** — rejected at the **TLS layer** (mTLS is mandatory).
4. **forged "alice"** — a cert with `CN=alice` signed by an *untrusted* CA →
   rejected at the **TLS layer** (you cannot forge the identity).

Cases 1 and 2 differ **only** by which certificate is presented, so the
different outcome is what demonstrates the certificate identity genuinely
reaches the authorization decision.

## Run

```sh
docker compose up --build --abort-on-container-exit --exit-code-from demo
docker compose down -v
```

The `demo` container exits non-zero if any check fails.

## How it works

- `certgen` (one-shot) builds a small PKI into a shared volume: a CA, a server
  cert (`CN=keyrack`, with SANs), client certs for `alice` and `bob`, and a
  forged `alice` signed by a separate **rogue** CA.
- `keyrack` is configured with `authn: mtls`, a `tls` block (`ca_cert` makes
  client certs mandatory), and the Cedar PDP as its authorizer.
- `cedar-pdp` loads `config/cedar-policy.cedar`, which permits only `alice`.
- `demo` runs `grpcurl` over TLS with each identity and asserts the outcomes.

## Production notes

| Demo | Production |
|------|------------|
| CN-based identity | SPIFFE/SVID SANs from a workload-identity issuer (SPIRE) |
| Self-signed demo CA | Your internal/enterprise PKI or service mesh CA |
| Per-principal `permit` | Attribute-based Cedar policies (tenant, environment, ABAC) |
| SQLite + software provider | PostgreSQL + an HSM/KMS provider |
