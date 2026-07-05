# KeyRack

**Sovereign key management with pluggable HSM backends.**

KeyRack is an open-source key lifecycle coordination layer. It tracks key
hierarchies, drives rotation, and delegates all cryptographic material to
HSM backends (PKCS#11, KMIP, Vault Transit). When backed by an HSM or
Vault provider, raw key material never leaves the backend; the software
provider holds key bytes in process memory (dev/test only).

- **Sovereign** — you control your keys. No cloud vendor lock-in.
- **Pluggable HSMs** — PKCS#11 (Thales, Entrust, YubiHSM, CloudHSM), KMIP for tenant-managed HSMs, Vault Transit.
- **API compatible** — AWS KMS and OpenStack Barbican shims let existing apps work without code changes.
- **Policy-driven** — external authorization via any PDP (Cedar, OPA). Every operation is authorized and audited.
- **Hierarchical keys** — KEK-wrapping hierarchy with namespace-scoped rules and cascade disable.
- **HYOK (Hold Your Own Key)** — tenants plug in their own HSM; disconnect immediately fails crypto operations on that backend. Cross-node cache staleness in the commercial HA tier is bounded by a configurable TTL.
- **Cryptographic audit** — Ed25519-signed events with BLAKE3 hash chain, delivered over NATS. Provides strong interior tamper-evidence; tail-truncation detection requires an external anchor; signing is opt-in and ephemeral by default.

## Quickstart

Start the full stack (KeyRack service + Cedar PDP) with Docker Compose:

```bash
git clone https://github.com/KeyRack-io/keyrack.git
cd keyrack
docker compose up -d keyrack-service
```

Wait a few seconds for the service to be healthy, then:

```bash
# Create an AES-256 key
KEY_ID=$(curl -s http://localhost:8080/v1/keys -X POST \
  -H 'Content-Type: application/json' \
  -d '{"key_spec": "AES_256", "description": "quickstart key"}' \
  | jq -r '.lid')

echo "Created key: $KEY_ID"

# Encrypt some data (base64-encoded plaintext)
CIPHERTEXT=$(curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-encrypt" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"plaintext": "aGVsbG8ga2V5cmFjaw=="}' \
  | jq -r '.ciphertext_blob')

echo "Ciphertext: ${CIPHERTEXT:0:40}..."

# Decrypt it back
curl -s "http://localhost:8080/v1/keys/$KEY_ID/actions-decrypt" -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"ciphertext_blob\": \"$CIPHERTEXT\"}" \
  | jq -r '.plaintext' | base64 -d

# Output: hello keyrack
```

To stop:

```bash
docker compose down
```

## Building from source

```bash
cargo build --workspace
cargo test --workspace
```

The service binary is `keyrack-service`. The CLI is `keyrack-cli`. Both are
built as part of the workspace.

## Configuration

KeyRack is configured via a YAML file. Set `KEYRACK_CONFIG` to point to it:

```yaml
grpc_addr: "0.0.0.0:50051"
rest_addr: "0.0.0.0:8080"

storage:
  type: sqlite
  path: "/var/lib/keyrack/keyrack.db"

provider:
  type: software        # or: pkcs11, kmip, vault_transit, in_memory
                        # for multi-tenant HYOK / multiple backends, use a
                        # `providers:` list + `provider_routing` (see OPERATOR.md)

pdp:
  type: http
  endpoint: "http://localhost:8181/v1/authorize"
  timeout_ms: 5000

audit:
  type: stdout           # or: file, nats
sign_audit_events: true
audit_signing_key_path: "/var/lib/keyrack/audit-signing-key"

authn:
  type: jwt              # or: mtls, bootstrap_token, forwarded_identity, chain, insecure
  jwks_url: "https://your-idp/.well-known/jwks.json"
  issuer: "https://your-idp"

cache:
  max_capacity: 10000
  ttl_secs: 300
```

See [docs/OPERATOR.md](docs/OPERATOR.md) for the full configuration reference.

## Repository layout

```
crates/
├── keyrack-core/           Core library: types, traits, providers, audit
├── keyrack-service/        gRPC + REST service binary
├── keyrack-cedar-pdp/      Standalone Cedar PDP binary
├── keyrack-cli/            CLI tools (lint, provision, migrate, admin)
├── keyrack-wasm/           WASM target + JS/TS bindings
├── keyrack-pii/            PII tokenization helper (BLAKE3 tokenizer)
├── keyrack-pkcs11/         PKCS#11 HSM provider
├── keyrack-kmip/           KMIP client provider (HYOK)
├── keyrack-postgres/       PostgreSQL storage backend
├── keyrack-sqlite/         SQLite storage backend
├── keyrack-nats/           NATS audit sink + state-change publisher
├── keyrack-vault/          HashiCorp Vault Transit provider
└── keyrack-test-support/   Shared test fixtures
docs/
├── OPERATOR.md             Running KeyRack in production
├── DEVELOPER.md            Using the library, writing providers
├── SECURITY.md             Threat model, invariants, disclosure
└── CEDAR_STARTER_SCHEMA.md Example Cedar schema for operators
proto/
└── keyrack/v1/             Protobuf definitions
```

## REST API

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/keys` | Create a key |
| `GET` | `/v1/keys` | List keys |
| `GET` | `/v1/keys/:id` | Get key |
| `GET` | `/v1/keys/:id/describe` | Describe key (full metadata) |
| `POST` | `/v1/keys/:id/actions-encrypt` | Encrypt data |
| `POST` | `/v1/keys/:id/actions-decrypt` | Decrypt data |
| `POST` | `/v1/keys/:id/actions-sign` | Sign data |
| `POST` | `/v1/keys/:id/actions-verify` | Verify signature |
| `POST` | `/v1/keys/:id/actions-generate-data-key` | Generate a data key |
| `POST` | `/v1/keys/:id/actions-rotate` | Rotate key |
| `POST` | `/v1/keys/:id/actions-enable` | Enable key |
| `POST` | `/v1/keys/:id/actions-disable` | Disable key |
| `GET` | `/v1/aliases` | List aliases |
| `POST` | `/v1/aliases` | Create alias |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |
| `GET` | `/metrics` | Prometheus metrics |

The same operations are available over gRPC on port 50051.

## Documentation

- [Why KeyRack?](docs/WHY_KEYRACK.md) — motivation, use cases, comparison
- [Integration guide](docs/INTEGRATION_GUIDE.md) — AuthN, AuthZ, Audit, production checklist
- [Operator guide](docs/OPERATOR.md) — configuration, deployment, monitoring
- [Developer guide](docs/DEVELOPER.md) — using the library, writing custom providers
- [Security model](docs/SECURITY.md) — threat model, invariants, vulnerability disclosure
- [Cedar starter schema](docs/CEDAR_STARTER_SCHEMA.md) — example PDP schema

## Demos

Eight runnable FOSS demos (each a `docker compose up` away):

| Demo | What it shows | Provider |
|------|--------------|----------|
| [01-foss-vault](demos/01-foss-vault/) | Key lifecycle with Vault Transit | Vault |
| [02-foss-softhsm](demos/02-foss-softhsm/) | HSM-backed crypto via PKCS#11 | SoftHSM |
| [04-hyok-full-stack](demos/04-hyok-full-stack/) | AuthN + AuthZ + Audit + HYOK disconnect | SoftHSM + NATS + Cedar |
| [06-provider-routing](demos/06-provider-routing/) | Tag-driven routing across HSM partitions | 2× SoftHSM tokens |
| [08-cascade-rotation](demos/08-cascade-rotation/) | Hierarchical cascade rotation + cooperative ack/complete | Software |
| [09-audit-tamper-evidence](demos/09-audit-tamper-evidence/) | Ed25519-signed + BLAKE3 hash-chained audit log verification | Software |
| [10-mtls-identity](demos/10-mtls-identity/) | mTLS client-certificate identity | Software |
| [11-multi-tenant-hyok](demos/11-multi-tenant-hyok/) | Multi-tenant HYOK with per-tenant HSMs | 2× SoftHSM tokens |

Run them all with a pass/fail summary via [`scripts/run-demos-ci.sh`](scripts/run-demos-ci.sh).

Plus a Kubernetes demo (needs `kind` + `kubectl`, not docker compose):

| Demo | What it shows | Platform |
|------|--------------|----------|
| [07-k8s-sidecar](demos/07-k8s-sidecar/) | App + KeyRack sidecar in one pod (localhost), Postgres + Cedar | kind |

AWS KMS-compatible access (including HYOK) is available via the commercial extensions.

## License

KeyRack's core is licensed under the **GNU Affero General Public License v3.0
or later** (AGPL-3.0-or-later). See [LICENSE](LICENSE) for full terms.

The Protocol Buffers definitions (`proto/`) and the high-level client SDK
(`keyrack` crate) are licensed under **Apache-2.0** to maximize interoperability
and ease of integration for applications.

Using KeyRack's engine inside a larger work that you distribute or operate as a
network service requires that work to comply with the AGPL. **Alternative
commercial licensing is available** for organizations that wish to embed KeyRack
without the AGPL's reciprocity obligations — contact the Licensor.
