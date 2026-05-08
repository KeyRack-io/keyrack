# KeyRack

**Sovereign key management with pluggable HSM backends.**

KeyRack is an open-source key lifecycle coordination layer. It tracks key
hierarchies, drives rotation, and delegates all cryptographic material to
HSM backends (PKCS#11, KMIP). It never stores raw key material.

- **Sovereign** — you control your keys. No cloud vendor lock-in.
- **Pluggable HSMs** — PKCS#11 (Thales, Entrust, YubiHSM, CloudHSM), KMIP for tenant-managed HSMs.
- **API compatible** — AWS KMS and OpenStack Barbican shims let existing apps work without code changes.
- **Policy-driven** — external authorization via any PDP (Cedar, OPA). Every operation is authorized and audited.
- **Hierarchical keys** — deterministic key derivation trees with namespace-scoped rules and cascade disable.

## Quickstart

Start the full stack (KeyRack service + Cedar PDP) with Docker Compose:

```bash
git clone https://github.com/keyrack/keyrack.git
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
  type: software        # or: pkcs11, in_memory

pdp:
  type: http
  endpoint: "http://localhost:8181/v1/authorize"
  timeout_ms: 5000

audit:
  type: stdout           # or: file, nats

authn:
  type: insecure         # or: bootstrap_token, mtls, jwt
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
├── keyrack-pii/            PII tokenization helper (coming soon)
├── keyrack-pkcs11/         PKCS#11 HSM provider
├── keyrack-kmip/           KMIP client provider (HYOK)
├── keyrack-postgres/       PostgreSQL storage backend
├── keyrack-sqlite/         SQLite storage backend
├── keyrack-nats/           NATS audit sink
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

- [Operator guide](docs/OPERATOR.md) — configuration, deployment, monitoring
- [Developer guide](docs/DEVELOPER.md) — using the library, writing custom providers
- [Security model](docs/SECURITY.md) — threat model, invariants, vulnerability disclosure
- [Cedar starter schema](docs/CEDAR_STARTER_SCHEMA.md) — example PDP schema
- [Migration design](MIGRATION.md) — key hierarchy migration semantics

## License

Business Source License 1.1, converting to Apache License 2.0 four years
after each release. See [LICENSE](LICENSE) for full terms.
