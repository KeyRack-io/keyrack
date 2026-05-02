# KeyRack

Sovereign KMS with pluggable HSM backends.

KeyRack is a key lifecycle coordination layer: it tracks key hierarchies,
drives rotation, and delegates all cryptographic material to HSM backends
(PKCS#11, KMIP). It never stores raw key material.

## License

Business Source License 1.1, converting to Apache License 2.0 four years
after each release. See [LICENSE](LICENSE) for full terms.

## Repository layout

```
crates/
├── keyrack-core/           Core library: types, traits, canonicalization, LID,
│                           rule engine, resolver, providers (software, in-memory),
│                           audit sinks, Sensitive<T>
├── keyrack-pkcs11/         PKCS#11 provider (production HSMs)
├── keyrack-kmip/           KMIP client provider (HYOK / external HSM)
├── keyrack-postgres/       PostgreSQL storage backend
├── keyrack-sqlite/         SQLite storage backend
├── keyrack-nats/           NATS audit sink
├── keyrack-test-support/   Shared test fixtures
├── keyrack-service/        gRPC + REST service binary        [W2]
├── keyrack-cedar-pdp/      Standalone Cedar PDP binary        [W2]
├── keyrack-cli/            CLI tools                          [W3]
├── keyrack-wasm/           WASM target + JS/TS bindings       [W4]
└── keyrack-pii/            PII tokenization helper            [W5]
docs/
└── SPEC.md                 Critical-path design decisions
proto/
└── keyrack/v1/             Proto definitions (W2)
```

Crates marked `[W2]`–`[W5]` are stubs; implementation lands in later
workstreams per [PLAN.md](PLAN.md).

## Building

```bash
cargo build --workspace
cargo test --workspace
```

## Documentation

- [PLAN.md](PLAN.md) — implementation plan
- [KEYRACK_SPEC.md](KEYRACK_SPEC.md) — a partner integration contract
- [MIGRATION.md](MIGRATION.md) — canonicalization and rule-change migration design
- [PDP_WIRE_FORMAT_REQS.md](PDP_WIRE_FORMAT_REQS.md) — PDP wire format constraints
- [docs/SPEC.md](docs/SPEC.md) — internal specification (critical-path artefacts)
