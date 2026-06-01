# Contributing to KeyRack

Thank you for your interest in contributing to KeyRack.

## How to contribute

### Reporting bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- KeyRack version and environment (OS, Rust version, storage backend)

### Security vulnerabilities

**Do not open a public issue.** See [SECURITY.md](docs/SECURITY.md) for
the disclosure process.

### Feature requests

Open an issue describing:
- The problem you're trying to solve
- Your proposed solution (if any)
- Whether this affects the core library, service, or a specific crate

### Pull requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the test suite: `cargo test --workspace`
5. Run clippy: `cargo clippy --workspace -- -D warnings`
6. Submit a pull request

For large changes, open an issue first to discuss the approach.

## Development setup

### Prerequisites

- Rust 1.80+
- Protobuf compiler (`protoc`)
- Docker (for E2E tests)
- Optional: SoftHSM2 (for PKCS#11 tests)

### Building

```bash
cargo build --workspace
cargo test --workspace
```

### Running with Docker

```bash
# Full E2E test suite (includes SoftHSM)
./scripts/e2e-docker.sh

# Quick mode (skip property tests)
./scripts/e2e-docker.sh --quick

# Clippy lint
./scripts/e2e-docker.sh --clippy
```

### Project structure

Each crate under `crates/` has a focused responsibility:

- **keyrack-core** — the foundation: types, traits, providers, canonicalization, audit.
  Changes here affect everything downstream.
- **keyrack-service** — the gRPC/REST server. Most feature work happens here.
- **keyrack-cedar-pdp** — standalone Cedar PDP. Small surface area.
- **keyrack-cli** — CLI tools. Operates against a running service.
- Storage crates (**keyrack-sqlite**, **keyrack-postgres**) — implement `StorageBackend`.
- Provider crates (**keyrack-pkcs11**, **keyrack-kmip**) — implement `CryptoProvider`.

## Code style

- Follow existing patterns in the codebase
- Use `#[must_use]` on builder methods and pure functions
- Wrap sensitive data in `Sensitive<T>` — never log plaintext
- Every RPC must go through `ops::execute` (PDP + audit enforcement)
- No `unsafe` code (workspace-wide `#![forbid(unsafe_code)]`)
- Comments should explain *why*, not *what*

## Testing

- Unit tests in each module (`#[cfg(test)]`)
- Integration tests in `crates/keyrack-service/tests/`
- Property tests via `proptest` for canonicalization and LID derivation
- E2E tests in Docker with SoftHSM (PKCS#11) and PostgreSQL

## License & Contributor License Agreement

KeyRack's core is licensed under **AGPL-3.0-or-later**; the Protocol Buffers
definitions and the high-level `keyrack` client SDK are **Apache-2.0**.

KeyRack is dual-licensed: it is offered both under the AGPL and under separate
commercial terms. To make that sustainable, all contributions require a
**Contributor License Agreement** ([CLA.md](CLA.md)), which grants the Licensor
the right to license your contribution under both the AGPL and commercial
terms. You retain copyright to your contributions.

Concretely:

1. Sign off every commit under the
   [Developer Certificate of Origin](https://developercertificate.org/)
   with `git commit -s`.
2. Accept the [CLA](CLA.md) when prompted on your first pull request (entities
   contributing on behalf of an employer should execute the corporate variant —
   see the CLA for details).

Pull requests cannot be merged until the CLA is on file.
