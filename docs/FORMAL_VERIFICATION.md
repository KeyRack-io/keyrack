# Formal Verification: Proptest + Kani

This document explains how to run the formal-methods Tier 0 verification
suite locally. These tests complement the standard `cargo test` suite with
property-based testing (proptest) and bounded model checking (Kani).

## Proptest (property-based invariants)

Proptest is already a dev-dependency. The invariant tests live in:

```
crates/keyrack-core/tests/formal_invariants.rs
```

### What is tested

| Invariant | Description |
|-----------|-------------|
| Encrypt/decrypt round-trip | For arbitrary plaintext + AAD, AES-GCM encrypt→decrypt recovers the original |
| Wrong-AAD rejection | Mismatched AAD always fails decryption (integrity) |
| Rotation preserves decryptability | Old-version ciphertext remains decryptable after N rotations |
| Cascade-disable permitted | State machine always permits disabling descendants |
| No plaintext in AuditEvent | Serialized audit events never contain raw key bytes |
| No plaintext in KeyRecord | Serialized key records never contain raw key material |

### Running

```bash
cd keyrack-oss
export CARGO_TARGET_DIR="$(pwd)/target"

# Run all tests including proptests
cargo test --workspace

# Run only the formal invariant tests (faster iteration)
cargo test -p keyrack-core --test formal_invariants

# Increase case count for deeper exploration (default: 200-300 per property)
PROPTEST_CASES=1000 cargo test -p keyrack-core --test formal_invariants
```

Proptest regression files are committed to the repo when a failure is found
(`proptest-regressions/`). They ensure previously-discovered edge cases
remain covered.

## Kani (bounded model checking)

Kani uses CBMC under the hood to exhaustively verify properties over bounded
inputs. The harnesses live in:

```
crates/keyrack-core/src/kani_proofs.rs
```

They are gated behind `#[cfg(kani)]` and invisible to normal builds/CI.

### What is proved

| Harness | Property |
|---------|----------|
| `sensitive_debug_never_leaks_key_material` | `Sensitive<T>::Debug` output is always `[REDACTED]` for any 4-byte key |
| `sensitive_display_never_leaks_key_material` | `Sensitive<T>::Display` is always `[REDACTED]` |
| `sensitive_expose_is_faithful` | `expose()` returns exactly the original bytes (correctness dual) |
| `sensitive_into_inner_is_faithful` | `into_inner()` returns exactly the original bytes |
| `sensitive_debug_is_constant_output` | Debug output is input-independent (no side-channel leakage) |

The proof strategy: since ALL key material flows through `Sensitive<T>`, and
`Sensitive<T>` does NOT implement `Serialize` (compile-time enforcement), these
harnesses prove that key material structurally cannot reach any serialized output.
The proptest suite verifies the end-to-end composition (serde_json serialization
of AuditEvent/KeyRecord) which Kani cannot model due to serde's complexity.

### Prerequisites

Install the Kani verifier (one-time):

```bash
cargo install --locked kani-verifier
cargo kani setup
```

See https://model-checking.github.io/kani/install-guide.html for full
instructions (requires CBMC, which `cargo kani setup` installs automatically).

### Running

```bash
cd keyrack-oss

# Run all Kani harnesses
cargo kani -p keyrack-core

# Run a specific harness
cargo kani -p keyrack-core --harness sensitive_debug_never_leaks_key_material
cargo kani -p keyrack-core --harness audit_event_serialization_no_plaintext_leak

# With verbose output
cargo kani -p keyrack-core --harness sensitive_debug_never_leaks_key_material --verbose
```

### Limitations and follow-ups

- Kani harnesses use bounded inputs (4 bytes) for tractability. The proptest
  suite covers larger inputs (16-32 byte keys) probabilistically.
- Full `serde_json` serialization is infeasible for Kani (CBMC cannot model
  the trait-dispatch complexity). The structural proof here (`Sensitive` never
  leaks through formatting) combines with proptest's end-to-end JSON checks
  to cover both the mechanism and the composition.
- Kani is **not yet in the CI gate** — this is a deliberate follow-up task
  (CI-wiring: add `cargo kani` to the verification workflow, run nightly or
  on crypto-touching PRs). The harnesses are runnable and green locally.
- Total Kani verification time: ~26 seconds for all 5 harnesses.

## CI integration status

| Tool | In CI? | Notes |
|------|--------|-------|
| Proptest | **Yes** | Runs as part of `cargo test --workspace` |
| Kani | **No** (follow-up) | Requires kani-verifier install; target: nightly or crypto-path PRs |
