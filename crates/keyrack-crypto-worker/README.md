# Provisional crypto worker — milestone 2

This unpublished crate implements a private isolated-process development harness.
It is not an enabled A3 provider, a production daemon, or a shared IPC/authority
contract. No service depends on it. Start requires the explicit
`--provisional-harness` flag and a base64 Ed25519 verification key supplied by a
trusted launcher. The test authority holds the signing key outside the worker.

The implementation reuses `keyrack-core` V1 `WrappingContext` and existing
`ParentWrappedMaterial` accessors. It changes neither shared type. Its private
fixture descriptor is only checked structurally; no worker lifecycle is inferred
from it. There is no public library, persisted worker envelope, hierarchy database,
production capability advertisement, or provider-object closure receipt.

## Implemented behavior

- AES-256-GCM application encryption/decryption with complete V1 context as AAD,
  worker-generated nonces, and bounded plaintext/ciphertext input.
- Independently verified, domain-separated signed test grants binding principal,
  complete context digest, operation, input digest, worker incarnation,
  generation, sequence and monotonic boot-relative deadlines.
- Authority checked before materialization, on warm cache hits and before result
  release. Replays consume a bounded sequence high-water mark; ambiguous failed
  attempts cannot be replayed. Every restart generates a new random incarnation.
- Bounded secret residency, non-renewing cache deadlines, operation counts,
  zeroizing owned secret buffers and expiry cleanup even with idle input.
- Serialized local fencing drains/suppresses work before its local observation;
  signed wrong-domain, stale or wrong-incarnation fences fail. Fencing is terminal
  for the incarnation: this slice invents no reinstatement protocol.
- Separate local residency-cleanup and authority-fence observations. Neither is
  an authenticated integration receipt, creation destruction or all-holder proof.
- Bounded input frames and queues; output backpressure terminates the worker and
  drops custody state instead of blocking expiry indefinitely. Provider errors
  are redacted. No raw-key return or generic parent-decrypt command exists.

## Validation

```sh
cargo test -p keyrack-crypto-worker
cargo clippy -p keyrack-crypto-worker --all-targets -- -D warnings
cargo fmt --all -- --check
```

Unit tests cover scoped/forged authority, replay, restarts, warm expiry, slow
materialization, use/capacity/input limits, authenticated context changes and
fencing. Subprocess tests keep the signer in the parent and materialization in a
different PID, exercise encryption/decryption, denial and fencing, and force
output backpressure.

## Contribution to the existing Vault lane

`docker-vault-ci-lane` belongs to the A2 track. This crate supplies a consumer
script, **not a second maintained CI stack**:

```sh
bash scripts/test-worker-vault-contribution.sh
```

Its test launcher needs these environment variables:

| Variable | Fixture requirement |
|---|---|
| `VAULT_ADDR` | Disposable localhost HTTP Vault; Transit mounted at `transit` |
| `KEYRACK_WORKER_VAULT_PARENT` | Dedicated `worker-fixture-*` parent, version 1, derived non-convergent `aes256-gcm96`, non-exportable, plaintext backup disabled |
| `KEYRACK_WORKER_VAULT_TOKEN_FILE` | File containing worker token, read on `transit/keys/worker-fixture-*`, update on `transit/datakey/wrapped/worker-fixture-*` and `transit/decrypt/worker-fixture-*` |
| `KEYRACK_WORKER_VAULT_COORDINATOR_TOKEN_FILE` | Valid token with self-lookup allowed and parent-decrypt denied |
| `KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE` | Test-parent create/configure/delete permission for the parent-loss control |

Only the worker token file/address/parent are passed into the subprocess; the
admin and coordinator tokens stay with the test launcher. Token files should be
mode 0600 in a private temporary directory. Never point these tests at production.
The parent-loss test creates and deletes a fresh random `worker-fixture-loss-*`
parent; fixture teardown owns cleanup after a failed run.

The Vault adapter is a development qualification probe. It calls native
`datakey/wrapped` with an exact parent version and the entire V1 canonical byte
string as the derived parent's `context`, then supplies the same bytes on
decrypt. It verifies parent settings, bounds responses and rejects unexpected
generation plaintext. This uses Vault's native derivation; `context` is not the
same parameter as `associated_data`. See the
[native Vault API](https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-data-key).

Live tests require the actual fixture and fail if absent; they do not fall back
to mocks. They verify every-byte context perturbation rejection, a valid
coordinator token's decrypt denial, separate-process crypto, and parent loss.
Warm use after out-of-band parent deletion is possible until the independently
signed ancestor deadline; at the bound it fails, and a cold reopen fails against
the deleted parent. That test does not claim immediate deletion detection.

The A2 lane must retain its **four original ignored Vault-provider tests**, in
addition to invoking this script. Local passes do not establish final acceptance;
canonical lane wiring and run evidence remain required.

## Limits and integration gates

The boundary/profile proposal is awaiting arbitration. Concrete production
profile encoding, shared IPC/authority/evidence codecs, and shared creation
results are not implemented. Native wrapped-only fixture generation runs at
trusted test setup, not through an authorized journaled creation API. Its local
observation is not a qualified durable creation result.

The current test engine supports one authority domain and AES-256 leaves. It has
no durable revocation authority, all-holder completion, explicit export, ancestor
graph, hierarchy publication, authority renewal/reinstatement, or production
transport. Monotonic test deadlines and policy constants are harness parameters;
they are not recommended deployment defaults or a universal five-second setting.

Residency cleanup is polled every 20 ms in the idle harness. A synchronous provider
call can delay the poll (local Vault requests have a two-second timeout). Usage
limits are per residency, not a durable lifetime nonce budget; admission/eviction
and multi-worker accounting need the production profile's reviewed limits.

Owned raw buffers and AES schedules enable available zeroization features.
Compiler/OS copies, HTTP header buffers, swap/crash dumps, and all GCM-derived
state are not proved erased. In particular, the pinned POLYVAL ARM PMULL backend
does not implement zeroizing Drop. This prototype makes no full-memory erasure,
host-root exclusion, hardware-custody, or child-HYOK claim.

The branch base is `27e0f51`; it lacks PKCS#11 concurrency fix `f63b347` present on
public main `e54c14d`. This slice does not exercise concurrent PKCS#11 login.
