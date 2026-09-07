# Provisional crypto worker — custody creation consumer

This unpublished crate implements a private isolated-process development harness.
It is not an enabled A3 provider, a production daemon, or a shared IPC/authority
contract. No service depends on it. Start requires the explicit
`--provisional-harness` flag and a base64 Ed25519 verification key supplied by a
trusted launcher. The test authority holds the signing key outside the worker.

The implementation consumes `keyrack_core::custody` from `0476087` (the rebased
successor of `a74f884`) for native creation, and retains V1 `WrappingContext` and `ParentWrappedMaterial` accessors
for the provisional encrypt/decrypt adapter. It changes none of these shared types. Its private
fixture descriptor is only checked structurally; no worker lifecycle is inferred
from it. There is no public library, persisted worker envelope, hierarchy database,
production capability advertisement, or provider-object closure receipt.

## Native creation admission

Vault startup now configures only the client. It performs no metadata lookup or
key generation before the worker creates its fresh incarnation and installs a
trusted test-launcher reservation. The private `generate` command carries base64
canonical `Evidence<AuthorityGrant>`; the configured verifier, exact issuer/key
names, provider/domain scope, generation, principal, request, attempt, clock and
ancestor bounds are checked before any provider access. The local software fixture
also defers plaintext seeding until the first authorized use; it cannot issue a
native-wrapped-only creation result.

The reservation is supplied in `KEYRACK_WORKER_CREATION_PLAN` as JSON containing
`operation`, `attempt`, `owner` (`instance` and `generation`), `envelope_ref`, and
`principal`. It is trusted harness setup, **not an A2 journal reservation or proof
of owner currentness**. The coordinator request stream cannot install or replace
it. The [creation consumer proposal](CREATION_CONSUMER_PROPOSAL.md) specifies the
proposed operation transcript and the remaining contract-owner decisions.

A single reservation bounds state. Admission consumes both the shared worker
sequence and the attempt before metadata access. The worker rechecks authority
after metadata, after native generation, and after signing the observation.
Timeouts, malformed replies, and post-call expiry leave the attempt consumed and
the ciphertext unusable. Neither a newer sequence nor another request can replace
that unresolved attempt within the incarnation. Restart rejects old-incarnation
grants; **durable reconciliation and cross-restart duplicate prevention remain
UNMET** and belong to storage integration.

Success returns canonical `Evidence<CreationResult>`, the exact independently
signed authority evidence, and a canonical `CustodyMaterialDescriptor`. The result
binds request/attempt/executor, storage owner, and complete material digest, with
`NativeWrappedOnlyGenerated`. It is neither provider-object closure nor verified
A2 publication permission. The observer key is created inside the worker; its
advertisement over the trusted test child channel is **not production key
distribution or attestation**. No other receipt family is migrated in this slice.

## Existing private crypto behavior

- AES-256-GCM application encryption/decryption with complete V1 context as AAD,
  worker-generated nonces, and bounded plaintext/ciphertext input.
- Independently verified, domain-separated signed test grants binding principal,
  complete context digest, operation, input digest, worker incarnation,
  generation, sequence and monotonic boot-relative deadlines.
- Authority checked before materialization, on warm cache hits and before the core
  returns an operation result. Replays consume a bounded sequence high-water mark;
  ambiguous failed attempts cannot be replayed. Every restart generates a new random incarnation.
- Bounded secret residency, non-renewing cache deadlines, operation counts,
  zeroizing owned secret buffers and expiry cleanup even with idle input.
- Serialized local fencing follows completed core work and purges before its
  local observation;
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
fencing. Failure coverage also checks failed-open replay consumption, warm hits
without provider calls, lease replacement after expiry, rejected-fence state
preservation, domain-wide purge across multiple residents, restart with the same
envelope and old grants/fences, and lease-counter exhaustion. Subprocess tests keep the signer in the parent and materialization in a
different PID, exercise encryption/decryption, denial and fencing, and force
output backpressure.

## Contribution to the existing Vault lane

`docker-vault-ci-lane` belongs to the A2 track. Its `vault-provider` job
(**Vault provider export tests**) in `.github/workflows/ci.yml` exists at
`a85272c`. It runs `scripts/test-vault-provider.sh`, which preserves and guards the
four original provider tests and exposes a post-test command hook using the same
`demos/01-foss-vault` fixture. This crate supplies that hook's worker consumer,
**not a second maintained CI stack**.

The worker contribution is present through A2 merge `bfa0060` (formerly
`f4d7bfc`), but the workflow at the worker base `4e639ad` still invokes only the
provider script with no hook arguments. The latest fetched A2 target `27b5923` contains that correction at
`c730a3a` and the PR-trigger fix `be72c05`. The invocation is:

```sh
bash scripts/test-vault-provider.sh -- bash scripts/test-worker-vault-contribution.sh --from-vault-provider-fixture
```

The worker helper provisions temporary restricted worker/coordinator tokens and a
test parent within that already-running demo fixture. Token files are created
privately and cleaned up; tokens/policies and the parent are revoked/deleted
after the worker tests. A2 still owns the server and its final teardown. The helper
refuses an address/token outside the expected localhost demo setup. It is trusted
test provisioning, not a deployment supervisor or isolation proof.

For an already-provisioned worker fixture, the same consumer also accepts the
explicit variables below without provisioning anything:

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
| `KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE` | Disposable test-admin permissions for parent-loss and qualification controls: create/read/configure/delete/rotate parents, native generation/decrypt/encrypt, and export of a separate exportable control parent |

Only the worker token file/address/parent are passed into the subprocess; the
admin and coordinator tokens stay with the test launcher. On Unix the worker
refuses a token file unless the opened file is regular, owned by its effective UID,
and has no group/world permission bits (0400 or 0600 are suitable). It refuses
final symlinks, bounds the read, and validates and reads the same file descriptor.
Platforms without this ownership check refuse Vault startup. Use a private
temporary directory. Never point these tests at production.
The parent-loss test creates and deletes a fresh random `worker-fixture-loss-*`
parent; fixture teardown owns cleanup after a failed run.

The Vault adapter is a development qualification probe. It calls native
`datakey/wrapped` with an exact parent version and the entire canonical `CustodyContext` frame (V1 plus explicit profile) as the derived parent's `context`, then supplies the same bytes on
decrypt. It verifies parent settings, bounds responses and rejects unexpected
generation plaintext or malformed/wrong-version ciphertext. The exact profile is
`UNQUALIFIED-vault-derived-worker-fixture-v1`; it enables no production capability.
This uses Vault's native derivation; `context` is not the
same parameter as `associated_data`. The [version-scoped qualification report](VAULT_PROFILE_QUALIFICATION.md) establishes the exact HKDF/AES-GCM construction,
endpoint AAD behavior and remaining production-profile gates. The test requires
Vault 1.17.6; the existing Compose minor tag is not an immutable image pin.

Live tests require the actual fixture and fail if absent; they do not fall back
to mocks. They verify every-byte custody-frame perturbation rejection (the historical
`every_v1_context_byte` test name is retained for the lane discovery guard), a valid
coordinator token's decrypt denial, authorized native generation with canonical provenance followed by separate-process
crypto, and parent loss.
Warm use after out-of-band parent deletion is possible until the independently
signed ancestor deadline; at the bound it fails, and a cold reopen fails against
the deleted parent. That test does not claim immediate deletion detection.

The A2 lane retains its **four original ignored Vault-provider tests**. The worker
script additionally guards discovery of its own four ignored live tests, so a
renamed, removed, or un-ignored test fails before running the suite. Local hook
passes do not establish CI acceptance. The hook is absent from this branch base
but restored on the A2 integration target at `c730a3a`. Actual CI run evidence for each worker revision and required
branch-protection contexts remain separate acceptance obligations. See [the A2 lane status](../../docs/VAULT_PROVIDER_TESTS.md)
for its trigger and gating scope.

## Limits and integration gates

**Distinct-UID fixture acceptance demonstrated on Linux.** The
[two-user supervisor fixture](SUPERVISOR_ISOLATION.md) passed in the existing Vault
lane at `049c5b8`: three native worker executions under a dedicated non-root user,
and six actual coordinator-user token-open attempts returning `EACCES`, before and
after startup, restart and credential replacement/revocation. It verifies real UID
and capability state, uses a clean coordinator environment and requires cleanup.
Root performs provisioning only; denial probes and worker tests execute non-root.
The ordinary same-UID subprocess suite alone still proves no deployment isolation.

The token loader independently enforces owner-only regular-file checks. A deployment
must preserve the tested separate identities, trusted supervisor, protected token
path and clean credential environment, and exclude equivalent credential access.
The fixture establishes its stated file-read acceptance property; it does not
attest arbitrary deployments, process-memory access controls or host-root exclusion.
Profile approval, durable storage and external authority remain separate integrations.

The shared canonical custody frame is adopted for native creation and Vault parent
operations. The [Vault construction investigation](VAULT_PROFILE_QUALIFICATION.md)
is verified for the recorded 1.17.6 build and fresh-parent conditions, using source
inspection, independent decryption and live controls. **Production profile approval
remains UNMET**; the contract codec itself does not qualify a provider. A2 owns
review of these findings, the proposed transcript/profile and eventual storage
acceptance. Encrypt/decrypt test grants, application-data AAD, local lease
cleanup and local fencing still use their explicitly provisional adapters; this
is not a completed shared IPC/authority migration. Native creation does not publish
anything into the hierarchy or bypass `VerifiedA2Closure` requirements.

The current test engine supports one authority domain and AES-256 leaves. It has
no durable revocation authority, all-holder completion, explicit export, ancestor
graph, hierarchy publication, authority renewal/reinstatement, or production
transport. Monotonic test deadlines and policy constants are harness parameters;
they are not recommended deployment defaults or a universal five-second setting.

Residency cleanup is polled every 20 ms in the idle harness. A synchronous provider
call can delay the poll (local Vault requests have a two-second timeout). Usage
limits are per residency, not a durable lifetime nonce budget; admission/eviction
and multi-worker accounting need the production profile's reviewed limits.

[Output release and cancellation](OUTPUT_RELEASE.md) now carry authority and
incarnation through encrypted staging and an atomic, nonblocking key-capsule
commit serialized with fencing. Cancelled responses have terminal status; queued
keys expire even behind blocked control output. The document defines admission,
irrevocable release and fence observation precisely, including OS preemption and
receiver-read limitations. This remains a private transport and creates no
canonical `OutputsSuppressed` claim.

Owned raw buffers and AES schedules enable available zeroization features.
Compiler/OS copies, HTTP header buffers, swap/crash dumps, and all GCM-derived
state are not proved erased. In particular, the pinned POLYVAL ARM PMULL backend
does not implement zeroizing Drop. This prototype makes no full-memory erasure,
host-root exclusion, hardware-custody, or child-HYOK claim.

The original branch base was `27e0f51`. After the A2 rebase recovery, this branch
is based on `4e639ad` and **includes** PKCS#11 concurrency fix `f63b347`. The worker
replays landed at `9e69991` and `bb1497e`; the original V1 material/wrapping files
remain unchanged. This slice does not exercise concurrent PKCS#11 login.
