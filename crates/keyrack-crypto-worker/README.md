# Provisional crypto worker — custody creation consumer

This unpublished crate implements a private isolated-process development harness.
It is not an enabled A3 provider, a production daemon, or a shared IPC/authority
contract. No service depends on it. Start requires the explicit
`--provisional-harness` flag and a base64 Ed25519 verification key supplied by a
trusted launcher. The test authority holds the signing key outside the worker.

The implementation consumes `keyrack_core::custody` from `a74f884` for native
creation, and retains V1 `WrappingContext` and `ParentWrappedMaterial` accessors
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

After integrating the worker files, the A2 job owner can invoke both suites by
extending its existing run step to:

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
| `KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE` | Test-parent create/configure/delete permission for the parent-loss control |

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
same parameter as `associated_data`. See the
[native Vault API](https://developer.hashicorp.com/vault/api-docs/secret/transit#generate-data-key).

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
passes do not establish CI acceptance. A2 must adopt the hook in its existing job
and supply run evidence. The owner reports that the existing job runs but is not
yet required by branch protection; worker integration does not change that rule.

## Limits and integration gates

**UNMET deployment acceptance gate — coordinator/worker credential isolation.**
The startup ownership/mode checks are enforced; they do not establish distinct
coordinator and worker identities. A same-UID coordinator or privileged launcher
can still read an owner-only file. The development subprocess tests run under one
UID and prove channel non-leakage and unsafe-file refusal, not deployment isolation.

A deployment must run the worker under a dedicated OS identity distinct from the
coordinator, provision its credential through a trusted supervisor the coordinator
cannot control, and protect the credential file and parent directories. It must
deny coordinator access through ACLs, shared mounts, process inspection, privilege
escalation and equivalent Vault credentials; the authority verification key and
worker configuration also belong to that trusted supervisor. Demonstrate denial
from the actual coordinator identity before claiming credential isolation. This
crate does not enforce or attest those deployment controls. Host-root remains
trusted under the process profile.

The shared canonical custody frame is adopted for native creation and Vault parent
operations. **Vault derived-parent construction is UNQUALIFIED**, as required by
`docs/CUSTODY_CONTRACT.md`; codec conformance and perturbation tests do not qualify
that construction. A2 owns review of the proposed transcript/profile and eventual
storage acceptance. Encrypt/decrypt test grants, application-data AAD, local lease
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

Owned raw buffers and AES schedules enable available zeroization features.
Compiler/OS copies, HTTP header buffers, swap/crash dumps, and all GCM-derived
state are not proved erased. In particular, the pinned POLYVAL ARM PMULL backend
does not implement zeroizing Drop. This prototype makes no full-memory erasure,
host-root exclusion, hardware-custody, or child-HYOK claim.

The original branch base is `27e0f51`; `a74f884` and its A2-owned prerequisites
were merged without modifying their contract, storage, or workflow files. This
ancestry still lacks PKCS#11 concurrency fix `f63b347` present on
public main `e54c14d`. This slice does not exercise concurrent PKCS#11 login.
