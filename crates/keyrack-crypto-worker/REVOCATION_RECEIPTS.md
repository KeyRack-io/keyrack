# Canonical local revocation receipts

The provisional executable accepts authenticated canonical
`Evidence<RevocationCommand>` and returns authenticated
`Evidence<RevocationResult>` for the command's whole authority scope. It consumes
A2's v1 ruling at `3fc2bd2` and source rename at `be2ede3`: one result, no per-operation field or third disposition.
This implements a local applied-fence observation, not all-holder completion,
production profile approval, destruction, or a revocation platform.

## Command and trust boundary

The private input frame is `{"command":"fence","evidence":"<base64>"}`. The decoded
bytes must be a canonical `Evidence<RevocationCommand>`; legacy signed JSON fences
are rejected rather than converted to invented canonical commands. Encrypt/decrypt
grants remain a separate provisional adapter. No other component depends on this
private JSON framing.

The launcher's independently configured Ed25519 key is trusted only as
`development-authority` / `development-authority-key`. The worker permits exactly
its configured security domain and the fixed `worker-development-fixture` provider.
Execution also enforces that provider binding, so a same-domain grant cannot add
another provider's material to the scope. Context-scoped revocation is unsupported
and rejected, even with a valid signature. The worker does not infer trusted scope
or signer identity from a received command.

Inside the release/fence mutex, immediately before application, the worker checks
its actual executor incarnation, exact issuer/provider/domain, monotonic clock,
half-open validity interval, configured authority horizon and a strictly newer
generation. Initial generation 1 is trusted harness policy, not a command-derived
bootstrap. Fencing is terminal for the incarnation; replay, stale commands and
commands for a restarted worker fail. No reinstatement protocol is introduced.

## Applied result

The mutable worker borrow and sequential command loop exclude concurrent provider
work while a fence is applied. Under the same lock used for key-capsule release,
the worker installs the use/admission fence, purges all local residents and cancels
all pending output capabilities. Delivery verifies that its incarnation matches
and that retained output generations precede the command's generation.

The whole-scope disposition is derived from the retained ledger:

| Evidence at the applied fence | Result |
| --- | --- |
| No admitted outputs, or all retained outputs committed and no operation is still computing | `Drained` (wire 1) |
| Pending outputs cancelled, including mixed history with earlier committed output | `FurtherReleaseBlocked` (wire 2); earlier commits are not recalled |
| Retained historical suppression, even if its notification may already have completed | Conservatively wire 2: the suppression postcondition still holds; this does not claim that the old notification remains pending |
| Indeterminate capsule outcome, recorded transport fault or unresolved ledger entry | Error; no successful canonical receipt |

`Drained` does not assert receiver consumption. `FurtherReleaseBlocked` covers every
unreleased response in the scope, including responses not named by lease
diagnostics. It asserts permanent loss of future release capability, not erasure
of all copies. The scope comes from the authenticated command, never a subset
selected by `observed_leases`. A2 renamed the source variant to
`FurtherReleaseBlocked` at `be2ede3`; wire values remain 1 and 2 and are encoded
solely by the shared codec.

The exact linearization point, atomic capsule assumption, staging-fault scope,
and release-admission/OS-preemption limit are described in
[OUTPUT_RELEASE.md](OUTPUT_RELEASE.md). A fence can cancel a key while ciphertext
staging is in flight; that observation does not assert that the staging syscall
or acknowledgement has completed. A capsule fault is recorded under the lock
before any fence can observe its outcome. Valid revocation still applies local
containment after a recorded fault, but returns no successful result.

The result copies the command's fence UUID, executor and complete authority
identity and hashes the entire canonical **command**, not the JSON, evidence
wrapper or signature. It calls `check_command()` before signing. Actual local
lease counters are sorted and truncated to at most 128 diagnostics. The purge
itself is never truncated. Empty or truncated diagnostics are not an exhaustive
holder census or evidence that no other worker holds material.

An incarnation-wide worker-generated Ed25519 observation key signs the complete
canonical evidence transcript as `development-worker-observation` /
`incarnation-key`. It is advertised in the trusted test child channel for both
local and Vault modes, independently of creation reservations. The supervisor
must bind that key to the launched executor and scope; this is not production key
distribution or attestation. Receivers must authenticate the evidence and call
`check_command()` against their independently retained command.

The private response is `{"revocation":"<base64 canonical evidence>"}`, carried
through nonsecret control framing because result admission has been fenced.
Signing/encoding/queue failures never roll back the applied fence. No delivered
receipt is promised if the writer or coordinator connection fails. Restart loses
local receipt state; lack of a receipt is not proof that containment did not occur.

## Availability limit

**Delivery outcome ledger depth: 4,096 admitted responses per incarnation.** Both
pending and terminal entries count. Entries are never evicted to admit more work.
At capacity, further result admission returns `worker limit exceeded`; an operation
may already have executed before its output reaches this gate, and its consumed
grant cannot simply be replayed. This prioritizes evidence integrity over continued
availability. It is a stated prototype limit, not a production sizing recommendation.

Expiry, successful delivery, cancellation, fence application and dropping keys do
**not** clear the ledger. There is no in-process clear/reset command. Only destroying
the worker/Delivery instance releases this in-memory ledger; launching a replacement
starts an empty ledger with a fresh random incarnation and requires fresh grants.
That restart does not preserve or establish old outcomes. Durable evidence retention
and ambiguous-restart reconciliation remain separate integration obligations.

## Verification

Ordinary tests authenticate emitted evidence, check exact command bindings, reject
wrong scope/provider/issuer/executor/clock/generation and forged or replayed commands,
exercise empty/committed/pending/mixed histories, retain containment on output faults
and receipt-queue failure, and purge 140 residents while reporting 128 sorted leases.
The real-process tests authenticate both a drained round trip and a mixed-history
fence after ciphertext staging begins. The existing live Vault subprocess exercises
the same canonical path. Codec tests remain owned by A2; these tests exercise the
worker's runtime obligations rather than treating successful serialization as proof.
