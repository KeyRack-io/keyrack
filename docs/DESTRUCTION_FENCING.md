# Dependency-aware destruction fencing

KeyRack checks its own persisted keys, versions, wrapped edges and creation and
migration journals before scheduling or claiming destruction. This does not
inventory application ciphertext or external dependencies, recursively erase a
subtree, or establish global revocation.

## Scheduling and approval

`ScheduleKeyDeletion` and REST
`POST /v1/keys/{key_id}/actions-schedule-deletion` accept
`allow_dependent_data_loss`, default `false`. Both require
`kms:ScheduleKeyDeletion`. Setting the flag also requires the separate
`kms:ScheduleKeyDeletionWithDependentDataLoss` permission on the same key,
even when it currently has no dependents. See the
[PDP action cross-reference](PDP_ACTION_CROSSREF.md#deletion-overrides-require-a-second-permission).

Without an override, another key's live wrapped version blocks deletion of its
parent. Logical `parent_lid` relationships alone remain nonblocking. Successful schedule
responses include `logical_only_children`, counting direct persisted children
with nonempty all-resident histories once each, regardless of lifecycle state.
Grandchildren and actual wrapped dependencies are excluded. The count is from
the fenced admission observation, not a reservation or data-loss approval. A key's own
wrapped versions are supported: destruction removes their stored envelopes
instead of opening the child or destroying its parent. Missing, malformed or
unsupported envelope bindings fail closed.

Nonterminal creation journals naming the key as parent or child, and nonterminal
migration journals naming it as child, old parent or new parent, always refuse
scheduling and claiming, including with an override. Completed receipts alone do
not block deletion; live envelopes and current wrapped descriptors still count
as dependencies. A committed migration retires old envelopes and creation
references atomically, so its old-parent receipt is not a live wrapping edge.

SQLite and PostgreSQL persist the scheduled time, override intent and a
server-captured snapshot in `deletion_schedules` (SQLite) or
`kr_deletion_schedules` (PostgreSQL), in the same writer transaction as the
lifecycle transition. Each approved edge binds the dependent LID,
dependent version, parent version and envelope reference. Clients cannot supply
the snapshot. This requires the storage schema migrations on upgrade; the
approval survives restart. A legacy PendingDeletion record without an approval
has no data-loss authorization: live dependents or nonterminal journals refuse
its claim, while dependency-free destruction remains eligible.

Scheduling and claiming use the same dependency query, including live envelope
indexes as well as key histories. Scheduling does not reserve future dependents.
The claim transaction rechecks the full set under the writer fence. Any current
edge outside the approved snapshot refuses the claim, including a new version
or envelope binding on an already approved child. Retired edges do not require
renewed approval. Unsupported storage implementations fail closed; metadata
caches must delegate these queries to authoritative storage.

A dependency refusal leaves the key PendingDeletion and performs no provider
destruction. The worker emits `kms:KeyDestructionRefused` with a reason and
blocking counts, and increments
`keyrack_deletion_claim_refusals_total{reason}`. Reasons distinguish
`in_flight_journal`, `dependent_data_loss_not_approved` and
`dependent_outside_approved_snapshot`; other claim errors use `storage_refusal`.
Audit delivery remains best-effort. Scheduling refusals return gRPC
`FAILED_PRECONDITION` or HTTP 409 with `FailedPrecondition`. Diagnostics include
counts, not other keys' LIDs.

Cancellation before a claim atomically removes the persisted intent and snapshot,
clears the scheduled date and returns the key to Disabled. Rescheduling needs a
new authorization and snapshot; cancellation never leaves reusable approval.

## Claim and completion

1. The reaper's scan is only a candidate. `claim_destruction` rereads the record
   under the storage writer lock, checks its OCC, due PendingDeletion state,
   full version history, envelope bindings and the approval against current
   dependencies. Empty, duplicate or malformed histories fail closed.
2. A successful claim inserts a permanent destruction journal and advances OCC.
   The claim transaction also persists loss markers before any provider effect.
   Later scans recover the same operation ID and exact snapshot from an incomplete
   journal; completed journals return no ticket. Generic updates, cancellation, reactivation, new
   wrapping references and conflicting migration reservations use the same
   writer fence. After a claim, cancellation returns gRPC FailedPrecondition or
   HTTP 409; a stale OCC can instead produce a concurrency-conflict error.
3. The service uses the claimed snapshot, pins provider instances once per
   effective provider binding and destroys all resident versions. Provider
   operations run outside SQL locks. Wrapped versions require no provider open
   or temporary child handle for destruction.
4. `complete_destruction` verifies the operation identity and exact snapshot,
   removes the key's own creation/migration envelopes, and publishes Destroyed
   atomically. It retains idempotency receipts without their envelope bytes and
   the permanent destruction tombstone. Generic CRUD cannot resurrect the key
   or publish Destroyed instead of this completion path.
5. With a valid override, the parent is destroyed without deleting or migrating
   dependents. Their records, lifecycle states and envelopes remain, while
   the claim transaction records the affected versions in the loss-marker table. All API responses
   carrying key metadata, including lists and mutation responses, read these
   markers freshly into `wrapping_parent_destroyed_versions`, matching the current
   material's parent LID and version. Historical markers do not block a different
   current wrapping edge. A marker-query
   failure fails the response rather than reporting an empty list. Later opens
   of affected wrapped versions return `wrapping parent destroyed` with gRPC
   `FAILED_PRECONDITION` / HTTP 409, before envelope or provider dispatch.

SQLite uses an immediate writer transaction; PostgreSQL uses the same
transaction-scoped advisory lock and READ COMMITTED protocol as creation/CRUD.
Claims, approvals and completion must not be emulated by independent reads and
writes. Cache wrappers delegate them to storage and invalidate local metadata.

## Failures and operational limits

- The parent fence also rejects ordinary writes that still reference it,
  including attempted rewrapping after its destruction. A dependent child can
  still use its own fenced envelope-erasure lifecycle; the loss marker is not
  a recovery or reactivation mechanism.
- A lost response, task cancellation, process crash, provider error, partial
  success or completion error **does not release the fence**. Later scans resume
  the same journal operation and immutable provider handles. Confirmed absence
  counts as a successful provider delete; access and transport failures retain
  PendingDeletion. Completion is idempotent for the same operation and snapshot.
  Loss markers remain visible even if the provider effect succeeded and SQL
  completion rolled back. `kms:KeyDestructionRetried` and
  `kms:KeyDestructionDeferred` report the operation ID and retry/failure reason;
  `keyrack_deletion_retries_total` counts resumed attempts. Audit is best-effort.
  Never clear the journal manually or reuse a provider handle for new material.
  There is no timeout fence release or abort API.
- Storage completion trusts the service's provider-success decision; the ticket
  is a storage execution capability, not PDP authority, signed evidence or a
  malicious-coordinator proof. `DestructionClaim::committed` and `DestructionClaim::recovered` are for trusted
  storage implementors. Non-Clone/move discipline is not in-process authenticity.
- Provider instances are pinned within an attempt, not independently qualified
  hardware identities. Reconfiguration before resolution and out-of-band backend
  administrators remain outside this guarantee. No durable per-version provider
  receipt or transactional audit outbox is introduced.
- The fence prevents conflicting persisted lifecycle changes. It does not drain
  in-flight crypto, erase other processes' working sets, recall exported keys,
  fence every provider-side operation from stale readers, or supply distributed
  revocation. Metadata cache TTL is not a crypto lease or HYOK cutoff guarantee.
- Material-reference scans and the existing global PostgreSQL writer lock are
  correctness-first, not cloud-scale throughput claims. The existing reaper list
  path also retains its limited/non-exhaustive pagination; the worker does not
  claim starvation-free collection of all due keys.
- Envelope erasure removes live database rows, not forensic copies in database
  free pages, WAL, replicas or backups. Their retention and physical erasure need
  separate storage controls.
- All writers must honor this protocol. Mixed deployment with older binaries
  that ignore the journal is unsafe; use a coordinated writer cutover. Direct SQL
  administrators, restoration of old database snapshots, qualified recovery and
  monotonic cross-system erasure evidence require separate controls.

## Executable checks

The shared `keyrack-test-support::destruction_conformance` suite exercises the
storage claim protocol for SQLite and live PostgreSQL. Backend tests cover
approval persistence, cancellation, restart, envelope removal and transaction
rollback. Service tests cover gRPC/REST scheduling, separate override permission,
claim-time refusals and parent-loss reporting. These are executable checks, not
a claim that a particular invocation has passed.

```sh
cargo test -p keyrack-sqlite
cargo test -p keyrack-service
# Against a disposable database; never a deployment database:
cargo test -p keyrack-postgres --features live-tests
# New or empty directory outside disposable build storage; retain the evidence:
python3 scripts/test-deletion-scheduling-controls.py --output /path/to/deletion-controls
python3 scripts/test-deletion-approval-controls.py --output /path/to/approval-controls
python3 scripts/test-destruction-recovery-controls.py --output /path/to/recovery-controls
```

The scheduling control runner copies the source into a disposable directory,
runs the baseline, then removes the shared dependency refusal in that copy.
It requires each selected surface/domain refusal to fail because scheduling
succeeded, while logical-only scheduling still passes. It retains source hashes,
commands and logs in `--output`; it does not edit the checkout. This runner covers
scheduling admission, not every claim, provider or completion failure. Existing
live-provider tests remain separate invocations.

The approval control runner separately removes snapshot comparison, journal
refusal, the extra PDP authorization, the claim recheck, envelope erasure and
the refusal counter, strict boolean decoding, claim-time loss markers, recovered
claims, parent-binding matching, legacy defaults and audit evidence. Each run
must fail its named test with the specific unsafe
outcome; compilation failures do not qualify. It restores the source and reruns
the baseline, retaining per-mutation hashes, logs and diagnostics. Surface
controls run gRPC and REST separately so a failure on one cannot mask the other.

The provider recovery control runner removes the Vault and KMIP absence checks
in a disposable copy and checks both failure to recover a missing key and
incorrect acceptance of other failures. Those fixtures exercise HTTP/TTLV
responses, not a claim of live hardware qualification.
