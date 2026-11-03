# Resident-key destruction fencing

This slice implements pre-destruction storage fencing. It does **not** activate
provider-wrapped hierarchy, subtree erasure, trusted-worker execution or global
revocation.

## Execution contract

`ScheduleKeyDeletion` refuses before changing the lifecycle when the key has any
`ParentWrapped` version, another key has a `ParentWrapped` version naming it as
parent, or any creation-journal row names it as parent or child. This applies to
the domain/library, gRPC and REST paths. gRPC returns `FAILED_PRECONDITION`; REST
returns HTTP 409 with `FailedPrecondition`. The diagnostic contains counts named
`own_parent_wrapped_versions`, `dependent_parent_wrapped_versions` and
`creation_journal_rows`, never the LIDs of other keys. Counts cover all versions
and all journal phases; a row matching both journal roles counts once. Logical
`parent_lid` relationships alone do not block scheduling. Successful gRPC and REST
schedule responses include `logical_only_children`: the number of direct
persisted child records whose versions all contain resident material, observed
by the same admission query. Each child counts once, regardless of lifecycle
state or version count; grandchildren and actual wrapped dependencies are not
included. The count is informational, not a reservation or approval of data loss.


Scheduling and claiming share `StorageBackend::destruction_dependencies` and
the backend's transaction query. Scheduling is an early observation, not a
reservation: a dependency introduced after scheduling still causes the claim to
refuse. The authoritative recheck remains under the same writer fence as claim
insertion. Unsupported storage implementations fail closed; cache wrappers must
query the underlying store. Dependency scans currently visit persisted key
histories, so this check adds database work to scheduling.

1. The reaper's scan result is only a candidate. `claim_destruction` re-reads the
   record under the storage writer lock and checks its OCC, due PendingDeletion
   state and entire resident version history. Empty/duplicate/malformed histories
   and any ParentWrapped version fail closed.
2. The same transaction rejects every parent/child creation-journal reference,
   including pending child rotations, and scans existing material references for
   legacy or directly stored ParentWrapped records. Logical `parent_lid` alone is
   not a wrapping dependency.
3. The transaction inserts a permanent claim journal and advances key OCC. Only
   successful commit of a **new** claim returns an execution ticket. Existing
   claims return no ticket. Generic updates, cancellation, reactivation and new
   wrapping references are fenced using the same writer protocol.
4. The service uses the claimed snapshot and pins provider instances once per
   effective provider binding before the first delete. It does not resolve a
   provider again between versions. Provider operations run outside SQL locks.
5. Only successful destruction of **every** version permits
   `complete_destruction`, which verifies operation identity and the exact stored
   snapshot before atomically publishing Destroyed. The journal remains as a
   terminal tombstone; generic CRUD cannot resurrect the record or publish
   Destroyed in place of this completion path.

SQLite uses its existing immediate writer transaction; PostgreSQL uses the same
transaction-scoped advisory lock and READ COMMITTED protocol as creation/CRUD.
An unsupported storage implementation fails closed, rather than emulating these
operations with separate reads/writes. The metadata cache delegates claims and
completion directly to storage and invalidates locally on both success and error.

Cancellation that wins before the claim still succeeds and returns the key to
Disabled. After a claim, a fresh cancellation returns gRPC FailedPrecondition or
HTTP 409. A stale OCC can instead produce the existing concurrency-conflict error.

## Failures and operational limits

- A lost response, task cancellation, process crash, provider error, partial
  success or completion error **does not release the fence**. Later scans do not
  retry destruction. An error is not evidence that material survived unchanged.
  There is no automatic takeover, timeout release or recovery/abort API in this
  slice. Do not clear journal rows manually to get retries: that discards the
  one-shot guarantee without resolving potentially completed external effects.
- Storage completion trusts the service's provider-success decision; the ticket
  is a storage execution capability, not PDP authority, signed evidence or a
  malicious-coordinator proof. `DestructionClaim::committed` is for trusted
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
  path also retains its limited/non-exhaustive pagination; this slice does not
  claim starvation-free collection of all due keys.
- All writers must honor this protocol. Mixed deployment with older binaries
  that ignore the journal is unsafe; use a coordinated writer cutover. Direct SQL
  administrators, restoration of old database snapshots, qualified recovery and
  monotonic cross-system erasure evidence require separate controls.

## Executable checks

`keyrack-test-support::destruction_conformance` is shared by SQLite and live
PostgreSQL: eligibility, one-shot claims, stale/fresh mutation rejection, exact
completion binding, all creation phases, pending child rotation, raw historical
wrapping references and terminal resurrection denial. Backend-specific tests add
independent connections/pools, restart/reconnect and injected transaction rollback.
Service tests pause a provider call while REST/gRPC cancellation and another reaper
compete, and exercise cancellation-first and partial-provider-failure outcomes.
The `integration::deletion_dependencies` tests cover each scheduling refusal on
gRPC and REST, the domain path, unchanged records after refusal, and logical-only
children. Reverted controls remove the shared scheduling check and require each
of the eight surface refusal tests to fail on its own assertion.

Dependent-data-loss override intent is outside this release. There is no flag to
bypass these checks or erase journal rows to make a key eligible.

```sh
cargo test -p keyrack-sqlite
cargo test -p keyrack-service
# Against a disposable database; never a deployment database:
cargo test -p keyrack-postgres --features live-tests
# New or empty directory outside disposable build storage; retain it as evidence:
python3 scripts/test-deletion-scheduling-controls.py --output /path/to/deletion-controls
```

The control runner copies the current source into a disposable directory, verifies
all ten baseline tests, then removes only the shared scheduling refusal in that
copy. It requires eight surface refusals and the domain refusal to fail for
unexpected successful scheduling, while the logical-only positive still passes.
The checkout is never edited. Source hashes, commands, logs and the result remain
in `--output`; a nonempty output directory is refused. `CARGO_TARGET_DIR` is
honored, and `--timeout` bounds each Cargo invocation (default 1,800 seconds).

These are implementation tests, not a new Tamarin proof or a production hierarchy
qualification. Existing ignored live-provider tests remain separate invocations.

The same runner separately replaces the shared logical-only count and each
transport's reported count with zero. The count assertion must fail for its
specific domain, gRPC or REST response while all refusal tests keep passing.
A final restored run must pass, with hashes and diagnostics retained in the receipt.
