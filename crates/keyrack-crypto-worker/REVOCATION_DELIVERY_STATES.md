# Delivery facts for revocation disposition arbitration

This is an enumeration of the current private worker transport, supplied before
canonical receipt implementation. It proposes no wire encoding. `Drained` and
`OutputsSuppressed` below name the existing custody variants; their aggregate
scope remains A2's decision. A2 has ruled that per-capsule mapping needs no third
variant: not-yet-committed output cancels as `OutputsSuppressed`, committed output
is irrevocable, and unresolved paths may claim neither. Canonical receipt wiring
remains held pending the fence-scoped receipt's per-operation granularity.

The code supports **two normal per-response output outcomes and now retains
incarnation-local outcome evidence under the release mutex**. A complete release capsule committed
before the fence makes output readable; destruction of its uncommitted transport
key suppresses output. A partially staged ciphertext is not partially released
plaintext. A mixed collection of responses is reachable. A transport fault with
uncertain disclosure is not either successful disposition.

## Observation boundary and population

The boundary is successful fence validation/application inside `Delivery::fence`
while holding the same mutex as final capsule admission and write. It is not the
arrival of an unverified command, acknowledgement enqueue, or receiver read.
The executable processes provider operations, preparation/enqueue, and fence
commands sequentially; a fence cannot interrupt that thread midway through a
provider call. The writer runs concurrently. Concurrent preparation/enqueue
interleavings are supported by the private Delivery API and tested, but are not
currently an executable command-processing interleaving.

Each accepted delivery has its own ID and one-use transport key. A successful
capsule write is one nonblocking FIFO write of at most 512 bytes. The writer has
already written every ciphertext record for that ID before attempting its
capsule. At the fence barrier that syscall cannot be halfway through: the fence
must wait for its mutex. Ciphertext staging is outside the mutex and can finish
a record after fence acceptance; the key cannot subsequently commit.

Sources: [delivery admission and writer](src/delivery.rs),
[runtime transition kernel](src/release_state.rs),
[executable command loop](src/main.rs), and the existing
[release point and OS-preemption limits](OUTPUT_RELEASE.md).

## Per-response enumeration

`S` means an output-suppression fact; `D` means a completed transport-commit fact.
These are proposed inputs to a receipt, not dispositions currently emitted.
“Readable” means that the receiver has enough bytes to recover the response;
the worker cannot observe whether it has actually read or used them.

| Condition at the fence boundary | Precisely what happened to output | Truthful disposition fact / limit |
|---|---|---|
| No accepted operation, or authorization/primitive failure before a result exists | Nothing was staged; no successful response exists. Redacted control errors are separate. | No response to classify. An empty affected set may be vacuously `Drained`; rejection is not proof of fence-caused suppression. |
| A result exists, but preparation or enqueue rejects it (size, capacity, identifier exhaustion, time or incarnation/generation) | Nothing was staged for that delivery; no capsule was committed. Any prepared transport key is dropped on rejection. No admitted delivery ID records this failure. | Suppression/non-release is a local fact if a result existed; not completed delivery. Include it only if the receipt's defined population includes such pre-enqueue results. |
| Prepared value held by another Delivery caller when fence is accepted | Nothing was staged; the later enqueue is refused and drops its key. Fence does not reach into the caller's still-held Prepared value. | Admission is fenced. Not a statement that all caller-owned buffers were already erased at the barrier. This overlap is absent from the current executable's single command thread. |
| Enqueued, no writer step yet | Nothing was staged. Fence drops the pending transport key. | `OutputsSuppressed`; not `Drained`. |
| Some complete ciphertext records staged | A ciphertext prefix remains, but no transport key was committed. Fence drops that key. | `OutputsSuppressed`; ciphertext prefix is not partial usable-output delivery. |
| A ciphertext staging syscall is currently in progress | That record may finish after fence acceptance. Its release key is dropped under the fence lock. | `OutputsSuppressed` for usable output; not “no bytes after fence.” |
| All ciphertext staged, capsule not attempted | Entire ciphertext remains unreadable without the withheld key. Fence drops the key. | `OutputsSuppressed`. |
| Capsule attempted and returned `EAGAIN` or `Interrupted` | Under the verified atomic FIFO assumption, zero capsule bytes committed. Permit remains pending until fence drops its key. | `OutputsSuppressed`, including a blocked writer. |
| Capsule write holds the mutex when a fence arrives | Fence has not yet been accepted. Full success resolves to the committed row below; retry resolves to the preceding row; hard failure resolves to a fault row. | No additional “half committed at an accepted fence” state under the pipe assumption. |
| Deadline elapsed, but the permit has not yet been swept | No capsule committed; the fence drops the still-present key. | Suppression is true. Do not claim the fence was the only cause: release was already ineligible. |
| Prior expiry/admission recheck removed the permit; ciphertext or a cancellation notification is still queued/writer-held | Nothing, some ciphertext, or all ciphertext was staged; no key committed. Cancellation happened before this fence. | `OutputsSuppressed` if this unresolved response belongs to the chosen cohort. Never infer `Drained` just from permit absence. |
| Suppression notification already committed and its job removed | No usable response was released; the receiver can learn it was cancelled. The outcome ledger retains suppression after the notification job is removed. | Historical suppression, not historical delivery. Outside a cohort of currently outstanding responses; relevant to an incarnation-wide history. |
| Complete capsule committed, including the interval before Writer clears its current job | All ciphertext and its complete key capsule precede fence acceptance. Output remains readable indefinitely. | `Drained` at the accepted transport-commit meaning; never `OutputsSuppressed` for this response. Receiver consumption cannot be claimed. |
| Capsule committed after release admission but after its clock deadline because of OS preemption | Same complete readable response as above; it still committed before an accepted fence because the mutex was held. | `Drained` as a delivery fact; **not** evidence of a hard physical deadline. The existing deadline limitation remains. |
| Normal shutdown/EOF already dropped pending keys and queues | Uncommitted outputs are suppressed; earlier committed outputs remain readable. A fence acknowledgement is not assured. | Not a successful new fence receipt. The command may not be processed, and a stopped transport rejects acknowledgement enqueue. |

These rows are exhaustive with respect to result existence/admission, staging
progress (none/prefix/all), and capsule outcome (not attempted/retry/committed),
plus eligibility loss and shutdown. Unverified/invalid fences change none of the
release policy and yield no applied-fence receipt; outputs may continue according
to their existing grants.

## Fault conditions and “partially committed”

The real sink verifies stdout is a FIFO and uses one nonblocking syscall per
bounded record. Within that contract, a partial capsule write is excluded. The
following cases describe explicit fault injection or broken transport assumptions,
not an additional normal state hidden by queue ordering.

| Fault | Output fact | Receipt consequence |
|---|---|---|
| Capsule construction/serialization fails before the syscall | No capsule written. The worker retains suppression, drops pending keys and latches transport failure before unlocking. | Non-release can be established, but the writer is aborting; do not promise a delivered acknowledgement. |
| Hard error while staging, or capsule error known to have written zero bytes | No key release for the affected response. Writer stops and drops remaining keys. Earlier releases remain. | Failed/aborted transport, not a new successful completion receipt. |
| Short ciphertext-record write | Incomplete ciphertext, no capsule yet; writer aborts. | No usable response, but the atomic-record contract failed. No successful fence receipt on that transport. |
| **Short capsule write** | A prefix may contain **the entire key**, even if the syscall omits the final JSON delimiter or newline. Output may already be readable. | Neither `Drained` nor `OutputsSuppressed` is justified from that return value. Treat disclosure as indeterminate and fail the receipt path. |
| Sink writes some/all bytes and then reports a non-retry error | Return status cannot establish how much key material escaped. | Same indeterminate result; no successful receipt. |
| Mutex poisoning, panic, process death or lost connection | Applied-fence state and/or acknowledgement delivery may be unavailable. Prior commits cannot be retracted. | Absence/failure of evidence, not either success disposition. |

The runtime kernel now sets private `Phase::Indeterminate` on a capsule callback
error. Delivery retains that phase, removes its key, latches transport failure and
stops admission **before releasing the fence mutex**. The injected test returns
`len - 1`, omitting only the capsule newline, and independently decrypts the
response. That entry remains indeterminate through expiry, repeated fences and
stop. No cancellation notification or successful fence observation follows it.
Other pending keys are suppressed; earlier committed outcomes remain committed.
All non-retry capsule errors are conservatively indeterminate, including an error
which might in fact have written zero bytes. A missing outcome is an error, never
an inferred suppression.

Valid fences still run the authenticated core callback and purge, even after a
transport fault. They then return an error, not the callback's successful local
observation. Invalid commands do not apply their requested purge. This means an
error can follow successful local containment; it does not mean revocation failed.

Staging/control writes remain outside the release mutex and carry no response key.
A fence can cancel an in-flight staging response before a staging error is known;
that local observation establishes key cancellation only, not writer or
acknowledgement completion. Once the writer records the error, later observations
fail. A deterministic suspended-staging fault test records this narrower scope.
There is no corresponding capsule-fault gap: its callback, outcome and fault latch
all hold the same mutex as the fence.

## Retained evidence and its bounds

Each successfully enqueued response reserves one entry in a `BTreeMap` keyed by
its monotonically assigned delivery ID. It records the worker incarnation,
generation, sequence, grant digest, authority interval and private phase. The
entry is allocated on admission, before any irreversible write. IDs may have gaps
when preparation/admission rejects a response; neither contiguity nor an empty
permit map implies an output outcome. Pre-enqueue failures have no ledger entry.

Pending entries transition to committed, suppressed or indeterminate. Terminal
phases are absorbing. Expiry, fence, writer failure and normal stop remove keys
without removing outcome entries. The ledger contains no plaintext, transport
keys or serialized capsules. Writer-held responses remain identifiable by their
entry even after their permit and queue slot disappear.

The ledger retains **at most 4,096 admitted responses per process incarnation**,
including pending responses. It never evicts or resets history to make room.
Further admissions fail with the existing limit error; prior outcomes and pending
work remain intact. This is a provisional bounded resource policy, not a shared
contract or a production throughput claim. Restart requires a fresh incarnation
and grants. It discards the in-memory ledger and cannot attest to the old worker's
outcomes; durable receipt/restart reconciliation remains external work.

The retained phases distinguish histories previously indistinguishable from queue
and permit state. They do **not** record exact ciphertext-byte progress, receiver
consumption, cancellation-notification delivery or fence-acknowledgement delivery.
Those are separate facts; this ledger cannot settle the outstanding A2 choice of
receipt population. A successful generic local observation is still not a
canonical `RevocationResult` or an `OutputsSuppressed` claim.

## Aggregate mapping and the actual contract choice

A deterministic mixed-history test commits response 1, partly stages response 2,
and fences before response 2's capsule. Response 1 stays released; response 2 gets
a cancellation notification. This is reachable in the real writer architecture.

| Defined receipt population | Existing variants sufficient? |
|---|---|
| One normal response | Yes: committed -> `Drained`; uncommitted key discarded -> `OutputsSuppressed`. |
| Outstanding, unresolved responses at the accepted fence barrier, with earlier completed releases excluded | Yes, if that scope is explicit. Actual cancellation of this set -> `OutputsSuppressed`; a confirmed empty set can be vacuously `Drained`. Prior committed bytes remain readable. Previously suppressed but unresolved notifications must not masquerade as delivered work. |
| An entire batch/history containing both committed and suppressed responses | **No**, if each variant describes the whole population. `Drained` misreports the cancelled responses; `OutputsSuppressed` misreports the committed ones. A third **mixed outcome** (or per-response outcomes) is required for that interpretation. It is not a “partially committed capsule” variant. |
| Transport failure with indeterminate disclosure | Neither success variant suffices. Fail or withhold the receipt. If the protocol requires encoding failures as results, it needs an explicit failure representation, not a successful completion disposition. |

**Ruling and remaining decision:** keep the two canonical variants for
per-capsule mapping. The mixed-history row is a counterexample to uniformly
labelling a whole population, not a request for a third per-capsule variant.
A2 still decides whether fence-scoped receipts need per-operation granularity.
Terminal retention and fault rejection are implemented independently; no shared
contract or canonical receipt emission changes here.

## Reproducible evidence

Existing tests cover authorization/enqueue, staged writes racing with fences,
full staging plus blocked capsule retry, invalid fences, expiry behind blocked
control output, irreversible prior commit, and release-admission preemption.
The real-process test `process_fence_cancels_staged_output_before_key_release`
exercises the concurrent writer case.

The following deterministic tests add the classification evidence:

- `fence_cancels_every_precommit_staging_position`: zero through every ciphertext
  record boundary, inclusive of full staging; cancellation and no capsule in each.
- `retained_outcomes_distinguish_commit_from_expiry_with_empty_queues`: identical
  queue/permit state but different retained terminal outcomes.
- `empty_queue_and_permits_can_hide_writer_held_cancellation`: both shared
  collections are empty while an unresolved suppressed response remains in the writer.
- `mixed_committed_and_cancelled_response_history_is_reachable`: one irrevocable
  prior response and one suppressed pending response in the same worker history.
- `injected_short_capsule_write_is_not_non_disclosure_evidence`: an out-of-contract
  short return leaks enough capsule bytes to decrypt; retained indeterminate state
  blocks success while still allowing the core purge callback.
- `full_history_rejects_admission_without_evicting_terminal_provenance`: exercises
  the 4,096-entry bound through actual writer commits and checks retained provenance.
- `shutdown_retains_uncommitted_outcomes_and_unknown_ids_never_suppress`: shutdown
  retention and fail-closed lookup for unknown IDs.
- `capsule_errors_are_sticky_and_preserve_other_delivery_outcomes`: zero, short,
  excessive and error returns preserve prior commits, classify the uncertain
  response and suppress other pending keys through repeated fence/stop/expiry.
- `pending_capsule_fault_excludes_a_concurrent_successful_fence`: deterministic
  suspended capsule error versus a concurrent fence under the release lock.
- `staging_fault_records_cancellation_and_prevents_later_observation` and
  `fence_during_staging_fault_only_establishes_key_cancellation`: distinguish
  recorded faults from an in-flight staging syscall with no release key.

Run with `cargo test -p keyrack-crypto-worker delivery::tests`. These tests establish
classification facts and counterexamples; they emit no canonical receipt and do
not approve any interpretation of the shared enum.
