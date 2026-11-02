# Wrapped-key migration

## Provider contract

The provider contract for 0.5.0 is:

```rust
async fn rewrap_wrapped_key(
    &self,
    old_context: &WrappingContext,
    old_parent: &KeyHandle,
    envelope: &[u8],
    new_context: &WrappingContext,
    new_parent: &KeyHandle,
) -> Result<Vec<u8>>;
```

`WrappingOperation::Rewrap` is required for both exact capability tuples.
Only parent identity/version and parent spec may change. Child identity,
version, purpose, format, provider, security domain and mechanism are preserved.
The default implementation refuses the operation. The software provider
implements it with zeroized temporary plaintext and no child object or lease.
Software wrapping provides no hardware custody.

A token implementation must unwrap and wrap inside the token, return only the
new envelope, and own cleanup through cancellation and crashes. Successful
return means intermediate objects have been removed. The operation must be
safe to repeat after a lost response, with no durable independently usable
child left behind. No token implementation is enabled by this change.

When the parent binding changes, the new envelope authenticates the new context
and rejects the old context. A rewrap already at the current parent version
retains the same context; context rejection does not distinguish identical input.
Deleting the service's original envelope does not revoke a separately retained
copy while its original parent still exists. Database deletion also does not
erase backups, database recovery logs or material previously exported elsewhere.

## Service and storage protocol

One logical key and a required operation UUID identify the operation. Omitting
the new parent means rewrap under the existing parent's current version; naming
a different parent means reparent. Every version moves, preserving version
numbers and key material. Cross-provider and cross-domain migration is refused.

The service authorizes the child, old parent and new parent under `kms:RewrapKey`
and records an attempt and outcome. Reservation rechecks all three snapshots
under the storage writer fence and pins the target parent version. Only a
resident wrapping parent is eligible, so a child cannot become its own ancestor.

The journal has three phases: reserved, staged and committed. Reserved recovery
may reproduce envelopes using the retry-safe provider primitive. Staged recovery
uses the durable envelopes and performs no new cryptography. Commit atomically
switches every version and `parent_lid`, removes old envelope bytes and retires
old active dependency references. Committed recovery returns the original result.
A client retries the same request and operation ID after an interrupted call.
The journal persists across service/storage restarts. Recovery requires the
provider's resident parent material to remain available: the in-memory software
provider does not make its resident keys persistent across a process exit.

While reserved or staged, writes affecting the child or either parent are
refused as retryable. This includes child rotation: it never publishes a version
under the old parent during migration. Creation and destruction use the same
writer fence. Existing unsupported wrapped-child rotation remains unsupported
outside a migration; this operation does not add that lifecycle.

`parent_lid` changes only through migration. Logical key identity remains stable;
future hierarchy resolution observes the new parent. Existing rule definitions,
keys and ciphertext are not implicitly rewritten by a hierarchy rule change.

Within one process, retries of the same operation share a serial execution
slot. Across processes, repeating the pure provider primitive is safe and the
first staged envelopes win. Once committed, later duplicate results cannot
replace the published envelopes. Existing crypto operations are not drained by
this storage fence. API tasks are bounded at 64 per process and retain their
audit outcome ownership after client cancellation; at capacity callers receive
a retryable refusal. A process crash can leave an attempt without an outcome.

`scripts/test-migration-controls.py` removes each storage fence in a disposable
source copy and requires a named assertion failure, then reruns restored tests.
The migration CI job also executes live PostgreSQL conformance and recovery.
