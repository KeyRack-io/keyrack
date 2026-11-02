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

The new envelope authenticates the new context and rejects the old context.
Deleting the service's original envelope does not revoke a separately retained
copy while its original parent still exists. Database deletion also does not
erase backups, database recovery logs or material previously exported elsewhere.

## Service and storage protocol (implementation in progress)

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

While reserved or staged, writes affecting the child or either parent are
refused as retryable. This includes child rotation: it never publishes a version
under the old parent during migration. Creation and destruction use the same
writer fence. Existing unsupported wrapped-child rotation remains unsupported
outside a migration; this operation does not add that lifecycle.

`parent_lid` changes only through migration. Logical key identity remains stable;
future hierarchy resolution observes the new parent. Existing rule definitions,
keys and ciphertext are not implicitly rewritten by a hierarchy rule change.

The implementation PR is stacked on #45. Rebase onto main after #45 merges;
do not merge the migration PR until its API parity, storage parity, recovery,
authorization and reverted-fence controls pass.
