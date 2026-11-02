# PDP Action Cross-Reference

Mapping of KeyRack gRPC RPCs to the PDP action strings sent in
`AuthzRequest.action`. Cross-referenced against PDP Service Contract
v1.0 §7.1.

## Cryptographic operations

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `Encrypt` | `kms:Encrypt` | Yes |
| `Decrypt` | `kms:Decrypt` | Yes |
| `ReEncrypt` (source) | `kms:ReEncryptFrom` | Directional correction; see below |
| `ReEncrypt` (destination) | `kms:ReEncryptTo` | Directional correction; see below |
| `GenerateDataKey` | `kms:GenerateDataKey` | Yes |
| `GenerateDataKeyWithoutPlaintext` | `kms:GenerateDataKeyWithoutPlaintext` | Yes |
| `GenerateRandom` | `kms:GenerateRandom` | Yes |
| `Sign` | `kms:Sign` | Yes |
| `Verify` | `kms:Verify` | Yes |

### ReEncrypt authorizes two keys

Both gRPC and REST require `kms:ReEncryptFrom` on the source key and
`kms:ReEncryptTo` on the destination key, before entering the crypto operation. A grant on
only one key is insufficient, including when the other key belongs to another
tenant. Policy authors must explicitly grant every permitted destination. This
keeps re-encryption-only delegation distinct from permission to retrieve plaintext
with `kms:Decrypt`; it does not require standalone `kms:Encrypt` rights either.

`ReEncrypt` is the API operation, not an IAM permission. AWS documents the two
directional permissions separately in its [ReEncrypt API reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
and [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_kms.html)
(verified 2026-09-07). KeyRack removes the old `kms:ReEncrypt` action without an
alias: an old aggregate grant must not silently acquire both directions. AWS's
`kms:ReEncrypt*` policy wildcard is not a literal KeyRack action or an implicit
Cedar wildcard expansion. Exact-action policies and custom Cedar schemas must
name the two permissions explicitly; granting From on a key does not grant To.
Even same-key requests require both permissions. The API operation name remains
`ReEncrypt`; permission names are not callable API operations.

Each leg has a fresh PDP `request_id`, including same-key re-encryption. The outer
operation ID remains the audit correlation ID and is carried in PDP context as
`operation_request_id`; `re_encrypt_role` is `source` or `destination`, and
`source_key_id` / `destination_key_id` bind the pair. Both responses must satisfy
the normal correlation/version/obligation contract. Denial, indeterminacy or PDP
failure on either leg prevents provider execution. Destination refusal produces
an `AuthorizationDenied` event naming that key, in addition to the overall denied
source operation; successful re-encryption emits one `kms:ReEncryptFrom`
operation-success event against the source. Destination authorization failures
use `kms:ReEncryptTo`. The source event describes the whole two-key operation,
not a separately callable source-only operation.
Transport/protocol failures are recorded as `Error`, not policy denials, with
`failure_phase=authorization` and an `authorization_status` in audit metadata.

The bundled Cedar engine currently evaluates action and resource identity but
does not populate its context/entities from the request attributes. Exact-resource
grants work; the new context fields do not make role- or tenant-attribute policies
work there. Provider scope and lifecycle checks remain separate, and source scope
is checked against the ciphertext's historical version, not the current primary.
Internal domain functions still require their caller's authorization/audit envelope.

## Key lifecycle

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `CreateKey` | `kms:CreateKey` | Yes |
| `GetKey` | `kms:GetKey` | Yes |
| `DescribeKey` | `kms:DescribeKey` | Yes |
| `UpdateKey` | `kms:UpdateKey` | Yes |
| `ListKeys` | `kms:ListKeys` | Yes |
| `EnableKey` | `kms:EnableKey` | Yes |
| `DisableKey` | `kms:DisableKey` | Yes |
| `ScheduleKeyDeletion` | `kms:ScheduleKeyDeletion` | Yes |
| `ScheduleKeyDeletion` (data-loss override) | `kms:ScheduleKeyDeletionWithDependentDataLoss` | New in 0.5.0 |
| `CancelKeyDeletion` | `kms:CancelKeyDeletion` | Yes |
| `RotateKey` | `kms:RotateKey` | Yes |
| `RewrapKey` (child and both parents) | `kms:RewrapKey` | New in 0.5.0 |
| `ReportKeyCompromise` | `kms:ReportKeyCompromise` | **No** |

### Deletion overrides require a second permission

Both gRPC `ScheduleKeyDeletion` and REST scheduling always require
`kms:ScheduleKeyDeletion`. When the decoded request sets
`allow_dependent_data_loss: true`, they also require
`kms:ScheduleKeyDeletionWithDependentDataLoss` on the same key, even if the
current dependency set is empty. The second action does not replace the first
and is not a separate callable operation. Direct domain/storage callers remain
responsible for their own authorization envelope.

Each check has a distinct PDP request ID and enforces the usual response
correlation, version and obligation contract. The override request context
contains `allow_dependent_data_loss: true` and `operation_request_id` to identify
the outer operation. A denial, indeterminate result or PDP failure on either
check prevents scheduling. The secondary refusal is audited under
`kms:ScheduleKeyDeletionWithDependentDataLoss`; the overall schedule audit
records `allow_dependent_data_loss` as well.

The permission authorizes loss of the wrapped dependents captured by storage
when scheduling, not arbitrary dependents added later. The claim rechecks that
snapshot under the writer fence. Nonterminal creation and migration journals
cannot be overridden. Cancellation removes the approval; deletion never
recursively deletes or migrates dependents. See the
[destruction contract](DESTRUCTION_FENCING.md).

Exact-action policies and custom Cedar schemas must explicitly declare and
grant `kms:ScheduleKeyDeletionWithDependentDataLoss` where needed. Existing
unrestricted-action grants also grant this action. The bundled Cedar engine's
context/entity limitation described above still applies: use an exact-action
grant on the intended resources rather than relying on the new context flag
for a policy condition.

### RewrapKey authorizes three roles

`RewrapKey` and `POST /v1/keys/{key_id}/rewrap` require `kms:RewrapKey`
on the child, the old parent and the new parent before reserving or resuming a
migration. All three checks run even when both parent roles have the same LID.
Every PDP question has an independent request ID and enforces response
correlation, version and obligations. The context includes `migration_role`
(`child`, `old_parent`, `new_parent`), `operation_id` and
`operation_request_id`. Resource attributes include current `owner_principal_id`
when present and user tags under `tag:<name>`; current records are reread even
when the operation ID already committed. Storage OCC binds authorization's
snapshots to the pending migration. A retry still authorizes the original old
parent recorded in the journal.

The action grants neither standalone decrypt/export nor key rotation.
[The Cedar example](examples/rewrap.cedar) grants exact resources; the bundled
engine's attribute/context limitation described above still applies.
Attempts and outcomes share `kms:RewrapKey`, the child resource, request ID and
operation ID. Audit `result: attempt` does not mean authorized or committed;
normal outcomes are `success`, `denied` or `error`. A client disconnect does
not cancel the admitted task; a process crash may leave an unresolved attempt.

## Key versioning

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `ListKeyVersions` | `kms:ListKeyVersions` | Yes |
| `GetKeyVersion` | `kms:GetKeyVersion` | Yes |

## Rotation management

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `EnableKeyRotation` | `kms:EnableKeyRotation` | Yes |
| `DisableKeyRotation` | `kms:DisableKeyRotation` | Yes |
| `GetKeyRotationStatus` | `kms:GetKeyRotationStatus` | Yes |
| `GetKeyRotationHistory` | `kms:GetKeyRotationHistory` | Yes |
| `GetKeyRotationPolicy` | `kms:GetKeyRotationPolicy` | Yes |
| `SetKeyRotationPolicy` | `kms:SetKeyRotationPolicy` | Yes |

## Hierarchy queries

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `GetKeyDependents` | `kms:GetKeyDependents` | Yes |
| `GetKeyAncestors` | `kms:GetKeyAncestors` | Yes |

## Aliases

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `CreateAlias` | `kms:CreateAlias` | Yes |
| `DeleteAlias` | `kms:DeleteAlias` | Yes |
| `ListAliases` | `kms:ListAliases` | Yes |

## Tags

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `TagResource` | `kms:TagResource` | Yes |
| `UntagResource` | `kms:UntagResource` | Yes |
| `ListResourceTags` | `kms:ListResourceTags` | Yes |

## HSM connections

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `CreateHsmConnection` | `kms:CreateHsmConnection` | Yes |
| `GetHsmConnection` | `kms:GetHsmConnection` | Yes |
| `ListHsmConnections` | `kms:ListHsmConnections` | Yes |
| `DeleteHsmConnection` | `kms:DeleteHsmConnection` | Yes |
| `GetHsmConnectionStatus` | `kms:GetHsmConnectionStatus` | Yes |

## Namespaces

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `RegisterNamespace` | `kms:RegisterNamespace` | Yes |
| `ListNamespaces` | `kms:ListNamespaces` | Yes |
| `DescribeNamespace` | `kms:DescribeNamespace` | Yes |

## Rotation jobs (cooperative protocol)

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `ListRotationJobs` | `kms:ListRotationJobs` | Yes |
| `AcknowledgeRotationJob` | `kms:AcknowledgeRotationJob` | Yes |
| `CompleteRotationJob` | `kms:CompleteRotationJob` | Yes |
| `FailRotationJob` | `kms:FailRotationJob` | Yes |

## Background worker actions (no RPC — internal only)

These actions identify background events rather than user-facing RPCs.
In particular, destruction claim refusal is an audit event, not another
permission that an external client can invoke; scheduling authorization
precedes the worker claim.

| Trigger | Action string | In contract §7.1? |
|---------|---------------|-------------------|
| Hierarchy cascade disable | `kms:CascadeDisable` | **No** |
| Rotation job expiry worker | `kms:RotationJobExpired` | **No** |
| Scheduled key destruction worker | `kms:KeyDestroyed` | **No** |
| Destruction claim refusal | `kms:KeyDestructionRefused` | New in 0.5.0 |

## Action registry maintenance

Keep custom PDP registries and schemas aligned with the authorization actions
above, including directional ReEncrypt, RewrapKey and the separate deletion
override. An unknown permission may produce `INDETERMINATE` with
`reason_code=UNKNOWN_ACTION`. Audit-only worker event names do not grant API
permissions and should not be treated as substitutes for scheduling authority.
