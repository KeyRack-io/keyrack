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
| `CancelKeyDeletion` | `kms:CancelKeyDeletion` | Yes |
| `RotateKey` | `kms:RotateKey` | Yes |
| `ReportKeyCompromise` | `kms:ReportKeyCompromise` | **No** |

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

These actions are emitted by KeyRack's background workers, not by
user-facing RPCs. They appear in audit logs and PDP authorization
calls but are not invoked by external clients.

| Trigger | Action string | In contract §7.1? |
|---------|---------------|-------------------|
| Hierarchy cascade disable | `kms:CascadeDisable` | **No** |
| Rotation job expiry worker | `kms:RotationJobExpired` | **No** |
| Scheduled key destruction worker | `kms:KeyDestroyed` | **No** |

## Summary

- **40 actions** match PDP Service Contract v1.0 §7.1 exactly.
- **4 actions** are KeyRack additions not yet in the contract:
  - `kms:ReportKeyCompromise` — user-facing RPC, added post-contract
  - `kms:CascadeDisable` — background worker
  - `kms:RotationJobExpired` — background worker
  - `kms:KeyDestroyed` — background worker

**Recommendation:** Register all 4 in the PDP action registry to avoid
`INDETERMINATE` with `reason_code=UNKNOWN_ACTION`. Propose adding them
to PDP Service Contract §7.1 in the next vocabulary minor bump.
