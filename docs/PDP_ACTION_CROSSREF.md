# PDP Action Cross-Reference

Mapping of KeyRack gRPC RPCs to the PDP action strings sent in
`AuthzRequest.action`. Cross-referenced against PDP Service Contract
v1.0 §7.1.

## Cryptographic operations

| gRPC RPC | Action string | In contract §7.1? |
|----------|---------------|-------------------|
| `Encrypt` | `kms:Encrypt` | Yes |
| `Decrypt` | `kms:Decrypt` | Yes |
| `ReEncrypt` | `kms:ReEncrypt` | Yes |
| `GenerateDataKey` | `kms:GenerateDataKey` | Yes |
| `GenerateDataKeyWithoutPlaintext` | `kms:GenerateDataKeyWithoutPlaintext` | Yes |
| `GenerateRandom` | `kms:GenerateRandom` | Yes |
| `Sign` | `kms:Sign` | Yes |
| `Verify` | `kms:Verify` | Yes |

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
