# KeyRack Internal Specification

Design decisions that are hard to change retroactively. Each section is
locked when its content is committed; the version tag in the section header
records the commit that locked it.

Companion documents:
- [KEYRACK_SPEC.md](../KEYRACK_SPEC.md) — a partner integration contract (customer requirements)
- [MIGRATION.md](../MIGRATION.md) — canonicalization and rule-change migration design
- [PDP_WIRE_FORMAT_REQS.md](../PDP_WIRE_FORMAT_REQS.md) — PDP wire format constraints

---

## 1. gRPC API Shape

**Status:** stub — proto definitions land in Workstream 2.

The proto definitions in `proto/keyrack/v1/` are the canonical service
interface. The RPC set matches `KEYRACK_SPEC.md` §3.1. REST is generated
from annotations on these protos.

---

## 2. Canonicalization V1

**Status:** locked.

Defines the byte format that turns an `AttributeSet` into a deterministic
`CanonicalForm`. The version field is stored in every key record; future
format changes bump the version and follow the alias-based migration in
`MIGRATION.md`.

### 2.1 Attribute value types

| Type tag | Byte | Rust type |
|---|---|---|
| String | `0x01` | `String` (UTF-8, NFC-normalised) |
| I64 | `0x02` | `i64` |
| Bool | `0x03` | `bool` |
| ListOfString | `0x04` | `Vec<String>` (each element NFC-normalised) |
| Record | `0x05` | `BTreeMap<String, AttributeValue>` (recursive) |

### 2.2 Encoding

The canonical form is a concatenation of key-value pair encodings. Each pair
is encoded as:

1. **Key**: TAG_STRING (`0x01`) + `u32 LE` byte length + NFC-normalised UTF-8 bytes.
2. **Value**: per the type-specific encoding below.

Pairs appear in `BTreeMap` iteration order (lexicographic by key bytes).
This is deterministic across Rust versions since `BTreeMap` is a B-tree
with stable ordering.

#### Value encodings

Each value is encoded as TAG (1 byte) + LENGTH (u32 LE, payload byte count) +
PAYLOAD:

| Type | Tag | Length | Payload |
|---|---|---|---|
| String | `0x01` | byte length of NFC-normalised UTF-8 | NFC UTF-8 bytes |
| I64 | `0x02` | always `8` | 8 bytes little-endian |
| Bool | `0x03` | always `1` | `0x01` (true) or `0x00` (false) |
| ListOfString | `0x04` | total payload bytes | `u32 LE` element count, then for each element: `u32 LE` byte length + NFC UTF-8 bytes |
| Record | `0x05` | total payload bytes | recursive: the same key-value encoding as the top level, with the inner `BTreeMap` sorted |

#### NFC normalisation

Every string value and every map key is NFC-normalised before encoding.
This ensures that `U+00E9` (precomposed e-acute) and `U+0065 U+0301`
(e + combining acute) produce the same canonical bytes.

#### Empty attribute set

An empty `AttributeSet` produces an empty `CanonicalForm` (zero bytes).

### 2.3 Worked examples

**Example 1:** `{"tenant": "acme"}`

```
01 06000000 "tenant"   -- key: TAG_STRING, len=6, "tenant"
01 04000000 "acme"     -- val: TAG_STRING, len=4, "acme"
```

Total: 1 + 4 + 6 + 1 + 4 + 4 = 20 bytes.

**Example 2:** `{"count": 42}`

```
01 05000000 "count"    -- key: TAG_STRING, len=5, "count"
02 08000000 2a000000 00000000  -- val: TAG_I64, len=8, 42 as i64 LE
```

**Example 3:** `{"active": true}`

```
01 06000000 "active"   -- key: TAG_STRING, len=6, "active"
03 01000000 01         -- val: TAG_BOOL, len=1, true
```

---

## 3. LID Derivation

**Status:** locked.

```
LID = BLAKE3(canonicalization_version_le32 || canonical_form_bytes)
```

- `canonicalization_version` is encoded as 4 bytes, little-endian `u32`.
  V1 = `[0x01, 0x00, 0x00, 0x00]`.
- `canonical_form_bytes` is the output of §2.
- The result is 32 bytes (256 bits).
- Displayed as `lid_` + 64 lowercase hex characters (68 chars total).
- `FromStr` / `Display` round-trip is a locked contract.
- `FromStr` accepts uppercase hex but `Display` always emits lowercase.

### 3.1 Rationale for including version in hash input

Including the version in the BLAKE3 input means the same attribute set
under different canonicalization versions produces a different LID. This
is deliberate: it makes canonicalization-version migration a
LID-identity-change, which the alias table (`lid_alias`) in
`MIGRATION.md` handles explicitly. Without the version in the hash,
a canonicalization bug fix that doesn't change the byte output would
be ambiguous — "is this the V1 LID or the V2 LID?"

### 3.2 Property tests

The following properties are tested with `proptest` (500 cases each):

1. **Determinism**: same `(version, form)` → same LID.
2. **Display/FromStr round-trip**: `lid.to_string().parse() == lid`.
3. **Display format**: starts with `lid_`, 68 chars, hex-only suffix.
4. **Collision resistance**: distinct canonical forms → distinct LIDs.
5. **Version sensitivity**: tested manually — same form, different
   version → different LID.

---

## 4. Ciphertext Header Byte Layout

**Status:** locked.

The self-describing ciphertext header prepended to every ciphertext blob.
Allows automatic key/version selection at decrypt time without out-of-band
metadata.

### 4.1 Format

| Offset | Length | Field |
|---|---|---|
| 0 | 4 | Magic bytes: `0x4B 0x52 0x43 0x4B` ("KRCK") |
| 4 | 2 | Header version (LE u16, currently `1`) |
| 6 | 32 | Key LID (raw 32 bytes) |
| 38 | 8 | Key version (LE u64) |
| 46 | 32 | Encryption context hash (BLAKE3 of sorted AAD pairs, or `[0x00; 32]` if none) |
| 78 | 2 | Reserved (LE u16, currently `0`; for future variable-length fields) |
| 80 | ... | Ciphertext payload |

Total fixed header: 80 bytes.

### 4.2 Encryption context hashing

The encryption context (AAD) is a set of key-value string pairs. The
pre-image is **opaque** — KeyRack does not interpret the values. Only the
BLAKE3 hash is persisted in the header.

Canonical hash computation:

1. Sort pairs by key (lexicographic byte order — guaranteed by `BTreeMap`).
2. For each pair: encode `key_len_u32_le || key_bytes || value_len_u32_le || value_bytes`.
3. Feed the concatenation to BLAKE3.

Empty context → `[0x00; 32]` (not the BLAKE3 of empty input). This makes
"no context supplied" distinguishable from "empty-map context" in storage.

The same canonical encoding is used as the AES-GCM AAD, so the tag binds
the same data the hash commits to.

### 4.3 Decode rules

1. Reject if buffer < 80 bytes.
2. Reject if magic ≠ `KRCK`.
3. Reject if header version ≠ `1` (future versions may extend the format).
4. Extract LID, key version, context hash from fixed offsets.
5. Payload starts at offset 80.

### 4.4 Implementation

`CiphertextHeader::encode()` → `[u8; 80]`, `CiphertextHeader::decode(&[u8])` → `Result`.
`wrap_payload` / `unwrap_payload` combine header + ciphertext into a single blob.

---

## 5. Audit Event Schema

**Status:** stub — to be locked during W1.

Versioned JSON schema for audit events emitted to all sinks.

### 5.1 Envelope

```json
{
  "schema_version": 1,
  "event_id": "uuid",
  "timestamp": "RFC 3339",
  "event_type": "key.created | key.state_changed | key.rotated | ...",
  "action": "kms:CreateKey | kms:Encrypt | ...",
  "principal": { "id": "opaque", "type": "opaque" },
  "resource": { "id": "lid_...", "type": "Key" },
  "result": "success | denied | error",
  "encryption_context_hash": "hex or null",
  "metadata": {}
}
```

---

## 6. Tags Model

**Status:** locked.

Two tag categories live on every `KeyRecord`:

### 6.1 Identity tags (`IdentityTags`)

Immutable, derived from the `AttributeSet` at key creation. Stored as a
separate `identity_tags` field (flat `BTreeMap<String, String>`) on
`KeyRecord`.

- Complex attribute values (`I64`, `Bool`, `ListOfString`, `Record`) are
  serialized to their JSON string representation.
- Visible in **audit events** and **PDP requests** only.
- **Excluded from tenant-facing API responses** (`KEYRACK_SPEC.md` §5.14,
  invariant 9).
- Never modified after initial derivation.

### 6.2 User tags (`UserTags`)

Mutable via `TagResource` / `UntagResource`. Stored as `user_tags`
(`BTreeMap<String, String>`) on `KeyRecord`. Visible in API responses.
Tenants and operators manage these freely.

### 6.3 Mutability enforcement

`validate_tag_mutation(identity_tags, tag_key)` is called before any
`TagResource` / `UntagResource`. If `tag_key` exists in the identity
tags, the operation returns `KeyRackError::ImmutableTag { key }`.

This is a hard boundary — there is no override, admin flag, or bypass.

### 6.4 PDP visibility

Both identity and user tags are included in the `AuthzRequest` context
sent to the PDP, so authorization policies can reference either.
Only user tags are returned in the `DescribeKey` / `ListKeys` tenant API
responses.

### 6.5 Serialization

Both tag types implement `Serialize` / `Deserialize` (serde). The wire
format is `{"key": "value", ...}`. Identity tags and user tags are
serialized as distinct fields, never merged.

---

## 7. Key State Machine

**Status:** locked.

```
creating ──► enabled ◄──► disabled
                │              │
                ▼              ▼
          pending_deletion ◄───┘
                │
                ▼
           destroyed
```

### 7.1 States

| State | `permits_encrypt` | `permits_decrypt` |
|---|---|---|
| `creating` | no | no |
| `enabled` | yes | yes |
| `disabled` | no | yes (data recovery) |
| `pending_deletion` | no | no |
| `destroyed` | no | no |

### 7.2 Valid transitions

| From | To | API | Notes |
|---|---|---|---|
| `creating` | `enabled` | `CreateKey` | Sync for software; async (`TaskRef`) for HSM |
| `enabled` | `disabled` | `DisableKey` | Blocks encrypt/sign; decrypt still allowed |
| `disabled` | `enabled` | `EnableKey` | |
| `enabled` | `pending_deletion` | `ScheduleKeyDeletion` | 7–30 day grace period |
| `disabled` | `pending_deletion` | `ScheduleKeyDeletion` | |
| `pending_deletion` | `disabled` | `CancelKeyDeletion` | Returns to disabled, not enabled |
| `pending_deletion` | `destroyed` | Background worker | HSM material erased, terminal |

`destroyed` is terminal — no transitions out.

### 7.3 Implementation

`KeyState::can_transition_to(target)` validates transitions. `KeyRecord::transition_to(target)` atomically:

1. Validates the transition.
2. Sets `self.state = target`.
3. Increments `self.occ_version` (feeds OCC in §9).
4. Updates `self.updated_at`.

Invalid transitions return `Err((from, to))` and leave the record unchanged.

### 7.4 KeyRecord fields

| Field | Type | Notes |
|---|---|---|
| `lid` | `Lid` | Derived via §2 + §3 |
| `canonicalization_version` | `CanonicalizationVersion` | Recorded at creation |
| `parent_lid` | `Option<Lid>` | Stored, not recomputed (MIGRATION.md) |
| `occ_version` | `u64` | Optimistic concurrency counter (§9.2) |
| `current_key_version` | `u64` | Active version number for encrypt/sign |
| `state` | `KeyState` | Current lifecycle state |
| `key_usage` | `KeyUsage` | `EncryptDecrypt` or `SignVerify` |
| `key_spec` | `KeySpec` | `Aes256`, `Ed25519`, `RsaPkcs1v15Sha256`, `EcdsaP256Sha256` |
| `origin` | `KeyOrigin` | `KeyRack` (generated internally) or `External` (imported) |
| `provider_class` | `ProviderClass` | `Software`, `Pkcs11`, `Kmip`, `InMemory` |
| `identity_tags` | `IdentityTags` | See §6.1 |
| `user_tags` | `UserTags` | See §6.2 |
| `created_at` | `DateTime<Utc>` | |
| `updated_at` | `DateTime<Utc>` | Bumped on every state/tag/version change |
| `scheduled_deletion_at` | `Option<DateTime<Utc>>` | Set by `ScheduleKeyDeletion` |
| `description` | `String` | Human-readable label |
| `key_versions` | `Vec<KeyVersionRecord>` | Rotation history; version 1 is original |

### 7.5 KeyVersionRecord fields

Each rotation creates a new `KeyVersionRecord`. Old versions are retained
for decrypt/verify of existing ciphertext. The ciphertext header's
`key_version` field (§4) references `version_number`.

| Field | Type | Notes |
|---|---|---|
| `version_number` | `u64` | Sequential (1, 2, 3, ...) |
| `key_handle` | `KeyHandle` | Provider-side handle to material |
| `created_at` | `DateTime<Utc>` | When this version was created |
| `is_primary` | `bool` | `true` for the current encrypt/sign version |

### 7.6 Version semantics

Two distinct version concepts:

- **`occ_version`** — monotonic storage counter. Bumped on every
  mutation (state change, tag edit, rotation, metadata update). Used
  by storage backends for optimistic concurrency (§9.2). Not related
  to key material.
- **`current_key_version` / `KeyVersionRecord.version_number`** — the
  rotation version. Each `RotateKey` creates a new version with fresh
  material. `current_key_version` on `KeyRecord` identifies the
  active version for encrypt/sign. The ciphertext header stores
  `key_version` so decrypt can select the right material.

---

## 8. Authz Request Schema (PDP Contract)

**Status:** stub — shape locked during W1; field details pending PDP team.

See `PDP_WIRE_FORMAT_REQS.md` for the full constraint set. The Rust
representation of the request lives in `keyrack-core::pdp`.

### 8.1 Rust types

```rust
pub struct AuthzRequest {
    pub request_id: String,
    pub action: Action,
    pub principal: Principal,
    pub resource: Resource,
    pub context: RequestContext,
}

pub struct AuthzResponse {
    pub request_id: String,
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub policy_version: Option<String>,
}

pub enum Decision {
    Permit,
    Forbid,
    Indeterminate,
}
```

---

## 9. Storage Schema with Optimistic Concurrency

**Status:** stub — to be locked during W1.

### 9.1 Core tables

- `keys` — primary key record with `version` column for OCC
- `key_versions` — per-rotation version records
- `lid_alias` — canonicalization migration aliases
- `aliases` — human-readable alias pointers
- `hsm_connections` — HSM connection records
- `rotation_jobs` — cooperative rotation job records
- `migration_state` — migration checkpoint (for `keyrack migrate`)
- `tags` — user tags (identity tags are on the `keys` row)

### 9.2 Optimistic concurrency

Every mutable operation on `keys` checks `WHERE version = $expected`
and increments on success. A concurrent conflict returns
`OptimisticConcurrencyError`; the caller retries.

---

## 10. Conformance Test Suite Scaffolding

**Status:** stub — scaffolding lands during W1.

The conformance harness is a set of trait-level tests that any provider
or storage implementation must pass. Phase 2 shim implementations
(AWS KMS, Barbican) validate against this harness.

The harness lives in `keyrack-test-support` and is consumed via
`#[cfg(test)]` in backend crates.
