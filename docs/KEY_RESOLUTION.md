# Key Resolution and Hierarchy

How KeyRack identifies, stores, and resolves keys through a hierarchical
parent-child structure.

---

## Core Concepts

Every key in KeyRack has two identifiers:

- **LID (Logical ID)**: A deterministic BLAKE3 hash derived from the key's
  attributes. Format: `lid_` followed by 64 hex characters. This is the
  primary identifier used in all APIs and storage.
- **KeyHandle**: A provider-internal reference (e.g. UUID, HSM label) that
  the crypto provider uses to locate the actual key material. Never exposed
  to callers.

These live in different places — the LID and metadata live in the
**storage backend** (SQLite/PostgreSQL), while the KeyHandle points to
material inside the **crypto provider** (software store, HSM, Vault, etc.).

---

## Where Things Live

```
┌─────────────────────────────────────────────────────────────────────┐
│                         KeyRack Service                             │
│                                                                     │
│  ┌───────────────────────────────────┐  ┌────────────────────────┐  │
│  │        Storage Backend            │  │    Crypto Provider     │  │
│  │       (SQLite / Postgres)         │  │ (Software / HSM /      │  │
│  │                                   │  │  Vault Transit / KMIP) │  │
│  │  KeyRecord:                       │  │                        │  │
│  │  ┌─────────────────────────────┐  │  │  Holds actual key      │  │
│  │  │ lid             (PK)       │  │  │  material. Addressed   │  │
│  │  │ parent_lid      (FK, opt)  │  │  │  by KeyHandle.key_id.  │  │
│  │  │ state                      │  │  │                        │  │
│  │  │ key_spec                   │  │  │  ┌──────────────────┐  │  │
│  │  │ key_usage                  │  │  │  │ key_id: "a1b2.." │  │  │
│  │  │ provider_class             │  │  │  │ AES-256 material │  │  │
│  │  │ current_key_version        │  │  │  └──────────────────┘  │  │
│  │  │ occ_version                │  │  │  ┌──────────────────┐  │  │
│  │  │ key_versions: [            │  │  │  │ key_id: "c3d4.." │  │  │
│  │  │   { version: 1,           │  │  │  │ Ed25519 material │  │  │
│  │  │     key_handle ──────────────────▶  └──────────────────┘  │  │
│  │  │     is_primary: false },   │  │  │                        │  │
│  │  │   { version: 2,           │  │  │                        │  │
│  │  │     key_handle ──────────────────▶  (newer material)      │  │
│  │  │     is_primary: true },    │  │  │                        │  │
│  │  │ ]                          │  │  └────────────────────────┘  │
│  │  │ identity_tags              │  │                               │
│  │  │ user_tags                  │  │                               │
│  │  └─────────────────────────────┘  │                               │
│  └───────────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

**Key point**: The storage backend holds *all metadata* including the
`parent_lid` relationship. The crypto provider holds *only key material*.
The link between them is the `KeyHandle` embedded in each `KeyVersionRecord`.

---

## Hierarchy: parent_lid

Keys form a tree via the `parent_lid` field on `KeyRecord`. A key
with `parent_lid = None` is a root key. A key with
`parent_lid = Some(lid_abc...)` is a child of that parent.

The hierarchy is set at creation time via `CreateKey(parent_key_id: ...)`.
Once set, `parent_lid` is immutable — it is stored, not recomputed.

```
               ┌──────────────┐
               │  Root CMK     │  parent_lid: None
               │  lid_aaa...   │  AES-256
               └──────┬───────┘
                      │
            ┌─────────┴─────────┐
            │                   │
     ┌──────┴───────┐    ┌─────┴────────┐
     │ Tenant Key    │    │ Signing Key   │  parent_lid: lid_aaa...
     │ lid_bbb...    │    │ lid_ccc...    │
     │ AES-256       │    │ Ed25519       │
     └──────┬────────┘    └──────────────┘
            │
     ┌──────┴────────┐
     │ DEK (data key) │  parent_lid: lid_bbb...
     │ lid_ddd...     │
     │ AES-256        │
     └────────────────┘
```

Storage tracks this relationship. The service provides two query APIs:

- **GetKeyDependents(key_id, recursive)** — BFS downward from a key,
  returns all children (or all descendants if recursive).
- **GetKeyAncestors(key_id)** — walks `parent_lid` upward to the root.

---

## Key Resolution: What Happens When You Call an API

### CreateKey

```
  Client                    Service                   Storage          Provider
    │                          │                         │                │
    │  CreateKey(spec, parent) │                         │                │
    │─────────────────────────▶│                         │                │
    │                          │  generate_key(spec)     │                │
    │                          │────────────────────────────────────────▶│
    │                          │                         │   KeyHandle    │
    │                          │◀────────────────────────────────────────│
    │                          │                         │                │
    │                          │  generate LID           │                │
    │                          │  (UUID → attrs →        │                │
    │                          │   canonicalize → BLAKE3) │                │
    │                          │                         │                │
    │                          │  parse parent_key_id    │                │
    │                          │  → parent_lid           │                │
    │                          │                         │                │
    │                          │  build KeyRecord {      │                │
    │                          │    lid, parent_lid,     │                │
    │                          │    key_versions: [{     │                │
    │                          │      handle, v1, primary│                │
    │                          │    }],                  │                │
    │                          │    state: Enabled, ...  │                │
    │                          │  }                      │                │
    │                          │                         │                │
    │                          │  create_key(record)     │                │
    │                          │────────────────────────▶│                │
    │                          │                         │                │
    │  CreateKeyResponse       │                         │                │
    │◀─────────────────────────│                         │                │
```

1. The provider generates key material and returns a `KeyHandle`.
2. A unique LID is derived by hashing a random UUID through the
   canonicalization pipeline.
3. If `parent_key_id` is specified, it is parsed into a `parent_lid`.
4. A `KeyRecord` is built combining the LID, parent_lid, KeyHandle,
   spec, and initial state (`Enabled`).
5. The record is persisted to storage.

### Encrypt (resolving a key for use)

```
  Client                    Service                   Storage          Provider
    │                          │                         │                │
    │  Encrypt(key_id, data)   │                         │                │
    │─────────────────────────▶│                         │                │
    │                          │                         │                │
    │                          │  parse key_id → LID     │                │
    │                          │  get_key(lid)           │                │
    │                          │────────────────────────▶│                │
    │                          │         KeyRecord       │                │
    │                          │◀────────────────────────│                │
    │                          │                         │                │
    │                          │  check state.permits_encrypt()           │
    │                          │  find primary version (is_primary=true)  │
    │                          │  extract key_handle                      │
    │                          │                         │                │
    │                          │  build CiphertextHeader │                │
    │                          │  (lid, version, ec_hash)│                │
    │                          │                         │                │
    │                          │  encrypt(handle, data, aad)              │
    │                          │────────────────────────────────────────▶│
    │                          │                      ciphertext          │
    │                          │◀────────────────────────────────────────│
    │                          │                         │                │
    │                          │  wrap: header + payload │                │
    │                          │                         │                │
    │  EncryptResponse(blob)   │                         │                │
    │◀─────────────────────────│                         │                │
```

1. The `key_id` string is parsed into a `Lid`.
2. The `KeyRecord` is fetched from storage by LID.
3. The record's state is checked (`permits_encrypt` — only `Enabled`).
4. The **primary** key version (the current one for new encryptions) is
   located within `key_versions`.
5. A `CiphertextHeader` is constructed containing the LID, key version
   number, and encryption context hash.
6. The provider encrypts using the `KeyHandle` from that version.
7. The header is prepended to the ciphertext payload.

### Decrypt (version resolution from ciphertext)

```
  Client                    Service                   Storage          Provider
    │                          │                         │                │
    │  Decrypt(key_id, blob)   │                         │                │
    │─────────────────────────▶│                         │                │
    │                          │                         │                │
    │                          │  unwrap blob → header + ciphertext       │
    │                          │  header contains: lid, key_version,      │
    │                          │                   ec_hash                │
    │                          │                         │                │
    │                          │  get_key(lid)           │                │
    │                          │────────────────────────▶│                │
    │                          │         KeyRecord       │                │
    │                          │◀────────────────────────│                │
    │                          │                         │                │
    │                          │  check state.permits_decrypt()           │
    │                          │  (Enabled, Disabled, or Compromised)     │
    │                          │                         │                │
    │                          │  find version matching  │                │
    │                          │  header.key_version     │                │
    │                          │  in key_versions[]      │                │
    │                          │  extract key_handle     │                │
    │                          │                         │                │
    │                          │  verify ec_hash matches │                │
    │                          │                         │                │
    │                          │  decrypt(handle, ct, aad)                │
    │                          │────────────────────────────────────────▶│
    │                          │                      plaintext           │
    │                          │◀────────────────────────────────────────│
    │                          │                         │                │
    │  DecryptResponse(pt)     │                         │                │
    │◀─────────────────────────│                         │                │
```

The critical difference from encrypt: the **version is extracted from the
ciphertext header**, not assumed to be the primary. This allows decryption
with any historical key version, enabling seamless key rotation — old
ciphertexts encrypted with version N can still be decrypted after the key
has been rotated to version N+1.

---

## Standard Scenarios

### Scenario 1: Single Root Key (simplest)

A standalone application using one AES-256 key for envelope encryption.

```
    ┌──────────────┐
    │  Root CMK     │  parent_lid: None
    │  lid_aaa...   │  AES-256, Enabled
    │               │
    │  Versions:    │
    │   v1 (primary)│──▶ KeyHandle → Provider material
    └──────────────┘

    Storage: one KeyRecord row
    Provider: one key material object
```

**Encrypt**: look up `lid_aaa`, get primary version (v1), encrypt with
that handle.

**After rotation to v2**:
```
    │  Versions:    │
    │   v1          │──▶ old material (retained for decrypt)
    │   v2 (primary)│──▶ new material (used for new encrypts)
```

New encrypts use v2. Old ciphertexts still decrypt via v1 (version
embedded in ciphertext header).

### Scenario 2: Tenant Isolation Hierarchy

A SaaS platform with per-tenant encryption keys derived from a root.

```
    ┌──────────────┐
    │  Platform CMK │  parent_lid: None
    │  lid_root...  │  AES-256
    └──────┬───────┘
           │
    ┌──────┴───────┐  ┌──────────────┐  ┌──────────────┐
    │ Tenant A Key  │  │ Tenant B Key  │  │ Tenant C Key  │
    │ lid_aaa...    │  │ lid_bbb...    │  │ lid_ccc...    │
    │ AES-256       │  │ AES-256       │  │ AES-256       │
    │ parent: root  │  │ parent: root  │  │ parent: root  │
    └───────────────┘  └──────────────┘  └──────────────┘

    Storage: 4 KeyRecord rows (root + 3 tenants)
             parent_lid links tenants → root
    Provider: 4 independent key material objects
```

**Key resolution**: Each tenant key is resolved independently by its own
LID. The `parent_lid` link is metadata-only — it does not affect how
encryption or decryption works.

**Where hierarchy matters**: Rotation cascade and disable cascade.
Rotating the root CMK creates rotation jobs for all children (see
KEY_ROTATION.md). Disabling the root cascades disable to all descendants.

### Scenario 3: Multi-Level Hierarchy (Envelope Encryption)

A storage system using a three-level key hierarchy.

```
    ┌──────────────────┐
    │  Root CMK         │  parent_lid: None
    │  lid_root...      │  AES-256, Software provider
    │  v1 (primary)     │
    └──────┬───────────┘
           │
    ┌──────┴───────────┐
    │  Volume KEK       │  parent_lid: lid_root
    │  lid_vol...       │  AES-256, Software provider
    │  v1 (primary)     │
    └──────┬───────────┘
           │
    ┌──────┴───────────┐
    │  Chunk DEK        │  parent_lid: lid_vol
    │  lid_chunk...     │  AES-256, Software provider
    │  v1 (primary)     │
    └──────────────────┘

    Storage: 3 KeyRecord rows with parent_lid chain
    Provider: 3 independent key material objects
```

**Key material is independent at each level**: Each key has its own
material in the provider. The hierarchy is a *metadata relationship*, not
a cryptographic derivation. The chunk DEK is not "derived from" the volume
KEK in a KDF sense — it is an independent key whose *lifecycle* is linked
to its parent.

**Querying the hierarchy**:
- `GetKeyAncestors(lid_chunk)` → `[lid_vol, lid_root]`
- `GetKeyDependents(lid_root, recursive=true)` →
  `[lid_vol (depth 1), lid_chunk (depth 2)]`

### Scenario 4: Mixed Provider Hierarchy

Keys at different levels can use different providers.

```
    ┌───────────────────┐
    │  HSM Root CMK      │  parent_lid: None
    │  lid_hsm...        │  AES-256, PKCS#11 provider
    │  KeyHandle → HSM   │
    └──────┬────────────┘
           │
    ┌──────┴────────────┐
    │  Software DEK      │  parent_lid: lid_hsm
    │  lid_sw...         │  AES-256, Software provider
    │  KeyHandle → disk  │
    └───────────────────┘

    Storage: 2 KeyRecord rows, different provider_class values
    HSM: holds root material (never leaves hardware)
    Software: holds DEK material (in-process memory/disk)
```

The hierarchy is agnostic to the provider backing each key. The
`provider_class` field on each `KeyRecord` records which provider holds
that key's material. When the service performs operations, it routes to
the correct provider based on the record's `provider_class`.

---

## LID Derivation

The LID is deterministic for a given set of attributes:

```
attributes → canonicalize(V1, attrs) → CanonicalForm (bytes)
                                            │
                        ┌───────────────────┘
                        ▼
              BLAKE3(version_le32 ‖ canonical_bytes) → 32 bytes
                        │
                        ▼
                    lid_<64 hex chars>
```

In the current `CreateKey` flow, the attributes contain a random UUID
(`_keyrack_key_id`), making each LID unique. The canonicalization version
is `V1` and is stored on the record to support future migration.

---

## Ciphertext Header

Every ciphertext blob produced by KeyRack is prefixed with a header:

```
┌──────────────────────────────────────────────────────────┐
│ CiphertextHeader                                          │
│  ┌────────────┬──────────────┬────────────────────────┐  │
│  │ LID        │ key_version  │ encryption_context_hash│  │
│  │ (32 bytes) │ (u64)        │ (32 bytes)             │  │
│  └────────────┴──────────────┴────────────────────────┘  │
│                                                           │
│ Payload (provider-produced ciphertext)                    │
│  ┌────────────────────────────────────────────────────┐  │
│  │ nonce ‖ ciphertext ‖ tag  (AES-256-GCM)           │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

The header is included in the AAD (Additional Authenticated Data) for
AES-GCM, binding the key identity and version to the ciphertext
cryptographically. Tampering with the header causes decryption to fail.

On decrypt, the header is parsed first to determine **which key** and
**which version** to use, then the matching `KeyHandle` is retrieved
from the stored `KeyRecord.key_versions[]`.
