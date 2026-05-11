# Key Rotation and Rule Changes

How key rotation works end-to-end in KeyRack, and what happens when
namespace routing rules change.

---

## Part 1: Key Rotation

### Rotation Model

KeyRack uses a **versioned key** model. Rotation does not replace a key —
it adds a new version while keeping all previous versions.

```
Before rotation:              After RotateKey:

┌────────────────────┐        ┌────────────────────┐
│  KeyRecord         │        │  KeyRecord         │
│  lid: lid_aaa...   │        │  lid: lid_aaa...   │
│  current_version: 1│        │  current_version: 2│
│                    │        │                    │
│  versions:         │        │  versions:         │
│   v1 (primary) ────┤        │   v1 ──────────────┤
│                    │        │   v2 (primary) ────┤
└────────────────────┘        └────────────────────┘

  Encrypt → uses v1             Encrypt → uses v2
  Decrypt → uses v1             Decrypt → v1 or v2
                                (version from ciphertext header)
```

Old ciphertexts still decrypt because the version number is embedded
in the ciphertext header. The service looks up the matching version's
`KeyHandle` for decryption, not the primary.

### Manual Rotation (RotateKey RPC)

When `RotateKey(key_id)` is called:

```
  Client                     Service                   Storage         Provider
    │                           │                         │               │
    │  RotateKey(key_id)        │                         │               │
    │──────────────────────────▶│                         │               │
    │                           │  PDP: authorize         │               │
    │                           │  get_key(lid)           │               │
    │                           │────────────────────────▶│               │
    │                           │       KeyRecord         │               │
    │                           │◀───────────────────────│               │
    │                           │                         │               │
    │                           │  check: state == Enabled│               │
    │                           │                         │               │
    │                           │  generate_key(spec)     │               │
    │                           │───────────────────────────────────────▶│
    │                           │                    new KeyHandle       │
    │                           │◀──────────────────────────────────────│
    │                           │                         │               │
    │                           │  v_old.is_primary = false               │
    │                           │  add KeyVersionRecord {                 │
    │                           │    version: old+1,                      │
    │                           │    handle: new_handle,                  │
    │                           │    is_primary: true                     │
    │                           │  }                                      │
    │                           │  bump occ_version       │               │
    │                           │                         │               │
    │                           │  update_key(record)     │               │
    │                           │────────────────────────▶│               │
    │                           │                         │               │
    │                           │  ┌──────────────────────────────────┐  │
    │                           │  │ Create rotation jobs for all     │  │
    │                           │  │ descendant keys (BFS traversal)  │  │
    │                           │  └──────────────────────────────────┘  │
    │                           │                         │               │
    │                           │  NATS: rotation-started │               │
    │                           │                         │               │
    │  RotateKeyResponse        │                         │               │
    │  (metadata, new_version)  │                         │               │
    │◀─────────────────────────│                         │               │
```

Steps:
1. PDP authorization check.
2. Fetch key record; verify state is `Enabled`.
3. Generate fresh key material via the crypto provider.
4. Demote current primary version; add a new `KeyVersionRecord` as primary.
5. Persist the updated record (OCC check on `occ_version`).
6. **Cascade**: BFS-walk all descendant keys (via `list_children`),
   creating a `RotationJob` for each one.
7. Publish NATS rotation event (if configured).
8. Audit event emitted.

**REST caveat**: The REST endpoint `POST /v1/keys/:key_id/actions-rotate`
performs the core rotation (new version, primary flip, persist) but does
**not** create descendant rotation jobs and does **not** publish NATS
events. Use the gRPC `RotateKey` RPC for full cascade behavior.

### Cascade: Rotation Jobs for Descendants

When a parent key rotates, every key in its subtree receives a
`RotationJob`. This is the **cooperative rotation** protocol.

```
  Parent rotated (v1 → v2)
         │
         ├─▶ RotationJob { parent: lid_parent, dependent: lid_child_A, new_version: 2 }
         ├─▶ RotationJob { parent: lid_parent, dependent: lid_child_B, new_version: 2 }
         │        │
         │        ├─▶ RotationJob { parent: lid_parent, dependent: lid_grandchild, ... }
         ...
```

The BFS traversal visits every descendant, not just direct children.

### Rotation Job Lifecycle

Each job follows this state machine:

```
  pending ──▶ acknowledged ──▶ completed
                    │
                    ├──▶ failed
                    │
                    └──▶ expired (auto, after 24h default)
```

The consuming service (e.g. a partner volume service) is expected to:

1. **Poll** for pending jobs via `ListRotationJobs(state=PENDING)`.
2. **Acknowledge** the job (`AcknowledgeRotationJob`).
3. **Re-wrap** its data under the new key version.
4. **Complete** the job (`CompleteRotationJob`) or **Fail** it
   (`FailRotationJob` with a reason).

A background worker periodically expires unacknowledged or
unfinished jobs past their `expires_at` deadline.

### Automatic Rotation (Rotation Policy)

Rotation policies are persisted as reserved user tags on the key:

| Tag | Value |
|-----|-------|
| `_keyrack_rotation_enabled` | `"true"` or `"false"` |
| `_keyrack_rotation_interval_days` | `"90"` (example) |

Set via `SetKeyRotationPolicy(key_id, { enabled, interval_days })` or
the convenience `EnableKeyRotation` / `DisableKeyRotation`.

**Current status**: The policy is persisted and queryable via
`GetKeyRotationPolicy` / `GetKeyRotationStatus`. The background
scheduler that automatically triggers `RotateKey` at the configured
interval is planned but not yet implemented (V1 Launch Plan item P0-A#5).

### Marking a Specific Key for Rotation

There is no separate "mark for rotation" API. To rotate a specific key:

- **Immediate**: Call `RotateKey(key_id)`. This generates new material
  and creates descendant rotation jobs immediately.
- **Scheduled**: Set a rotation policy with
  `SetKeyRotationPolicy(key_id, { enabled: true, interval_days: N })`.
  Once the background scheduler is wired, this will auto-rotate.
- **Compromise**: Call `ReportKeyCompromise(key_id)`. This transitions
  the key to `Compromised` state (decrypt/verify still allowed, but
  encrypt/sign is blocked). This is a lifecycle action, not rotation —
  the operator should then rotate or create a replacement key.

---

## Part 2: Key Disable Cascade

Disabling a key cascades to all descendants:

```
  DisableKey(lid_parent)
         │
         │  1. parent transitions: Enabled → Disabled
         │
         │  2. BFS over children via list_children():
         │
         ├──▶ child_A: Enabled → Disabled
         │        │
         │        ├──▶ grandchild: Enabled → Disabled
         │
         ├──▶ child_B: Enabled → Disabled
         ...
```

Only `Enabled` children are disabled. Children in other states are
skipped. The cascade count and duration are logged.

---

## Part 3: Rule Changes

### What Are Rules?

Rules (defined in `rule.rs`) are namespace routing rules that determine
the **key hierarchy** — given a key's attributes, which key is its
parent? They are declared in YAML and loaded into a `RuleRegistry`.

Example rules:

```yaml
namespaces:
  - name: _infrastructure_
    routing_rules:
      - match_pattern: { kind: root }
        parent: null                     # root key (no parent)
      - match_pattern: { kind: tenant-root, tenant: "$T" }
        parent: { kind: root }          # parent is the root key

  - name: acme-app
    attachment: { tenant: acme }
    routing_rules:
      - match_pattern: { kind: dek, user: "$U", doc: "$D" }
        parent: { kind: user-kek, user: "$U" }
      - match_pattern: { kind: user-kek, user: "$U" }
        parent: { kind: app-root }
      - match_pattern: { kind: app-root }
        parent: "_attachment_"           # crosses to infrastructure
```

These produce a hierarchy like:

```
  root
   └── tenant-root (tenant=acme)       ← infrastructure namespace
        └── app-root                    ← acme-app attachment boundary
             └── user-kek (user=alice)
                  └── dek (user=alice, doc=001)
```

### What Happens When Rules Change?

Changing rules means the hierarchy changes — keys that were children of
one parent might now belong to a different parent. This is a **migration**,
handled via the CLI tooling.

The process is:

```
                                   ┌──────────────────────┐
  1. Plan                          │  keyrack migrate     │
     ─────▶                        │    rule-change-plan   │
                                   │    --old-rules X.yaml │
                                   │    --new-rules Y.yaml │
                                   │    --storage db       │
                                   └──────────┬───────────┘
                                              │
                                    Produces JSON plan file
                                    listing all affected keys
                                              │
                                              ▼
                                   ┌──────────────────────┐
  2. Apply                         │  keyrack migrate     │
     ─────▶                        │    rule-change-apply  │
                                   │    --new-rules Y.yaml │
                                   │    --storage db       │
                                   │    [--opt-out]        │
                                   │    [--batch-size 100] │
                                   └──────────┬───────────┘
                                              │
                                   Updates parent_lid on each
                                   affected KeyRecord in storage
                                              │
                                              ▼
                                   ┌──────────────────────┐
  3. (Optional) Rollback           │  keyrack migrate     │
     ─────▶                        │    rule-change-rollback│
                                   │    --storage db       │
                                   └──────────────────────┘
                                   Reverts parent_lid to old values
```

#### Step 1: Plan (`rule-change-plan`)

The planner:
1. Loads the old and new rule YAML files and validates both.
2. Hashes both files (BLAKE3) to ensure integrity.
3. Iterates over **every key** in storage.
4. For each key, evaluates the old rules and new rules against the key's
   `identity_tags` to determine the old parent and new parent.
5. If old parent != new parent, the key is marked `Rewrap`.
6. If they match, the key is marked `Skip`.
7. Writes a JSON plan file.

The plan is a diff — it shows exactly which keys are affected and how.

#### Step 2: Apply (`rule-change-apply`)

The applier:
1. Loads and validates the plan and new rules YAML.
2. Verifies the rules YAML hash matches the plan (prevents applying
   the wrong version).
3. For each `Rewrap` entry:
   - Resolves the new parent LID using the new rule registry.
   - Updates the key's `parent_lid` in storage.
   - Bumps `occ_version`.
4. Checkpoints the plan file periodically (configurable `batch-size`)
   for **resumability** — if the process is interrupted, re-running
   picks up where it left off.

**Opt-out mode**: `--opt-out` accepts the rule change for new keys but
does not migrate existing keys. Old keys keep their old `parent_lid`;
only newly created keys will use the new rules.

**Cryptographic rewrap**: Currently, the CLI only updates `parent_lid`
metadata. Full cryptographic rewrap (decrypting under the old parent and
re-encrypting under the new parent) requires `CryptoProvider` access,
which will be wired when the CLI gains gRPC client support.

#### Step 3: Rollback (`rule-change-rollback`)

The rollback reads the plan file and reverts each applied entry's
`parent_lid` to the old value.

### How Rules Are Performed Via the API

At the gRPC/REST layer:

- **RegisterNamespace(name, yaml_config)**: Registers a namespace with its
  rule YAML. Currently in-memory only (not persisted — the service logs
  the registration).
- **DescribeNamespace(name)**: Returns the namespace's config, max depth,
  and rule count.
- **ListNamespaces()**: Lists registered namespaces.

The actual rule engine lives in `keyrack-core` (`rule.rs`, `resolver.rs`)
and is consumed by:
- The **CLI linter** (`keyrack lint`) for validating rules at deploy time.
- The **resolver** for computing key chains from attributes.
- The **migration tool** for planning and applying rule changes.

### Other Rotations

| Action | What it does |
|--------|-------------|
| `RotateKey(key_id)` | Immediate rotation: new version + descendant jobs |
| `SetKeyRotationPolicy(key_id, policy)` | Persist automatic rotation interval |
| `EnableKeyRotation(key_id)` | Shorthand: enable auto-rotation |
| `DisableKeyRotation(key_id)` | Shorthand: disable auto-rotation |
| `ReportKeyCompromise(key_id)` | Mark key as compromised (not rotation — blocks encrypt/sign) |
| `DisableKey(key_id)` | Disable key + cascade to descendants |
| `ScheduleKeyDeletion(key_id, days)` | Schedule destruction after grace period |

All of these go through the same `ops::execute` path ensuring PDP
authorization and audit event emission.

---

## Audit Trail

Every operation described above emits an `AuditEvent` with:

- Event type (e.g. `KeyRotated`, `RotationPolicyChanged`,
  `RotationJobStateChanged`, `CascadeDisable`)
- The action (e.g. `kms:RotateKey`, `kms:SetKeyRotationPolicy`)
- Principal who initiated the action
- Resource affected (key LID)
- Result (success/denied/error)
- `request_id` for end-to-end correlation
- Optional Ed25519 signature + BLAKE3 hash chain for tamper evidence

Events are dispatched to the configured sink (stdout, file, or NATS).
