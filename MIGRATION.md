# KeyRack Migration Design

This document specifies how KeyRack handles **changes that would invalidate
existing keys' relationships** — specifically rule-change migrations and
canonicalization migrations. These are different problems with different
mechanisms; this document covers both.

This is a Phase 1 deliverable so the *primitives* and *opt-out semantics* are
pinned down before the runtime ships. The tooling that exposes these
primitives (`keyrack migrate plan|apply|rollback`) support both
canonicalization migrations and rule-change migrations.

---

## Background: what is a "key" in KeyRack?

A KeyRack key is identified by its **Logical ID (LID)**:

```
LID = BLAKE3(canonicalization_version || canonical_form(attribute_set))
```

The LID is **the** identifier — it is also the public `key_id` exposed to
external clients. It is fully determined by:

1. The attribute set the request was made with
2. The canonicalization function version

It is **not** affected by:

- The namespace's rules (rules determine *parent relationships*, not identity)
- The provider backing the key (HSM, software, etc.)
- The version (rotation creates a new version of the same LID)

This separation matters: it means rule changes do not invalidate LIDs, but
canonicalization changes do.

A stored key record contains:

```rust
struct KeyRecord {
    lid: Lid,
    canonicalization_version: u32,
    parent_lid: Option<Lid>,
    version: u64,
    state: KeyState,
    backend_ref: ProviderRef,        // points at the actual HSM material
    identity_tags: Map<String, String>,  // immutable; derived from attrs
    user_tags: Map<String, String>,      // mutable; operator-set
    created_at: Timestamp,
    /* ... audit fields ... */
}
```

Critically, **`parent_lid` is stored**, not recomputed each time. This means
existing keys preserve their parent relationships even when rules change.
Rules only determine *what parent a new key gets at provisioning time*.

---

## The two migration cases

### Case A: Rule changes

The operator edits `namespaces.yaml`. Existing keys are not invalidated;
their LIDs are unchanged. What changes is what *new* keys would resolve to,
and what existing keys *would resolve to* if their parent were recomputed.

Default behaviour: existing keys keep their existing parents. The hierarchy
**forks** — old subtrees are reachable through old paths, new keys go under
new paths.

This is sometimes the right default ("our new policy is for new tenants
only"). Sometimes it isn't ("we discovered a security issue and need every
key reorganised under stricter parents"). Hence: **opt-in migration**.

### Case B: Canonicalization changes

The operator (or a KeyRack release) changes the canonicalization function:
adds a new field, fixes a bug, changes encoding. Now the *same* attribute
set hashes to a *different* LID. This invalidates every existing key's
identity.

Migration here is **mandatory** if the change ships, and is handled via
**aliasing**: every old LID maps to the equivalent new LID, and the storage
layer transparently resolves either form. New writes use the new
canonicalization; old reads work via the alias table until they're rewritten.

These two cases use entirely different mechanisms. The CLI surface
(`keyrack migrate`) hides the distinction with subcommands, but
internally they share little code.

---

## Case A: Rule-change migration

### Mechanics

The migration runs in three phases:

#### Phase 1: Plan

`keyrack migrate plan --from-namespace=namespaces.yaml.old --to=namespaces.yaml.new`

1. Load both namespace YAMLs.
2. Run `keyrack lint` against both. Reject if either is invalid.
3. Enumerate existing keys whose namespace matches the changed namespace.
4. For each existing key:
   - Compute its parent under the *new* rules (using stored `identity_tags` as the attribute set)
   - Compare to its current `parent_lid`
   - If different: add to migration set
5. Emit plan as JSON file:
   ```json
   {
     "namespace": "docs-app",
     "from_yaml_hash": "...",
     "to_yaml_hash": "...",
     "migrations": [
       {
         "lid": "...",
         "current_parent": "...",
         "new_parent": "...",
         "current_parent_resolves_via": "...",
         "new_parent_resolves_via": "..."
       }
       /* ... */
     ],
     "summary": {
       "total_keys": 12000,
       "to_migrate": 487,
       "estimated_duration": "12m",
       "estimated_hsm_ops": 974
     }
   }
   ```
6. Plans are auditable, reproducible, and can be reviewed before execution.

#### Phase 2: Apply

`keyrack migrate apply <plan.json>`

1. Validate plan against current state (reject if any key has changed since plan was generated, or new keys have been created that would also need migrating).
2. For each migration entry:
   - **Resolve** the new parent (lazy-provision if needed)
   - **Rewrap** the existing key to the new parent (`Provider::rewrap`)
   - **Update storage**: set `parent_lid = new_parent`, increment `version`, record migration in audit log
   - Emit `key.migrated` event to NATS with old/new parent
3. Operations are batched (default batch size 50, configurable) and throttled (default 10 batches/sec, configurable).
4. **Resumable**: progress is checkpointed to a `migration_state` table. If the process crashes or is killed, `apply` can be re-run with the same plan and will continue from where it left off.
5. If a single rewrap fails: log the failure, continue with remaining (unless `--abort-on-failure` is set). Failed entries are reported at the end.

#### Phase 3: Rollback (optional)

`keyrack migrate rollback <plan.json>`

If the migration was successful but the operator decides to revert:

1. For each migrated key:
   - Rewrap back to the original parent
   - Decrement state version
2. Emit `key.migration_rolled_back` events.
3. The original namespace YAML is restored manually (rollback only handles the data plane).

Rollback only works if the original parents still exist and have not been
deleted. If a parent has been pending-deletion'd or destroyed during the
intervening period, those rollback entries fail and require manual recovery.

### Opt-out: forked-hierarchy mode

`keyrack migrate plan --opt-out` produces a plan with **no migration
entries** and only updates the namespace YAML. Existing keys keep their
existing parents (forked hierarchy); new keys use new rules.

This is useful when:
- The rule change is intentionally additive (new tenants only)
- Migration cost is unacceptable (large namespace, slow HSM)
- The operator wants to stage: deploy new rules, observe new keys, schedule migration later

### Atomicity and consistency

The migration is **not** transactionally atomic across all keys. By design.
For a 100,000-key migration, atomic transactions are infeasible.

The guarantees are instead:

- **Per-key atomicity**: each key's migration (rewrap + storage update) is atomic. Either it migrates fully or it stays on the old parent.
- **Eventual consistency**: at any point during a migration, some keys are on old parents, some on new. Both work for encrypt/decrypt as long as both parents exist and are enabled.
- **Forward progress**: the plan + checkpoint design ensures the migration converges to "every entry in the plan is processed" given enough time.

The operator decides whether their service can tolerate this transitional
state (most can — it's invisible to clients) or needs to take downtime for
the migration window.

### Throughput and operational considerations

- **HSM is the bottleneck.** Each rewrap is an HSM operation. Network HSMs
  do ~100–1000 ops/sec. Plan accordingly.
- **Throttling defaults are conservative.** 10 batches × 50 ops = 500
  ops/sec ceiling. Operators tune up if their HSM can handle it.
- **Cache invalidation.** After each batch, an invalidation event is emitted
  for the migrated LIDs so other replicas drop stale parent references.
- **Audit volume.** A 100k-key migration emits ~200k audit events
  (rewrap + storage update). The audit pipeline must handle this. Default
  NATS subjects are partitioned by namespace to spread load.

### Required primitives (Phase 1 OSS)

For migration tooling (Phase 2 OSS) to ship, Phase 1 must provide:

- `Provider::rewrap(blob, old_parent, new_parent) -> Blob` — the core HSM op
- Storage-layer atomic update (parent_lid, version) with optimistic concurrency
- `migration_state` table with checkpoint columns
- NATS event topics for migration progress
- Audit event types for migrate-began, migrate-key, migrate-completed, migrate-failed, migrate-rolled-back

These are tracked as core and service deliverables.

---

## Case B: Canonicalization migration

### Mechanics

When the canonicalization function changes (e.g., from v1 to v2), every LID
in the system would change. This is handled via aliasing.

#### Storage shape

Add an `alias` table:

```sql
CREATE TABLE lid_alias (
    old_lid BYTEA PRIMARY KEY,
    new_lid BYTEA NOT NULL,
    canonicalization_from INT NOT NULL,
    canonicalization_to INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    INDEX (new_lid)
);
```

#### Resolution path

When a request comes in with a LID:

1. Compute the LID under the **current** canonicalization version.
2. Look up `keys` table by that LID. If found, use it.
3. If not found, look up `lid_alias` table. If found, follow alias to the canonical record.
4. If still not found, return `KeyNotFound`.

When provisioning new keys, only the current canonicalization is used.

#### Migration

`keyrack migrate plan --canonicalization-from=v1 --to=v2` does:

1. For each key in the storage:
   - Recompute its LID under v2 from its stored `identity_tags`
   - If the new LID differs from the stored LID (which it will for affected keys):
     - Record an alias entry: `(old_lid=v1_lid, new_lid=v2_lid, ...)`
     - Update the key record's `lid` to `v2_lid`
     - Update the `canonicalization_version` field to 2
     - Update any `parent_lid` references that point to migrated keys

2. The migration is **transactionally atomic per-key but not globally**, similar to rule-change migration.

3. After migration: external clients can present **either** the old LID or the new LID; both work via the alias table. The new LID is the canonical form going forward.

#### Forward compatibility

The alias table is permanent — old LIDs remain valid forever (or until the
operator chooses to garbage-collect them, with the understanding that
clients still using them will start getting `KeyNotFound`).

This is what makes canonicalization changes safe: they don't break existing
client integrations as long as the alias table is intact.

### When to bump canonicalization

The canonicalization version is bumped only when the canonicalization
function itself changes. Examples that **would** require a bump:

- Adding a new normalisation step (e.g., Unicode NFC normalisation that wasn't there before)
- Changing the encoding of integer values
- Fixing a bug where two distinct attribute sets canonicalise to the same form

Examples that **would not** require a bump:

- Adding a new attribute key (existing keys are unaffected; they never had that attribute)
- Performance improvements to the canonicalization function that don't change output
- Internal refactoring

### Multi-step migration

If you bump from v1 → v3, the migration can be done in one step (recompute
all v1 LIDs to v3 LIDs and write aliases) or in two steps (v1 → v2, then
v2 → v3, with aliases at each stage). Single-step is simpler and recommended
unless there's an operational reason to stage.

The alias table records the *from* and *to* versions, so multi-version
chains are introspectable.

---

## Audit story

Every migration emits a structured audit trail:

```json
{
  "event": "migrate.began",
  "type": "rule_change" | "canonicalization",
  "plan_id": "...",
  "namespace": "docs-app" /* for rule_change */,
  "from_version": 1, "to_version": 2 /* for canonicalization */,
  "principal": "...",
  "estimated_keys": 487,
  "timestamp": "..."
}

{
  "event": "migrate.key",
  "plan_id": "...",
  "lid": "...",
  "result": "success" | "failure",
  "old_parent": "...", "new_parent": "..." /* rule_change */,
  "old_lid": "...", "new_lid": "..." /* canonicalization */,
  "timestamp": "..."
}

{
  "event": "migrate.completed" | "migrate.failed" | "migrate.rolled_back",
  "plan_id": "...",
  "summary": {
    "total": 487, "succeeded": 484, "failed": 3,
    "duration": "..."
  },
  "timestamp": "..."
}
```

These integrate with the standard KeyRack audit pipeline (NATS / file / etc.).
Compliance evidence packs (Phase 2 Workstream 13) will include "all
migrations in last N months" as a standard query.

---

## Operator runbook (sketch)

The full runbook lives in `OPERATOR.md`. Sketch:

### Rule-change migration

```bash
# 1. Author new namespace YAML
$ vim namespaces/docs-app.yaml.new

# 2. Lint both old and new
$ keyrack lint namespaces/docs-app.yaml
$ keyrack lint namespaces/docs-app.yaml.new

# 3. Generate plan
$ keyrack migrate plan \
    --from-namespace=namespaces/docs-app.yaml \
    --to=namespaces/docs-app.yaml.new \
    --output=migration-plan-2026-04-27.json

# 4. Review plan
$ jq '.summary' migration-plan-2026-04-27.json
{
  "total_keys": 12000,
  "to_migrate": 487,
  "estimated_duration": "12m",
  "estimated_hsm_ops": 974
}

# 5. (Optional) Take rotation/migration window
# 6. Apply
$ keyrack migrate apply migration-plan-2026-04-27.json \
    --batch-size=50 --rate=10/s

# 7. Update active namespace YAML
$ mv namespaces/docs-app.yaml.new namespaces/docs-app.yaml
$ keyrack admin reload-namespace docs-app

# 8. Verify
$ keyrack admin inspect-namespace docs-app
```

### Canonicalization migration

This is rarer and typically tied to a KeyRack release.

```bash
# 1. Plan
$ keyrack migrate plan \
    --canonicalization-from=1 --to=2 \
    --output=canon-migration-2026-04-27.json

# 2. Review (this will likely affect EVERY key)
$ jq '.summary' canon-migration-2026-04-27.json

# 3. Schedule maintenance window — alias table writes touch all key records
# 4. Apply
$ keyrack migrate apply canon-migration-2026-04-27.json

# 5. Verify
$ keyrack admin canonicalization-status
{ "current_version": 2, "alias_count": 487123, "keys": 487123 }
```

---

## Open questions / future work

1. **GC of old aliases.** At what point are old LIDs no longer valid? Operator decision; tooling should report alias table size and last-used timestamps.

2. **Nested migrations.** A canonicalization migration during a rule-change migration window: the design says "don't do that" but tooling should reject it explicitly.

3. **Hot rule changes.** Some rule changes are safe to apply without rewrap (e.g. adding a new branch that only affects new keys). The lint should flag "this change is hot-applicable" and the plan should be empty in that case. Already covered by `--opt-out` but worth automating the detection.

4. **Selective migration.** Migrate only keys matching a filter (e.g. only `tenant=acme`). The plan generator should support a filter expression.

5. **Migration during cascade-disable.** If a tenant root is cascade-disabled, attempts to migrate its descendants must fail loudly (the descendants are unusable, rewrap can't proceed). Document and test.

These don't block the Phase 2 deliverable but inform the v2 evolution of the
migration tooling.
