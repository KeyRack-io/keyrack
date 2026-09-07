// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of KeyRack.
//
// KeyRack is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// KeyRack is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
// more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with KeyRack. If not, see <https://www.gnu.org/licenses/>.
//
// Alternative commercial licensing is available; contact the Licensor.

use clap::{Args, Subcommand};
use keyrack_core::key::{KeyRecord, KeyState};
use keyrack_core::migration::{self, MigrationAction, MigrationEntry, MigrationPlan};
use keyrack_core::storage::{KeyFilter, StorageBackend};

#[derive(Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub command: MigrateCommand,
}

#[derive(Subcommand)]
pub enum MigrateCommand {
    /// Generate a migration plan for canonicalization version upgrade.
    Plan {
        /// Source canonicalization version (must be supported by this binary).
        #[arg(long)]
        from_canonicalization: String,

        /// Target canonicalization version (e.g. v2).
        #[arg(long)]
        to: String,

        /// Output plan file path.
        #[arg(short, long, default_value = "migration-plan.json")]
        output: std::path::PathBuf,

        /// Database path for direct storage access (`SQLite`).
        #[arg(long)]
        storage: String,
    },

    /// Apply a previously generated migration plan.
    Apply {
        /// Path to the migration plan JSON file.
        plan_file: std::path::PathBuf,

        /// Database path for direct storage access (`SQLite`).
        #[arg(long)]
        storage: String,
    },

    /// Roll back a previously applied migration.
    Rollback {
        /// Path to the migration plan JSON file.
        plan_file: std::path::PathBuf,

        /// Database path for direct storage access (`SQLite`).
        #[arg(long)]
        storage: String,
    },

    /// Plan a rule-change migration: diff old vs. new namespace YAML
    /// and compute which keys need rewrapping under new parent rules.
    RuleChangePlan {
        /// Path to the old namespace YAML file.
        #[arg(long)]
        old_rules: std::path::PathBuf,

        /// Path to the new namespace YAML file.
        #[arg(long)]
        new_rules: std::path::PathBuf,

        /// Output plan file path.
        #[arg(short, long, default_value = "rule-change-plan.json")]
        output: std::path::PathBuf,

        /// Database path for direct storage access.
        #[arg(long)]
        storage: String,
    },

    /// Apply a rule-change migration plan (rewrap operations).
    RuleChangeApply {
        /// Path to the rule-change plan JSON file.
        plan_file: std::path::PathBuf,

        /// Path to the new namespace YAML file (used to resolve
        /// new parent LIDs at apply time).
        #[arg(long)]
        new_rules: std::path::PathBuf,

        /// Database path for direct storage access.
        #[arg(long)]
        storage: String,

        /// Maximum number of keys to process per batch.
        #[arg(long, default_value = "100")]
        batch_size: usize,

        /// Opt-out mode: accept the rule change but don't migrate
        /// existing keys. Old keys keep old parents, new keys get
        /// new parents.
        #[arg(long, default_value = "false")]
        opt_out: bool,
    },

    /// Roll back a rule-change migration.
    RuleChangeRollback {
        /// Path to the rule-change plan JSON file.
        plan_file: std::path::PathBuf,

        /// Database path for direct storage access.
        #[arg(long)]
        storage: String,
    },
}

pub async fn run(args: MigrateArgs) -> anyhow::Result<()> {
    match args.command {
        MigrateCommand::Plan {
            from_canonicalization,
            to,
            output,
            storage,
        } => plan_migration(&from_canonicalization, &to, &output, &storage).await,
        MigrateCommand::Apply { plan_file, storage } => apply_migration(&plan_file, &storage).await,
        MigrateCommand::Rollback { plan_file, storage } => {
            rollback_migration(&plan_file, &storage).await
        }
        MigrateCommand::RuleChangePlan {
            old_rules,
            new_rules,
            output,
            storage,
        } => plan_rule_change(&old_rules, &new_rules, &output, &storage).await,
        MigrateCommand::RuleChangeApply {
            plan_file,
            new_rules,
            storage,
            batch_size,
            opt_out,
        } => apply_rule_change(&plan_file, &new_rules, &storage, batch_size, opt_out).await,
        MigrateCommand::RuleChangeRollback { plan_file, storage } => {
            rollback_rule_change(&plan_file, &storage).await
        }
    }
}

fn open_storage(path: &str) -> anyhow::Result<keyrack_sqlite::SqliteStorage> {
    keyrack_sqlite::SqliteStorage::open(path)
        .map_err(|e| anyhow::anyhow!("cannot open storage at {path}: {e}"))
}

/// Paginate through all keys in storage, collecting every record.
async fn list_all_keys(db: &impl StorageBackend) -> anyhow::Result<Vec<KeyRecord>> {
    let mut all_keys = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let filter = KeyFilter {
            cursor,
            ..KeyFilter::default()
        };
        let page = db
            .list_keys(&filter)
            .await
            .map_err(|e| anyhow::anyhow!("failed to list keys: {e}"))?;
        all_keys.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(all_keys)
}

async fn plan_migration(
    from_str: &str,
    to_str: &str,
    output: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let from_version =
        migration::parse_canon_version(from_str).map_err(|e| anyhow::anyhow!("{e}"))?;
    let to_version = migration::parse_canon_version(to_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    if from_version == to_version {
        anyhow::bail!("source and target canonicalization versions are the same");
    }

    let db = open_storage(storage_path)?;

    let all_keys = list_all_keys(&db).await?;

    let mut entries = Vec::new();

    for record in &all_keys {
        if record.canonicalization_version == from_version {
            let new_lid = migration::rederive_lid(&record.lid, &record.identity_tags, to_version)?;
            entries.push(MigrationEntry {
                old_lid: record.lid.to_string(),
                new_lid: Some(new_lid.to_string()),
                from_version: migration::canon_version_to_u32(from_version),
                to_version: migration::canon_version_to_u32(to_version),
                action: MigrationAction::RederiveLid,
                applied: false,
            });
        } else {
            entries.push(MigrationEntry {
                old_lid: record.lid.to_string(),
                new_lid: None,
                from_version: migration::canon_version_to_u32(record.canonicalization_version),
                to_version: migration::canon_version_to_u32(to_version),
                action: MigrationAction::Skip,
                applied: false,
            });
        }
    }

    let plan = MigrationPlan {
        from_canonicalization: migration::canon_version_to_u32(from_version),
        to_canonicalization: migration::canon_version_to_u32(to_version),
        entries,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let actionable = plan
        .entries
        .iter()
        .filter(|e| e.action == MigrationAction::RederiveLid)
        .count();
    let skipped = plan.entries.len() - actionable;

    let json = serde_json::to_string_pretty(&plan)?;
    std::fs::write(output, &json)?;

    eprintln!(
        "migration plan written to {}: {} key(s) to migrate, {} skipped",
        output.display(),
        actionable,
        skipped,
    );

    Ok(())
}

/// Validate the entire plan before opening storage, even entries execution would
/// otherwise skip. A checkpoint is not authority to accept an obsolete format.
fn validate_migration_plan(
    plan: &MigrationPlan,
) -> anyhow::Result<(
    keyrack_core::canon::CanonicalizationVersion,
    keyrack_core::canon::CanonicalizationVersion,
)> {
    let parse = |version: u32| {
        migration::parse_canon_version(&version.to_string()).map_err(anyhow::Error::msg)
    };
    let from = parse(plan.from_canonicalization)?;
    let to = parse(plan.to_canonicalization)?;
    for (index, entry) in plan.entries.iter().enumerate() {
        let entry_from = parse(entry.from_version)?;
        let entry_to = parse(entry.to_version)?;
        if entry_to != to
            || (entry_from != from && !(entry.action == MigrationAction::Skip && entry_from == to))
        {
            anyhow::bail!("entry {index} canonicalization versions disagree with the plan");
        }
    }
    // Only V2 is supported today, so no canonicalization migration can run.
    // Keep apply/rollback consistent with the planner instead of treating a
    // hand-authored same-version plan as an implicit migration/recovery API.
    if from == to {
        anyhow::bail!("source and target canonicalization versions are the same");
    }
    Ok((from, to))
}

/// Deserialization rejects unsupported stored versions; additionally require the
/// supported record version to match the plan before modifying it or its alias.
async fn migration_source_record(
    db: &impl StorageBackend,
    old_lid: &keyrack_core::lid::Lid,
    expected: keyrack_core::canon::CanonicalizationVersion,
) -> anyhow::Result<KeyRecord> {
    let record = db.get_key(old_lid).await?;
    if record.canonicalization_version != expected {
        anyhow::bail!("source record {old_lid} canonicalization version disagrees with the plan");
    }
    Ok(record)
}

#[allow(clippy::too_many_lines)]
async fn apply_migration(plan_file: &std::path::Path, storage_path: &str) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let mut plan: MigrationPlan = serde_json::from_str(&plan_json)?;

    let (from_version, to_version) = validate_migration_plan(&plan)?;

    let db = open_storage(storage_path)?;

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for entry in &mut plan.entries {
        if entry.applied || entry.action == MigrationAction::Skip {
            skipped += 1;
            continue;
        }

        let old_lid: keyrack_core::lid::Lid = entry
            .old_lid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid LID '{}': {e}", entry.old_lid))?;

        let record = match migration_source_record(&db, &old_lid, from_version).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(lid = %entry.old_lid, error = %e, "key not found");
                errors += 1;
                continue;
            }
        };

        let new_lid = migration::rederive_lid(&record.lid, &record.identity_tags, to_version)?;
        let new_lid_str = new_lid.to_string();

        let mut updated = record.clone();
        updated.lid = new_lid;
        updated.canonicalization_version = to_version;
        updated.occ_version += 1;

        if let Err(e) = db.create_key(&updated).await {
            tracing::error!(old = %entry.old_lid, new = %new_lid_str, error = %e, "failed to create migrated key");
            errors += 1;
            continue;
        }

        let alias = keyrack_core::storage::AliasRecord {
            alias_name: format!("migration:{}", entry.old_lid),
            target_lid: new_lid,
            created_at: chrono::Utc::now(),
        };
        if let Err(e) = db.create_alias(&alias).await {
            tracing::warn!(alias = %alias.alias_name, error = %e, "alias creation failed (may already exist)");
        }

        entry.new_lid = Some(new_lid_str);
        entry.applied = true;
        applied += 1;
    }

    let updated_json = serde_json::to_string_pretty(&plan)?;
    std::fs::write(plan_file, &updated_json)?;

    eprintln!("migration apply: {applied} migrated, {skipped} skipped, {errors} errors");
    if errors > 0 {
        anyhow::bail!("{errors} key(s) failed during migration");
    }
    Ok(())
}

async fn rollback_migration(plan_file: &std::path::Path, storage_path: &str) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let plan: MigrationPlan = serde_json::from_str(&plan_json)?;

    let (from_version, to_version) = validate_migration_plan(&plan)?;
    let db = open_storage(storage_path)?;

    let mut rolled_back = 0usize;
    let mut skipped = 0usize;

    let mut errors = 0usize;

    for entry in &plan.entries {
        if !entry.applied || entry.action == MigrationAction::Skip {
            skipped += 1;
            continue;
        }

        let old_lid = entry
            .old_lid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid source LID '{}': {e}", entry.old_lid))?;
        migration_source_record(&db, &old_lid, from_version).await?;

        if let Some(new_lid_str) = &entry.new_lid {
            let new_lid: keyrack_core::lid::Lid = match new_lid_str.parse() {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(lid = %new_lid_str, error = %e, "invalid migrated LID, skipping cleanup");
                    errors += 1;
                    continue;
                }
            };

            match db.get_key(&new_lid).await {
                Ok(record) => {
                    if record.canonicalization_version != to_version {
                        anyhow::bail!("migrated record {new_lid} canonicalization version disagrees with the plan");
                    }
                    let mut destroyed = record.clone();
                    destroyed.state = KeyState::Destroyed;
                    destroyed.occ_version += 1;
                    if let Err(e) = db.update_key(&destroyed).await {
                        tracing::error!(lid = %new_lid_str, error = %e, "failed to destroy migrated key copy");
                        errors += 1;
                        continue;
                    }
                    tracing::info!(lid = %new_lid_str, "marked migrated key copy as destroyed");
                }
                Err(e) => {
                    // An unreadable legacy/corrupt destination must not be
                    // mistaken for an already-cleaned-up record.
                    return Err(e.into());
                }
            }
        }

        let alias_name = format!("migration:{}", entry.old_lid);
        match db.delete_alias(&alias_name).await {
            Ok(()) => {
                tracing::info!(alias = %alias_name, "removed migration alias");
            }
            Err(e) => {
                tracing::warn!(alias = %alias_name, error = %e, "failed to remove alias");
            }
        }

        rolled_back += 1;
    }

    eprintln!("migration rollback: {rolled_back} rolled back, {skipped} skipped, {errors} errors");
    if errors > 0 {
        anyhow::bail!("{errors} key(s) failed during rollback");
    }
    Ok(())
}

// ── Rule-change migration ───────────────────────────────────────────

/// A rule-change migration plan entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RuleChangeEntry {
    key_lid: String,
    old_parent_lid: Option<String>,
    new_parent_lid: Option<String>,
    action: RuleChangeAction,
    applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum RuleChangeAction {
    Rewrap,
    OptOut,
    Skip,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RuleChangePlan {
    old_rules_hash: String,
    new_rules_hash: String,
    entries: Vec<RuleChangeEntry>,
    created_at: String,
    resumable: bool,
}

async fn plan_rule_change(
    old_rules: &std::path::Path,
    new_rules: &std::path::Path,
    output: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let old_yaml = std::fs::read_to_string(old_rules)
        .map_err(|e| anyhow::anyhow!("cannot read old rules: {e}"))?;
    let new_yaml = std::fs::read_to_string(new_rules)
        .map_err(|e| anyhow::anyhow!("cannot read new rules: {e}"))?;

    let old_hash = blake3::hash(old_yaml.as_bytes()).to_hex().to_string();
    let new_hash = blake3::hash(new_yaml.as_bytes()).to_hex().to_string();

    if old_hash == new_hash {
        anyhow::bail!("old and new rules are identical (same BLAKE3 hash)");
    }

    let old_registry = keyrack_core::rule::RuleRegistry::from_yaml(&old_yaml)
        .map_err(|e| anyhow::anyhow!("invalid old rules YAML: {e}"))?;
    let new_registry = keyrack_core::rule::RuleRegistry::from_yaml(&new_yaml)
        .map_err(|e| anyhow::anyhow!("invalid new rules YAML: {e}"))?;

    let db = open_storage(storage_path)?;

    let all_keys = list_all_keys(&db).await?;

    let mut entries = Vec::new();

    for record in &all_keys {
        let attrs = record.identity_tags.as_map();

        let old_parent = old_registry
            .match_rule(attrs)
            .and_then(|m| m.rule.resolve_parent(&m.bindings));
        let new_parent = new_registry
            .match_rule(attrs)
            .and_then(|m| m.rule.resolve_parent(&m.bindings));

        if old_parent == new_parent {
            entries.push(RuleChangeEntry {
                key_lid: record.lid.to_string(),
                old_parent_lid: record
                    .parent_lid
                    .as_ref()
                    .map(std::string::ToString::to_string),
                new_parent_lid: record
                    .parent_lid
                    .as_ref()
                    .map(std::string::ToString::to_string),
                action: RuleChangeAction::Skip,
                applied: false,
            });
        } else {
            entries.push(RuleChangeEntry {
                key_lid: record.lid.to_string(),
                old_parent_lid: record
                    .parent_lid
                    .as_ref()
                    .map(std::string::ToString::to_string),
                new_parent_lid: None, // Computed at apply time from new rules
                action: RuleChangeAction::Rewrap,
                applied: false,
            });
        }
    }

    let rewrap_count = entries
        .iter()
        .filter(|e| e.action == RuleChangeAction::Rewrap)
        .count();
    let skip_count = entries.len() - rewrap_count;

    let plan = RuleChangePlan {
        old_rules_hash: old_hash,
        new_rules_hash: new_hash,
        entries,
        created_at: chrono::Utc::now().to_rfc3339(),
        resumable: true,
    };

    let json = serde_json::to_string_pretty(&plan)?;
    std::fs::write(output, &json)?;

    eprintln!(
        "rule-change plan written to {}: {} key(s) to rewrap, {} unchanged",
        output.display(),
        rewrap_count,
        skip_count,
    );

    Ok(())
}

async fn apply_rule_change(
    plan_file: &std::path::Path,
    new_rules_path: &std::path::Path,
    storage_path: &str,
    batch_size: usize,
    opt_out: bool,
) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let mut plan: RuleChangePlan = serde_json::from_str(&plan_json)?;

    let new_yaml = std::fs::read_to_string(new_rules_path)
        .map_err(|e| anyhow::anyhow!("cannot read new rules: {e}"))?;
    let new_hash = blake3::hash(new_yaml.as_bytes()).to_hex().to_string();
    if new_hash != plan.new_rules_hash {
        anyhow::bail!(
            "new rules file hash ({new_hash}) does not match plan hash ({}); \
             use the same YAML that was used to create this plan",
            plan.new_rules_hash,
        );
    }
    let new_registry = keyrack_core::rule::RuleRegistry::from_yaml(&new_yaml)
        .map_err(|e| anyhow::anyhow!("invalid new rules YAML: {e}"))?;
    let resolver_config = keyrack_core::resolver::ResolverConfig::default();

    let db = open_storage(storage_path)?;

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut opted_out = 0usize;
    let mut errors = 0usize;
    let mut batch_count = 0usize;

    for i in 0..plan.entries.len() {
        if plan.entries[i].applied || plan.entries[i].action == RuleChangeAction::Skip {
            skipped += 1;
            continue;
        }

        if opt_out {
            plan.entries[i].action = RuleChangeAction::OptOut;
            plan.entries[i].applied = true;
            opted_out += 1;
            continue;
        }

        let key_lid: keyrack_core::lid::Lid = plan.entries[i]
            .key_lid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid LID '{}': {e}", plan.entries[i].key_lid))?;

        let record = match db.get_key(&key_lid).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(lid = %plan.entries[i].key_lid, error = %e, "key not found");
                errors += 1;
                continue;
            }
        };

        // Resolve the new parent LID from the new rules
        let attrs = record.identity_tags.as_map();
        let new_parent_lid =
            match keyrack_core::resolver::resolve_chain(&new_registry, attrs, &resolver_config) {
                Ok(chain) if chain.len() >= 2 => Some(chain[1]),
                _ => None,
            };

        let new_parent_str = new_parent_lid
            .as_ref()
            .map(std::string::ToString::to_string);

        // TODO(crypto): This only updates `parent_lid` metadata in the
        // database. A full rule-change migration must also rewrap the key
        // material under the new parent's wrapping key, which requires a
        // CryptoProvider. The CLI currently only has direct storage access;
        // cryptographic rewrap will be wired once the CLI gains gRPC client
        // support to keyrack-service (which owns the CryptoProvider).
        let mut updated = record.clone();
        updated.parent_lid = new_parent_lid;
        updated.occ_version += 1;

        if let Err(e) = db.update_key(&updated).await {
            tracing::error!(lid = %plan.entries[i].key_lid, error = %e, "failed to update parent");
            errors += 1;
            continue;
        }

        plan.entries[i].new_parent_lid = new_parent_str;
        plan.entries[i].applied = true;
        applied += 1;
        batch_count += 1;

        if batch_count >= batch_size {
            let checkpoint_json = serde_json::to_string_pretty(&plan)?;
            std::fs::write(plan_file, &checkpoint_json)?;
            tracing::info!(applied, "checkpoint saved");
            batch_count = 0;
        }
    }

    let final_json = serde_json::to_string_pretty(&plan)?;
    std::fs::write(plan_file, &final_json)?;

    eprintln!(
        "rule-change apply: {applied} rewrapped, {opted_out} opted-out, {skipped} skipped, {errors} errors"
    );
    if errors > 0 {
        anyhow::bail!("{errors} key(s) failed during rule-change migration (plan is resumable)");
    }
    Ok(())
}

async fn rollback_rule_change(
    plan_file: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let plan: RuleChangePlan = serde_json::from_str(&plan_json)?;

    let db = open_storage(storage_path)?;

    let mut rolled_back = 0usize;
    let mut skipped = 0usize;

    for entry in &plan.entries {
        if !entry.applied || entry.action != RuleChangeAction::Rewrap {
            skipped += 1;
            continue;
        }

        let key_lid: keyrack_core::lid::Lid = if let Ok(l) = entry.key_lid.parse() {
            l
        } else {
            skipped += 1;
            continue;
        };

        let record = match db.get_key(&key_lid).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(lid = %entry.key_lid, error = %e, "key not found for rollback");
                skipped += 1;
                continue;
            }
        };

        let old_parent_lid = entry.old_parent_lid.as_ref().and_then(|s| s.parse().ok());
        let mut reverted = record.clone();
        reverted.parent_lid = old_parent_lid;
        reverted.occ_version += 1;

        if let Err(e) = db.update_key(&reverted).await {
            tracing::error!(lid = %entry.key_lid, error = %e, "rollback failed");
        } else {
            rolled_back += 1;
        }
    }

    eprintln!("rule-change rollback: {rolled_back} reverted, {skipped} skipped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "keyrack-migration-version-test-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn plan(from: u32, to: u32, entries: Vec<MigrationEntry>) -> MigrationPlan {
        MigrationPlan {
            from_canonicalization: from,
            to_canonicalization: to,
            entries,
            created_at: "2026-09-07T00:00:00Z".into(),
        }
    }

    fn entry(from: u32, to: u32, action: MigrationAction, applied: bool) -> MigrationEntry {
        MigrationEntry {
            old_lid: keyrack_core::lid::Lid::from_bytes([0x41; 32]).to_string(),
            new_lid: Some(keyrack_core::lid::Lid::from_bytes([0x42; 32]).to_string()),
            from_version: from,
            to_version: to,
            action,
            applied,
        }
    }

    fn invalid_plans() -> Vec<(MigrationPlan, &'static str)> {
        let mut cases = vec![
            (plan(1, 2, vec![]), "unknown canonicalization version: 1"),
            (plan(2, 1, vec![]), "unknown canonicalization version: 1"),
            (plan(2, 2, vec![]), "versions are the same"),
        ];
        for action in [MigrationAction::RederiveLid, MigrationAction::Skip] {
            for applied in [false, true] {
                cases.push((
                    plan(1, 2, vec![entry(1, 2, action, applied)]),
                    "unknown canonicalization version: 1",
                ));
                // Hide obsolete versions in a plan with supported headers.
                // Skipped and already-applied checkpoints still need validation.
                cases.push((
                    plan(2, 2, vec![entry(1, 2, action, applied)]),
                    "unknown canonicalization version: 1",
                ));
                cases.push((
                    plan(2, 2, vec![entry(2, 1, action, applied)]),
                    "unknown canonicalization version: 1",
                ));
                cases.push((
                    plan(2, 2, vec![entry(2, 2, action, applied)]),
                    "versions are the same",
                ));
            }
        }
        cases
    }

    #[tokio::test]
    async fn invalid_migration_versions_never_open_storage_or_rewrite_plans() {
        for (plan, expected_error) in invalid_plans() {
            for rollback in [false, true] {
                let scratch = Scratch::new();
                let plan_path = scratch.0.join("plan.json");
                let database_path = scratch.0.join("must-not-exist.sqlite");
                let original = serde_json::to_string(&plan).unwrap();
                std::fs::write(&plan_path, &original).unwrap();
                let storage = database_path.to_str().unwrap();
                let result = if rollback {
                    rollback_migration(&plan_path, storage).await
                } else {
                    apply_migration(&plan_path, storage).await
                };
                let error = result.unwrap_err().to_string();
                assert!(error.contains(expected_error), "{error}");
                assert!(!database_path.exists(), "validation opened SQLite");
                assert_eq!(std::fs::read_to_string(&plan_path).unwrap(), original);
                assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
            }
        }
    }

    #[tokio::test]
    async fn rejected_legacy_rollback_preserves_existing_alias_and_database_bytes() {
        for (from, entry_from) in [(1, 1), (2, 1), (2, 2)] {
            let scratch = Scratch::new();
            let plan_path = scratch.0.join("plan.json");
            let database_path = scratch.0.join("existing.sqlite");
            let migration_entry = entry(entry_from, 2, MigrationAction::RederiveLid, true);
            let alias_name = format!("migration:{}", migration_entry.old_lid);
            let target = migration_entry.new_lid.as_ref().unwrap().parse().unwrap();
            let original_plan =
                serde_json::to_string(&plan(from, 2, vec![migration_entry])).unwrap();
            std::fs::write(&plan_path, &original_plan).unwrap();
            let db = open_storage(database_path.to_str().unwrap()).unwrap();
            db.create_alias(&keyrack_core::storage::AliasRecord {
                alias_name: alias_name.clone(),
                target_lid: target,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
            drop(db);
            let original_database = std::fs::read(&database_path).unwrap();

            assert!(
                rollback_migration(&plan_path, database_path.to_str().unwrap())
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&database_path).unwrap(), original_database);
            assert_eq!(std::fs::read_to_string(&plan_path).unwrap(), original_plan);
            let db = open_storage(database_path.to_str().unwrap()).unwrap();
            assert_eq!(db.resolve_alias(&alias_name).await.unwrap(), target);
        }
    }
}
