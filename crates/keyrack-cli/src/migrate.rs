// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1

use clap::{Args, Subcommand};
use keyrack_core::migration::{
    self, MigrationAction, MigrationEntry, MigrationPlan,
};
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
        /// Source canonicalization version (e.g. v1).
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
        MigrateCommand::Apply { plan_file, storage } => {
            apply_migration(&plan_file, &storage).await
        }
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

async fn plan_migration(
    from_str: &str,
    to_str: &str,
    output: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let from_version = migration::parse_canon_version(from_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let to_version = migration::parse_canon_version(to_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if from_version == to_version {
        anyhow::bail!("source and target canonicalization versions are the same");
    }

    let db = open_storage(storage_path)?;

    let filter = KeyFilter::default();
    let page = db.list_keys(&filter).await
        .map_err(|e| anyhow::anyhow!("failed to list keys: {e}"))?;

    let mut entries = Vec::new();

    for record in &page.items {
        if record.canonicalization_version == from_version {
            let new_lid = migration::rederive_lid(
                &record.lid,
                &record.identity_tags,
                to_version,
            );
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

    let actionable = plan.entries.iter().filter(|e| e.action == MigrationAction::RederiveLid).count();
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

#[allow(clippy::too_many_lines)]
async fn apply_migration(
    plan_file: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let mut plan: MigrationPlan = serde_json::from_str(&plan_json)?;

    let to_version = migration::parse_canon_version(&format!("v{}", plan.to_canonicalization))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let db = open_storage(storage_path)?;

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    for entry in &mut plan.entries {
        if entry.applied || entry.action == MigrationAction::Skip {
            skipped += 1;
            continue;
        }

        let old_lid: keyrack_core::lid::Lid = entry.old_lid.parse()
            .map_err(|e| anyhow::anyhow!("invalid LID '{}': {e}", entry.old_lid))?;

        let record = match db.get_key(&old_lid).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(lid = %entry.old_lid, error = %e, "key not found");
                errors += 1;
                continue;
            }
        };

        let new_lid = migration::rederive_lid(&record.lid, &record.identity_tags, to_version);
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

async fn rollback_migration(
    plan_file: &std::path::Path,
    storage_path: &str,
) -> anyhow::Result<()> {
    let plan_json = std::fs::read_to_string(plan_file)
        .map_err(|e| anyhow::anyhow!("cannot read plan file: {e}"))?;
    let plan: MigrationPlan = serde_json::from_str(&plan_json)?;

    let db = open_storage(storage_path)?;

    let mut rolled_back = 0usize;
    let mut skipped = 0usize;

    for entry in &plan.entries {
        if !entry.applied || entry.action == MigrationAction::Skip {
            skipped += 1;
            continue;
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

    eprintln!("migration rollback: {rolled_back} rolled back, {skipped} skipped");
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
    let filter = KeyFilter::default();
    let page = db.list_keys(&filter).await
        .map_err(|e| anyhow::anyhow!("failed to list keys: {e}"))?;

    let mut entries = Vec::new();

    for record in &page.items {
        let attrs = record.identity_tags.as_map();

        let old_parent = old_registry.match_rule(attrs)
            .and_then(|m| m.rule.resolve_parent(&m.bindings));
        let new_parent = new_registry.match_rule(attrs)
            .and_then(|m| m.rule.resolve_parent(&m.bindings));

        if old_parent != new_parent {
            entries.push(RuleChangeEntry {
                key_lid: record.lid.to_string(),
                old_parent_lid: record.parent_lid.as_ref().map(|l| l.to_string()),
                new_parent_lid: None, // Computed at apply time from new rules
                action: RuleChangeAction::Rewrap,
                applied: false,
            });
        } else {
            entries.push(RuleChangeEntry {
                key_lid: record.lid.to_string(),
                old_parent_lid: record.parent_lid.as_ref().map(|l| l.to_string()),
                new_parent_lid: record.parent_lid.as_ref().map(|l| l.to_string()),
                action: RuleChangeAction::Skip,
                applied: false,
            });
        }
    }

    let rewrap_count = entries.iter().filter(|e| e.action == RuleChangeAction::Rewrap).count();
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

        let key_lid: keyrack_core::lid::Lid = plan.entries[i].key_lid.parse()
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
        let new_parent_lid = match keyrack_core::resolver::resolve_chain(
            &new_registry,
            attrs,
            &resolver_config,
        ) {
            Ok(chain) if chain.len() >= 2 => {
                Some(chain[1].clone())
            }
            _ => None,
        };

        let new_parent_str = new_parent_lid.as_ref().map(|l| l.to_string());

        let mut updated = record.clone();
        updated.parent_lid = new_parent_lid;
        updated.occ_version += 1;

        if let Err(e) = db.update_key(&updated).await {
            tracing::error!(lid = %plan.entries[i].key_lid, error = %e, "failed to rewrap");
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

        let key_lid: keyrack_core::lid::Lid = match entry.key_lid.parse() {
            Ok(l) => l,
            Err(_) => {
                skipped += 1;
                continue;
            }
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
