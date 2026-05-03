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
