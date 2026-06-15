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

use clap::Args;
use keyrack_core::resolver::{resolve_chain, ResolverConfig};
use keyrack_core::rule::RuleRegistry;
use keyrack_service::proto::key_service_client::KeyServiceClient;
use keyrack_service::proto::{CreateKeyRequest, GetKeyRequest, KeySpec};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

#[derive(Args)]
pub struct ProvisionArgs {
    /// Namespace to provision keys for.
    #[arg(long)]
    pub namespace: String,

    /// Path to the namespace YAML file (for offline resolution).
    #[arg(long)]
    pub namespace_file: PathBuf,

    /// Path to CSV or JSON input file containing attribute sets.
    #[arg(long)]
    pub inputs: PathBuf,

    /// gRPC endpoint of the keyrack service.
    #[arg(long, default_value = "http://localhost:9090")]
    pub endpoint: String,

    /// Number of concurrent gRPC calls.
    #[arg(long, default_value = "4")]
    pub parallelism: usize,

    /// Show what would be created without calling `CreateKey`.
    #[arg(long)]
    pub dry_run: bool,

    /// Resume from a previous progress checkpoint.
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// Output format: human (default) or json.
    #[arg(long, default_value = "human")]
    pub format: super::lint::OutputFormat,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Checkpoint {
    completed_lids: HashSet<String>,
}

#[allow(clippy::too_many_lines)]
pub async fn run(args: ProvisionArgs) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(&args.namespace_file)
        .map_err(|e| anyhow::anyhow!("cannot read namespace file: {e}"))?;
    let registry = RuleRegistry::from_yaml(&yaml)
        .map_err(|e| anyhow::anyhow!("invalid namespace YAML: {e}"))?;

    let rows = load_inputs(&args.inputs)?;
    if rows.is_empty() {
        eprintln!("no input rows found");
        return Ok(());
    }
    eprintln!("loaded {} input row(s)", rows.len());

    let config = ResolverConfig::default();

    let mut all_lids: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    let mut seen = HashSet::new();

    for (i, attrs) in rows.iter().enumerate() {
        let chain = resolve_chain(&registry, attrs, &config)
            .map_err(|e| anyhow::anyhow!("row {i}: resolution failed: {e}"))?;
        for lid in chain {
            let lid_str = lid.to_string();
            if seen.insert(lid_str.clone()) {
                all_lids.push((lid_str, attrs.clone()));
            }
        }
    }

    eprintln!("{} unique LID(s) to provision", all_lids.len());

    let mut checkpoint = if let Some(ref path) = args.resume {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str::<Checkpoint>(&data)?
        } else {
            Checkpoint {
                completed_lids: HashSet::new(),
            }
        }
    } else {
        Checkpoint {
            completed_lids: HashSet::new(),
        }
    };

    let pending: Vec<_> = all_lids
        .iter()
        .filter(|(lid, _)| !checkpoint.completed_lids.contains(lid))
        .collect();

    eprintln!("{} LID(s) remaining after checkpoint", pending.len());

    if args.dry_run {
        for (lid, attrs) in &pending {
            match args.format {
                super::lint::OutputFormat::Human => {
                    eprintln!("  [dry-run] would provision LID {lid} (attrs: {attrs:?})");
                }
                super::lint::OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "action": "create",
                            "lid": lid,
                            "attributes": attrs,
                        })
                    );
                }
            }
        }
        eprintln!(
            "dry-run complete: {} key(s) would be created",
            pending.len()
        );
        return Ok(());
    }

    let mut client = KeyServiceClient::connect(args.endpoint.clone())
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to {}: {e}", args.endpoint))?;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(args.parallelism));
    let checkpoint_path = args.resume.clone();
    let completed = std::sync::Arc::new(tokio::sync::Mutex::new(checkpoint.completed_lids.clone()));

    let mut created = 0usize;
    let mut skipped = 0usize;

    for (lid, attrs) in &pending {
        let _permit = semaphore.acquire().await?;

        let get_resp = client
            .get_key(tonic::Request::new(GetKeyRequest {
                key_id: lid.clone(),
            }))
            .await;

        if get_resp.is_ok() {
            skipped += 1;
            let mut locked = completed.lock().await;
            locked.insert(lid.clone());
            tracing::info!(lid = %lid, "key already exists, skipping");
            continue;
        }

        let create_resp = client
            .create_key(tonic::Request::new(CreateKeyRequest {
                key_spec: KeySpec::Aes256.into(),
                key_usage: Some(1),
                description: format!("provisioned by keyrack-cli for {}", args.namespace),
                tags: std::collections::HashMap::default(),
                parent_key_id: None,
                hsm_connection_id: None,
                attributes: attrs.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                namespace: Some(args.namespace.clone()),
            }))
            .await;

        match create_resp {
            Ok(resp) => {
                created += 1;
                let key_id = resp
                    .into_inner()
                    .metadata
                    .map(|m| m.key_id)
                    .unwrap_or_default();
                tracing::info!(lid = %lid, key_id = %key_id, "key provisioned");
            }
            Err(e) => {
                tracing::error!(lid = %lid, error = %e, "failed to create key");
                if let Some(ref cp) = checkpoint_path {
                    let locked = completed.lock().await;
                    checkpoint.completed_lids.clone_from(&locked);
                    let data = serde_json::to_string_pretty(&checkpoint)?;
                    std::fs::write(cp, data)?;
                    eprintln!("checkpoint saved to {}", cp.display());
                }
                return Err(anyhow::anyhow!("provision failed at LID {lid}: {e}"));
            }
        }

        let mut locked = completed.lock().await;
        locked.insert(lid.clone());
    }

    if let Some(ref cp) = checkpoint_path {
        let locked = completed.lock().await;
        checkpoint.completed_lids.clone_from(&locked);
        let data = serde_json::to_string_pretty(&checkpoint)?;
        std::fs::write(cp, data)?;
    }

    eprintln!("provision complete: {created} created, {skipped} skipped (already existed)");
    Ok(())
}

fn load_inputs(path: &PathBuf) -> anyhow::Result<Vec<BTreeMap<String, String>>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "json" => {
            let data = std::fs::read_to_string(path)?;
            let rows: Vec<BTreeMap<String, String>> = serde_json::from_str(&data)?;
            Ok(rows)
        }
        "csv" => {
            let mut reader = csv::Reader::from_path(path)?;
            let headers: Vec<String> = reader.headers()?.iter().map(String::from).collect();

            let mut rows = Vec::new();
            for result in reader.records() {
                let record = result?;
                let mut map = BTreeMap::new();
                for (i, field) in record.iter().enumerate() {
                    if let Some(header) = headers.get(i) {
                        map.insert(header.clone(), field.to_string());
                    }
                }
                rows.push(map);
            }
            Ok(rows)
        }
        _ => anyhow::bail!("unsupported input format: expected .csv or .json, got .{ext}"),
    }
}
