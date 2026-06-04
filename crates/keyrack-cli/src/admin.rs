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
use keyrack_core::rule::RuleRegistry;
use keyrack_service::proto::key_service_client::KeyServiceClient;
use keyrack_service::proto::{DescribeKeyRequest, DisableKeyRequest, RotateKeyRequest};

#[derive(Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Inspect a key record by LID.
    InspectKey {
        /// The Logical ID of the key.
        lid: String,

        /// gRPC endpoint.
        #[arg(long, default_value = "http://localhost:9090")]
        endpoint: String,

        /// Output format.
        #[arg(long, default_value = "human")]
        format: super::lint::OutputFormat,
    },

    /// Display parsed rules and specificity for a namespace YAML.
    InspectNamespace {
        /// Namespace name to inspect.
        name: String,

        /// Path to the namespace YAML file.
        #[arg(short, long)]
        file: std::path::PathBuf,

        /// Output format.
        #[arg(long, default_value = "human")]
        format: super::lint::OutputFormat,
    },

    /// Query audit log JSONL files.
    AuditQuery {
        /// Filter by action (e.g. Encrypt).
        #[arg(long)]
        action: Option<String>,

        /// Filter by time window (e.g. 1h, 30m, 7d).
        #[arg(long)]
        since: Option<String>,

        /// Filter by principal ID.
        #[arg(long)]
        principal: Option<String>,

        /// Path to the JSONL audit log.
        #[arg(long)]
        log_file: std::path::PathBuf,

        /// Output format.
        #[arg(long, default_value = "human")]
        format: super::lint::OutputFormat,
    },

    /// Rotate a key by LID.
    Rotate {
        /// The Logical ID of the key to rotate.
        lid: String,

        /// gRPC endpoint.
        #[arg(long, default_value = "http://localhost:9090")]
        endpoint: String,
    },

    /// Cascade-disable a root key and all descendants.
    CascadeDisable {
        /// The Logical ID of the root key.
        root_lid: String,

        /// gRPC endpoint.
        #[arg(long, default_value = "http://localhost:9090")]
        endpoint: String,
    },
}

pub async fn run(args: AdminArgs) -> anyhow::Result<()> {
    match args.command {
        AdminCommand::InspectKey {
            lid,
            endpoint,
            format,
        } => inspect_key(&lid, &endpoint, &format).await,
        AdminCommand::InspectNamespace { name, file, format } => {
            inspect_namespace(&name, &file, &format)
        }
        AdminCommand::AuditQuery {
            action,
            since,
            principal,
            log_file,
            format,
        } => audit_query(
            action.as_deref(),
            since.as_deref(),
            principal.as_deref(),
            &log_file,
            &format,
        ),
        AdminCommand::Rotate { lid, endpoint } => rotate_key(&lid, &endpoint).await,
        AdminCommand::CascadeDisable { root_lid, endpoint } => {
            cascade_disable(&root_lid, &endpoint).await
        }
    }
}

async fn inspect_key(
    lid: &str,
    endpoint: &str,
    format: &super::lint::OutputFormat,
) -> anyhow::Result<()> {
    let mut client = KeyServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to {endpoint}: {e}"))?;

    let resp = client
        .describe_key(tonic::Request::new(DescribeKeyRequest {
            key_id: lid.to_string(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("DescribeKey failed: {e}"))?;

    let meta = resp
        .into_inner()
        .metadata
        .ok_or_else(|| anyhow::anyhow!("no metadata in response"))?;

    match format {
        super::lint::OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&format_key_metadata(&meta))?
            );
        }
        super::lint::OutputFormat::Human => {
            let m = format_key_metadata(&meta);
            println!("Key: {}", meta.key_id);
            println!(
                "  Spec:        {:?}",
                keyrack_service::proto::KeySpec::try_from(meta.key_spec)
                    .unwrap_or(keyrack_service::proto::KeySpec::Unspecified)
            );
            println!(
                "  Usage:       {:?}",
                keyrack_service::proto::KeyUsage::try_from(meta.key_usage)
                    .unwrap_or(keyrack_service::proto::KeyUsage::Unspecified)
            );
            println!(
                "  State:       {:?}",
                keyrack_service::proto::KeyState::try_from(meta.state)
                    .unwrap_or(keyrack_service::proto::KeyState::Unspecified)
            );
            println!(
                "  Origin:      {:?}",
                keyrack_service::proto::KeyOrigin::try_from(meta.origin)
                    .unwrap_or(keyrack_service::proto::KeyOrigin::Unspecified)
            );
            println!("  Description: {}", meta.description);
            println!("  Version:     {}", meta.current_key_version);
            println!("  OCC:         {}", meta.occ_version);
            if let Some(parent) = &meta.parent_key_id {
                println!("  Parent:      {parent}");
            }
            if let Some(hsm) = &meta.hsm_connection_id {
                println!("  HSM Conn:    {hsm}");
            }
            if !meta.user_tags.is_empty() {
                println!("  Tags:");
                for (k, v) in &meta.user_tags {
                    println!("    {k}: {v}");
                }
            }
            if let Some(ts) = m.get("created_at") {
                println!("  Created:     {ts}");
            }
        }
    }
    Ok(())
}

fn format_key_metadata(meta: &keyrack_service::proto::KeyMetadata) -> serde_json::Value {
    serde_json::json!({
        "key_id": meta.key_id,
        "key_spec": meta.key_spec,
        "key_usage": meta.key_usage,
        "state": meta.state,
        "origin": meta.origin,
        "description": meta.description,
        "current_key_version": meta.current_key_version,
        "occ_version": meta.occ_version,
        "parent_key_id": meta.parent_key_id,
        "hsm_connection_id": meta.hsm_connection_id,
        "user_tags": meta.user_tags,
        "created_at": meta.created_at.as_ref().map(|ts| {
            chrono::DateTime::from_timestamp(ts.seconds, ts.nanos.try_into().unwrap_or(0))
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default()
        }),
    })
}

fn inspect_namespace(
    name: &str,
    file: &std::path::Path,
    format: &super::lint::OutputFormat,
) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", file.display()))?;
    let registry = RuleRegistry::from_yaml(&yaml)
        .map_err(|e| anyhow::anyhow!("invalid namespace YAML: {e}"))?;

    let ns = registry
        .get_namespace(name)
        .ok_or_else(|| anyhow::anyhow!("namespace '{name}' not found in file"))?;

    match format {
        super::lint::OutputFormat::Json => {
            let rules_json: Vec<serde_json::Value> = ns.routing_rules.iter().enumerate().map(|(i, rule)| {
                let spec = rule.specificity();
                serde_json::json!({
                    "index": i,
                    "match_pattern": rule.match_pattern,
                    "parent": format!("{:?}", rule.parent),
                    "priority": rule.priority,
                    "specificity": { "concrete": spec.concrete_count, "variable": spec.variable_count },
                    "key_spec": rule.key_spec.as_ref().map(|ks| format!("{ks:?}")),
                })
            }).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": ns.name,
                    "max_depth": ns.max_depth,
                    "attachment": ns.attachment,
                    "rules": rules_json,
                }))?
            );
        }
        super::lint::OutputFormat::Human => {
            println!("Namespace: {}", ns.name);
            println!("  Max depth:  {}", ns.max_depth);
            if let Some(ref att) = ns.attachment {
                println!("  Attachment: {att:?}");
            }
            println!("  Rules ({}):", ns.routing_rules.len());
            for (i, rule) in ns.routing_rules.iter().enumerate() {
                let spec = rule.specificity();
                println!(
                    "    [{i}] match={:?}  parent={:?}  priority={}  specificity=({},{})",
                    rule.match_pattern,
                    rule.parent,
                    rule.priority,
                    spec.concrete_count,
                    spec.variable_count
                );
            }
        }
    }
    Ok(())
}

fn audit_query(
    action_filter: Option<&str>,
    since_filter: Option<&str>,
    principal_filter: Option<&str>,
    log_file: &std::path::Path,
    format: &super::lint::OutputFormat,
) -> anyhow::Result<()> {
    let since_cutoff = if let Some(since) = since_filter {
        Some(parse_duration_ago(since)?)
    } else {
        None
    };

    let file = std::fs::File::open(log_file)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", log_file.display()))?;
    let reader = std::io::BufReader::new(file);

    let mut count = 0u64;
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| anyhow::anyhow!("malformed JSONL line: {e}"))?;

        if let Some(action) = action_filter {
            let event_action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
            if !event_action.contains(action) {
                continue;
            }
        }

        if let Some(principal) = principal_filter {
            let p_id = event
                .get("principal")
                .and_then(|p| p.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !p_id.contains(principal) {
                continue;
            }
        }

        if let Some(cutoff) = since_cutoff {
            let ts_str = event
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                if ts.with_timezone(&chrono::Utc) < cutoff {
                    continue;
                }
            }
        }

        match format {
            super::lint::OutputFormat::Json => {
                println!("{}", serde_json::to_string(&event)?);
            }
            super::lint::OutputFormat::Human => {
                let ts = event
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                let result = event.get("result").and_then(|v| v.as_str()).unwrap_or("?");
                let principal = event
                    .get("principal")
                    .and_then(|p| p.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let resource = event
                    .get("resource")
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!(
                    "{ts}  {action:<30}  {result:<8}  principal={principal}  resource={resource}"
                );
            }
        }
        count += 1;
    }

    eprintln!("{count} event(s) matched");
    Ok(())
}

fn parse_duration_ago(s: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    let s = s.trim();
    let (num_str, unit) = s.split_at(s.len().saturating_sub(1));
    let num: i64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration: {s} — expected format like 1h, 30m, 7d"))?;
    let duration = match unit {
        "s" => chrono::TimeDelta::seconds(num),
        "m" => chrono::TimeDelta::minutes(num),
        "h" => chrono::TimeDelta::hours(num),
        "d" => chrono::TimeDelta::days(num),
        _ => anyhow::bail!("unsupported duration unit '{unit}' — use s, m, h, or d"),
    };
    Ok(chrono::Utc::now() - duration)
}

async fn rotate_key(lid: &str, endpoint: &str) -> anyhow::Result<()> {
    let mut client = KeyServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to {endpoint}: {e}"))?;

    let resp = client
        .rotate_key(tonic::Request::new(RotateKeyRequest {
            key_id: lid.to_string(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("RotateKey failed: {e}"))?;

    let inner = resp.into_inner();
    println!("rotated key {lid} → new version {}", inner.new_version);
    Ok(())
}

async fn cascade_disable(root_lid: &str, endpoint: &str) -> anyhow::Result<()> {
    let mut client = KeyServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to {endpoint}: {e}"))?;

    let resp = client
        .disable_key(tonic::Request::new(DisableKeyRequest {
            key_id: root_lid.to_string(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("DisableKey failed: {e}"))?;

    let meta = resp.into_inner().metadata;
    if let Some(m) = meta {
        println!(
            "disabled key {} (state: {:?})",
            m.key_id,
            keyrack_service::proto::KeyState::try_from(m.state)
                .unwrap_or(keyrack_service::proto::KeyState::Unspecified)
        );
    } else {
        println!("disabled key {root_lid}");
    }
    eprintln!("note: cascade disable is orchestrated server-side");
    Ok(())
}
