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
use keyrack_service::proto::key_service_client::KeyServiceClient;
use keyrack_service::proto::ExplainRoutingRequest;

#[derive(Args)]
pub struct RoutingArgs {
    #[command(subcommand)]
    pub command: RoutingCommand,
}

#[derive(Subcommand)]
pub enum RoutingCommand {
    /// Dry-run provider resolution: preview which backend would be selected
    /// for a given set of attributes and selectors, without creating a key.
    Explain {
        /// Key attributes as key=value pairs (repeatable).
        #[arg(short, long = "attr", value_parser = parse_key_val)]
        attributes: Vec<(String, String)>,

        /// Namespace.
        #[arg(long)]
        namespace: Option<String>,

        /// Explicit backend selector (`backend_id`).
        #[arg(long)]
        backend_id: Option<String>,

        /// Deprecated alias for `backend_id`.
        #[arg(long)]
        hsm_connection_id: Option<String>,

        /// gRPC endpoint.
        #[arg(long, default_value = "http://localhost:9090")]
        endpoint: String,

        /// Output format.
        #[arg(long, default_value = "human")]
        format: super::lint::OutputFormat,
    },
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid attribute (expected key=value): {s}"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

pub async fn run(args: RoutingArgs) -> anyhow::Result<()> {
    match args.command {
        RoutingCommand::Explain {
            attributes,
            namespace,
            backend_id,
            hsm_connection_id,
            endpoint,
            format,
        } => {
            explain(
                &attributes,
                namespace.as_deref(),
                backend_id.as_deref(),
                hsm_connection_id.as_deref(),
                &endpoint,
                &format,
            )
            .await
        }
    }
}

async fn explain(
    attributes: &[(String, String)],
    namespace: Option<&str>,
    backend_id: Option<&str>,
    hsm_connection_id: Option<&str>,
    endpoint: &str,
    format: &super::lint::OutputFormat,
) -> anyhow::Result<()> {
    let mut client = KeyServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| anyhow::anyhow!("cannot connect to {endpoint}: {e}"))?;

    let attrs: std::collections::HashMap<String, String> = attributes.iter().cloned().collect();

    let resp = client
        .explain_routing(tonic::Request::new(ExplainRoutingRequest {
            attributes: attrs,
            namespace: namespace.map(ToString::to_string),
            backend_id: backend_id.map(ToString::to_string),
            hsm_connection_id: hsm_connection_id.map(ToString::to_string),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("ExplainRouting failed: {e}"))?;

    let inner = resp.into_inner();
    let outcome_str = match keyrack_service::proto::RoutingOutcome::try_from(inner.outcome) {
        Ok(keyrack_service::proto::RoutingOutcome::Routed) => "ROUTED",
        Ok(keyrack_service::proto::RoutingOutcome::Delegated) => "DELEGATED",
        Ok(keyrack_service::proto::RoutingOutcome::Default) => "DEFAULT",
        Ok(keyrack_service::proto::RoutingOutcome::Denied) => "DENIED",
        Ok(keyrack_service::proto::RoutingOutcome::Clash) => "CLASH",
        _ => "UNKNOWN",
    };

    match format {
        super::lint::OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "outcome": outcome_str,
                    "selected_backend_id": inner.selected_backend_id,
                    "matched_rule_index": inner.matched_rule_index,
                    "deny_reason": inner.deny_reason,
                    "policy_configured": inner.policy_configured,
                }))?
            );
        }
        super::lint::OutputFormat::Human => {
            println!("Routing resolution (dry-run):");
            println!("  Outcome:          {outcome_str}");
            if !inner.selected_backend_id.is_empty() {
                println!("  Selected backend: {}", inner.selected_backend_id);
            }
            if inner.matched_rule_index >= 0 {
                println!("  Matched rule:     #{}", inner.matched_rule_index);
            } else {
                println!("  Matched rule:     (none — default)");
            }
            if !inner.deny_reason.is_empty() {
                println!("  Deny reason:      {}", inner.deny_reason);
            }
            println!(
                "  Policy configured: {}",
                if inner.policy_configured { "yes" } else { "no" }
            );
        }
    }
    Ok(())
}
