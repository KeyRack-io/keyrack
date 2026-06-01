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
use keyrack_core::lint::{self, Severity};
use keyrack_core::rule::RuleRegistry;
use std::path::PathBuf;

#[derive(Args)]
pub struct LintArgs {
    /// Path to the namespace YAML file.
    #[arg(short, long)]
    pub file: PathBuf,

    /// Output format: human (default) or json.
    #[arg(long, default_value = "human")]
    pub format: OutputFormat,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[allow(clippy::needless_pass_by_value)]
pub fn run(args: LintArgs) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(&args.file)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", args.file.display()))?;

    let registry = match RuleRegistry::from_yaml(&yaml) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fatal: namespace file is invalid: {e}");
            std::process::exit(2);
        }
    };

    let diags = lint::lint(&registry);

    match args.format {
        OutputFormat::Human => {
            for d in &diags {
                let color = match d.severity {
                    Severity::Error => "\x1b[31m",
                    Severity::Warning => "\x1b[33m",
                    Severity::Info => "\x1b[36m",
                };
                eprintln!("{color}{d}\x1b[0m");
            }
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&diags)
                    .unwrap_or_else(|_| "[]".into())
            );
        }
    }

    let has_errors = diags.iter().any(|d| d.severity == Severity::Error);
    let has_warnings = diags.iter().any(|d| d.severity == Severity::Warning);

    if has_errors {
        std::process::exit(2);
    } else if has_warnings {
        std::process::exit(1);
    }

    if diags.is_empty() {
        eprintln!(
            "✓ {} namespace(s) validated, no issues found.",
            registry.namespaces().len()
        );
    }

    Ok(())
}
