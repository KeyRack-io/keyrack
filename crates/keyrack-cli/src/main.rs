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

//! `keyrack` — CLI tools for namespace linting, key provisioning,
//! administration, and migration.

#![forbid(unsafe_code)]

mod admin;
mod lint;
mod migrate;
mod provision;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "keyrack",
    about = "KeyRack CLI — lint, provision, admin, migrate",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a namespace YAML file offline.
    Lint(lint::LintArgs),

    /// Eagerly provision keys for a set of attribute inputs.
    Provision(provision::ProvisionArgs),

    /// Administrative queries and manual operations.
    Admin(admin::AdminArgs),

    /// Canonicalization migration utilities.
    Migrate(migrate::MigrateArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Lint(args) => lint::run(args),
        Commands::Provision(args) => provision::run(args).await,
        Commands::Admin(args) => admin::run(args).await,
        Commands::Migrate(args) => migrate::run(args).await,
    }
}
