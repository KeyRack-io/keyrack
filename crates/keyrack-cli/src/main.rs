// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

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
