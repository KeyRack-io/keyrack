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

//! PostgreSQL conformance tests — require a live database.
//!
//! Enable with: `cargo test -p keyrack-postgres --features live-tests`
//!
//! Env var: `DATABASE_URL=postgres://user:pass@host/db`

#![cfg(feature = "live-tests")]

use keyrack_postgres::PostgresStorage;

async fn make_store() -> PostgresStorage {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for live PostgreSQL tests");
    PostgresStorage::connect(&url)
        .await
        .expect("failed to connect to PostgreSQL")
}

keyrack_test_support::storage_conformance_tests!(make_store().await);
