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

//! `PostgreSQL` conformance tests — require a live database.
//!
//! Enable with: `cargo test -p keyrack-postgres --features live-tests`
//!
//! Env var: `DATABASE_URL=postgres://user:pass@host/db`

#![cfg(feature = "live-tests")]

use keyrack_postgres::PostgresStorage;

async fn make_store() -> PostgresStorage {
    let url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live PostgreSQL tests");
    PostgresStorage::connect(&url)
        .await
        .expect("failed to connect to PostgreSQL")
}

keyrack_test_support::storage_conformance_tests!(make_store().await);
