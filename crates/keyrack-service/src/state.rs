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

//! Shared application state injected into every gRPC handler.

use keyrack_core::audit::AuditSink;
use keyrack_core::pdp::PolicyDecisionPoint;
use keyrack_core::provider::CryptoProvider;
use keyrack_core::storage::StorageBackend;
use std::sync::Arc;

/// Shared state available to all RPC handlers.
///
/// Each field is trait-object-based so the service can be configured
/// with different backends (`SQLite` vs `Postgres`, Software vs PKCS#11, etc.)
/// at startup.
pub struct ServiceState {
    pub storage: Arc<dyn StorageBackend>,
    pub provider: Arc<dyn CryptoProvider>,
    pub pdp: Arc<dyn PolicyDecisionPoint>,
    pub audit: Arc<dyn AuditSink>,
}
