// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use keyrack_core::storage::StorageBackend;
use keyrack_sqlite::SqliteStorage;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn in_memory() -> Arc<dyn StorageBackend> {
    Arc::new(SqliteStorage::in_memory().unwrap())
}

#[tokio::test]
async fn old_versions_decrypt_and_new_version_names_parent_current() {
    keyrack_test_support::rotation_conformance::old_versions_decrypt_and_new_version_names_parent_current(
        in_memory(),
    )
    .await;
}

#[tokio::test]
async fn crash_recovery_each_phase() {
    let active_path: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let reconnect_path = active_path.clone();
    keyrack_test_support::rotation_conformance::crash_recovery_each_phase(
        {
            let active_path = active_path.clone();
            move || {
                let active_path = active_path.clone();
                async move {
                    let path = std::env::temp_dir().join(format!(
                        "keyrack-rotation-recovery-{}.sqlite",
                        Uuid::new_v4()
                    ));
                    *active_path.lock().unwrap() = Some(path.clone());
                    Arc::new(SqliteStorage::open(&path).unwrap()) as Arc<dyn StorageBackend>
                }
            }
        },
        move |store| {
            let reconnect_path = reconnect_path.clone();
            async move {
                let path = reconnect_path.lock().unwrap().clone().unwrap();
                drop(store);
                Arc::new(SqliteStorage::open(&path).unwrap()) as Arc<dyn StorageBackend>
            }
        },
    )
    .await;
    let last_path = active_path.lock().unwrap().take();
    if let Some(path) = last_path {
        std::fs::remove_file(path).ok();
    }
}

#[tokio::test]
async fn journal_pins_parent_current_version_and_lineage() {
    keyrack_test_support::rotation_conformance::journal_pins_parent_current_version_and_lineage(
        in_memory(),
    )
    .await;
}

#[tokio::test]
async fn withdraw_semantics() {
    keyrack_test_support::rotation_conformance::withdraw_semantics(in_memory().as_ref()).await;
}

#[tokio::test]
async fn rotation_and_migration_fences() {
    keyrack_test_support::rotation_conformance::rotation_and_migration_fences(
        in_memory(),
        in_memory(),
    )
    .await;
}
