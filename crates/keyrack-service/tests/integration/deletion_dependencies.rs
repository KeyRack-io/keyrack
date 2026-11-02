// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use keyrack_core::key::{KeyRecord, KeyState};
use keyrack_service::domain::{self, DomainError};
use keyrack_test_support::creation_conformance;

#[derive(Clone, Copy)]
enum Blocker {
    DependentWrappedVersion,
    ParentJournal,
    ChildJournal,
}

impl Blocker {
    fn count(self) -> &'static str {
        match self {
            Self::DependentWrappedVersion => "dependent_parent_wrapped_versions=1",
            Self::ParentJournal | Self::ChildJournal => "creation_journal_rows=1",
        }
    }
}

async fn fixture(blocker: Blocker) -> (Arc<ServiceState>, KeyRecord, String) {
    let (state, _, _) = build_test_state();
    let (parent, mut request) = creation_conformance::fixture();
    state.storage.create_key(&parent).await.unwrap();
    let (target, other) = match blocker {
        Blocker::DependentWrappedVersion => {
            state.storage.create_key(&request.record).await.unwrap();
            (parent, request.record.lid.to_string())
        }
        Blocker::ParentJournal => {
            state.storage.reserve_creation(&request).await.unwrap();
            (parent, request.record.lid.to_string())
        }
        Blocker::ChildJournal => {
            // An existing resident child with an outstanding next-version
            // creation isolates the child-journal gate from wrapped history.
            let mut resident = request.record.clone();
            resident.key_versions[0].material = parent.key_versions[0].material.clone();
            state.storage.create_key(&resident).await.unwrap();
            let mut next = request.record.key_versions[0].clone();
            next.version_number = 2;
            request.record = resident.clone();
            request.record.key_versions[0].is_primary = false;
            request.record.key_versions.push(next);
            request.record.current_key_version = 2;
            request.record.occ_version += 1;
            request.expected_key_occ = Some(resident.occ_version);
            request.context_bytes = request.context().unwrap().canonical_bytes().unwrap();
            state.storage.reserve_creation(&request).await.unwrap();
            (resident, parent.lid.to_string())
        }
    };
    (state, target, other)
}

async fn assert_unchanged(state: &ServiceState, before: &KeyRecord) {
    let after = state.storage.get_key(&before.lid).await.unwrap();
    assert!(keyrack_core::creation::same_json(before, &after).unwrap());
}

async fn grpc_refusal(blocker: Blocker) {
    let (state, target, other) = fixture(blocker).await;
    let service = keyrack_service::grpc::KeyServiceImpl::new(state.clone());
    let error = service
        .schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
            allow_dependent_data_loss: false,
            key_id: target.lid.to_string(),
            grace_period_days: 7,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains(blocker.count()), "{error}");
    assert!(!error.message().contains(&other), "{error}");
    assert_unchanged(&state, &target).await;
}

async fn rest_schedule(state: Arc<ServiceState>, key: &str) -> (u16, serde_json::Value) {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let response = keyrack_service::rest::router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/v1/keys/{key}/actions-schedule-deletion"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"grace_period_days":7}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn rest_refusal(blocker: Blocker) {
    let (state, target, other) = fixture(blocker).await;
    let (status, body) = rest_schedule(state.clone(), &target.lid.to_string()).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "FailedPrecondition");
    assert!(
        body["message"].as_str().unwrap().contains(blocker.count()),
        "{body}"
    );
    assert!(!body.to_string().contains(&other), "{body}");
    assert_unchanged(&state, &target).await;
}

#[tokio::test]
async fn grpc_refuses_dependent_wrapped_version() {
    grpc_refusal(Blocker::DependentWrappedVersion).await;
}
#[tokio::test]
async fn grpc_refuses_parent_creation_journal() {
    grpc_refusal(Blocker::ParentJournal).await;
}
#[tokio::test]
async fn grpc_refuses_child_creation_journal() {
    grpc_refusal(Blocker::ChildJournal).await;
}
#[tokio::test]
async fn rest_refuses_dependent_wrapped_version() {
    rest_refusal(Blocker::DependentWrappedVersion).await;
}
#[tokio::test]
async fn rest_refuses_parent_creation_journal() {
    rest_refusal(Blocker::ParentJournal).await;
}
#[tokio::test]
async fn rest_refuses_child_creation_journal() {
    rest_refusal(Blocker::ChildJournal).await;
}

#[tokio::test]
async fn domain_refuses_each_dependency_kind_without_mutation() {
    for blocker in [
        Blocker::DependentWrappedVersion,
        Blocker::ParentJournal,
        Blocker::ChildJournal,
    ] {
        let (state, target, other) = fixture(blocker).await;
        let error = domain::schedule_key_deletion(&state, &target.lid.to_string(), 7)
            .await
            .unwrap_err();
        assert!(matches!(&error, DomainError::FailedPrecondition(_)));
        assert!(error.to_string().contains(blocker.count()), "{error}");
        assert!(!error.to_string().contains(&other));
        assert_unchanged(&state, &target).await;
    }
}

#[tokio::test]
async fn logical_only_children_allow_scheduling_on_every_surface() {
    for surface in ["domain", "grpc", "rest"] {
        for count in [0_u64, 2] {
            let (state, _, _) = build_test_state();
            let (parent, _) = creation_conformance::fixture();
            state.storage.create_key(&parent).await.unwrap();
            let mut children = Vec::new();
            for _ in 0..count {
                let mut child = creation_conformance::fixture().1.record;
                child.parent_lid = Some(parent.lid);
                child.key_versions[0].material = parent.key_versions[0].material.clone();
                // A child is counted once, not once per resident version.
                let mut historical = child.key_versions[0].clone();
                historical.version_number = 2;
                historical.is_primary = false;
                child.key_versions.push(historical);
                state.storage.create_key(&child).await.unwrap();
                children.push(child);
            }
            let key = parent.lid.to_string();
            match surface {
                "domain" => {
                    let observation = domain::ensure_deletion_can_be_scheduled(&state, &parent.lid)
                        .await
                        .unwrap();
                    assert_eq!(
                        observation.logical_only_children, count,
                        "logical-only child count must match admission"
                    );
                    domain::schedule_key_deletion(&state, &key, 7)
                        .await
                        .unwrap();
                }
                "grpc" => {
                    let response = keyrack_service::grpc::KeyServiceImpl::new(state.clone())
                        .schedule_key_deletion(Request::new(proto::ScheduleKeyDeletionRequest {
                            allow_dependent_data_loss: false,
                            key_id: key,
                            grace_period_days: 7,
                        }))
                        .await
                        .unwrap()
                        .into_inner();
                    assert_eq!(
                        response.logical_only_children, count,
                        "gRPC logical-only child count must match admission"
                    );
                }
                _ => {
                    let (status, body) = rest_schedule(state.clone(), &key).await;
                    assert_eq!(status, 200);
                    assert_eq!(
                        body["logical_only_children"].as_u64(),
                        Some(count),
                        "REST logical-only child count must match admission: {body}"
                    );
                }
            }
            assert_eq!(
                state.storage.get_key(&parent.lid).await.unwrap().state,
                KeyState::PendingDeletion
            );
            for child in children {
                assert_eq!(
                    state.storage.get_key(&child.lid).await.unwrap().state,
                    KeyState::Enabled
                );
            }
        }
    }
}
