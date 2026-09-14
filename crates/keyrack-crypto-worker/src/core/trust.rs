// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private launch-time trust; never deserialized from coordinator requests.
use ed25519_dalek::VerifyingKey;
use keyrack_core::custody::{EvidenceKey, WrappingIdentifier};
use std::num::NonZeroU64;

pub(crate) struct TrustConfig {
    pub authority: EvidenceKey,
    pub initial_generation: NonZeroU64,
    pub observer_issuer: WrappingIdentifier,
    pub observer_key_id: WrappingIdentifier,
}

impl TrustConfig {
    // Compatibility wrapper for the explicitly provisional launcher only.
    pub fn fixture(key: VerifyingKey) -> Self {
        Self {
            authority: super::creation::authority_key(key),
            initial_generation: NonZeroU64::new(1).unwrap(),
            observer_issuer: WrappingIdentifier::new("development-worker-observation").unwrap(),
            observer_key_id: WrappingIdentifier::new("incarnation-key").unwrap(),
        }
    }
}
