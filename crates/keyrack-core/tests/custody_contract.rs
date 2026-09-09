// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

use ed25519_dalek::{Signer, SigningKey};
use keyrack_core::creation::CreationOwner;
use keyrack_core::custody::*;
use keyrack_core::key::{KeySpec, ProviderRef};
use keyrack_core::lid::Lid;
use keyrack_core::wrapping::{WrappedKeyFormat, WrappingContextVersion, WrappingKeyPurpose};
use proptest::prelude::*;
use serde_json::Value;
use std::fmt::Debug;
use std::num::NonZeroU64;
use uuid::Uuid;

fn id(s: &str) -> WrappingIdentifier {
    WrappingIdentifier::new(s).unwrap()
}
fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}
fn executor() -> ExecutorIncarnation {
    ExecutorIncarnation::new([0x44; 32]).unwrap()
}
fn context() -> CustodyContext {
    CustodyContext {
        wrapping: WrappingContext {
            version: WrappingContextVersion::V1,
            child: VersionedKeyId::new(Lid::from_bytes([0x11; 32]), 2).unwrap(),
            parent: VersionedKeyId::new(Lid::from_bytes([0x22; 32]), 3).unwrap(),
            parent_spec: KeySpec::Aes256,
            child_spec: KeySpec::Aes256,
            key_format: WrappedKeyFormat::RawSecret,
            purpose: WrappingKeyPurpose::EncryptDecrypt,
            provider_ref: ProviderRef::new("vault-a"),
            security_domain: id("tenant-a"),
            mechanism: id("fixture-wrap-v1"),
            public_material_sha256: None,
        },
        profile: CustodyProfile {
            boundary: ExecutionBoundary::TrustedHostWorkerMemory,
            id: id("fixture-worker-v1"),
        },
    }
}
fn material() -> CustodyMaterialDescriptor {
    CustodyMaterialDescriptor {
        context: context(),
        envelope_ref: id("envelope-1"),
        envelope_sha256: [0x33; 32],
    }
}
fn request() -> RequestBinding {
    RequestBinding {
        operation: Uuid::from_bytes([0x55; 16]),
        attempt: Uuid::from_bytes([0x66; 16]),
        executor: executor(),
        context_sha256: context().sha256().unwrap(),
        request_sha256: [0x77; 32],
    }
}
fn authority() -> AuthorityIdentity {
    AuthorityIdentity {
        issuer: id("authority-a"),
        scope: AuthorityScope::Context(context().sha256().unwrap()),
        generation: nz(7),
    }
}
fn validity() -> Validity {
    Validity {
        clock: ClockDomain::ExecutorMonotonicMilliseconds(executor()),
        not_before: 100,
        not_after: 200,
    }
}
fn now(n: u64) -> ClockReading {
    ClockReading {
        domain: validity().clock,
        milliseconds: n,
    }
}
fn grant() -> AuthorityGrant {
    AuthorityGrant {
        authority: authority(),
        request: request(),
        principal: id("principal-a"),
        operation: CryptoOperation::Encrypt,
        sequence: nz(9),
        validity: validity(),
        ancestor_not_after: 180,
    }
}
fn lease() -> LeaseIdentity {
    LeaseIdentity {
        executor: executor(),
        counter: nz(11),
    }
}
fn lease_record() -> LeaseRecord {
    LeaseRecord {
        lease: lease(),
        context_sha256: context().sha256().unwrap(),
        authority: authority(),
        residency: Validity {
            not_after: 500,
            ..validity()
        },
    }
}
fn creation() -> CreationResult {
    CreationResult {
        request: request(),
        owner: CreationOwner {
            instance: Uuid::from_bytes([0x88; 16]),
            generation: 13,
        },
        material_sha256: material().sha256().unwrap(),
        outcome: CreationOutcome::NativeWrappedOnlyGenerated,
    }
}
fn cleanup() -> LeaseCleanupResult {
    LeaseCleanupResult {
        record: lease_record(),
        reason: LeaseCleanupReason::Released,
    }
}
fn command() -> RevocationCommand {
    RevocationCommand {
        fence: Uuid::from_bytes([0x99; 16]),
        executor: executor(),
        authority: AuthorityIdentity {
            generation: nz(8),
            ..authority()
        },
        validity: validity(),
    }
}
fn revocation() -> RevocationResult {
    RevocationResult {
        fence: command().fence,
        executor: executor(),
        authority: command().authority,
        command_sha256: command().sha256().unwrap(),
        in_flight: InFlightDisposition::Drained,
        observed_leases: vec![lease()],
    }
}
fn signer() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
} // PUBLIC TEST KEY ONLY
fn key(issuer: &str) -> EvidenceKey {
    EvidenceKey {
        issuer: id(issuer),
        key_id: id("key-1"),
        key: signer().verifying_key(),
    }
}
fn signed<T: EvidenceClaims>(claims: T, issuer: &str) -> Evidence<T> {
    let mut evidence = Evidence {
        issuer: id(issuer),
        key_id: id("key-1"),
        claims,
        signature: [0; 64],
    };
    evidence.signature = signer().sign(&evidence.signing_bytes().unwrap()).to_bytes();
    evidence
}
fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!("vectors/custody-contract-v1.json")).unwrap()
}
fn vector<'a>(data: &'a Value, name: &str) -> &'a Value {
    data["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
}
fn check_vector<T: Canonical + PartialEq + Debug>(data: &Value, name: &str, value: &T) {
    let v = vector(data, name);
    let expected = unhex(v["hex"].as_str().unwrap());
    assert_eq!(value.canonical_bytes().unwrap(), expected, "{name}");
    assert_eq!(
        value.sha256().unwrap().as_slice(),
        unhex(v["sha256"].as_str().unwrap()),
        "{name}"
    );
    assert_eq!(
        &T::from_canonical_bytes(&expected).unwrap(),
        value,
        "{name}"
    );
}

#[test]
fn independently_encoded_golden_vectors_match_typed_values() {
    let f = fixtures();
    check_vector(&f, "profile_worker", &context().profile);
    check_vector(&f, "context_worker", &context());
    check_vector(&f, "material_worker", &material());
    check_vector(&f, "request_worker", &request());
    check_vector(&f, "authority_context", &authority());
    check_vector(&f, "grant_encrypt", &grant());
    check_vector(&f, "lease_identity", &lease());
    check_vector(&f, "lease_record", &lease_record());
    check_vector(&f, "creation_worker", &creation());
    check_vector(&f, "cleanup_released", &cleanup());
    check_vector(&f, "revocation_command", &command());
    check_vector(&f, "revocation_drained", &revocation());
    assert_eq!(
        signer().verifying_key().as_bytes().as_slice(),
        unhex(f["verifying_key_hex"].as_str().unwrap())
    );
    macro_rules! evidence {
        ($name:literal, $claims:expr, $issuer:literal) => {{
            let e = signed($claims, $issuer);
            check_vector(&f, $name, &e);
            assert_eq!(
                e.signing_bytes().unwrap(),
                unhex(vector(&f, $name)["signing_hex"].as_str().unwrap())
            );
            e.authenticate(&key($issuer)).unwrap();
        }};
    }
    evidence!("evidence_grant", grant(), "authority-a");
    evidence!("evidence_creation", creation(), "executor-a");
    evidence!("evidence_cleanup", cleanup(), "executor-a");
    evidence!("evidence_command", command(), "authority-a");
    evidence!("evidence_revocation", revocation(), "executor-a");
}

fn reject_truncation_and_junk<T: Canonical>(bytes: &[u8]) {
    assert_eq!(
        T::from_canonical_bytes(bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes
    );
    for n in 0..bytes.len() {
        assert!(
            T::from_canonical_bytes(&bytes[..n]).is_err(),
            "accepted prefix {n}"
        );
    }
    let mut junk = bytes.to_vec();
    junk.push(0);
    assert!(T::from_canonical_bytes(&junk).is_err());
    junk = bytes.to_vec();
    junk[b"KeyRack:CustodyContract\0".len()] = 0xff;
    assert!(T::from_canonical_bytes(&junk).is_err());
}

#[test]
fn every_reference_variant_decodes_strictly_including_all_receipt_families() {
    let data = fixtures();
    let vectors = data["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 17, "vector set unexpectedly reduced");
    for v in vectors {
        let bytes = unhex(v["hex"].as_str().unwrap());
        match v["kind"].as_u64().unwrap() {
            1 => reject_truncation_and_junk::<CustodyProfile>(&bytes),
            2 => reject_truncation_and_junk::<CustodyContext>(&bytes),
            3 => reject_truncation_and_junk::<CustodyMaterialDescriptor>(&bytes),
            4 => reject_truncation_and_junk::<RequestBinding>(&bytes),
            5 => reject_truncation_and_junk::<AuthorityIdentity>(&bytes),
            6 => reject_truncation_and_junk::<AuthorityGrant>(&bytes),
            7 => reject_truncation_and_junk::<LeaseIdentity>(&bytes),
            8 => reject_truncation_and_junk::<LeaseRecord>(&bytes),
            9 => reject_truncation_and_junk::<CreationResult>(&bytes),
            10 => reject_truncation_and_junk::<LeaseCleanupResult>(&bytes),
            11 => reject_truncation_and_junk::<RevocationCommand>(&bytes),
            12 => reject_truncation_and_junk::<RevocationResult>(&bytes),
            13 => match v["name"].as_str().unwrap() {
                "evidence_grant" => reject_truncation_and_junk::<Evidence<AuthorityGrant>>(&bytes),
                "evidence_creation" => {
                    reject_truncation_and_junk::<Evidence<CreationResult>>(&bytes);
                }
                "evidence_cleanup" => {
                    reject_truncation_and_junk::<Evidence<LeaseCleanupResult>>(&bytes);
                }
                "evidence_command" => {
                    reject_truncation_and_junk::<Evidence<RevocationCommand>>(&bytes);
                }
                "evidence_revocation" => {
                    reject_truncation_and_junk::<Evidence<RevocationResult>>(&bytes);
                }
                other => panic!("unhandled evidence vector {other}"),
            },
            other => panic!("unhandled kind {other}"),
        }
    }
}

#[test]
fn receipt_families_are_not_interchangeable_on_the_wire() {
    let c = creation().canonical_bytes().unwrap();
    let l = cleanup().canonical_bytes().unwrap();
    let r = revocation().canonical_bytes().unwrap();
    assert!(CreationResult::from_canonical_bytes(&l).is_err());
    assert!(CreationResult::from_canonical_bytes(&r).is_err());
    assert!(LeaseCleanupResult::from_canonical_bytes(&c).is_err());
    assert!(LeaseCleanupResult::from_canonical_bytes(&r).is_err());
    assert!(RevocationResult::from_canonical_bytes(&c).is_err());
    assert!(RevocationResult::from_canonical_bytes(&l).is_err());
    let e = signed(cleanup(), "executor-a").canonical_bytes().unwrap();
    assert!(Evidence::<CreationResult>::from_canonical_bytes(&e).is_err());
    assert!(Evidence::<RevocationResult>::from_canonical_bytes(&e).is_err());
}

#[test]
fn every_single_byte_change_to_signed_grant_is_rejected() {
    let bytes = signed(grant(), "authority-a").canonical_bytes().unwrap();
    for offset in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        if let Ok(evidence) = Evidence::<AuthorityGrant>::from_canonical_bytes(&changed) {
            assert!(
                evidence.authenticate(&key("authority-a")).is_err(),
                "offset {offset}"
            );
        }
    }
}

#[test]
fn signature_requires_trusted_key_and_exact_signer_names() {
    let e = signed(grant(), "authority-a");
    assert!(e.clone().authenticate(&key("other-issuer")).is_err());
    let mut wrong = key("authority-a");
    wrong.key_id = id("another-key");
    assert!(e.clone().authenticate(&wrong).is_err());
    wrong = key("authority-a");
    wrong.key = SigningKey::from_bytes(&[0x43; 32]).verifying_key();
    assert!(e.clone().authenticate(&wrong).is_err());
    let mut wrong_claim = e;
    wrong_claim.claims.authority.issuer = id("forged-authority");
    assert!(wrong_claim.signing_bytes().is_err());
}

fn check(g: &AuthorityGrant, n: u64) -> Result<()> {
    g.check_request(
        &request(),
        &context(),
        &id("principal-a"),
        CryptoOperation::Encrypt,
        now(n),
    )
}

#[test]
fn authentication_is_not_freshness_and_residency_is_not_authority() {
    let evidence = signed(grant(), "authority-a")
        .authenticate(&key("authority-a"))
        .unwrap();
    assert!(check(evidence.claims(), 100).is_ok());
    assert!(check(evidence.claims(), 99).is_err());
    assert!(check(evidence.claims(), 179).is_ok());
    assert!(check(evidence.claims(), 180).is_err()); // ancestor cutoff, before grant expiry
    assert!(lease_record().residency.check_at(now(250)).is_ok());
    assert!(check(evidence.claims(), 250).is_err()); // warm cache grants no authority
    assert!(lease_record().residency.check_at(now(500)).is_err());
    let mut g = grant();
    g.ancestor_not_after = 300;
    assert!(check(&g, 199).is_ok());
    assert!(check(&g, 200).is_err()); // half-open own authority window
    let wrong_time = ClockReading {
        domain: ClockDomain::UnixMilliseconds,
        milliseconds: 150,
    };
    assert!(g.validity.check_at(wrong_time).is_err());
}

#[test]
fn request_principal_operation_incarnation_scope_and_input_are_exact() {
    let base = grant();
    assert!(check(&base, 150).is_ok());
    let mut mutations = vec![];
    let mut g = base.clone();
    g.principal = id("other-principal");
    mutations.push(g);
    let mut g = base.clone();
    g.operation = CryptoOperation::Decrypt;
    mutations.push(g);
    let mut g = base.clone();
    g.request.request_sha256[0] ^= 1;
    mutations.push(g);
    let mut g = base.clone();
    g.request.context_sha256[0] ^= 1;
    mutations.push(g);
    let mut g = base.clone();
    g.request.attempt = Uuid::from_bytes([1; 16]);
    mutations.push(g);
    let mut g = base.clone();
    g.request.operation = Uuid::from_bytes([1; 16]);
    mutations.push(g);
    let mut g = base.clone();
    g.request.executor = ExecutorIncarnation::new([1; 32]).unwrap();
    mutations.push(g);
    for g in mutations {
        assert!(check(&g, 150).is_err());
    }
    let mut g = base;
    g.authority.scope = AuthorityScope::SecurityDomain {
        provider_ref: ProviderRef::new("vault-a"),
        security_domain: id("tenant-a"),
    };
    assert!(check(&g, 150).is_ok());
    g.authority.scope = AuthorityScope::SecurityDomain {
        provider_ref: ProviderRef::new("vault-b"),
        security_domain: id("tenant-a"),
    };
    assert!(check(&g, 150).is_err());
    g.authority.scope = AuthorityScope::SecurityDomain {
        provider_ref: ProviderRef::new("vault-a"),
        security_domain: id("tenant-b"),
    };
    assert!(check(&g, 150).is_err());
}

#[test]
fn wrapping_only_key_does_not_accept_generic_encrypt_or_decrypt_grant() {
    let mut c = context();
    c.wrapping.purpose = WrappingKeyPurpose::WrapUnwrap;
    let mut g = grant();
    g.request.context_sha256 = c.sha256().unwrap();
    g.authority.scope = AuthorityScope::Context(c.sha256().unwrap());
    for operation in [CryptoOperation::Encrypt, CryptoOperation::Decrypt] {
        g.operation = operation;
        assert!(g
            .check_request(&g.request, &c, &g.principal, operation, now(150))
            .is_err());
    }
    g.operation = CryptoOperation::GenerateWrapped;
    g.check_request(&g.request, &c, &g.principal, g.operation, now(150))
        .unwrap();
}

#[test]
fn creation_requires_exact_owner_attempt_material_and_compatible_profile() {
    let c = creation();
    c.check_attempt(&request(), c.owner, &material()).unwrap();
    let mut wrong_request = request();
    wrong_request.attempt = Uuid::from_bytes([1; 16]);
    assert!(c
        .check_attempt(&wrong_request, c.owner, &material())
        .is_err());
    assert!(c
        .check_attempt(
            &request(),
            CreationOwner {
                generation: 14,
                ..c.owner
            },
            &material()
        )
        .is_err());
    let mut m = material();
    m.envelope_sha256[0] ^= 1;
    assert!(c.check_material(&m).is_err());
    m = material();
    m.envelope_ref = id("other-envelope");
    assert!(c.check_material(&m).is_err());
    for (boundary, outcome) in [
        (
            ExecutionBoundary::ProviderSessionObject,
            CreationOutcome::ProviderSessionClosed { session: id("s") },
        ),
        (
            ExecutionBoundary::ProviderJournaledTemporaryObject,
            CreationOutcome::ProviderTemporaryObjectDestroyed { object: id("o") },
        ),
    ] {
        let mut result = c.clone();
        result.outcome = outcome;
        assert!(result.check_material(&material()).is_err());
        let mut m = material();
        m.context.profile.boundary = boundary;
        result.request.context_sha256 = m.context.sha256().unwrap();
        result.material_sha256 = m.sha256().unwrap();
        result.check_material(&m).unwrap(); // structural consistency, not provider qualification
    }
}

#[test]
fn context_binds_every_placement_and_key_field_without_changing_v1() {
    let base = context();
    let v1 = base.wrapping.canonical_bytes().unwrap();
    let bytes = base.canonical_bytes().unwrap();
    assert!(CustodyContext::from_canonical_bytes(&v1).is_err());
    assert!(bytes.windows(v1.len()).any(|w| w == v1));
    let mut alternatives = vec![];
    macro_rules! change {
        ($field:ident, $value:expr) => {{
            let mut c = base.clone();
            c.wrapping.$field = $value;
            alternatives.push(c);
        }};
    }
    change!(
        child,
        VersionedKeyId::new(base.wrapping.child.lid, 4).unwrap()
    );
    change!(
        parent,
        VersionedKeyId::new(base.wrapping.parent.lid, 4).unwrap()
    );
    change!(
        child,
        VersionedKeyId::new(Lid::from_bytes([0x12; 32]), 2).unwrap()
    );
    change!(
        parent,
        VersionedKeyId::new(Lid::from_bytes([0x23; 32]), 3).unwrap()
    );
    change!(child_spec, KeySpec::Aes128);
    change!(parent_spec, KeySpec::Aes128);
    change!(provider_ref, ProviderRef::new("vault-b"));
    change!(security_domain, id("tenant-b"));
    change!(mechanism, id("other-wrap-v1"));
    change!(
        key_format,
        WrappedKeyFormat::ProviderNative(id("opaque-v1"))
    );
    change!(purpose, WrappingKeyPurpose::WrapUnwrap);
    let mut c = base.clone();
    c.profile.id = id("other-profile-v1");
    alternatives.push(c);
    let mut c = base.clone();
    c.profile.boundary = ExecutionBoundary::ProviderSessionObject;
    alternatives.push(c);
    for c in alternatives {
        assert_ne!(c.canonical_bytes().unwrap(), bytes);
        assert_ne!(c.sha256().unwrap(), base.sha256().unwrap());
        assert!(grant()
            .check_request(
                &request(),
                &c,
                &id("principal-a"),
                CryptoOperation::Encrypt,
                now(150)
            )
            .is_err());
    }
    assert_eq!(base.wrapping.canonical_bytes().unwrap(), v1);
}

#[test]
fn decoding_a_profile_name_does_not_qualify_it() {
    let c = CustodyContext::from_canonical_bytes(&context().canonical_bytes().unwrap()).unwrap();
    assert!(c.require_profile(&[]).is_err());
    c.require_profile(std::slice::from_ref(&c.profile)).unwrap();
    let mut wrong = c.profile.clone();
    wrong.boundary = ExecutionBoundary::ProviderSessionObject;
    assert!(c.require_profile(&[wrong]).is_err());
    let mut wrong = c.profile.clone();
    wrong.id = id("*");
    assert!(c.require_profile(&[wrong]).is_err());
}

#[test]
fn revocation_disposition_tags_remain_v1_and_unknown_outcomes_fail_closed() {
    // Empty diagnostics make the final fields exactly disposition:u8, count:u16.
    // This tests the wire contract, not runtime drain/suppression truthfulness.
    let mut result = revocation();
    result.observed_leases.clear();
    for (disposition, tag) in [
        (InFlightDisposition::Drained, 1),
        (InFlightDisposition::OutputsSuppressed, 2),
    ] {
        result.in_flight = disposition;
        let bytes = result.canonical_bytes().unwrap();
        assert_eq!(&bytes[bytes.len() - 3..], &[tag, 0, 0]);
        assert_eq!(
            RevocationResult::from_canonical_bytes(&bytes).unwrap(),
            result
        );
        for unknown in [0, 3, 255] {
            let mut changed = bytes.clone();
            let offset = changed.len() - 3;
            changed[offset] = unknown;
            assert!(RevocationResult::from_canonical_bytes(&changed).is_err());
        }
    }
}

#[test]
fn revocation_disposition_cannot_be_relabelled_after_signing() {
    for disposition in [
        InFlightDisposition::Drained,
        InFlightDisposition::OutputsSuppressed,
    ] {
        let mut result = revocation();
        result.in_flight = disposition;
        let evidence = signed(result, "executor-a");
        evidence.clone().authenticate(&key("executor-a")).unwrap();
        let mut changed = evidence;
        changed.claims.in_flight = match disposition {
            InFlightDisposition::Drained => InFlightDisposition::OutputsSuppressed,
            InFlightDisposition::OutputsSuppressed => InFlightDisposition::Drained,
        };
        assert!(changed.authenticate(&key("executor-a")).is_err());
    }
}

#[test]
fn both_revocation_dispositions_require_the_exact_canonical_command() {
    for disposition in [
        InFlightDisposition::Drained,
        InFlightDisposition::OutputsSuppressed,
    ] {
        let mut result = revocation();
        result.in_flight = disposition;
        result.check_command(&command()).unwrap();
        let mut changed = command();
        changed.authority.issuer = id("other-authority");
        assert!(result.check_command(&changed).is_err());
        changed = command();
        changed.authority.scope = AuthorityScope::Context([0xab; 32]);
        assert!(result.check_command(&changed).is_err());
        changed = command();
        changed.authority.generation = nz(9);
        assert!(result.check_command(&changed).is_err());
        changed = command();
        changed.executor = ExecutorIncarnation::new([1; 32]).unwrap();
        assert!(result.check_command(&changed).is_err());
        changed = command();
        changed.fence = Uuid::from_bytes([1; 16]);
        assert!(result.check_command(&changed).is_err());
        changed = command();
        changed.validity.not_after -= 1;
        assert!(result.check_command(&changed).is_err());
        result.command_sha256[0] ^= 1;
        assert!(result.check_command(&command()).is_err());
    }
}

#[test]
fn local_fence_is_bound_to_command_and_does_not_claim_global_completion() {
    revocation().check_command(&command()).unwrap();
    let mut changed = command();
    changed.authority.generation = nz(9);
    assert!(revocation().check_command(&changed).is_err());
    changed = command();
    changed.executor = ExecutorIncarnation::new([1; 32]).unwrap();
    assert!(revocation().check_command(&changed).is_err());
    changed = command();
    changed.fence = Uuid::from_bytes([1; 16]);
    assert!(revocation().check_command(&changed).is_err());
    let mut result = revocation();
    result.observed_leases.clear();
    result.check_command(&command()).unwrap(); // diagnostics are not a holder census
    result.observed_leases = (1..=128)
        .map(|n| LeaseIdentity {
            counter: nz(n),
            ..lease()
        })
        .collect();
    result.canonical_bytes().unwrap();
    result.observed_leases.push(LeaseIdentity {
        counter: nz(129),
        ..lease()
    });
    assert!(result.canonical_bytes().is_err());
    result.observed_leases = vec![lease(), lease()];
    assert!(result.canonical_bytes().is_err());
    result.observed_leases = vec![
        LeaseIdentity {
            counter: nz(12),
            ..lease()
        },
        lease(),
    ];
    assert!(result.canonical_bytes().is_err());
    result.observed_leases = vec![LeaseIdentity {
        executor: ExecutorIncarnation::new([1; 32]).unwrap(),
        ..lease()
    }];
    assert!(result.canonical_bytes().is_err());
}

#[test]
fn malformed_bounds_unknown_tags_zero_ids_and_conflicting_clocks_fail_closed() {
    let header = b"KeyRack:CustodyContract\0".len() + 3;
    let mut bytes = context().canonical_bytes().unwrap();
    bytes[header..header + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CustodyContext::from_canonical_bytes(&bytes).is_err());
    bytes = context().profile.canonical_bytes().unwrap();
    bytes[header] = 255;
    assert!(CustodyProfile::from_canonical_bytes(&bytes).is_err());
    bytes = context().profile.canonical_bytes().unwrap();
    bytes[header + 1..header + 3].copy_from_slice(&257_u16.to_be_bytes());
    assert!(CustodyProfile::from_canonical_bytes(&bytes).is_err());
    bytes = signed(grant(), "authority-a").canonical_bytes().unwrap();
    bytes[header] = 255;
    assert!(Evidence::<AuthorityGrant>::from_canonical_bytes(&bytes).is_err());
    assert!(CustodyContext::from_canonical_bytes(&vec![0; MAX_CONTRACT_BYTES + 1]).is_err());
    assert!(ExecutorIncarnation::new([0; 32]).is_err());
    let mut r = request();
    r.attempt = Uuid::nil();
    assert!(r.canonical_bytes().is_err());
    let mut c = context();
    c.wrapping.parent.lid = c.wrapping.child.lid;
    assert!(c.canonical_bytes().is_err());
    let mut g = grant();
    g.validity.not_after = g.validity.not_before;
    assert!(g.canonical_bytes().is_err());
    let mut l = lease_record();
    l.lease.executor = ExecutorIncarnation::new([1; 32]).unwrap();
    assert!(l.canonical_bytes().is_err());
    l = lease_record();
    l.context_sha256[0] ^= 1;
    assert!(l.canonical_bytes().is_err());
}

fn accepted_is_canonical<T: Canonical>(bytes: &[u8]) {
    if let Ok(value) = T::from_canonical_bytes(bytes) {
        assert_eq!(value.canonical_bytes().unwrap(), bytes);
    }
}

proptest! {
    #[test]
    fn arbitrary_inputs_never_panic_or_decode_noncanonically(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        accepted_is_canonical::<CustodyProfile>(&bytes);
        accepted_is_canonical::<CustodyContext>(&bytes);
        accepted_is_canonical::<CustodyMaterialDescriptor>(&bytes);
        accepted_is_canonical::<RequestBinding>(&bytes);
        accepted_is_canonical::<AuthorityIdentity>(&bytes);
        accepted_is_canonical::<AuthorityGrant>(&bytes);
        accepted_is_canonical::<LeaseIdentity>(&bytes);
        accepted_is_canonical::<LeaseRecord>(&bytes);
        accepted_is_canonical::<CreationResult>(&bytes);
        accepted_is_canonical::<LeaseCleanupResult>(&bytes);
        accepted_is_canonical::<RevocationCommand>(&bytes);
        accepted_is_canonical::<RevocationResult>(&bytes);
        accepted_is_canonical::<Evidence<AuthorityGrant>>(&bytes);
    }

    #[test]
    fn mutated_structured_grants_are_canonical_if_accepted(index in 0_usize..1024, byte in any::<u8>()) {
        let mut bytes = grant().canonical_bytes().unwrap();
        let n = index % bytes.len();
        bytes[n] = byte;
        accepted_is_canonical::<AuthorityGrant>(&bytes);
    }

    #[test]
    fn exact_provider_identifiers_roundtrip_without_normalization(name in "[a-zA-Z0-9._:/-]{1,256}") {
        let mut c = context();
        c.wrapping.provider_ref = ProviderRef::new(name.clone());
        let bytes = c.canonical_bytes().unwrap();
        let decoded = CustodyContext::from_canonical_bytes(&bytes).unwrap();
        prop_assert_eq!(decoded.wrapping.provider_ref.as_str(), name.as_str());
        prop_assert_eq!(decoded, c);
    }
}
