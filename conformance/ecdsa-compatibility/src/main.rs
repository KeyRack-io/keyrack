// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use p256_new::ecdsa::signature::{
    hazmat::{PrehashSigner as _, PrehashVerifier as _},
    Signer as _, Verifier as _,
};
use p256_old::ecdsa::signature::{
    hazmat::{PrehashSigner as _, PrehashVerifier as _},
    Signer as _, Verifier as _,
};
use sha2::{Digest, Sha256, Sha384};

fn wire_bytes(mut bytes: Vec<u8>, label: &str) -> Vec<u8> {
    if std::env::var("ECDSA_CORRUPT").ok().as_deref() == Some(label) {
        *bytes.last_mut().unwrap() ^= 1;
    }
    bytes
}

// Sign in one implementation and parse/verify in the other, including both wire
// encodings and negative controls. No encode/decode pair shares an implementation.
macro_rules! direction {
    ($source:ident, $target:ident, $size:expr, $point:ident, $digests:expr) => {{
        let message = b"ECDSA cross-version compatibility";
        let key = $source::ecdsa::SigningKey::from_slice(&[7u8; $size]).unwrap();
        let point = key.verifying_key().$point(false);
        let verifier = $target::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes()).unwrap();
        let signature: $source::ecdsa::Signature = key.sign(message);
        let der = signature.to_der();
        let fixed = signature.to_bytes();
        let direction = concat!(stringify!($source), "-", stringify!($target));
        for encoding in ["der", "fixed"] {
            let label = format!("{direction}:{encoding}:message");
            let sig = if encoding == "der" {
                $target::ecdsa::Signature::from_der(&wire_bytes(der.as_bytes().to_vec(), &label))
                    .unwrap()
            } else {
                $target::ecdsa::Signature::from_slice(&wire_bytes(fixed.to_vec(), &label)).unwrap()
            };
            assert!(
                verifier.verify(message, &sig).is_ok(),
                "{label}: valid signature refused"
            );
            assert!(verifier.verify(b"altered message", &sig).is_err());
        }
        for digest in $digests {
            let signature: $source::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
            let der = signature.to_der();
            let fixed = signature.to_bytes();
            for encoding in ["der", "fixed"] {
                let label = format!("{direction}:{encoding}:prehash");
                let sig = if encoding == "der" {
                    $target::ecdsa::Signature::from_der(&wire_bytes(
                        der.as_bytes().to_vec(),
                        &label,
                    ))
                    .unwrap()
                } else {
                    $target::ecdsa::Signature::from_slice(&wire_bytes(fixed.to_vec(), &label))
                        .unwrap()
                };
                assert!(
                    verifier.verify_prehash(&digest, &sig).is_ok(),
                    "{label}: valid signature refused"
                );
                let mut altered = digest.clone();
                altered[0] ^= 1;
                assert!(verifier.verify_prehash(&altered, &sig).is_err());
            }
        }
        println!(
            "PASS {} -> {}: DER/fixed, message/prehash, altered-input refusals",
            stringify!($source),
            stringify!($target)
        );
    }};
}
fn main() {
    let message = b"ECDSA cross-version compatibility";
    let p256_digests = vec![
        Sha256::digest(message).to_vec(),
        Sha384::digest(message).to_vec(),
    ];
    let p384_digests = vec![Sha384::digest(message).to_vec()];
    direction!(
        p256_old,
        p256_new,
        32,
        to_encoded_point,
        p256_digests.clone()
    );
    direction!(p256_new, p256_old, 32, to_sec1_point, p256_digests);
    direction!(
        p384_old,
        p384_new,
        48,
        to_encoded_point,
        p384_digests.clone()
    );
    direction!(p384_new, p384_old, 48, to_sec1_point, p384_digests);
}
