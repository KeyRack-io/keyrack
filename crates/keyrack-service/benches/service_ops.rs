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

//! Service-level operation benchmarks.
//!
//! Targets from PLAN.md W7:
//! - Encrypt under 5ms p99 (software provider, PKCS#11 depends on HSM)
//! - PDP authorization under 1ms p99 (in-process Cedar)
//!
//! Run: cargo bench -p keyrack-service

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use keyrack_core::attr::{AttributeSet, AttributeValue};
use keyrack_core::canon::{canonicalize, CanonicalizationVersion};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::software::SoftwareProvider;
use keyrack_core::provider::CryptoProvider;

fn bench_encrypt_software(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = SoftwareProvider::new();

    let handle = rt.block_on(async { provider.generate_key(&KeySpec::Aes256).await.unwrap() });

    let plaintext = vec![0u8; 256];
    let aad = b"benchmark-context";

    c.bench_function("encrypt AES-256-GCM (256 bytes, software)", |b| {
        b.to_async(&rt).iter(|| async {
            let result = provider.encrypt(&handle, &plaintext, aad).await.unwrap();
            criterion::black_box(result);
        });
    });
}

fn bench_decrypt_software(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = SoftwareProvider::new();

    let handle = rt.block_on(async { provider.generate_key(&KeySpec::Aes256).await.unwrap() });

    let plaintext = vec![0u8; 256];
    let aad = b"benchmark-context";

    let ciphertext =
        rt.block_on(async { provider.encrypt(&handle, &plaintext, aad).await.unwrap() });

    c.bench_function("decrypt AES-256-GCM (256 bytes, software)", |b| {
        b.to_async(&rt).iter(|| async {
            let result = provider
                .decrypt(&handle, &ciphertext.ciphertext, aad)
                .await
                .unwrap();
            criterion::black_box(result);
        });
    });
}

fn bench_encrypt_payload_sizes(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = SoftwareProvider::new();

    let handle = rt.block_on(async { provider.generate_key(&KeySpec::Aes256).await.unwrap() });

    let aad = b"bench";

    let mut group = c.benchmark_group("encrypt_by_size");
    for size in [64, 256, 1024, 4096, 16384] {
        let plaintext = vec![0u8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.to_async(&rt).iter(|| async {
                let result = provider.encrypt(&handle, pt, aad).await.unwrap();
                criterion::black_box(result);
            });
        });
    }
    group.finish();
}

fn bench_sign_ed25519(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = SoftwareProvider::new();

    let handle = rt.block_on(async { provider.generate_key(&KeySpec::Ed25519).await.unwrap() });

    let message = b"benchmark signing payload for ed25519";

    c.bench_function("sign Ed25519", |b| {
        b.to_async(&rt).iter(|| async {
            let sig = provider
                .sign(
                    &handle,
                    keyrack_core::provider::SigningAlgorithm::Ed25519,
                    message,
                )
                .await
                .unwrap();
            criterion::black_box(sig);
        });
    });
}

fn bench_canonicalize_and_lid(c: &mut Criterion) {
    let mut attrs = AttributeSet::new();
    attrs.insert("kind", AttributeValue::String("dek".into()));
    attrs.insert("user", AttributeValue::String("alice".into()));
    attrs.insert("tenant", AttributeValue::String("acme-corp".into()));
    attrs.insert("service", AttributeValue::String("storage".into()));

    c.bench_function("canonicalize + LID derive (4 attrs)", |b| {
        b.iter(|| {
            let form = canonicalize(CanonicalizationVersion::V1, &attrs);
            let lid = keyrack_core::lid::Lid::derive(CanonicalizationVersion::V1, &form);
            criterion::black_box(lid);
        });
    });
}

fn bench_key_generation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let provider = SoftwareProvider::new();

    c.bench_function("generate AES-256 key (software)", |b| {
        b.to_async(&rt).iter(|| async {
            let handle = provider.generate_key(&KeySpec::Aes256).await.unwrap();
            criterion::black_box(handle);
        });
    });
}

criterion_group!(
    benches,
    bench_encrypt_software,
    bench_decrypt_software,
    bench_encrypt_payload_sizes,
    bench_sign_ed25519,
    bench_canonicalize_and_lid,
    bench_key_generation,
);
criterion_main!(benches);
