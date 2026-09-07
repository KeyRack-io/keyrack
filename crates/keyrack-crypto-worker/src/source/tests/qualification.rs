// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Version-scoped API/algorithm qualification controls, called by the existing
//! ignored live test. No standalone fixture, fallback or production capability.
use super::*;
use hkdf::Hkdf;
use reqwest::{blocking::Response, Method, StatusCode};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use std::collections::HashMap;

fn decode<T: DeserializeOwned>(response: Response) -> T {
    assert!(
        response.status().is_success(),
        "qualification request refused"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    response.take(65_537).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 65_536);
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("invalid qualification response"))
}

fn request(
    source: &VaultFixture,
    method: Method,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Response {
    let mut request = source
        .client
        .request(method, format!("{}/v1/{path}", source.address))
        .header("X-Vault-Token", source.token.as_str());
    if let Some(body) = body {
        request = request.json(body);
    }
    request
        .send()
        .unwrap_or_else(|_| panic!("qualification fixture unavailable"))
}

fn post(source: &VaultFixture, path: &str, body: &serde_json::Value) -> Reply {
    decode(request(source, Method::POST, path, Some(body)))
}

fn denied(source: &VaultFixture, path: &str, body: &serde_json::Value) {
    assert_eq!(
        request(source, Method::POST, path, Some(body)).status(),
        StatusCode::BAD_REQUEST
    );
}

fn plaintext(reply: Reply) -> Zeroizing<Vec<u8>> {
    let text = reply
        .data
        .plaintext
        .expect("plaintext required only inside qualification control");
    Zeroizing::new(STANDARD.decode(text.0.as_str()).unwrap())
}

/// Only fresh test-owned control parents are ever deleted. A2's final container
/// teardown also removes them if the test runner is killed before this Drop.
struct Controls {
    source: VaultFixture,
    names: Vec<String>,
}
impl Controls {
    fn create(&mut self, derived: bool, exportable: bool) -> String {
        let name = format!("worker-fixture-qualification-{}", uuid::Uuid::new_v4());
        self.names.push(name.clone());
        let response = request(
            &self.source,
            Method::POST,
            &format!("transit/keys/{name}"),
            Some(&json!({
                "type": "aes256-gcm96", "derived": derived, "exportable": exportable,
                "allow_plaintext_backup": false, "convergent_encryption": false,
            })),
        );
        assert!(response.status().is_success());
        name
    }
    fn cleanup(&mut self) -> bool {
        let mut ok = true;
        for name in self.names.drain(..) {
            let config = self
                .source
                .client
                .post(format!(
                    "{}/v1/transit/keys/{name}/config",
                    self.source.address
                ))
                .header("X-Vault-Token", self.source.token.as_str())
                .json(&json!({"deletion_allowed": true}))
                .send();
            ok &= config.is_ok_and(|r| r.status().is_success());
            let deleted = self
                .source
                .client
                .delete(format!("{}/v1/transit/keys/{name}", self.source.address))
                .header("X-Vault-Token", self.source.token.as_str())
                .send();
            ok &= deleted.is_ok_and(|r| r.status().is_success());
        }
        ok
    }
}
impl Drop for Controls {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Deserialize)]
struct ExportData {
    keys: HashMap<String, SecretText>,
}
#[derive(Deserialize)]
struct ExportReply {
    data: ExportData,
}

fn independent_open(
    parent: &[u8],
    context: &[u8],
    ciphertext: &str,
    aad: &[u8],
) -> Result<Secret, Error> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, parent)
        .expand(context, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    let encoded = ciphertext.splitn(3, ':').nth(2).ok_or(Error::Material)?;
    let payload = STANDARD.decode(encoded).map_err(|_| Error::Material)?;
    if payload.len() < 28 {
        return Err(Error::Material);
    }
    let nonce: [u8; 12] = payload[..12].try_into().map_err(|_| Error::Material)?;
    let plaintext = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto)?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &payload[12..],
                aad,
            },
        )
        .map_err(|_| Error::Material)?;
    Ok(Secret(Zeroizing::new(plaintext)))
}

pub(super) fn verify_pinned_vault_binding(worker: &VaultFixture, context: &[u8]) {
    #[derive(Deserialize)]
    struct Health {
        version: String,
    }
    let health: Health = decode(request(worker, Method::GET, "sys/health", None));
    assert_eq!(
        health.version, "1.17.6",
        "review source and requalify before changing the tested version"
    );
    let decrypt_path = format!("transit/decrypt/{}", worker.parent);
    let envelope = &worker.ciphertext;
    let encoded_context = STANDARD.encode(context);
    for body in [
        json!({"ciphertext": envelope}),
        json!({"ciphertext": envelope, "context": ""}),
        json!({"ciphertext": envelope, "context": "!!!"}),
        json!({"ciphertext": envelope, "context": encoded_context, "associated_data": STANDARD.encode(b"extra-AAD")}),
    ] {
        denied(worker, &decrypt_path, &body);
    }
    let mut raw = STANDARD
        .decode(envelope.strip_prefix("vault:v1:").unwrap())
        .unwrap();
    assert_eq!(raw.len(), 60);
    for index in [0, 12, 59] {
        raw[index] ^= 1;
        denied(
            worker,
            &decrypt_path,
            &json!({"ciphertext": format!("vault:v1:{}", STANDARD.encode(&raw)), "context": encoded_context}),
        );
        raw[index] ^= 1;
    }
    let expected = plaintext(post(
        worker,
        &decrypt_path,
        &json!({"ciphertext": envelope, "context": encoded_context}),
    ));
    // Vault decodes the bytes, not their base64 display; its version parser also
    // accepts aliases. Canonical envelope hashing remains the worker's duty.
    let aliases = [
        envelope.replacen("vault:v1:", "vault:v01:", 1),
        envelope.replacen("vault:v1:", "vault:v0:", 1),
    ];
    for alias in aliases {
        let opened = plaintext(post(
            worker,
            &decrypt_path,
            &json!({"ciphertext": alias, "context": encoded_context}),
        ));
        assert!(opened.as_slice().eq(expected.as_slice()));
        assert_ne!(digest(alias.as_bytes()), digest(envelope.as_bytes()));
    }
    let mut display_alias = encoded_context.clone();
    display_alias.insert_str(4, "\r\n");
    let opened = plaintext(post(
        worker,
        &decrypt_path,
        &json!({"ciphertext": envelope, "context": display_alias}),
    ));
    assert!(opened.as_slice().eq(expected.as_slice()));
    assert_eq!(
        request(
            worker,
            Method::POST,
            &format!("transit/datakey/plaintext/{}", worker.parent),
            Some(&json!({"context": encoded_context}))
        )
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            worker,
            Method::GET,
            &format!("transit/export/encryption-key/{}", worker.parent),
            None
        )
        .status(),
        StatusCode::FORBIDDEN
    );

    let admin = crate::credential::load(std::path::Path::new(
        &std::env::var("KEYRACK_WORKER_VAULT_ADMIN_TOKEN_FILE")
            .expect("qualification controls require fixture admin"),
    ))
    .unwrap();
    let mut controls = Controls {
        source: VaultFixture::new(&worker.address, admin, "unused-control".into()).unwrap(),
        names: Vec::new(),
    };
    // Exportability is ONLY an independent-algorithm control. The runtime adapter
    // must reject it; no existing/non-exportable fixture parent is weakened.
    let parent = controls.create(true, true);
    let s = &controls.source;
    let generate_path = format!("transit/datakey/wrapped/{parent}");
    let decrypt_path = format!("transit/decrypt/{parent}");
    let aad = STANDARD.encode(b"unsupported-datakey-AAD");
    let generated = post(
        s,
        &generate_path,
        &json!({"bits": 256, "key_version": 1, "context": encoded_context, "associated_data": aad}),
    );
    assert!(generated.data.plaintext.is_none());
    let ciphertext = generated.data.ciphertext.unwrap();
    let exported: ExportReply = decode(request(
        s,
        Method::GET,
        &format!("transit/export/encryption-key/{parent}/1"),
        None,
    ));
    let root = Zeroizing::new(STANDARD.decode(exported.data.keys["1"].0.as_str()).unwrap());
    let independent = independent_open(&root, context, &ciphertext, &[]).unwrap();
    let vault = plaintext(post(
        s,
        &decrypt_path,
        &json!({"ciphertext": ciphertext, "context": encoded_context}),
    ));
    assert!(independent.0.as_slice().eq(vault.as_slice()));
    assert_eq!(vault.len(), 32);
    assert!(independent_open(&root, context, &ciphertext, b"unsupported-datakey-AAD").is_err());
    denied(
        s,
        &decrypt_path,
        &json!({"ciphertext": ciphertext, "context": encoded_context, "associated_data": aad}),
    );
    for index in 0..context.len() {
        let mut changed = context.to_vec();
        changed[index] ^= 1;
        assert!(
            independent_open(&root, &changed, &ciphertext, &[]).is_err(),
            "independent KDF accepted changed context byte {index}"
        );
    }
    // Explicit AAD is supported by ordinary encrypt/decrypt, which makes its
    // absence from datakey/wrapped a meaningful endpoint distinction.
    let ordinary = post(s, &format!("transit/encrypt/{parent}"), &json!({"plaintext": STANDARD.encode(b"public-control"), "context": encoded_context, "associated_data": aad})).data.ciphertext.unwrap();
    assert!(plaintext(post(
        s,
        &decrypt_path,
        &json!({"ciphertext": ordinary, "context": encoded_context, "associated_data": aad})
    ))
    .as_slice()
    .eq(b"public-control"));
    denied(
        s,
        &decrypt_path,
        &json!({"ciphertext": ordinary, "context": encoded_context}),
    );
    // A second genuine datakey for the same context also authenticates. Context
    // binding is not an attempt ID or a unique ciphertext commitment.
    let second = post(
        s,
        &generate_path,
        &json!({"bits": 256, "key_version": 1, "context": encoded_context}),
    )
    .data
    .ciphertext
    .unwrap();
    assert_ne!(digest(second.as_bytes()), digest(ciphertext.as_bytes()));
    assert!(independent_open(&root, context, &second, &[]).is_ok());
    let rotation = request(
        s,
        Method::POST,
        &format!("transit/keys/{parent}/rotate"),
        Some(&json!({})),
    );
    assert!(rotation.status().is_success());
    let pinned = post(
        s,
        &generate_path,
        &json!({"bits": 256, "key_version": 1, "context": encoded_context}),
    )
    .data
    .ciphertext
    .unwrap();
    assert!(pinned.starts_with("vault:v1:"));
    assert!(independent_open(&root, context, &pinned, &[]).is_ok());
    let latest = post(
        s,
        &generate_path,
        &json!({"bits": 256, "context": encoded_context}),
    )
    .data
    .ciphertext
    .unwrap();
    assert!(latest.starts_with("vault:v2:"));
    assert!(independent_open(&root, context, &latest, &[]).is_err());
    denied(
        s,
        &decrypt_path,
        &json!({"ciphertext": ciphertext.replacen("vault:v1:", "vault:v2:", 1), "context": encoded_context}),
    );
    let mut inadmissible =
        VaultFixture::new(&worker.address, Zeroizing::new(s.token.to_string()), parent).unwrap();
    assert!(inadmissible
        .prepare_generation(&crate::fixture::custody_context(&crate::fixture::context()))
        .is_err());

    let plain_parent = controls.create(false, false);
    let s = &controls.source;
    let generated = post(
        s,
        &format!("transit/datakey/wrapped/{plain_parent}"),
        &json!({"context": encoded_context}),
    )
    .data
    .ciphertext
    .unwrap();
    let path = format!("transit/decrypt/{plain_parent}");
    let without = plaintext(post(s, &path, &json!({"ciphertext": generated})));
    let changed = plaintext(post(
        s,
        &path,
        &json!({"ciphertext": generated, "context": STANDARD.encode(b"ignored-nonderived-context")}),
    ));
    assert!(without.as_slice().eq(changed.as_slice()));
    let mut inadmissible = VaultFixture::new(
        &worker.address,
        Zeroizing::new(s.token.to_string()),
        plain_parent,
    )
    .unwrap();
    assert!(inadmissible
        .prepare_generation(&crate::fixture::custody_context(&crate::fixture::context()))
        .is_err());
    assert!(controls.cleanup(), "qualification control cleanup failed");
    eprintln!("Vault 1.17.6 qualification controls passed: full-frame HKDF-SHA256/AES-GCM, endpoint AAD distinction, byte/display/version/ciphertext controls, parent guards and cleanup");
}
