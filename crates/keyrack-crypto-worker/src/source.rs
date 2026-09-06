// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Development material adapters, not enabled A3 provider capabilities.
use std::{io::Read, time::Duration};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyrack_core::wrapping::WrappingContext;
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use zeroize::Zeroizing;

use crate::core::{digest, Error, MaterialSource, Secret};

pub(crate) struct LocalFixture {
    parent: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl LocalFixture {
    pub(crate) fn new(context: &WrappingContext) -> Result<Self, Error> {
        let mut parent = Zeroizing::new([0; 32]);
        let mut child = Zeroizing::new(vec![0; 32]);
        let mut nonce = [0; 12];
        OsRng.fill_bytes(parent.as_mut());
        OsRng.fill_bytes(&mut child);
        OsRng.fill_bytes(&mut nonce);
        let aad = context.canonical_bytes().map_err(|_| Error::Context)?;
        let ciphertext = Aes256Gcm::new_from_slice(parent.as_ref())
            .map_err(|_| Error::Crypto)?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &child,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(Self {
            parent,
            nonce,
            ciphertext,
        })
    }
}

impl MaterialSource for LocalFixture {
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error> {
        let aad = context.canonical_bytes().map_err(|_| Error::Context)?;
        let plaintext = Aes256Gcm::new_from_slice(self.parent.as_ref())
            .map_err(|_| Error::Crypto)?
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Material)?;
        Ok(Secret(Zeroizing::new(plaintext)))
    }
}

// Distinct native generation observation; never an object-closure receipt. This
// test adapter has no journal/publication API and loses unresolved attempts on exit.
pub(crate) struct NativeWrappedOnlyGeneration {
    pub(crate) context_sha256: [u8; 32],
    pub(crate) ciphertext_sha256: [u8; 32],
    pub(crate) parent_version: u64,
}

struct SecretText(Zeroizing<String>);
impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[derive(Deserialize)]
struct Data {
    ciphertext: Option<String>,
    plaintext: Option<SecretText>,
    derived: Option<bool>,
    convergent_encryption: Option<bool>,
    #[serde(rename = "type")]
    key_type: Option<String>,
    exportable: Option<bool>,
    allow_plaintext_backup: Option<bool>,
}

#[derive(Deserialize)]
struct Reply {
    data: Data,
}

pub(crate) struct VaultFixture {
    client: Client,
    address: String,
    token: Zeroizing<String>,
    parent: String,
    ciphertext: String,
    pub(crate) generation: NativeWrappedOnlyGeneration,
}

impl VaultFixture {
    /// Local fixture only. Endpoint and credential come from the trusted test
    /// launcher, never the coordinator request stream. Redirects are disabled.
    pub(crate) fn new(
        address: &str,
        token: Zeroizing<String>,
        parent: String,
        context: &WrappingContext,
    ) -> Result<Self, Error> {
        if !parent
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            || parent.is_empty()
        {
            return Err(Error::Context);
        }
        let url = reqwest::Url::parse(address).map_err(|_| Error::Context)?;
        if !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Context);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| Error::Material)?;
        let mut result = Self {
            client,
            address: address.trim_end_matches('/').to_owned(),
            token,
            parent,
            ciphertext: String::new(),
            generation: NativeWrappedOnlyGeneration {
                context_sha256: [0; 32],
                ciphertext_sha256: [0; 32],
                parent_version: 0,
            },
        };
        let metadata = result.request(&format!("keys/{}", result.parent), None)?;
        if metadata.derived != Some(true)
            || metadata.convergent_encryption != Some(false)
            || metadata.key_type.as_deref() != Some("aes256-gcm96")
            || metadata.exportable != Some(false)
            || metadata.allow_plaintext_backup != Some(false)
        {
            return Err(Error::Material);
        }
        let canonical = context.canonical_bytes().map_err(|_| Error::Context)?;
        let response = result.request(&format!("datakey/wrapped/{}", result.parent), Some(&json!({
            "bits": 256, "key_version": context.parent.version.get(), "context": STANDARD.encode(&canonical),
        })))?;
        if response.plaintext.is_some() {
            return Err(Error::Material);
        }
        result.ciphertext = response.ciphertext.ok_or(Error::Material)?;
        let expected = format!("vault:v{}:", context.parent.version.get());
        if !result.ciphertext.starts_with(&expected) || result.ciphertext.len() > 4096 {
            return Err(Error::Material);
        }
        result.generation = NativeWrappedOnlyGeneration {
            context_sha256: digest(&canonical),
            ciphertext_sha256: digest(result.ciphertext.as_bytes()),
            parent_version: context.parent.version.get(),
        };
        Ok(result)
    }

    fn request(&self, path: &str, body: Option<&serde_json::Value>) -> Result<Data, Error> {
        let url = format!("{}/v1/transit/{path}", self.address);
        let request = body.map_or_else(
            || self.client.get(&url),
            |body| self.client.post(&url).json(body),
        );
        let response = request
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .map_err(|_| Error::Material)?;
        // Never surface provider response text, URLs or headers through errors.
        if !response.status().is_success() {
            return Err(Error::Material);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Material)?;
        if bytes.len() > 65_536 {
            return Err(Error::Limit);
        }
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|_| Error::Material)?;
        Ok(reply.data)
    }

    // Qualification hook tests native authentication of every existing V1 byte.
    // This is not a V2 profile encoder or a coordinator-facing decrypt operation.
    pub(crate) fn open_bytes(&self, canonical: &[u8]) -> Result<Secret, Error> {
        let reply = self.request(
            &format!("decrypt/{}", self.parent),
            Some(&json!({
                "ciphertext": self.ciphertext, "context": STANDARD.encode(canonical),
            })),
        )?;
        let encoded = reply.plaintext.ok_or(Error::Material)?;
        let decoded = Zeroizing::new(
            STANDARD
                .decode(encoded.0.as_str())
                .map_err(|_| Error::Material)?,
        );
        if decoded.len() != 32 {
            return Err(Error::Material);
        }
        Ok(Secret(decoded))
    }
}

impl MaterialSource for VaultFixture {
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error> {
        self.open_bytes(&context.canonical_bytes().map_err(|_| Error::Context)?)
    }
}

pub(crate) enum Source {
    Local(LocalFixture),
    Vault(VaultFixture),
}
impl MaterialSource for Source {
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error> {
        match self {
            Self::Local(source) => source.open(context),
            Self::Vault(source) => source.open(context),
        }
    }
}

#[cfg(test)]
mod tests;
