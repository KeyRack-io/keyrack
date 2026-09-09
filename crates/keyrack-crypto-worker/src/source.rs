// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Development material adapters, not enabled A3 provider capabilities.
use std::{io::Read, time::Duration};

use crate::core::creation::NativeGeneration;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use keyrack_core::{
    custody::{Canonical, CustodyContext, CustodyMaterialDescriptor, WrappingIdentifier},
    wrapping::WrappingContext,
};
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
    intended_context: Vec<u8>,
}

impl LocalFixture {
    pub(crate) fn new(context: &WrappingContext) -> Result<Self, Error> {
        Ok(Self {
            parent: Zeroizing::new([0; 32]),
            nonce: [0; 12],
            ciphertext: Vec::new(),
            intended_context: context.canonical_bytes().map_err(|_| Error::Context)?,
        })
    }

    fn seed_after_admission(&mut self) -> Result<(), Error> {
        let mut child = Zeroizing::new(vec![0; 32]);
        OsRng.fill_bytes(self.parent.as_mut());
        OsRng.fill_bytes(&mut child);
        OsRng.fill_bytes(&mut self.nonce);
        self.ciphertext = Aes256Gcm::new_from_slice(self.parent.as_ref())
            .map_err(|_| Error::Crypto)?
            .encrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &child,
                    aad: &self.intended_context,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(())
    }
}

impl MaterialSource for LocalFixture {
    fn open(&mut self, context: &WrappingContext) -> Result<Secret, Error> {
        let aad = context.canonical_bytes().map_err(|_| Error::Context)?;
        if aad != self.intended_context {
            return Err(Error::Context);
        }
        if self.ciphertext.is_empty() {
            self.seed_after_admission()?;
        }
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
    active: bool,
    generation_started: bool,
    generated_context: Option<CustodyContext>,
}

impl VaultFixture {
    /// Local fixture only. Endpoint and credential come from the trusted test
    /// launcher, never the coordinator request stream. Redirects are disabled.
    pub(crate) fn new(
        address: &str,
        token: Zeroizing<String>,
        parent: String,
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
        Ok(Self {
            client,
            address: address.trim_end_matches('/').to_owned(),
            token,
            parent,
            ciphertext: String::new(),
            active: false,
            generation_started: false,
            generated_context: None,
        })
    }

    fn prepare_native(&mut self, context: &CustodyContext) -> Result<(), Error> {
        if self.generated_context.is_some() {
            return Err(Error::Replay);
        }
        // Mark before the first request; even a lost response is not retryable.
        self.generated_context = Some(context.clone());
        let metadata = self.request(&format!("keys/{}", self.parent), None)?;
        if metadata.derived != Some(true)
            || metadata.convergent_encryption != Some(false)
            || metadata.key_type.as_deref() != Some("aes256-gcm96")
            || metadata.exportable != Some(false)
            || metadata.allow_plaintext_backup != Some(false)
        {
            return Err(Error::Material);
        }
        Ok(())
    }

    fn native_generate(&mut self, context: &CustodyContext) -> Result<(), Error> {
        if self.generation_started || self.generated_context.as_ref() != Some(context) {
            return Err(Error::Replay);
        }
        self.generation_started = true;
        let canonical = context.canonical_bytes().map_err(|_| Error::Context)?;
        let response = self.request(&format!("datakey/wrapped/{}", self.parent), Some(&json!({
            "bits": 256, "key_version": context.wrapping.parent.version.get(), "context": STANDARD.encode(&canonical),
        })))?;
        if response.plaintext.is_some() {
            return Err(Error::Material);
        }
        self.ciphertext = response.ciphertext.ok_or(Error::Material)?;
        let expected = format!("vault:v{}:", context.wrapping.parent.version.get());
        if self.ciphertext.len() > 4096 {
            return Err(Error::Material);
        }
        let encoded = self
            .ciphertext
            .strip_prefix(&expected)
            .ok_or(Error::Material)?;
        let payload = STANDARD.decode(encoded).map_err(|_| Error::Material)?;
        // Vault aes256-gcm96: nonce (12) + 256-bit child (32) + GCM tag (16).
        if payload.len() != 60 || STANDARD.encode(&payload) != encoded {
            return Err(Error::Material);
        }
        Ok(())
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

    // Qualification probe for the complete canonical custody frame (including
    // its profile). Native derived context remains an UNQUALIFIED construction.
    pub(crate) fn open_bytes(&self, canonical: &[u8]) -> Result<Secret, Error> {
        if !self.active {
            return Err(Error::Material);
        }
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
        let custody = crate::fixture::custody_context(context);
        if self.generated_context.as_ref() != Some(&custody) {
            return Err(Error::Context);
        }
        self.open_bytes(&custody.canonical_bytes().map_err(|_| Error::Context)?)
    }
}

pub(crate) enum Source {
    Local(LocalFixture),
    Vault(Box<VaultFixture>),
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

impl NativeGeneration for VaultFixture {
    fn prepare_generation(&mut self, context: &CustodyContext) -> Result<(), Error> {
        self.prepare_native(context)
    }
    fn generate_wrapped(
        &mut self,
        context: &CustodyContext,
        envelope_ref: &WrappingIdentifier,
    ) -> Result<CustodyMaterialDescriptor, Error> {
        self.native_generate(context)?;
        Ok(CustodyMaterialDescriptor {
            context: context.clone(),
            envelope_ref: envelope_ref.clone(),
            envelope_sha256: digest(self.ciphertext.as_bytes()),
        })
    }
    fn activate_generated(&mut self) {
        self.active = true;
    }
}
impl NativeGeneration for Source {
    fn prepare_generation(&mut self, context: &CustodyContext) -> Result<(), Error> {
        match self {
            Self::Vault(source) => source.prepare_generation(context),
            Self::Local(_) => Err(Error::Context),
        }
    }
    fn generate_wrapped(
        &mut self,
        context: &CustodyContext,
        envelope_ref: &WrappingIdentifier,
    ) -> Result<CustodyMaterialDescriptor, Error> {
        match self {
            Self::Vault(source) => source.generate_wrapped(context, envelope_ref),
            // Software plaintext generation must not masquerade as native.
            Self::Local(_) => Err(Error::Context),
        }
    }
    fn activate_generated(&mut self) {
        if let Self::Vault(source) = self {
            source.activate_generated();
        }
    }
}
