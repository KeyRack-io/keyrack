// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local validation and deferred construction of configured external backends.

use crate::config::ProviderConfig;
use crate::deferred_provider::{
    blocking_factory, AvailabilityProbe, DeferredProvider, ProviderFactory,
};
use keyrack_core::audit::AuditSink;
use keyrack_core::key::{KeySpec, ProviderClass};
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, KeySpecCapability, ProviderCapabilities,
};
use std::sync::Arc;

/// Validate local inputs before allowing a remote failure to be deferred.
/// Backend authentication is deliberately not part of this validation.
pub fn validate_remote_config(config: &ProviderConfig) -> Result<(), String> {
    match config {
        ProviderConfig::VaultTransit {
            vault_addr,
            vault_token,
            mount_path,
        } => {
            let url = reqwest::Url::parse(vault_addr).map_err(|_| "invalid Vault address")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("invalid Vault address: expected an HTTP(S) origin without credentials, query or fragment".into());
            }
            reqwest::header::HeaderValue::from_str(vault_token)
                .map_err(|_| "invalid Vault token header")?;
            if vault_token.is_empty() {
                return Err("Vault token must not be empty".into());
            }
            let mount = mount_path.as_deref().unwrap_or("transit");
            if mount
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || mount
                    .chars()
                    .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '/' | '_' | '-'))
            {
                return Err("invalid Vault mount path".into());
            }
        }
        ProviderConfig::Pkcs11 {
            lib_path,
            token_label,
            token_label_ref,
            pin,
            pin_ref,
        } => {
            if token_label.is_empty() == token_label_ref.is_none() {
                return Err("set exactly one of token_label or token_label_ref".into());
            }
            if pin.is_some() == pin_ref.is_some() {
                return Err("set exactly one of pin or pin_ref".into());
            }
            if pin.as_ref().is_some_and(|value| value.expose().is_empty()) {
                return Err("PKCS#11 PIN must not be empty".into());
            }
            // Loading the local module and its function table is independent
            // of token discovery, initialization, sessions and authentication.
            // A module's own error is not a local path/configuration failure.
            if let Err(
                cryptoki::error::Error::LibraryLoading(_)
                | cryptoki::error::Error::NullFunctionPointer,
            ) = cryptoki::context::Pkcs11::new(lib_path)
            {
                return Err("invalid PKCS#11 library: cannot load module/function table".into());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Static algorithm declarations used before a token or server is reachable.
/// Integration checks compare these with each constructed provider's public
/// capabilities. No cryptographic or live-readiness claim follows from them.
pub fn remote_capabilities(class: ProviderClass) -> ProviderCapabilities {
    use CryptoOperation::{
        Decrypt, DestroyKey, Encrypt, GenerateDataKey, GenerateKey, ReEncrypt, Sign, Verify,
    };
    let vault = class == ProviderClass::VaultTransit;
    let mut symmetric = vec![GenerateKey, Encrypt, Decrypt];
    if !vault {
        symmetric.extend([GenerateDataKey, ReEncrypt]);
    }
    symmetric.push(DestroyKey);
    let signing = vec![GenerateKey, Sign, Verify, DestroyKey];
    let mut key_specs = vec![
        KeySpecCapability {
            key_spec: KeySpec::Aes256,
            operations: symmetric,
        },
        KeySpecCapability {
            key_spec: KeySpec::Ed25519,
            operations: signing.clone(),
        },
        KeySpecCapability {
            key_spec: KeySpec::EcdsaP256Sha256,
            operations: signing.clone(),
        },
        KeySpecCapability {
            key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
            operations: signing.clone(),
        },
    ];
    if vault {
        key_specs.push(KeySpecCapability {
            key_spec: KeySpec::RsaPssSha256 { key_size: 2048 },
            operations: signing,
        });
    }
    ProviderCapabilities {
        provider_name: if vault { "vault-transit" } else { "pkcs11" }.into(),
        key_specs,
        supports_generate_random: true,
        supports_atomic_data_key: false,
        supports_atomic_re_encrypt: false,
        supports_key_import: vault,
    }
}

/// Return a wrapper for the eagerly connecting provider types. Other types
/// have no remote constructor and can be passed through `defer_ready_provider`.
pub async fn defer_remote_provider(
    name: &str,
    config: &ProviderConfig,
    audit: &Arc<dyn AuditSink>,
) -> Result<Option<(Arc<dyn CryptoProvider>, ProviderClass)>, Box<dyn std::error::Error>> {
    validate_remote_config(config)?;
    let (class, factory, probe): (ProviderClass, ProviderFactory, Option<AvailabilityProbe>) =
        match config {
            ProviderConfig::VaultTransit {
                vault_addr,
                vault_token,
                mount_path,
            } => {
                let addr = vault_addr.clone();
                let token = keyrack_core::secret::SecretString::new(vault_token.clone());
                let mount = mount_path.clone();
                let factory: ProviderFactory = Arc::new(move || {
                    let addr = addr.clone();
                    let token = token.clone();
                    let mount = mount.clone();
                    Box::pin(async move {
                        let provider = keyrack_vault::VaultTransitProvider::new(
                            &addr,
                            token.expose(),
                            mount.as_deref(),
                        )
                        .await?;
                        Ok(Arc::new(provider) as Arc<dyn CryptoProvider>)
                    })
                });
                // Vault currently inherits a no-op readiness method. Its public
                // constructor performs a read-only mount-tuning request, so use
                // that same authenticated probe without changing the provider.
                let health_factory = factory.clone();
                let probe: AvailabilityProbe = Arc::new(move || {
                    let health_factory = health_factory.clone();
                    Box::pin(async move { health_factory().await.map(|_| ()) })
                });
                (ProviderClass::VaultTransit, factory, Some(probe))
            }
            ProviderConfig::Pkcs11 {
                lib_path,
                token_label,
                token_label_ref,
                pin,
                pin_ref,
            } => {
                let label = if let Some(reference) = token_label_ref {
                    crate::secret_ref::resolve_pin_ref_under(
                        reference,
                        &crate::secret_ref::secret_root(),
                    )?
                    .expose()
                    .to_owned()
                } else {
                    token_label.clone()
                };
                let pin = crate::secret_ref::resolve_pkcs11_pin(
                    name,
                    pin.as_ref(),
                    pin_ref.as_deref(),
                    "construct",
                    audit,
                )
                .await?;
                let library = lib_path.clone();
                let factory = blocking_factory(move || {
                    let provider = keyrack_pkcs11::Pkcs11Provider::new(
                        &keyrack_pkcs11::Pkcs11ProviderConfig {
                            lib_path: library.clone(),
                            token_label: label.clone(),
                            pin: pin.expose().to_owned(),
                        },
                    )?;
                    Ok(Arc::new(provider) as Arc<dyn CryptoProvider>)
                });
                (ProviderClass::Pkcs11, factory, None)
            }
            _ => return Ok(None),
        };
    Ok(Some((
        Arc::new(DeferredProvider::new(
            name.to_owned(),
            remote_capabilities(class),
            factory,
            probe,
        )),
        class,
    )))
}

pub fn defer_ready_provider(
    name: &str,
    provider: Arc<dyn CryptoProvider>,
) -> Arc<dyn CryptoProvider> {
    let capabilities = provider.capabilities();
    let factory: ProviderFactory = Arc::new(move || {
        let provider = provider.clone();
        Box::pin(async move { Ok(provider) })
    });
    Arc::new(DeferredProvider::new(
        name.to_owned(),
        capabilities,
        factory,
        None,
    ))
}
