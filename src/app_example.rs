//! KeyRack: Rust consuming application example
//!
//! This file demonstrates the target API for an application using the KeyRack
//! library. It is syntactically valid Rust but references the `keyrack` crate
//! which does not exist yet — this is the API we intend to build.

use keyrack::{attrs, KeyRack, Namespace, ResolvedKey, RoutingRule, UnwrapResult};

// ---------------------------------------------------------------------------
// Your application's data model (NOT part of KeyRack)
// ---------------------------------------------------------------------------

struct EncryptedDocument {
    id: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    /// The key version used at encryption time. Store this alongside every
    /// piece of encrypted data so decryption can target the correct version.
    ///
    /// You do NOT need to store the LID — the attributes that identify the
    /// key (tenant, user, doc ID, etc.) are your own domain data that you
    /// already know when you need to decrypt.
    key_version: u32,
}

// ---------------------------------------------------------------------------
// Helper: extract usable key bytes from a ResolvedKey regardless of backend
// ---------------------------------------------------------------------------

/// Convenience wrapper that handles both Transit and KMIP backends.
/// In a real app you'd typically use one path based on your deployment.
async fn get_key_bytes(resolved: &ResolvedKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match resolved.unwrap_result() {
        // Transit backend: the service already unwrapped; bytes are here.
        UnwrapResult::Executed(secret_bytes) => Ok(secret_bytes.to_vec()),

        // KMIP backend: we received operations to run against the HSM.
        // Key material never leaves the HSM boundary.
        UnwrapResult::Renderable(ops) => {
            let bytes = my_hsm_client::execute_kmip_ops(ops).await?;
            Ok(bytes)
        }
    }
}

// ===========================================================================
//  MAIN: application lifecycle
// ===========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -----------------------------------------------------------------------
    // 1. CONNECT TO KEYRACK
    // -----------------------------------------------------------------------

    let kr = KeyRack::builder()
        .service_url("https://keyrack.internal:8443")
        .build()
        .await?;

    // -----------------------------------------------------------------------
    // 2. REGISTER NAMESPACE (once per application, typically at deploy time)
    // -----------------------------------------------------------------------
    //
    // Routing rules define the key hierarchy AND the cryptographic parameters.
    // This is where crypto agility lives — update these rules to upgrade
    // algorithms for all newly created keys, without touching application code.

    kr.register_namespace(Namespace {
        name: "docs-app".into(),
        attachment: attrs! { tenant: "acme" }, // attach to infrastructure hierarchy
        rules: vec![
            // Document DEK → wrapped by user KEK
            RoutingRule::new(
                attrs! { kind: "dek", tenant: "$T", user: "$U", doc: "$D" },
                Some(attrs! { kind: "user-kek", tenant: "$T", user: "$U" }),
            ),
            // User KEK → wrapped by app root
            RoutingRule::new(
                attrs! { kind: "user-kek", tenant: "$T", user: "$U" },
                Some(attrs! { kind: "app-root", tenant: "$T" }),
            ),
            // App root → attached to infrastructure hierarchy
            RoutingRule::new(
                attrs! { kind: "app-root", tenant: "$T" },
                None, // parent resolved via attachment
            ),
        ],
    })
    .await?;

    // -----------------------------------------------------------------------
    // 3. ENCRYPT NEW DATA
    // -----------------------------------------------------------------------

    // Describe what this key is *for* using attributes. These are your own
    // domain concepts — KeyRack resolves them to the correct key, provisioning
    // the entire chain lazily if it doesn't exist yet.
    let resolved = kr
        .resolve(&attrs! {
            kind: "dek",
            tenant: "acme",
            user: "user-123",
            doc: "invoice-42",
        })
        .await?;

    // resolved.version() is the ONLY thing from KeyRack you need to persist.
    // The attributes (tenant, user, doc) are your own data — you already know
    // them when it's time to decrypt.
    let version = resolved.version();
    println!("Resolved key version: {}", version);

    // Get key material and encrypt
    let dek = get_key_bytes(&resolved).await?;
    let plaintext = b"sensitive invoice data";
    let (ciphertext, nonce) = my_crypto::aes_gcm_encrypt(&dek, plaintext)?;

    // Persist: ciphertext + nonce + version number
    let doc = EncryptedDocument {
        id: "invoice-42".into(),
        ciphertext,
        nonce,
        key_version: version,
    };
    my_database::store(&doc).await?;

    // -----------------------------------------------------------------------
    // 4. DECRYPT EXISTING DATA
    // -----------------------------------------------------------------------

    let doc = my_database::load("invoice-42").await?;

    // Reconstruct the same attributes (they're your domain data) and pass
    // the stored version to get the EXACT key material used at encryption.
    let resolved = kr
        .resolve_at_version(
            &attrs! {
                kind: "dek",
                tenant: "acme",
                user: "user-123",
                doc: "invoice-42",
            },
            doc.key_version,
        )
        .await?;

    let dek = get_key_bytes(&resolved).await?;
    let decrypted = my_crypto::aes_gcm_decrypt(&dek, &doc.ciphertext, &doc.nonce)?;
    assert_eq!(decrypted, plaintext);

    // For applications that don't store the version at all ("lazy mode"),
    // KeyRack can try versions from latest downward. This is viable when
    // rotation is infrequent — the performance cost is negligible:
    //
    //   let resolved = kr.resolve_try_versions(
    //       &attrs! { kind: "dek", tenant: "acme", user: "user-123", doc: "invoice-42" },
    //   ).await?;
    //   // Returns an iterator of ResolvedKey from latest version down to v1.
    //   // The app tries each until decryption succeeds.

    // -----------------------------------------------------------------------
    // 5. CRYPTO AGILITY
    // -----------------------------------------------------------------------
    //
    // Suppose the operator updates routing rules to use a stronger algorithm
    // (e.g. AES-128-GCM → AES-256-GCM, or to a post-quantum cipher).
    //
    // No application code changes. The routing rules are the single source
    // of truth for key specs:
    //
    //   - Existing keys: unchanged, still decryptable via stored version
    //   - New keys: automatically use the updated spec
    //
    // You can inspect what spec was used if you need to log it:

    let new_resolved = kr
        .resolve(&attrs! {
            kind: "dek",
            tenant: "acme",
            user: "user-456",
            doc: "invoice-99",
        })
        .await?;

    // The key spec is metadata returned alongside the key — never hard-coded.
    println!(
        "invoice-99 uses algorithm={}, key_size={}",
        new_resolved.key_spec().algorithm,
        new_resolved.key_spec().size,
    );

    // Both invoice-42 (old spec) and invoice-99 (new spec) decrypt correctly.
    // The stored version number is enough — KeyRack knows which algorithm and
    // parameters were used for each version.

    // -----------------------------------------------------------------------
    // 6. DATA RE-ENCRYPTION (the app's job during DEK rotation)
    // -----------------------------------------------------------------------
    //
    // KEK rotation (re-wrapping child keys) is handled entirely by the
    // KeyRack service — the app is not involved.
    //
    // DEK rotation is the app's responsibility: when KeyRack creates a new
    // version of a DEK, the app must re-encrypt its data with the new version.
    // This is typically run in a background worker, not the request path.

    let events = kr.poll_data_reencryption_jobs("docs-app").await?;

    for event in &events {
        // event.attributes(): which key was rotated (e.g. kind=dek, tenant=acme, ...)
        // event.old_version(): the version being retired
        // event.new_version(): the new current version
        kr.acknowledge_reencryption_job(&event.id()).await?;

        // Find all your data encrypted with the old DEK version.
        // This query is YOUR responsibility — only you know your data model.
        let affected = my_database::find_by_key_version(
            event.attributes(),
            event.old_version(),
        )
        .await?;

        for doc in &affected {
            // Decrypt with old version
            let old_key = kr
                .resolve_at_version(event.attributes(), doc.key_version)
                .await?;
            let old_dek = get_key_bytes(&old_key).await?;
            let plaintext =
                my_crypto::aes_gcm_decrypt(&old_dek, &doc.ciphertext, &doc.nonce)?;

            // Re-encrypt with new version
            let new_key = kr.resolve(event.attributes()).await?;
            let new_dek = get_key_bytes(&new_key).await?;
            let (new_ct, new_nonce) = my_crypto::aes_gcm_encrypt(&new_dek, &plaintext)?;

            // Update stored data with new ciphertext and new version
            my_database::update(&doc.id, &new_ct, &new_nonce, new_key.version()).await?;
        }

        kr.complete_reencryption_job(&event.id()).await?;
    }

    println!("Processed {} re-encryption jobs", events.len());
    Ok(())
}

// ===========================================================================
//  Placeholder modules — YOUR code, not part of KeyRack
// ===========================================================================

mod my_crypto {
    use std::error::Error;

    pub fn aes_gcm_encrypt(
        _key: &[u8],
        _plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        todo!("your AES-GCM encrypt implementation")
    }

    pub fn aes_gcm_decrypt(
        _key: &[u8],
        _ciphertext: &[u8],
        _nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        todo!("your AES-GCM decrypt implementation")
    }
}

mod my_hsm_client {
    use keyrack::RenderedOps;
    use std::error::Error;

    pub async fn execute_kmip_ops(_ops: &RenderedOps) -> Result<Vec<u8>, Box<dyn Error>> {
        todo!("execute KMIP operations against your HSM")
    }
}

mod my_database {
    use super::EncryptedDocument;
    use keyrack::Attributes;
    use std::error::Error;

    pub async fn store(_doc: &EncryptedDocument) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    pub async fn load(_id: &str) -> Result<EncryptedDocument, Box<dyn Error>> {
        todo!()
    }

    pub async fn find_by_key_version(
        _attrs: &Attributes,
        _version: u32,
    ) -> Result<Vec<EncryptedDocument>, Box<dyn Error>> {
        todo!()
    }

    pub async fn update(
        _id: &str,
        _ciphertext: &[u8],
        _nonce: &[u8],
        _key_version: u32,
    ) -> Result<(), Box<dyn Error>> {
        todo!()
    }
}
