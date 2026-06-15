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

//! Secret-reference resolution for provider credentials (HSM PIN custody,
//! Stage 1).
//!
//! A PKCS#11 provider PIN may be supplied either inline (`pin`, Model A
//! back-compat) or as a **reference** (`pin_ref: "file:<path>"`). References
//! are resolved KeyRack-side under a configurable allowlist root
//! (`KEYRACK_SECRET_ROOT`, default [`DEFAULT_SECRET_ROOT`]); the partner that
//! forwards the reference never reads the PIN bytes. The resolved PIN is a
//! [`SecretString`] (redacted by construction) and every resolution emits a
//! `secret_access` audit event.
//!
//! Errors carry only the reference path + allowlist root — never PIN bytes.
//! See `keyrack-internal/docs/architecture/adr-0001-hsm-pin-custody.md`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrack_core::audit::{
    AuditAction, AuditEvent, AuditPrincipal, AuditResource, AuditResult, AuditSink, EventType,
};
use keyrack_core::secret::SecretString;

/// Default allowlist root for `file:` secret references. Operators provision
/// PIN files here via a secret mount (K8s Secret / Vault Agent / CSI volume).
pub const DEFAULT_SECRET_ROOT: &str = "/etc/keyrack/secrets";

/// Environment variable overriding [`DEFAULT_SECRET_ROOT`].
pub const SECRET_ROOT_ENV: &str = "KEYRACK_SECRET_ROOT";

/// Failure resolving a secret reference. `Display` NEVER includes secret bytes
/// — only the reference and the allowlist root, for operator diagnosis.
#[derive(Debug)]
pub enum SecretRefError {
    /// The reference did not use a supported scheme (only `file:` today).
    UnsupportedScheme { reference: String },
    /// The allowlist root itself could not be resolved (missing/unreadable).
    RootUnavailable { root: String, source: String },
    /// The resolved path escapes the allowlist root.
    OutsideAllowlist { reference: String, root: String },
    /// The referenced file does not exist (or is not reachable) under the root.
    NotFound { reference: String, root: String },
    /// The referenced file could not be read.
    Io { reference: String, source: String },
    /// The referenced file was not valid UTF-8.
    NotUtf8 { reference: String },
    /// The referenced file was empty after trimming.
    Empty { reference: String },
}

impl std::fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedScheme { reference } => write!(
                f,
                "unsupported secret reference '{reference}': only 'file:<path>' is supported"
            ),
            Self::RootUnavailable { root, source } => write!(
                f,
                "secret allowlist root '{root}' is unavailable ({source}); \
                 set {SECRET_ROOT_ENV} or create the directory"
            ),
            Self::OutsideAllowlist { reference, root } => write!(
                f,
                "secret reference '{reference}' resolves outside the allowlist root '{root}'"
            ),
            Self::NotFound { reference, root } => write!(
                f,
                "secret reference '{reference}' not found under allowlist root '{root}'"
            ),
            Self::Io { reference, source } => {
                write!(f, "failed to read secret reference '{reference}': {source}")
            }
            Self::NotUtf8 { reference } => {
                write!(f, "secret reference '{reference}' is not valid UTF-8")
            }
            Self::Empty { reference } => {
                write!(f, "secret reference '{reference}' is empty")
            }
        }
    }
}

impl std::error::Error for SecretRefError {}

/// The configured allowlist root (`KEYRACK_SECRET_ROOT` or the default).
#[must_use]
pub fn secret_root() -> PathBuf {
    std::env::var(SECRET_ROOT_ENV)
        .map_or_else(|_| PathBuf::from(DEFAULT_SECRET_ROOT), PathBuf::from)
}

/// Resolve a `file:` PIN reference under the given allowlist root.
///
/// Relative paths are joined to the root; absolute paths are accepted only if
/// they canonicalize within the root. Canonicalization defeats `..` traversal
/// and symlink escape. Returns the file contents (one trailing newline
/// trimmed) wrapped in a redacting [`SecretString`].
pub fn resolve_pin_ref_under(reference: &str, root: &Path) -> Result<SecretString, SecretRefError> {
    let raw = reference
        .strip_prefix("file:")
        .ok_or_else(|| SecretRefError::UnsupportedScheme {
            reference: reference.to_string(),
        })?;
    // Tolerate the file://<path> form as well as file:<path>.
    let raw = raw.strip_prefix("//").unwrap_or(raw);
    let candidate = Path::new(raw);

    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };

    let canon_root = root
        .canonicalize()
        .map_err(|e| SecretRefError::RootUnavailable {
            root: root.display().to_string(),
            source: e.to_string(),
        })?;

    let canon_file = joined.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SecretRefError::NotFound {
                reference: reference.to_string(),
                root: canon_root.display().to_string(),
            }
        } else {
            SecretRefError::Io {
                reference: reference.to_string(),
                source: e.to_string(),
            }
        }
    })?;

    if !canon_file.starts_with(&canon_root) {
        return Err(SecretRefError::OutsideAllowlist {
            reference: reference.to_string(),
            root: canon_root.display().to_string(),
        });
    }

    let bytes = std::fs::read(&canon_file).map_err(|e| SecretRefError::Io {
        reference: reference.to_string(),
        source: e.to_string(),
    })?;

    let mut pin = String::from_utf8(bytes).map_err(|_| SecretRefError::NotUtf8 {
        reference: reference.to_string(),
    })?;

    // Trim a single trailing newline (\n or \r\n) — secret files commonly have
    // one — but preserve any other (potentially significant) characters.
    if pin.ends_with('\n') {
        pin.pop();
        if pin.ends_with('\r') {
            pin.pop();
        }
    }

    if pin.is_empty() {
        return Err(SecretRefError::Empty {
            reference: reference.to_string(),
        });
    }

    Ok(SecretString::new(pin))
}

/// Resolve a PKCS#11 provider PIN from exactly one of `pin` (inline) or
/// `pin_ref` (a `file:` reference). Emits a `secret_access` audit event for
/// every `pin_ref` resolution (success or failure).
///
/// `phase` is the resolution context (`"construct"`, `"rehydrate"`, `"use"`).
pub async fn resolve_pkcs11_pin(
    provider_name: &str,
    pin: Option<&SecretString>,
    pin_ref: Option<&str>,
    phase: &str,
    audit: &Arc<dyn AuditSink>,
) -> Result<SecretString, Box<dyn std::error::Error>> {
    resolve_pkcs11_pin_under(provider_name, pin, pin_ref, phase, &secret_root(), audit).await
}

/// As [`resolve_pkcs11_pin`], but with an explicit allowlist `root` (rather than
/// reading [`secret_root`]). Lets tests exercise the resolution + audit path
/// deterministically without mutating process-global environment.
pub async fn resolve_pkcs11_pin_under(
    provider_name: &str,
    pin: Option<&SecretString>,
    pin_ref: Option<&str>,
    phase: &str,
    root: &Path,
    audit: &Arc<dyn AuditSink>,
) -> Result<SecretString, Box<dyn std::error::Error>> {
    match (pin, pin_ref) {
        (Some(_), Some(_)) => Err(format!(
            "pkcs11 provider '{provider_name}': set exactly one of `pin` or `pin_ref`, not both"
        )
        .into()),
        (None, None) => Err(format!(
            "pkcs11 provider '{provider_name}': a PIN is required — set inline `pin` \
             or a `pin_ref: \"file:<path>\"` reference"
        )
        .into()),
        // Model A (back-compat): inline PIN. No file read, no secret_access event.
        (Some(inline), None) => Ok(inline.clone()),
        // Model C/D: reference resolved KeyRack-side under the allowlist root.
        (None, Some(reference)) => match resolve_pin_ref_under(reference, root) {
            Ok(secret) => {
                emit_secret_access(audit, provider_name, reference, phase, Ok(())).await;
                Ok(secret)
            }
            Err(e) => {
                let reason = e.to_string();
                emit_secret_access(audit, provider_name, reference, phase, Err(&reason)).await;
                Err(format!("pkcs11 provider '{provider_name}': {reason}").into())
            }
        },
    }
}

/// Emit a structured `secret_access` audit event. The event records the
/// reference, provider, phase, and result — never the PIN bytes.
async fn emit_secret_access(
    audit: &Arc<dyn AuditSink>,
    provider_name: &str,
    reference: &str,
    phase: &str,
    result: Result<(), &str>,
) {
    let audit_result = if result.is_ok() {
        AuditResult::Success
    } else {
        AuditResult::Error
    };

    let mut event = AuditEvent::new(
        EventType::SecretAccess,
        AuditAction::AccessSecret,
        AuditPrincipal {
            id: keyrack_core::pdp::SYSTEM_PRINCIPAL_ID.to_string(),
            principal_type: "System".to_string(),
        },
        AuditResource {
            id: provider_name.to_string(),
            resource_type: "hsm_provider".to_string(),
        },
        audit_result,
    );
    event.metadata.insert("secret_ref".into(), reference.into());
    event.metadata.insert("phase".into(), phase.into());
    event
        .metadata
        .insert("provider_ref".into(), provider_name.into());
    if let Err(reason) = result {
        event.metadata.insert("error".into(), reason.into());
    }

    if let Err(e) = audit.emit(&event).await {
        tracing::error!(error = %e, provider = %provider_name, "failed to emit secret_access audit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp directory, removed on drop (no external test-only deps).
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let p =
                std::env::temp_dir().join(format!("keyrack-secretref-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolves_relative_reference_under_root() {
        let dir = TempRoot::new();
        dir.write("tenant-a.pin", b"1234\n");
        let secret = resolve_pin_ref_under("file:tenant-a.pin", dir.path()).unwrap();
        assert_eq!(secret.expose(), "1234");
    }

    #[test]
    fn resolves_absolute_reference_within_root() {
        let dir = TempRoot::new();
        let p = dir.write("abs.pin", b"abcd");
        let reference = format!("file:{}", p.display());
        let secret = resolve_pin_ref_under(&reference, dir.path()).unwrap();
        assert_eq!(secret.expose(), "abcd");
    }

    #[test]
    fn trims_only_one_trailing_newline() {
        let dir = TempRoot::new();
        dir.write("crlf.pin", b"pw\r\n");
        assert_eq!(
            resolve_pin_ref_under("file:crlf.pin", dir.path())
                .unwrap()
                .expose(),
            "pw"
        );
        dir.write("two.pin", b"pw\n\n");
        assert_eq!(
            resolve_pin_ref_under("file:two.pin", dir.path())
                .unwrap()
                .expose(),
            "pw\n"
        );
    }

    #[test]
    fn rejects_traversal_outside_root() {
        let root = TempRoot::new();
        let outside = TempRoot::new();
        outside.write("secret.pin", b"leak");
        let reference = format!("file:{}/secret.pin", outside.path().display());
        let err = resolve_pin_ref_under(&reference, root.path()).unwrap_err();
        assert!(matches!(err, SecretRefError::OutsideAllowlist { .. }));
        // The error must not leak the secret bytes.
        assert!(!err.to_string().contains("leak"));
    }

    #[test]
    fn rejects_dotdot_escape() {
        let root = TempRoot::new();
        let child = root.path().join("nested");
        std::fs::create_dir(&child).unwrap();
        let outside = TempRoot::new();
        outside.write("x.pin", b"leak");
        let reference = format!("file:{}/x.pin", outside.path().display());
        let err = resolve_pin_ref_under(&reference, &child).unwrap_err();
        assert!(matches!(err, SecretRefError::OutsideAllowlist { .. }));
    }

    #[test]
    fn missing_file_is_not_found() {
        let dir = TempRoot::new();
        let err = resolve_pin_ref_under("file:nope.pin", dir.path()).unwrap_err();
        assert!(matches!(err, SecretRefError::NotFound { .. }));
    }

    #[test]
    fn empty_file_rejected() {
        let dir = TempRoot::new();
        dir.write("empty.pin", b"\n");
        let err = resolve_pin_ref_under("file:empty.pin", dir.path()).unwrap_err();
        assert!(matches!(err, SecretRefError::Empty { .. }));
    }

    #[test]
    fn non_file_scheme_rejected() {
        let dir = TempRoot::new();
        let err = resolve_pin_ref_under("env:SOME_PIN", dir.path()).unwrap_err();
        assert!(matches!(err, SecretRefError::UnsupportedScheme { .. }));
    }

    // ---- resolve_pkcs11_pin_under: inline-vs-ref selection + audit emission ----

    /// Captures emitted audit events for assertion.
    struct CapturingSink(std::sync::Mutex<Vec<AuditEvent>>);

    impl CapturingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self(std::sync::Mutex::new(Vec::new())))
        }
        fn events(&self) -> Vec<AuditEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuditSink for CapturingSink {
        async fn emit(&self, event: &AuditEvent) -> keyrack_core::error::Result<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn inline_pin_returns_pin_and_emits_no_event() {
        let dir = TempRoot::new();
        let sink = CapturingSink::new();
        let audit: Arc<dyn AuditSink> = sink.clone();
        let inline = SecretString::new("inline-pin");
        let resolved = resolve_pkcs11_pin_under(
            "tenant-a-hsm",
            Some(&inline),
            None,
            "construct",
            dir.path(),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(resolved.expose(), "inline-pin");
        // Model A: no file read, no secret_access event.
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn both_pin_and_ref_is_error() {
        let dir = TempRoot::new();
        let sink = CapturingSink::new();
        let audit: Arc<dyn AuditSink> = sink.clone();
        let inline = SecretString::new("x");
        let err = resolve_pkcs11_pin_under(
            "p",
            Some(&inline),
            Some("file:a.pin"),
            "construct",
            dir.path(),
            &audit,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"));
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn neither_pin_nor_ref_is_error() {
        let dir = TempRoot::new();
        let sink = CapturingSink::new();
        let audit: Arc<dyn AuditSink> = sink.clone();
        let err = resolve_pkcs11_pin_under("p", None, None, "construct", dir.path(), &audit)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("PIN is required"));
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn pin_ref_resolution_emits_secret_access_event() {
        let dir = TempRoot::new();
        dir.write("tenant-a.pin", b"s3cr3t\n");
        let sink = CapturingSink::new();
        let audit: Arc<dyn AuditSink> = sink.clone();

        let resolved = resolve_pkcs11_pin_under(
            "tenant-a-hsm",
            None,
            Some("file:tenant-a.pin"),
            "construct",
            dir.path(),
            &audit,
        )
        .await
        .unwrap();
        assert_eq!(resolved.expose(), "s3cr3t");

        let events = sink.events();
        assert_eq!(events.len(), 1, "exactly one secret_access event");
        let ev = &events[0];
        assert_eq!(ev.event_type, EventType::SecretAccess);
        assert_eq!(ev.action, AuditAction::AccessSecret);
        assert_eq!(ev.result, AuditResult::Success);
        assert_eq!(ev.resource.resource_type, "hsm_provider");
        assert_eq!(ev.resource.id, "tenant-a-hsm");
        assert_eq!(ev.principal.principal_type, "System");
        assert_eq!(ev.metadata["secret_ref"], "file:tenant-a.pin");
        assert_eq!(ev.metadata["phase"], "construct");
        assert_eq!(ev.metadata["provider_ref"], "tenant-a-hsm");
        assert!(ev.metadata.get("error").is_none());

        // The serialized event must NEVER contain the PIN bytes.
        let json = serde_json::to_string(ev).unwrap();
        assert!(!json.contains("s3cr3t"), "audit event leaked PIN: {json}");
    }

    #[tokio::test]
    async fn pin_ref_failure_emits_error_event_without_leaking() {
        let dir = TempRoot::new();
        // Reference a file that does not exist under the root.
        let sink = CapturingSink::new();
        let audit: Arc<dyn AuditSink> = sink.clone();

        let err = resolve_pkcs11_pin_under(
            "tenant-b-hsm",
            None,
            Some("file:missing.pin"),
            "rehydrate",
            dir.path(),
            &audit,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not found"));

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.event_type, EventType::SecretAccess);
        assert_eq!(ev.result, AuditResult::Error);
        assert_eq!(ev.metadata["phase"], "rehydrate");
        assert!(ev.metadata.get("error").is_some());
    }
}
