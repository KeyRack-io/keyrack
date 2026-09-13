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

//! PKCS#11 `CryptoProvider` implementation.

use crate::ecdsa_der;
use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use keyrack_core::error::{KeyRackError, Result};
use keyrack_core::key::KeySpec;
use keyrack_core::provider::{
    CryptoOperation, CryptoProvider, EncryptOutput, KeyHandle, KeySpecCapability,
    ProviderCapabilities, SigningAlgorithm,
};
use keyrack_core::sensitive::Sensitive;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// DER-encoded OID for P-256 (secp256r1): 1.2.840.10045.3.1.7
const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// DER-encoded OID for Ed25519: 1.3.101.112
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// P-256 ECDSA component size in bytes.
const P256_COMPONENT_LEN: usize = 32;

fn make_auth_pin(pin: &str) -> AuthPin {
    AuthPin::new(pin.to_owned().into_boxed_str())
}

/// Classify a cryptoki error as a transient HSM connectivity/session failure.
///
/// `GeneralError` is included because that is what a module reports once its
/// in-memory view of a token has been invalidated — the token going away under
/// a live module wedges it, and every later call on that slot fails this way
/// even after the token comes back. It is a connectivity fault, not a
/// permanent provider defect, so it must read as "unavailable, retry" rather
/// than "broken build".
///
/// `CryptokiNotInitialized` is included for a sharper reason: it is a state
/// *recovery itself creates*. An attempt finalizes the library and then fails
/// to initialize it, and every call arriving afterwards reports this until an
/// attempt succeeds. Reading it as a permanent provider defect told callers
/// their request could never work, when in fact only a reinitialization stood
/// between them and a healthy token.
fn is_transient_pkcs11_error(e: &cryptoki::error::Error) -> bool {
    matches!(
        e,
        cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::DeviceError
                | cryptoki::error::RvError::DeviceRemoved
                | cryptoki::error::RvError::TokenNotPresent
                | cryptoki::error::RvError::SessionClosed
                | cryptoki::error::RvError::SessionHandleInvalid
                | cryptoki::error::RvError::SlotIdInvalid
                | cryptoki::error::RvError::CryptokiNotInitialized
                | cryptoki::error::RvError::GeneralError,
            _,
        )
    )
}

/// Map a cryptoki error to the appropriate `KeyRackError` variant,
/// distinguishing transient HSM failures from permanent provider errors.
fn map_pkcs11_error(context: &str, e: &cryptoki::error::Error) -> KeyRackError {
    if is_transient_pkcs11_error(e) {
        KeyRackError::ProviderUnavailable(format!("{context}: {e}"))
    } else {
        KeyRackError::Provider(format!("{context}: {e}"))
    }
}

/// Whether a failure could be the module's stale view of its token rather than
/// something about the request itself.
///
/// Deliberately not the `ProviderUnavailable`-versus-`Provider` distinction.
/// That one exists to tell a client whether retrying is worthwhile, and it is
/// derived from the return code the module chose — so gating recovery on it
/// made the mechanism depend on a vendor's choice of code. `SoftHSM` answers
/// `CKR_GENERAL_ERROR` for a token it has lost, which maps to a retryable
/// failure and recovers; a module answering a code that maps to a permanent
/// fault would never have had recovery attempted at all, which is how a
/// rotation after custody returned could report a permanent provider error
/// while an encrypt on the same token recovered.
///
/// Both provider-side variants therefore reach the recovery path. A request
/// that is simply invalid can now provoke at most one reinitialization per
/// library per interval, which is latency for the tokens sharing that library;
/// a token that never comes back is worse.
fn may_be_module_failure(error: &KeyRackError) -> bool {
    matches!(
        error,
        KeyRackError::Provider(_) | KeyRackError::ProviderUnavailable(_)
    )
}

/// Shortest interval between two module reinitializations, per library.
///
/// A reinitialization is process-wide for the library, so while custody is
/// still absent — when it cannot possibly succeed — repeating it per request
/// would keep interrupting the providers that are still healthy. One attempt
/// per interval bounds that to a rare event while still restoring service
/// within a few seconds of custody actually returning.
const MIN_REINIT_INTERVAL: Duration = Duration::from_secs(2);

/// How long recovery waits for in-flight calls to drain before giving up.
///
/// If the module does not go quiet in this time, recovery is abandoned rather
/// than forced: see [`Gate`] for why finalizing under active calls is not an
/// option.
const QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);

/// Admission control for one PKCS#11 library, so that it can be reinitialized
/// with no call in flight.
///
/// `C_Finalize` may not be called while other threads are inside the library
/// — PKCS#11 puts that on the application, and a module that is finalized
/// under active calls does not return an error, it takes the process down.
/// So every call registers here for its duration, and recovery closes the
/// gate and waits for the count to reach zero before finalizing. If it never
/// reaches zero, recovery is skipped: a token that stays unavailable is a far
/// better outcome than a crash that takes every other provider with it.
struct Gate {
    inner: Mutex<GateState>,
    changed: Condvar,
    /// How long recovery waits for the module to go quiet. A field rather than
    /// a constant so tests can drive the admission behaviour without waiting
    /// the production value.
    quiesce_timeout: Duration,
}

#[derive(Default)]
struct GateState {
    in_flight: usize,
    closed: bool,
}

/// Registers one in-flight call for as long as it is held.
struct InFlight<'a> {
    gate: &'a Gate,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.inner.lock() {
            state.in_flight -= 1;
            if state.in_flight == 0 {
                self.gate.changed.notify_all();
            }
        }
    }
}

/// Holds the gate closed, with the module guaranteed quiet, for as long as it
/// is held.
struct Quiesced<'a> {
    gate: &'a Gate,
}

impl Drop for Quiesced<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.gate.inner.lock() {
            state.closed = false;
        }
        self.gate.changed.notify_all();
    }
}

impl Gate {
    fn new() -> Self {
        Self::with_quiesce_timeout(QUIESCE_TIMEOUT)
    }

    fn with_quiesce_timeout(quiesce_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(GateState::default()),
            changed: Condvar::new(),
            quiesce_timeout,
        }
    }

    /// How long a caller waits for a recovery window to end before giving up.
    ///
    /// This must exceed the longest window recovery can legitimately hold, or
    /// a caller can time out at the very moment the window closes and be told
    /// its healthy token is unavailable. The window is bounded by the drain
    /// wait plus the reinitialization itself, so twice the drain wait clears it
    /// with room to spare while still bounding the wait on a gate that nobody
    /// is going to reopen.
    fn admission_timeout(&self) -> Duration {
        self.quiesce_timeout * 2
    }

    /// Admit one call, waiting while the module is being reinitialized.
    ///
    /// A caller blocked here is a caller whose own token may be perfectly
    /// healthy — reinitializing is per library, not per token — so waiting for
    /// the window is the right answer and refusing is the wrong one.
    fn enter(&self) -> Result<InFlight<'_>> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KeyRackError::Provider("PKCS#11 module gate poisoned".into()))?;
        let deadline = Instant::now() + self.admission_timeout();
        while state.closed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(KeyRackError::ProviderUnavailable(
                    "PKCS#11 module is being reinitialized and did not become available".into(),
                ));
            }
            let (guard, _) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| KeyRackError::Provider("PKCS#11 module gate poisoned".into()))?;
            state = guard;
        }
        state.in_flight += 1;
        Ok(InFlight { gate: self })
    }

    /// Close the gate and wait for the module to go quiet.
    ///
    /// `None` means it did not, and the caller must not finalize.
    fn quiesce(&self) -> Option<Quiesced<'_>> {
        let mut state = self.inner.lock().ok()?;
        state.closed = true;

        let deadline = Instant::now() + self.quiesce_timeout;
        while state.in_flight > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.closed = false;
                drop(state);
                self.changed.notify_all();
                return None;
            }
            let (guard, _) = self.changed.wait_timeout(state, remaining).ok()?;
            state = guard;
        }

        drop(state);
        Some(Quiesced { gate: self })
    }
}

/// An initialized PKCS#11 module, shared by every provider on that library.
///
/// PKCS#11 permits `C_Initialize` only once per library per process, so
/// providers backed by the same `.so` (several tokens / HSM partitions driven
/// by one vendor library) share this and select different slots.
///
/// The module also owns recovery, because that is the granularity the
/// operation has: reinitializing is the only way to clear a module's stale
/// view of a token, and it affects every provider on the library at once.
/// Keeping it here means concurrent failures collapse into one attempt
/// instead of one per provider.
struct SharedModule {
    lib_path: String,
    ctx: Pkcs11,
    /// Advanced by each successful reinitialization. A caller that saw a
    /// failure under generation *n* and finds the generation already past *n*
    /// knows someone else recovered, and can simply retry.
    generation: AtomicU64,
    gate: Gate,
    reinit: Mutex<LastReinit>,
}

/// What a recovery attempt did.
///
/// Recovery used to answer yes or no, which made "reinitialized", "not
/// attempted because one ran moments ago", "abandoned because calls would not
/// drain" and "attempted, and the library is now down" indistinguishable — to
/// the caller, to the logs and to a test. That gap is why a failure in the
/// field could not be attributed without another host's logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryOutcome {
    /// This call reinitialized the module.
    Reinitialized,
    /// Another caller reinitialized it after this failure was seen.
    AlreadyRecovered,
    /// Not attempted: one ran within [`MIN_REINIT_INTERVAL`].
    DeferredByInterval,
    /// Attempted and abandoned: calls inside the library would not drain, and
    /// finalizing under them would take the process down.
    NotQuiesced,
    /// Attempted, and `C_Finalize` did not take effect, so the library could
    /// not be reinitialized. It is still initialized; nothing was recovered.
    NotFinalized,
    /// Attempted, and the library is now **finalized and not initialized**:
    /// every call on it will report that until an attempt succeeds.
    ModuleDown,
}

impl RecoveryOutcome {
    /// Whether the caller may retry its operation now.
    fn permits_retry(self) -> bool {
        matches!(self, Self::Reinitialized | Self::AlreadyRecovered)
    }

    /// The reason, for a log field and for the caller's message.
    fn reason(self) -> &'static str {
        match self {
            Self::Reinitialized => "module reinitialized",
            Self::AlreadyRecovered => "another caller reinitialized the module",
            Self::DeferredByInterval => "deferred: a reinitialization ran moments ago",
            Self::NotQuiesced => "abandoned: calls inside the library did not drain",
            Self::NotFinalized => "the library could not be finalized, so not reinitialized",
            Self::ModuleDown => "the library is finalized and could not be initialized",
        }
    }
}

/// The failure to report when recovery did not complete.
///
/// Every outcome here is temporary by construction: the interval expires, calls
/// in the library finish, a later attempt can initialize. So the answer must be
/// the retryable one. Returning the operation's original failure instead is what
/// turned a deferred recovery into a permanent error at the client — a client
/// whose retry policy keys on the retryable status stops after one attempt, and
/// no retry budget can rescue it. The original failure is kept in the message,
/// where it is diagnostic rather than decisive.
fn recovery_pending_error(outcome: RecoveryOutcome, original: &KeyRackError) -> KeyRackError {
    KeyRackError::ProviderUnavailable(format!(
        "PKCS#11 module recovery incomplete ({}); retry. Underlying failure: {original}",
        outcome.reason()
    ))
}

struct LastReinit {
    at: Option<Instant>,
    /// Set when an attempt left the library finalized and not initialized.
    ///
    /// While it holds, the interval does not apply. Rationing exists to keep
    /// reinitializations from disrupting the providers still using the library,
    /// and a library that is not initialized has none to disrupt: every call on
    /// it fails until an attempt succeeds. Deferring in that state defers the
    /// only thing that can help.
    left_uninitialized: bool,
}

impl LastReinit {
    /// Whether the interval since the last attempt has elapsed.
    fn may_attempt_now(&self) -> bool {
        if self.left_uninitialized {
            return true;
        }
        match self.at {
            Some(at) => at.elapsed() >= MIN_REINIT_INTERVAL,
            None => true,
        }
    }

    /// Record that an attempt has run. Called when the attempt finishes, never
    /// before it starts: an attempt that was abandoned without touching the
    /// library has not spent what the interval exists to ration, and arming
    /// the window up front meant a skipped recovery suppressed the next real
    /// one. Recording afterwards also makes an abandoned attempt
    /// self-limiting, because giving up on the drain already takes longer than
    /// the interval.
    fn record_attempt(&mut self) {
        self.at = Some(Instant::now());
    }
}

impl SharedModule {
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Reinitialize the library so it re-reads the tokens present now.
    ///
    /// `C_Finalize` + `C_Initialize` is deliberate: it runs on the *same*
    /// loaded library, so every provider's existing handle and slot stay
    /// valid and no provider has to be rebuilt. Unloading the library instead
    /// would only work once every clone had been dropped, which no provider
    /// can guarantee for another.
    ///
    /// Reports what it did, so the caller can answer accurately and an
    /// operator can tell a deferred attempt from a failed one.
    fn recover(&self, seen_generation: u64) -> RecoveryOutcome {
        let Ok(mut last) = self.reinit.lock() else {
            // A poisoned lock means an earlier attempt panicked mid-way, so
            // the library's state is unknown and this is not a deferral.
            return RecoveryOutcome::NotFinalized;
        };

        // Another caller already recovered this failure out from under us.
        if self.generation() != seen_generation {
            return RecoveryOutcome::AlreadyRecovered;
        }

        if !last.may_attempt_now() {
            return RecoveryOutcome::DeferredByInterval;
        }

        tracing::warn!(
            lib_path = %self.lib_path,
            "PKCS#11 module reported an unusable token; reinitializing the library"
        );

        // Finalizing while another thread is inside the library crashes the
        // process, so recovery only proceeds once the module is quiet.
        let Some(_quiesced) = self.gate.quiesce() else {
            // Nothing was touched, so the interval is not armed: the next
            // failure may try again as soon as the module goes quiet.
            tracing::error!(
                lib_path = %self.lib_path,
                "PKCS#11 calls did not drain; skipping reinitialization rather than \
                 finalizing the library under them"
            );
            return RecoveryOutcome::NotQuiesced;
        };
        last.record_attempt();

        // A module that is already finalized (or was never usable) reports an
        // error here that says nothing about whether the reinitialization will
        // work, so this is logged and stepped past rather than treated as
        // fatal. C_Initialize below is the step that decides.
        if let Err(error) = self.ctx.clone().finalize() {
            tracing::debug!(
                lib_path = %self.lib_path,
                %error,
                "C_Finalize before reinitialization did not succeed; continuing"
            );
        }

        match self
            .ctx
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        {
            Ok(()) => {
                last.left_uninitialized = false;
                self.generation.fetch_add(1, Ordering::AcqRel);
                tracing::info!(
                    lib_path = %self.lib_path,
                    "PKCS#11 module reinitialized"
                );
                RecoveryOutcome::Reinitialized
            }
            // The module is initialized, just not by this call — the finalize
            // above did not take effect. Nothing was recovered, but the
            // library is still usable by whoever holds it.
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::CryptokiAlreadyInitialized,
                _,
            )) => {
                last.left_uninitialized = false;
                tracing::error!(
                    lib_path = %self.lib_path,
                    "PKCS#11 module could not be finalized, so it cannot be reinitialized"
                );
                RecoveryOutcome::NotFinalized
            }
            // C_Finalize took effect and C_Initialize did not, so the library
            // is now down: nothing on it can work until an attempt succeeds.
            // Recovery created this state, and it must not then ration the
            // only operation that clears it.
            Err(error) => {
                last.left_uninitialized = true;
                tracing::error!(
                    lib_path = %self.lib_path,
                    %error,
                    "PKCS#11 module reinitialization failed; the library is left \
                     uninitialized and the next attempt will not be deferred"
                );
                RecoveryOutcome::ModuleDown
            }
        }
    }
}

/// Process-wide registry of initialized PKCS#11 modules, keyed by library
/// path. See [`SharedModule`] for why one module is shared per library.
fn shared_module(lib_path: &str) -> Result<Arc<SharedModule>> {
    static MODULES: OnceLock<Mutex<HashMap<String, Arc<SharedModule>>>> = OnceLock::new();
    let modules = MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = modules
        .lock()
        .map_err(|_| KeyRackError::Provider("PKCS#11 module registry poisoned".into()))?;

    if let Some(module) = guard.get(lib_path) {
        return Ok(Arc::clone(module));
    }

    let ctx = Pkcs11::new(Path::new(lib_path))
        .map_err(|e| KeyRackError::Provider(format!("load PKCS#11 lib: {e}")))?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| KeyRackError::Provider(format!("C_Initialize: {e}")))?;

    let module = Arc::new(SharedModule {
        lib_path: lib_path.to_owned(),
        ctx,
        generation: AtomicU64::new(0),
        gate: Gate::new(),
        reinit: Mutex::new(LastReinit {
            at: None,
            left_uninitialized: false,
        }),
    });
    guard.insert(lib_path.to_owned(), Arc::clone(&module));
    Ok(module)
}

/// Configuration for constructing a [`Pkcs11Provider`].
#[derive(Clone)]
pub struct Pkcs11ProviderConfig {
    pub lib_path: String,
    pub token_label: String,
    pub pin: String,
}

/// PKCS#11 cryptographic provider.
///
/// All cryptographic operations are dispatched to the HSM via PKCS#11.
/// Sessions are opened per-operation — production HSMs benefit from a
/// session pool (future enhancement behind a feature flag).
///
/// Nothing about a token is cached beyond what can be re-derived: the slot is
/// re-resolved from `token_label` after the module is reinitialized, so a
/// token that returns on a different slot is still found.
pub struct Pkcs11Provider {
    module: Arc<SharedModule>,
    token_label: String,
    slot: RwLock<cryptoki::slot::Slot>,
    pin: Zeroizing<String>,
}

impl Pkcs11Provider {
    /// Create a new provider by loading the PKCS#11 shared library,
    /// finding the token by label, and verifying connectivity.
    pub fn new(config: &Pkcs11ProviderConfig) -> Result<Self> {
        // Share one initialized module per library path so several providers
        // (e.g. one per tenant token) can be backed by the same `.so` without
        // a second `C_Initialize` failing with ALREADY_INITIALIZED.
        let module = shared_module(&config.lib_path)?;
        let ctx = &module.ctx;

        // Construction touches the library like any other call, so it waits
        // out a reinitialization rather than racing one.
        let in_flight = module.gate.enter()?;

        let slot = find_slot_by_label(ctx, &config.token_label)?;

        // Verify we can actually log in
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| KeyRackError::Provider(format!("open session: {e}")))?;
        session
            .login(UserType::User, Some(&make_auth_pin(&config.pin)))
            .map_err(|e| KeyRackError::Provider(format!("login: {e}")))?;
        drop(session);

        tracing::info!(
            token_label = %config.token_label,
            "PKCS#11 provider initialized"
        );

        drop(in_flight);
        Ok(Self {
            module,
            token_label: config.token_label.clone(),
            slot: RwLock::new(slot),
            pin: Zeroizing::new(config.pin.clone()),
        })
    }

    fn current_slot(&self) -> Result<cryptoki::slot::Slot> {
        self.slot
            .read()
            .map(|s| *s)
            .map_err(|_| KeyRackError::Provider("PKCS#11 slot lock poisoned".into()))
    }

    /// Run a synchronous PKCS#11 operation on a blocking Tokio thread.
    ///
    /// A token can be taken away from a running module — an HSM restart, a
    /// re-attached partition, a token volume that disappears. That leaves the
    /// module holding an unusable view of the token, and it does not clear
    /// when the token returns: every later call on that slot keeps failing,
    /// including on a brand-new session, until the module is reinitialized.
    /// So when an operation fails that way, this reinitializes the module and
    /// tries once more, which is what turns "down until the process is
    /// restarted" into "down until custody comes back".
    async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: Fn(&Session) -> Result<R> + Send + Sync + 'static,
        R: Send + 'static,
    {
        let f = Arc::new(f);
        let generation = self.module.generation();

        let first = self.attempt(Arc::clone(&f)).await;
        let Err(error) = first else {
            return first;
        };
        if !may_be_module_failure(&error) {
            return Err(error);
        }

        let module = Arc::clone(&self.module);
        let outcome = tokio::task::spawn_blocking(move || module.recover(generation))
            .await
            .map_err(|e| KeyRackError::Provider(format!("blocking task: {e}")))?;
        tracing::debug!(
            lib_path = %self.module.lib_path,
            token_label = %self.token_label,
            outcome = ?outcome,
            retry = outcome.permits_retry(),
            "PKCS#11 recovery attempt finished"
        );
        if !outcome.permits_retry() {
            return Err(recovery_pending_error(outcome, &error));
        }

        // The token may have come back on a different slot, so re-resolve it
        // by label before retrying. If it cannot be found, the original
        // failure is the honest one to report.
        if let Err(resolve_error) = self.resolve_slot() {
            tracing::warn!(
                token_label = %self.token_label,
                error = %resolve_error,
                "token not found after reinitializing the PKCS#11 module"
            );
            return Err(error);
        }

        self.attempt(f).await
    }

    /// Re-resolve this provider's slot from its token label.
    fn resolve_slot(&self) -> Result<()> {
        let in_flight = self.module.gate.enter()?;
        let resolved = find_slot_by_label(&self.module.ctx, &self.token_label);
        drop(in_flight);
        let slot = resolved?;
        let mut current = self
            .slot
            .write()
            .map_err(|_| KeyRackError::Provider("PKCS#11 slot lock poisoned".into()))?;
        if *current != slot {
            tracing::info!(
                token_label = %self.token_label,
                "token returned on a different PKCS#11 slot; rebinding"
            );
            *current = slot;
        }
        Ok(())
    }

    /// One pass at the operation: fresh session, login, run.
    async fn attempt<F, R>(&self, f: Arc<F>) -> Result<R>
    where
        F: Fn(&Session) -> Result<R> + Send + Sync + 'static,
        R: Send + 'static,
    {
        let module = Arc::clone(&self.module);
        let slot = self.current_slot()?;
        let pin = Zeroizing::new(self.pin.as_str().to_owned());

        tokio::task::spawn_blocking(move || {
            // Registered for the whole call, so a concurrent recovery waits
            // for this to finish instead of finalizing the library under it.
            let _in_flight = module.gate.enter()?;

            let session = module
                .ctx
                .open_rw_session(slot)
                .map_err(|e| map_pkcs11_error("open session", &e))?;
            // Login state is shared by this process's sessions on the token.
            // Another operation may already have authenticated it. Accept only
            // that precise state; constructor login remains strict so a new
            // provider cannot inherit authentication instead of proving its PIN.
            match session.login(UserType::User, Some(&make_auth_pin(&pin))) {
                Ok(())
                | Err(cryptoki::error::Error::Pkcs11(
                    cryptoki::error::RvError::UserAlreadyLoggedIn,
                    _,
                )) => {}
                Err(error) => return Err(map_pkcs11_error("login", &error)),
            }
            f(&session)
        })
        .await
        .map_err(|e| KeyRackError::Provider(format!("blocking task: {e}")))?
    }
}

fn find_slot_by_label(ctx: &Pkcs11, label: &str) -> Result<cryptoki::slot::Slot> {
    let slots = ctx
        .get_slots_with_initialized_token()
        .map_err(|e| KeyRackError::Provider(format!("get slots: {e}")))?;

    for slot in &slots {
        if let Ok(info) = ctx.get_token_info(*slot) {
            let token_label = info.label().trim();
            if token_label == label {
                return Ok(*slot);
            }
        }
    }

    Err(KeyRackError::Provider(format!(
        "no token with label \"{label}\" found"
    )))
}

fn find_object(session: &Session, label: &str, class: ObjectClass) -> Result<ObjectHandle> {
    let template = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(class),
    ];
    let objects = session
        .find_objects(&template)
        .map_err(|e| map_pkcs11_error("find_objects", &e))?;

    objects
        .into_iter()
        .next()
        .ok_or_else(|| KeyRackError::Provider(format!("object not found: {label}")))
}

fn generate_aes_key(session: &Session, label: &str) -> Result<()> {
    let template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::ValueLen(32.into()),
    ];
    session
        .generate_key(&Mechanism::AesKeyGen, &template)
        .map_err(|e| KeyRackError::Provider(format!("AES keygen: {e}")))?;
    Ok(())
}

fn generate_rsa_key_pair(session: &Session, label: &str, key_size: u32) -> Result<()> {
    let bits = u64::from(key_size);
    if !(2048..=4096).contains(&bits) {
        return Err(KeyRackError::Provider(format!(
            "RSA key size must be 2048–4096, got {key_size}"
        )));
    }

    let pub_exponent: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::ModulusBits(bits.into()),
        Attribute::PublicExponent(pub_exponent),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| KeyRackError::Provider(format!("RSA keygen: {e}")))?;
    Ok(())
}

fn generate_ec_key_pair(session: &Session, label: &str, ec_params: &[u8]) -> Result<()> {
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::EcParams(ec_params.to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| KeyRackError::Provider(format!("EC keygen: {e}")))?;
    Ok(())
}

fn generate_ed25519_key_pair(session: &Session, label: &str) -> Result<()> {
    let pub_template = vec![
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
    ];
    let priv_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
            &pub_template,
            &priv_template,
        )
        .map_err(|e| KeyRackError::Provider(format!("Ed25519 keygen: {e}")))?;
    Ok(())
}

fn pkcs11_encrypt(
    session: &Session,
    label: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptOutput> {
    let obj = find_object(session, label, ObjectClass::SECRET_KEY)?;

    let nonce_bytes = session
        .generate_random_vec(12)
        .map_err(|e| map_pkcs11_error("generate nonce", &e))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let gcm_params = GcmParams::new(&mut nonce, aad, 128.into())
        .map_err(|e| KeyRackError::Provider(format!("GCM params: {e}")))?;
    let ct = session
        .encrypt(&Mechanism::AesGcm(gcm_params), obj, plaintext)
        .map_err(|e| map_pkcs11_error("AES-GCM encrypt", &e))?;

    // Wire format: 12-byte nonce || ciphertext+tag
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    Ok(EncryptOutput { ciphertext: out })
}

fn pkcs11_decrypt(
    session: &Session,
    label: &str,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Sensitive<Vec<u8>>> {
    if ciphertext.len() < 12 + 16 {
        return Err(KeyRackError::Provider(
            "ciphertext too short (need nonce + tag)".into(),
        ));
    }

    let obj = find_object(session, label, ObjectClass::SECRET_KEY)?;

    let (nonce_slice, ct) = ciphertext.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_slice);

    let gcm_params = GcmParams::new(&mut nonce, aad, 128.into())
        .map_err(|e| KeyRackError::Provider(format!("GCM params: {e}")))?;
    let pt = session
        .decrypt(&Mechanism::AesGcm(gcm_params), obj, ct)
        .map_err(|e| {
            if is_transient_pkcs11_error(&e) {
                KeyRackError::ProviderUnavailable(format!("AES-GCM decrypt: {e}"))
            } else {
                KeyRackError::EncryptionContextMismatch
            }
        })?;

    Ok(Sensitive::new(pt))
}

fn pkcs11_sign(
    session: &Session,
    label: &str,
    algorithm: SigningAlgorithm,
    message: &[u8],
) -> Result<Vec<u8>> {
    let priv_handle = find_object(session, label, ObjectClass::PRIVATE_KEY)?;

    match algorithm {
        SigningAlgorithm::Ed25519 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
            session
                .sign(&Mechanism::Eddsa(params), priv_handle, message)
                .map_err(|e| map_pkcs11_error("Ed25519 sign", &e))
        }

        SigningAlgorithm::RsaPkcs1v15Sha256 => session
            .sign(&Mechanism::Sha256RsaPkcs, priv_handle, message)
            .map_err(|e| map_pkcs11_error("RSA sign", &e)),

        SigningAlgorithm::RsaPssSha256 => {
            let pss_params = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            };
            session
                .sign(
                    &Mechanism::Sha256RsaPkcsPss(pss_params),
                    priv_handle,
                    message,
                )
                .map_err(|e| map_pkcs11_error("RSA-PSS sign", &e))
        }

        SigningAlgorithm::EcdsaP256Sha256 => {
            let hash = sha256_hash(message);
            let raw_sig = session
                .sign(&Mechanism::Ecdsa, priv_handle, &hash)
                .map_err(|e| map_pkcs11_error("ECDSA sign", &e))?;
            ecdsa_der::raw_to_der(&raw_sig, P256_COMPONENT_LEN)
        }

        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
        other => Err(KeyRackError::Provider(format!(
            "unsupported signing algorithm for pkcs11: {other:?}"
        ))),
    }
}

fn pkcs11_verify(
    session: &Session,
    label: &str,
    algorithm: SigningAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let pub_handle = find_object(session, label, ObjectClass::PUBLIC_KEY)?;

    let result = match algorithm {
        SigningAlgorithm::Ed25519 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519);
            session.verify(&Mechanism::Eddsa(params), pub_handle, message, signature)
        }

        SigningAlgorithm::RsaPkcs1v15Sha256 => {
            session.verify(&Mechanism::Sha256RsaPkcs, pub_handle, message, signature)
        }

        SigningAlgorithm::RsaPssSha256 => {
            let pss_params = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            };
            session.verify(
                &Mechanism::Sha256RsaPkcsPss(pss_params),
                pub_handle,
                message,
                signature,
            )
        }

        SigningAlgorithm::EcdsaP256Sha256 => {
            let hash = sha256_hash(message);
            let raw_sig = ecdsa_der::der_to_raw(signature, P256_COMPONENT_LEN)?;
            session.verify(&Mechanism::Ecdsa, pub_handle, &hash, &raw_sig)
        }

        // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
        other => {
            return Err(KeyRackError::Provider(format!(
                "unsupported signing algorithm for pkcs11: {other:?}"
            )))
        }
    };

    match result {
        Ok(()) => Ok(true),
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::SignatureInvalid
            | cryptoki::error::RvError::SignatureLenRange,
            _,
        )) => Ok(false),
        Err(e) => Err(map_pkcs11_error("verify", &e)),
    }
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    sha256_compute(data)
}

/// Pure-Rust SHA-256 (no external dependency for this single use case).
#[allow(clippy::many_single_char_names)]
fn sha256_compute(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn destroy_objects_by_label(session: &Session, label: &str) -> Result<()> {
    let template = vec![Attribute::Label(label.as_bytes().to_vec())];
    let objects = session
        .find_objects(&template)
        .map_err(|e| map_pkcs11_error("find for destroy", &e))?;

    for obj in objects {
        session
            .destroy_object(obj)
            .map_err(|e| map_pkcs11_error("destroy_object", &e))?;
    }
    Ok(())
}

#[async_trait]
impl CryptoProvider for Pkcs11Provider {
    async fn generate_key(&self, spec: &KeySpec) -> Result<KeyHandle> {
        let spec_owned = spec.clone();
        let label = uuid::Uuid::new_v4().to_string();
        let label_for_closure = label.clone();
        let spec_for_handle = spec.clone();

        self.run(move |session| {
            match &spec_owned {
                KeySpec::Aes256 => generate_aes_key(session, &label_for_closure)?,
                KeySpec::Ed25519 => generate_ed25519_key_pair(session, &label_for_closure)?,
                KeySpec::EcdsaP256Sha256 => {
                    generate_ec_key_pair(session, &label_for_closure, P256_OID_DER)?;
                }
                KeySpec::RsaPkcs1v15Sha256 { key_size } | KeySpec::RsaPssSha256 { key_size } => {
                    generate_rsa_key_pair(session, &label_for_closure, *key_size)?;
                }
                // TODO(proto-align): wire P-384/SHA-384-512/HMAC into pkcs11.
                other => {
                    return Err(KeyRackError::Provider(format!(
                        "unsupported key spec for pkcs11: {other:?}"
                    )));
                }
            }
            Ok(())
        })
        .await?;

        Ok(KeyHandle {
            key_id: label,
            key_spec: spec_for_handle,
        })
    }

    async fn encrypt(
        &self,
        handle: &KeyHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncryptOutput> {
        let label = handle.key_id.clone();
        let plaintext = plaintext.to_vec();
        let aad = aad.to_vec();

        self.run(move |session| pkcs11_encrypt(session, &label, &plaintext, &aad))
            .await
    }

    async fn decrypt(
        &self,
        handle: &KeyHandle,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Sensitive<Vec<u8>>> {
        let label = handle.key_id.clone();
        let ciphertext = ciphertext.to_vec();
        let aad = aad.to_vec();

        self.run(move |session| pkcs11_decrypt(session, &label, &ciphertext, &aad))
            .await
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let label = handle.key_id.clone();
        let message = message.to_vec();

        self.run(move |session| pkcs11_sign(session, &label, algorithm, &message))
            .await
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        algorithm: SigningAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let label = handle.key_id.clone();
        let message = message.to_vec();
        let signature = signature.to_vec();

        self.run(move |session| pkcs11_verify(session, &label, algorithm, &message, &signature))
            .await
    }

    async fn generate_random(&self, length: usize) -> Result<Sensitive<Vec<u8>>> {
        #[allow(clippy::cast_possible_truncation)]
        let len = length as u32;
        self.run(move |session| {
            let bytes = session
                .generate_random_vec(len)
                .map_err(|e| map_pkcs11_error("generate_random", &e))?;
            Ok(Sensitive::new(bytes))
        })
        .await
    }

    async fn destroy_key(&self, handle: &KeyHandle) -> Result<()> {
        let label = handle.key_id.clone();

        self.run(move |session| destroy_objects_by_label(session, &label))
            .await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        use CryptoOperation::{
            Decrypt, DestroyKey, Encrypt, GenerateDataKey, GenerateKey, ReEncrypt, Sign, Verify,
        };

        let symmetric_ops = vec![
            GenerateKey,
            Encrypt,
            Decrypt,
            GenerateDataKey,
            ReEncrypt,
            DestroyKey,
        ];
        let signing_ops = vec![GenerateKey, Sign, Verify, DestroyKey];

        ProviderCapabilities {
            provider_name: "pkcs11".into(),
            key_specs: vec![
                KeySpecCapability {
                    key_spec: KeySpec::Aes256,
                    operations: symmetric_ops,
                },
                KeySpecCapability {
                    key_spec: KeySpec::Ed25519,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::EcdsaP256Sha256,
                    operations: signing_ops.clone(),
                },
                KeySpecCapability {
                    key_spec: KeySpec::RsaPkcs1v15Sha256 { key_size: 2048 },
                    operations: signing_ops,
                },
            ],
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // If you flip either flag to true you MUST have overridden the
    // corresponding method to keep plaintext in-boundary AND added a
    // test proving it. This guard converts a silent capability lie
    // into a conscious, reviewed change.
    //
    // NOTE: Pkcs11Provider cannot be constructed without a live PKCS#11
    // library, so this test inspects the hardcoded values returned by
    // capabilities() at the source level. When SoftHSM integration
    // tests are available, replace this with a live capabilities() call.
    // ── recovery trigger ────────────────────────────────────────────────
    //
    // These are unit tests on purpose. The container proof drives the real
    // binary against SoftHSM, which loses a token by having its directory
    // moved away and answers CKR_GENERAL_ERROR immediately — so every
    // failure it can produce is already retryable, and it cannot show what
    // happens to a module that answers a permanent code. A harness that can
    // only produce the failures it already handles agrees with itself.

    /// A permanent-looking provider error must still reach the recovery path.
    /// This is the whole of the rotation defect: the trigger was the
    /// client-facing variant, so a module that reported a permanent fault was
    /// never offered recovery, whatever state it was actually in.
    #[test]
    fn a_permanent_provider_error_still_warrants_recovery() {
        assert!(
            may_be_module_failure(&KeyRackError::Provider("C_GenerateKey: failed".into())),
            "a permanent provider error may still be a wedged module"
        );
        assert!(may_be_module_failure(&KeyRackError::ProviderUnavailable(
            "token not present".into()
        )));
    }

    /// Recovery must not be provoked by failures that are not the provider's.
    #[test]
    fn non_provider_failures_do_not_warrant_recovery() {
        for error in [
            KeyRackError::Storage("record not written".into()),
            KeyRackError::Other("something else entirely".into()),
        ] {
            assert!(
                !may_be_module_failure(&error),
                "reinitializing the library cannot help with {error}"
            );
        }
    }

    /// A state recovery creates must read as recoverable. An attempt that
    /// finalizes the library and then fails to initialize it leaves every
    /// later call reporting this code; classifying it permanent told callers
    /// their request could never work when a reinitialization was all that
    /// stood in the way.
    #[test]
    fn an_uninitialized_library_reads_as_retryable_not_as_a_permanent_fault() {
        let error = cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiNotInitialized,
            cryptoki::context::Function::OpenSession,
        );
        assert!(is_transient_pkcs11_error(&error));
        assert!(
            matches!(
                map_pkcs11_error("open session", &error),
                KeyRackError::ProviderUnavailable(_)
            ),
            "a client's retry policy keys on this variant; a permanent answer stops it"
        );
    }

    /// Only an outcome that actually restored the module may send the caller
    /// back to retry its operation.
    #[test]
    fn only_a_completed_recovery_permits_a_retry() {
        assert!(RecoveryOutcome::Reinitialized.permits_retry());
        assert!(RecoveryOutcome::AlreadyRecovered.permits_retry());
        for outcome in [
            RecoveryOutcome::DeferredByInterval,
            RecoveryOutcome::NotQuiesced,
            RecoveryOutcome::NotFinalized,
            RecoveryOutcome::ModuleDown,
        ] {
            assert!(
                !outcome.permits_retry(),
                "{outcome:?} did not restore the module"
            );
        }
    }

    /// Every incomplete outcome is temporary, and each must say which one it
    /// was. Answering the operation's own failure instead is what let a
    /// deferred recovery reach a client as a permanent error.
    #[test]
    fn an_incomplete_recovery_is_reported_as_retryable_and_names_itself() {
        let original = KeyRackError::Provider("open session: not initialized".into());
        let mut seen = Vec::new();
        for outcome in [
            RecoveryOutcome::DeferredByInterval,
            RecoveryOutcome::NotQuiesced,
            RecoveryOutcome::NotFinalized,
            RecoveryOutcome::ModuleDown,
        ] {
            let reported = recovery_pending_error(outcome, &original);
            assert!(
                matches!(reported, KeyRackError::ProviderUnavailable(_)),
                "{outcome:?} is temporary, so it must read as retryable"
            );
            let text = reported.to_string();
            assert!(
                text.contains(outcome.reason()),
                "{outcome:?} must be distinguishable in the answer: {text}"
            );
            assert!(
                text.contains("open session: not initialized"),
                "the underlying failure stays in the message for diagnosis: {text}"
            );
            seen.push(outcome.reason());
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 4, "each outcome needs its own reason");
    }

    /// A library left finalized has no providers left to protect, so the
    /// interval that exists to protect them must not defer the only operation
    /// that can bring it back.
    #[test]
    fn a_down_library_is_not_rationed() {
        let mut last = LastReinit {
            at: None,
            left_uninitialized: false,
        };
        last.record_attempt();
        assert!(
            !last.may_attempt_now(),
            "a healthy module is protected by the interval"
        );
        last.left_uninitialized = true;
        assert!(
            last.may_attempt_now(),
            "a down library must be repairable before the interval expires"
        );
    }

    /// The interval exists to ration reinitializations, so it is armed by an
    /// attempt that ran — not by one that was abandoned before touching the
    /// library, which used to suppress the next genuine attempt for the whole
    /// interval.
    #[test]
    fn the_interval_is_armed_by_an_attempt_that_ran() {
        let mut last = LastReinit {
            at: None,
            left_uninitialized: false,
        };
        assert!(last.may_attempt_now(), "nothing has been attempted yet");
        last.record_attempt();
        assert!(
            !last.may_attempt_now(),
            "an attempt that ran holds the window for the interval"
        );
    }

    // ── admission during a recovery window ──────────────────────────────

    /// A caller whose own token is healthy must wait out a recovery window
    /// rather than be told the token is unavailable. Reinitializing is per
    /// library, so this caller is very often a different token entirely.
    ///
    /// The window here is longer than the drain bound and shorter than the
    /// admission bound, which is precisely the case a single shared bound
    /// could not survive: the caller's patience ran out at the same moment
    /// the window it was waiting for closed. The pre-existing test for this
    /// behaviour held the gate for 50ms against a five-second bound, so it
    /// could only ever observe the case that already worked.
    #[test]
    fn a_caller_waits_out_a_recovery_window_instead_of_being_refused() {
        let drain = Duration::from_millis(200);
        let gate = Arc::new(Gate::with_quiesce_timeout(drain));
        let holder = Arc::clone(&gate);
        let recovery = std::thread::spawn(move || {
            let quiesced = holder.quiesce().expect("gate is idle, so it quiesces");
            std::thread::sleep(drain + drain / 2);
            drop(quiesced);
        });
        // Arrive while the gate is already closed, as a concurrent caller does.
        std::thread::sleep(Duration::from_millis(20));
        let admitted = gate.enter();
        recovery.join().unwrap();
        assert!(
            admitted.is_ok(),
            "a caller arriving during a bounded recovery must be admitted after it, got {:?}",
            admitted.err()
        );
    }

    /// The bound still exists: a gate held closed longer than any legitimate
    /// recovery window fails the caller instead of hanging it forever.
    #[test]
    fn a_caller_is_refused_when_the_window_outlasts_the_bound() {
        let gate = Arc::new(Gate::with_quiesce_timeout(Duration::from_millis(50)));
        let holder = Arc::clone(&gate);
        let stuck = std::thread::spawn(move || {
            let quiesced = holder.quiesce().expect("gate is idle, so it quiesces");
            std::thread::sleep(Duration::from_millis(500));
            drop(quiesced);
        });
        std::thread::sleep(Duration::from_millis(10));
        let admitted = gate.enter();
        stuck.join().unwrap();
        assert!(
            matches!(admitted, Err(KeyRackError::ProviderUnavailable(_))),
            "a gate nobody reopens must be reported unavailable, not waited on forever"
        );
    }

    #[test]
    fn capability_flags_are_honest() {
        let caps = ProviderCapabilities {
            provider_name: "pkcs11".into(),
            key_specs: Vec::new(),
            supports_generate_random: true,
            supports_atomic_data_key: false,
            supports_atomic_re_encrypt: false,
            supports_key_import: false,
        };
        assert!(
            !caps.supports_atomic_data_key,
            "supports_atomic_data_key must be false without a generate_data_key override"
        );
        assert!(
            !caps.supports_atomic_re_encrypt,
            "supports_atomic_re_encrypt must be false without a re_encrypt override"
        );
    }

    #[test]
    fn sha256_known_vector() {
        let hash = sha256_compute(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sha256_abc() {
        let hash = sha256_compute(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    // ── module recovery admission control ────────────────────────────────
    //
    // These need no PKCS#11 library: the property under test is that
    // reinitialization can never run while a call is inside the module,
    // because finalizing under an active call takes the process down rather
    // than returning an error.

    #[test]
    fn a_wedged_module_reads_as_unavailable_not_as_a_permanent_fault() {
        // The status a caller sees decides whether they ever come back, and a
        // module holding a stale view of a token recovers on the next call.
        let wedged = cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::GeneralError,
            cryptoki::context::Function::Login,
        );
        assert!(is_transient_pkcs11_error(&wedged));
        assert!(matches!(
            map_pkcs11_error("login", &wedged),
            KeyRackError::ProviderUnavailable(_)
        ));

        // A genuinely permanent fault must not be dressed up as retryable.
        let permanent = cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::AttributeValueInvalid,
            cryptoki::context::Function::Encrypt,
        );
        assert!(!is_transient_pkcs11_error(&permanent));
        assert!(matches!(
            map_pkcs11_error("encrypt", &permanent),
            KeyRackError::Provider(_)
        ));
    }

    #[test]
    fn quiescing_waits_for_calls_already_inside_the_module() {
        let gate = Arc::new(Gate::new());
        let in_flight = gate.enter().expect("gate admits the first call");

        let waiting = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let quiesced = {
            let gate = Arc::clone(&gate);
            let waiting = Arc::clone(&waiting);
            std::thread::spawn(move || {
                waiting.store(true, Ordering::Release);
                gate.quiesce().is_some()
            })
        };

        // Give the waiter a chance to observe the in-flight call.
        while !waiting.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !quiesced.is_finished(),
            "quiesce returned while a call was still inside the module"
        );

        drop(in_flight);
        assert!(
            quiesced.join().expect("quiesce thread"),
            "quiesce should succeed once the module goes quiet"
        );
    }

    #[test]
    fn a_call_that_never_returns_blocks_recovery_rather_than_crashing_it() {
        let gate = Gate::new();
        let _stuck = gate.enter().expect("gate admits the call");

        let started = Instant::now();
        assert!(
            gate.quiesce().is_none(),
            "recovery must refuse to finalize a module it could not quiet"
        );
        assert!(
            started.elapsed() >= QUIESCE_TIMEOUT,
            "quiesce gave up before waiting for the module to go quiet"
        );

        // Having given up, it must leave the gate open — a failed recovery
        // may not lock out the calls that were still working.
        gate.enter().expect("gate reopened after a failed quiesce");
    }

    #[test]
    fn calls_wait_while_the_module_is_being_reinitialized() {
        let gate = Arc::new(Gate::new());
        let quiesced = gate.quiesce().expect("an idle module quiesces at once");

        let admitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let caller = {
            let gate = Arc::clone(&gate);
            let admitted = Arc::clone(&admitted);
            std::thread::spawn(move || {
                let entered = gate.enter().is_ok();
                admitted.store(entered, Ordering::Release);
            })
        };

        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !admitted.load(Ordering::Acquire),
            "a call was admitted while the module was being reinitialized"
        );

        drop(quiesced);
        caller.join().expect("caller thread");
        assert!(
            admitted.load(Ordering::Acquire),
            "calls must resume once reinitialization finishes"
        );
    }
}

#[cfg(all(test, feature = "softhsm-tests"))]
mod concurrent_login_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tokio::task::JoinSet;

    /// Requires a disposable `SoftHSM` token. Missing fixture configuration fails
    /// the test; it never silently skips. This performs one incorrect-PIN check
    /// without ambient login, so it must not target a production token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sessions_reuse_login_without_weakening_constructor() {
        let pin_file = std::env::var("KMS_PKCS11_PIN_FILE")
            .expect("KMS_PKCS11_PIN_FILE is required for the SoftHSM regression");
        let config = Pkcs11ProviderConfig {
            lib_path: std::env::var("KMS_PKCS11_LIB")
                .expect("KMS_PKCS11_LIB is required for the SoftHSM regression"),
            token_label: std::env::var("KMS_PKCS11_TOKEN_LABEL")
                .expect("KMS_PKCS11_TOKEN_LABEL is required for the SoftHSM regression"),
            pin: std::fs::read_to_string(pin_file)
                .expect("SoftHSM regression PIN file is unavailable"),
        };
        assert!(
            !config.pin.is_empty() && config.pin.is_ascii(),
            "fixture PIN must be nonempty ASCII"
        );
        // Each constructor proves its PIN before an anchor or worker exists.
        let first = Arc::new(Pkcs11Provider::new(&config).expect("first provider initialization"));
        let second =
            Arc::new(Pkcs11Provider::new(&config).expect("second provider initialization"));
        let handle = first
            .generate_key(&KeySpec::Aes256)
            .await
            .expect("regression key generation");
        let anchor = first
            .module
            .ctx
            .open_rw_session(first.current_slot().expect("anchor slot"))
            .expect("anchor session open");
        anchor
            .login(UserType::User, Some(&make_auth_pin(&config.pin)))
            .expect("anchor session login");
        // Keep the wrong PIN the same valid length, rather than testing a length error.
        let mut wrong_config = config.clone();
        let replacement = if wrong_config.pin.starts_with('1') {
            "2"
        } else {
            "1"
        };
        wrong_config.pin.replace_range(0..1, replacement);
        let ambient_wrong_pin_denied = Pkcs11Provider::new(&wrong_config).is_err();
        // The anchor makes the original strict per-operation login fail even if
        // a scheduler would otherwise serialize these short crypto operations.
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = JoinSet::new();
        for index in 0..8 {
            let provider = if index % 2 == 0 {
                Arc::clone(&first)
            } else {
                Arc::clone(&second)
            };
            let handle = handle.clone();
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                let plaintext = format!("concurrent-login-regression-{index}").into_bytes();
                let aad = b"concurrent-login-regression-aad";
                let ciphertext = provider.encrypt(&handle, &plaintext, aad).await?;
                let decrypted = provider
                    .decrypt(&handle, &ciphertext.ciphertext, aad)
                    .await?;
                if decrypted.expose().as_slice() != plaintext.as_slice() {
                    return Err(KeyRackError::Provider(
                        "regression round trip mismatch".into(),
                    ));
                }
                Ok::<(), KeyRackError>(())
            });
        }
        let mut completed = 0;
        while let Some(result) = tasks.join_next().await {
            if matches!(result, Ok(Ok(()))) {
                completed += 1;
            }
        }
        drop(anchor);
        let cold_wrong_pin_denied = Pkcs11Provider::new(&wrong_config).is_err();
        let cold_correct_pin_accepted = Pkcs11Provider::new(&config).is_ok();
        first
            .destroy_key(&handle)
            .await
            .expect("regression key cleanup");
        assert!(
            ambient_wrong_pin_denied,
            "constructor bypassed credential validation"
        );
        assert!(
            cold_wrong_pin_denied,
            "constructor accepted an incorrect PIN"
        );
        assert!(
            cold_correct_pin_accepted,
            "correct credentials could not authenticate again"
        );
        assert_eq!(
            completed, 8,
            "concurrent real crypto operations must all complete"
        );
    }
}
