// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Initialize the image's dedicated `SoftHSM` store, or verify its existing token.
//! The entrypoint holds the shared store lock across initialization and service
//! execution. This program never resets an initialized token or changes a PIN.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::slot::{Slot, TokenInfo};
use cryptoki::types::AuthPin;
use keyrack_core::secret::SecretString;
use keyrack_service::secret_ref::{resolve_pin_ref_under, secret_root};

type InitResult<T> = Result<T, &'static str>;

struct Inputs {
    label: SecretString,
    user_pin: SecretString,
    so_pin: SecretString,
}

fn reference(variable: &str, default: &str) -> InitResult<String> {
    match std::env::var(variable) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(std::env::VarError::NotUnicode(_)) => Err("configuration is not UTF-8"),
    }
}

fn inputs() -> InitResult<Inputs> {
    let root = secret_root();
    let resolve = |variable, default| {
        resolve_pin_ref_under(&reference(variable, default)?, &root)
            .map_err(|_| "required secret file cannot be resolved")
    };
    let input = Inputs {
        label: resolve("KEYRACK_SOFTHSM_TOKEN_LABEL_REF", "file:token-label")?,
        user_pin: resolve("KEYRACK_SOFTHSM_USER_PIN_REF", "file:user-pin")?,
        so_pin: resolve("KEYRACK_SOFTHSM_SO_PIN_REF", "file:so-pin")?,
    };
    validate_label(input.label.expose())?;
    Ok(input)
}

fn validate_label(label: &str) -> InitResult<()> {
    // cryptoki pads to 32 bytes and silently truncates longer labels. Provider
    // lookup trims surrounding whitespace, so neither form is accepted here.
    if label.is_empty()
        || label.len() > 32
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err("token label must be 1..=32 UTF-8 bytes without edge whitespace or controls");
    }
    Ok(())
}

fn enumerate(module: &Pkcs11) -> InitResult<Vec<(Slot, TokenInfo)>> {
    module
        .get_slots_with_token()
        .map_err(|_| "cannot enumerate SoftHSM tokens")?
        .into_iter()
        .map(|slot| {
            let info = module
                .get_token_info(slot)
                .map_err(|_| "cannot inspect SoftHSM token")?;
            if !info
                .manufacturer_id()
                .to_ascii_lowercase()
                .contains("softhsm")
                || !info.model().to_ascii_lowercase().contains("softhsm")
            {
                return Err("initializer requires a SoftHSM token store");
            }
            Ok((slot, info))
        })
        .collect()
}

fn select<'a>(tokens: &'a [(Slot, TokenInfo)], label: &str) -> InitResult<&'a (Slot, TokenInfo)> {
    let initialized: Vec<_> = tokens
        .iter()
        .filter(|(_, info)| info.token_initialized())
        .collect();
    // The packaged profile owns one dedicated token store. An unrelated token
    // or duplicates are a configuration error, never permission to reset it.
    match initialized.as_slice() {
        [token] if token.1.label() == label => Ok(token),
        [] => {
            let empty: Vec<_> = tokens
                .iter()
                .filter(|(_, info)| !info.token_initialized())
                .collect();
            match empty.as_slice() {
                [token] => Ok(token),
                _ => Err("expected exactly one empty token slot"),
            }
        }
        [_] => Err("dedicated store contains a different token label"),
        _ => Err("dedicated store contains multiple initialized tokens"),
    }
}

fn validate_pins(input: &Inputs, info: &TokenInfo) -> InitResult<()> {
    let allowed = info.min_pin_length()..=info.max_pin_length();
    if !allowed.contains(&input.user_pin.expose().len())
        || !allowed.contains(&input.so_pin.expose().len())
    {
        return Err("PIN length is outside the token's allowed range");
    }
    Ok(())
}

fn auth(pin: &SecretString) -> AuthPin {
    AuthPin::new(pin.expose().to_owned().into_boxed_str())
}

fn initialize(module: &Pkcs11, input: &Inputs) -> InitResult<()> {
    let tokens = enumerate(module)?;
    let (slot, info) = select(&tokens, input.label.expose())?;
    validate_pins(input, info)?;
    if !info.token_initialized() {
        module
            .init_token(*slot, &auth(&input.so_pin), input.label.expose())
            .map_err(|_| "cannot initialize empty token")?;
    }

    // SoftHSM may assign another slot number on initialization. Rediscover by
    // exact label and recheck the dedicated-store invariant before login.
    let tokens = enumerate(module)?;
    let (slot, info) = select(&tokens, input.label.expose())?;
    if !info.token_initialized() {
        return Err("token initialization did not complete");
    }
    validate_pins(input, info)?;
    let session = module
        .open_rw_session(*slot)
        .map_err(|_| "cannot open token initialization session")?;

    // A fresh process must prove BOTH supplied credentials on every run.
    // USER_ALREADY_LOGGED_IN is not accepted as proof of a supplied PIN.
    session
        .login(UserType::So, Some(&auth(&input.so_pin)))
        .map_err(|_| "SO PIN verification failed")?;
    if !info.user_pin_initialized() {
        // Resume the only permitted partial initialization: C_InitToken already
        // succeeded, but C_InitPIN did not. Never reset an existing user PIN.
        session
            .init_pin(&auth(&input.user_pin))
            .map_err(|_| "cannot initialize user PIN")?;
    }
    session.logout().map_err(|_| "SO logout failed")?;
    session
        .login(UserType::User, Some(&auth(&input.user_pin)))
        .map_err(|_| "user PIN verification failed")?;
    session.logout().map_err(|_| "user logout failed")?;
    session.close().map_err(|_| "token session close failed")?;
    let tokens = enumerate(module)?;
    let (_, info) = select(&tokens, input.label.expose())?;
    if !info.token_initialized() || !info.user_pin_initialized() {
        return Err("token initialization is incomplete");
    }
    Ok(())
}

fn run() -> InitResult<()> {
    if std::env::args_os().len() != 1 {
        return Err("arguments are not accepted; configure secret file references");
    }
    let input = inputs()?;
    let library = reference("KEYRACK_SOFTHSM_LIB", "/usr/lib/softhsm/libsofthsm2.so")?;
    let module = Pkcs11::new(library).map_err(|_| "cannot load SoftHSM module")?;
    module
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|_| "cannot initialize SoftHSM module")?;
    let result = initialize(&module, &input);
    let finalized = module
        .finalize()
        .map_err(|_| "cannot finalize SoftHSM module");
    result.and(finalized)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => {
            println!("SoftHSM token initialized and credentials verified");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("SoftHSM initialization refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_label;

    #[test]
    fn labels_cannot_be_truncated_or_lookup_trimmed() {
        for label in ["", " leading", "trailing ", "tab\tlabel", "nul\0label"] {
            assert!(validate_label(label).is_err(), "invalid label accepted");
        }
        assert!(validate_label(&"x".repeat(33)).is_err());
        assert!(validate_label(&"é".repeat(17)).is_err());
        assert!(validate_label(&"é".repeat(16)).is_ok());
        assert!(validate_label("keyrack-token").is_ok());
    }
}
