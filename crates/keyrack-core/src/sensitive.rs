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

//! `Sensitive<T>` — a wrapper that prevents plaintext from appearing in logs.
//!
//! Every type carrying key material, plaintext, or secrets should be wrapped
//! in `Sensitive`. The wrapper's `Debug` and `Display` impls emit
//! `[REDACTED]` regardless of log level, satisfying `KEYRACK_SPEC.md`
//! invariant 2 ("no plaintext key material in logs") and the acceptance
//! criterion in §11.1.
//!
//! The inner value is accessible via `.expose()` — a deliberate verb that
//! stands out in code review and grep.

use std::fmt;
use zeroize::Zeroize;

/// Wrapper that redacts its contents from `Debug` and `Display` output.
///
/// The inner value is zeroized on drop when `T: Zeroize`.
/// Uses `Option<T>` internally so `into_inner` can extract the value
/// without unsafe code while still zeroizing on normal drop.
pub struct Sensitive<T: Zeroize>(Option<T>);

impl<T: Zeroize> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Self(Some(value))
    }

    /// Access the inner value. Named to be conspicuous in code review.
    ///
    /// # Panics
    ///
    /// Panics if called after `into_inner` (which consumes `self`, so this
    /// can only happen through internal misuse, not public API).
    pub fn expose(&self) -> &T {
        self.0.as_ref().expect("value consumed")
    }

    /// Consume the wrapper and return the inner value without zeroizing.
    pub fn into_inner(mut self) -> T {
        self.0.take().expect("value consumed")
    }
}

impl<T: Zeroize> Drop for Sensitive<T> {
    fn drop(&mut self) {
        if let Some(ref mut v) = self.0 {
            v.zeroize();
        }
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize + Clone> Clone for Sensitive<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Sensitive<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for Sensitive<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Sensitive::new(vec![1u8, 2, 3]);
        assert_eq!(format!("{s:?}"), "[REDACTED]");
    }

    #[test]
    fn display_is_redacted() {
        let s = Sensitive::new(vec![0xFFu8; 32]);
        assert_eq!(format!("{s}"), "[REDACTED]");
    }

    #[test]
    fn expose_returns_inner() {
        let s = Sensitive::new(vec![42u8]);
        assert_eq!(s.expose(), &vec![42u8]);
    }

    #[test]
    fn into_inner_returns_value() {
        let s = Sensitive::new(vec![1u8, 2, 3]);
        let v = s.into_inner();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn clone_preserves_value() {
        let a = Sensitive::new(vec![10u8]);
        let b = a.clone();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn equality() {
        let a = Sensitive::new(vec![1u8]);
        let b = Sensitive::new(vec![1u8]);
        let c = Sensitive::new(vec![2u8]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn format_in_struct_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Wrapper {
            key: Sensitive<Vec<u8>>,
            label: String,
        }

        let w = Wrapper {
            key: Sensitive::new(vec![0xDE, 0xAD]),
            label: "my-key".into(),
        };

        let debug = format!("{w:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("my-key"));
        assert!(!debug.contains("222")); // 0xDE = 222
        assert!(!debug.contains("173")); // 0xAD = 173
    }
}
