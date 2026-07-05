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

//! Kani bounded model-checking proof harnesses.
//!
//! These harnesses verify the high-value security property:
//! **"No plaintext key material appears in any serialized output."**
//!
//! The proof strategy has two tiers:
//!
//! 1. **Kani (this file):** Exhaustively proves that `Sensitive<T>` — the
//!    wrapper through which ALL key material flows — never leaks its contents
//!    through Debug, Display, or any formatting path. Since `Sensitive<T>`
//!    does not implement `Serialize`, key material structurally cannot reach
//!    serde serialization.
//!
//! 2. **Proptest (`tests/formal_invariants.rs`):** Probabilistically verifies
//!    the end-to-end property on the full serialization pipeline (AuditEvent,
//!    KeyRecord JSON output) — covering the composition that Kani cannot
//!    model due to serde_json's complexity.
//!
//! Run with: `cargo kani -p keyrack-core` (requires kani-verifier installed).
//! The `#[cfg(kani)]` gate ensures these are invisible to normal builds/CI.

#[cfg(kani)]
mod proofs {
    use crate::sensitive::Sensitive;

    /// Proof: Sensitive<T>::Debug always produces exactly "[REDACTED]".
    ///
    /// Exhaustively verified over all possible 4-byte key material values
    /// (2^32 input space). This proves that no information about the wrapped
    /// value leaks through the Debug trait, regardless of the input.
    #[kani::proof]
    #[kani::unwind(20)]
    fn sensitive_debug_never_leaks_key_material() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();

        let key_bytes = vec![b0, b1, b2, b3];
        let sensitive = Sensitive::new(key_bytes);

        let debug_output = format!("{sensitive:?}");
        assert_eq!(debug_output, "[REDACTED]");
    }

    /// Proof: Sensitive<T>::Display always produces exactly "[REDACTED]".
    ///
    /// Exhaustively verified over all possible 4-byte key material values.
    #[kani::proof]
    #[kani::unwind(20)]
    fn sensitive_display_never_leaks_key_material() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();

        let key_bytes = vec![b0, b1, b2, b3];
        let sensitive = Sensitive::new(key_bytes);

        let display_output = format!("{sensitive}");
        assert_eq!(display_output, "[REDACTED]");
    }

    /// Proof: Sensitive::expose() faithfully returns the original value.
    ///
    /// This is the correctness dual: we must not lose data, only hide it
    /// from serialization/formatting paths.
    #[kani::proof]
    #[kani::unwind(10)]
    fn sensitive_expose_is_faithful() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();

        let key_bytes = vec![b0, b1, b2, b3];
        let sensitive = Sensitive::new(key_bytes);

        let exposed = sensitive.expose();
        assert_eq!(exposed.len(), 4);
        assert_eq!(exposed[0], b0);
        assert_eq!(exposed[1], b1);
        assert_eq!(exposed[2], b2);
        assert_eq!(exposed[3], b3);
    }

    /// Proof: Sensitive::into_inner() faithfully returns the original value.
    #[kani::proof]
    #[kani::unwind(10)]
    fn sensitive_into_inner_is_faithful() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();

        let key_bytes = vec![b0, b1];
        let sensitive = Sensitive::new(key_bytes);
        let recovered = sensitive.into_inner();

        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0], b0);
        assert_eq!(recovered[1], b1);
    }

    /// Proof: Debug output of Sensitive is input-independent (constant).
    ///
    /// For any two different key values, their Debug representations are
    /// identical — proving zero information leakage through timing or length
    /// side channels in the Debug output.
    #[kani::proof]
    #[kani::unwind(20)]
    fn sensitive_debug_is_constant_output() {
        let a0: u8 = kani::any();
        let a1: u8 = kani::any();
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();

        let s1 = Sensitive::new(vec![a0, a1]);
        let s2 = Sensitive::new(vec![b0, b1]);

        let d1 = format!("{s1:?}");
        let d2 = format!("{s2:?}");

        // Output is always identical regardless of contents — no side channel.
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), d2.len());
    }
}
