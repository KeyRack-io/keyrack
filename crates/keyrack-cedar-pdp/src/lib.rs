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

//! Standalone Cedar PDP companion for `KeyRack`.
//!
//! This binary wraps the `cedar-policy` crate, serves the `KeyRack`
//! authz request schema over HTTP, and hot-reloads policy bundles.
//!
//! Operators who want Cedar without OPA-level complexity deploy this
//! as a sidecar.  Operators who already use OPA, `AuthZed`, AVP, or
//! another PDP point `KeyRack` at their existing service instead and
//! ignore this binary.
//!
//! **WARNING:** Embedding the PDP in the same trust domain as the key
//! plane collapses the trust boundary.  This binary is documented as
//! dev/test/single-binary smallest-deployment use only.

pub mod engine;
pub mod server;
