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

//! `KeyRack` core library.
//!
//! Types, traits, canonicalization, LID derivation, rule engine, resolver,
//! providers (software, in-memory), audit sinks, and `Sensitive<T>`.

#![forbid(unsafe_code)]

pub mod attr;
pub mod audit;
pub mod authn;
pub mod canon;
pub mod cascade;
pub mod encryption_context;
pub mod error;
pub mod header;
pub mod hsm;
pub mod key;
pub mod lid;
pub mod lint;
pub mod migration;
pub mod pdp;
pub mod provider;
pub mod provisioner;
pub mod resolver;
pub mod rotation;
pub mod rule;
pub mod sensitive;
pub mod storage;
pub mod tags;
