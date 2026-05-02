// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: BUSL-1.1
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Change Date: 2030-01-01
// Change License: Apache License, Version 2.0

//! KeyRack core library.
//!
//! Types, traits, canonicalization, LID derivation, rule engine, resolver,
//! providers (software, in-memory), audit sinks, and `Sensitive<T>`.

#![forbid(unsafe_code)]

pub mod attr;
pub mod canon;
pub mod error;
pub mod key;
pub mod lid;
pub mod sensitive;
pub mod tags;
