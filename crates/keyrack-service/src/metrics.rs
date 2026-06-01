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

//! Prometheus metrics instrumentation for the KeyRack service.

use metrics::{counter, histogram};

pub const OP_DURATION: &str = "keyrack_operation_duration_seconds";
pub const OP_TOTAL: &str = "keyrack_operations_total";
pub const PDP_DURATION: &str = "keyrack_pdp_request_duration_seconds";
pub const PDP_ERRORS: &str = "keyrack_pdp_errors_total";
pub const AUDIT_EMIT_ERRORS: &str = "keyrack_audit_emit_errors_total";

pub fn record_op(action: &str, result: &str, duration: std::time::Duration) {
    histogram!(OP_DURATION, "action" => action.to_owned(), "result" => result.to_owned())
        .record(duration.as_secs_f64());
    counter!(OP_TOTAL, "action" => action.to_owned(), "result" => result.to_owned())
        .increment(1);
}

pub fn record_pdp(duration: std::time::Duration, success: bool) {
    histogram!(PDP_DURATION).record(duration.as_secs_f64());
    if !success {
        counter!(PDP_ERRORS).increment(1);
    }
}

pub fn record_audit_error() {
    counter!(AUDIT_EMIT_ERRORS).increment(1);
}
