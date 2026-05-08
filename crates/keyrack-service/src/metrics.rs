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
