// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's usage-tap fault reporting: a plane names a usage-tap fault on its door's answer, and
//! the kernel counts it here.
//!
//! This module once also held the protocol-cell dispatch (`OpDispatch`, `frame`, `chat`, `op_for`,
//! `protocol_error`, `request_handler`), resolved through the kernel's protocol registry. The codec
//! cells are the plane's (`busbar_contract::codec` names their shapes, and the plane that owns the
//! dialects implements and drives them); production never installed a declaration into that
//! registry, so no cell was ever resolved there, and the dispatch went with the registry (Q128
//! contract p11 finding 1).

// THE USAGE-TAP FAULT COUNT (row 155): a plane returns a usage-tap fault as data on its door's
// answer (`abi::plane::OnPieceOut::tap_fault`), and the kernel counts it here on
// `busbar_kernel::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL`, warning once per `(protocol, reason)`.

/// Process-lifetime warn-once latch for the usage-tap decode fault class, keyed `protocol:reason`. A
/// live protocol/dialect the tap reader cannot decode fails on EVERY 2xx body of that shape, so an
/// unlatched `warn!` spams per request; [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL) carries the per-request
/// volume. This records the fault (increments the counter) and returns `true` only the FIRST time a
/// given `(protocol, reason)` is seen, so the caller warns once and logs `debug!` thereafter.
pub fn usage_tap_decode_fail_should_warn(protocol: &str, reason: &'static str) -> bool {
    metrics::counter!(
        crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL,
        "protocol" => protocol.to_string(),
        "reason" => reason,
    )
    .increment(1);
    static SEEN: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    seen.insert(format!("{protocol}:{reason}"))
}

/// COUNT ONE USAGE-TAP FAULT a plane's answer carried for a unit read in `protocol`: one increment
/// of [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL) under
/// `reason`, warned the first time the `(protocol, reason)` is seen and logged at debug after. The
/// request billed 0 tokens for its tap; the plane names the fault, the kernel counts it.
pub fn usage_tap_fault(protocol: &str, reason: &'static str) {
    if usage_tap_decode_fail_should_warn(protocol, reason) {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage could not be read; \
             billing 0 tokens for this request"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = protocol,
            reason = reason,
            "usage tap: a same-protocol 2xx body's usage still could not be read; \
             billing 0 tokens for this request"
        );
    }
}

#[cfg(test)]
#[path = "tests/usage_tap_tests.rs"]
mod usage_tap_tests;
