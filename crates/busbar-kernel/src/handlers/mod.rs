// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE-TAP FAULT HOST SERVICES (#83a HOST): the warn-once latch and the decode reporter a
//! plane's codec reaches through `busbar_contract::codec`, both counting on
//! `busbar_kernel::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL`, armed at boot
//! ([`crate::plane_host::arm_codec_host_services`]).
//!
//! The protocol request/operation handler registry that lived here (`request_handler`, `op_for`,
//! `chat`, `protocol_error` and the `OpDispatch` frame) read the kernel's protocol registry and had
//! no production caller once the llm plane served through its door; it is deleted (ARCHITECT
//! ruling Q2, 2026-10-07). A plane's operations are its own.

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

/// THE HOST'S USAGE-TAP FAULT REPORTER — what [`OperationHandler::extract_usage`](busbar_contract::codec::OperationHandler::extract_usage)'s default reports
/// through when a cell's own reader refuses a same-protocol 2xx body (the request bills 0 tokens).
/// Counted on [`BILLING_TAP_DECODE_FAIL_TOTAL`](crate::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL) and warned once per `(protocol, reason)`, exactly as
/// the default did inline before the trait moved into the contract, which takes no logging or metrics
/// dependency. Armed at boot by [`crate::plane_host::arm_codec_host_services`], so it is armed
/// before any cell is reachable.
pub fn report_usage_tap_decode_failure(
    ingress_protocol: &str,
    e: &busbar_contract::codec::CodecError,
) {
    if usage_tap_decode_fail_should_warn(ingress_protocol, "decode") {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = ingress_protocol,
            error = ?e,
            "usage tap: read_response failed to decode a same-protocol 2xx body; \
             billing 0 tokens for this request"
        );
    } else {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::USAGE_TAP_DECODE_FAILED,
            protocol = ingress_protocol,
            error = ?e,
            "usage tap: read_response still failing to decode a same-protocol 2xx body; \
             billing 0 tokens for this request"
        );
    }
}
