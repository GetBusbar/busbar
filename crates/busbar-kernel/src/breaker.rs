// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker vocabulary the host and the dialect readers share, and the served path's two-stage
//! disposition pipeline:
//! - Stage 1 (the dialects): per-protocol extraction of a [`RawUpstreamError`] from a response.
//! - Stage 1b ([`normalize_raw_error`], the breaker unit's `normalize`): the operator `error_map`
//!   and the HTTP-status defaults place it in a [`StatusClass`].
//! - Stage 2 ([`classify`]): the class's [`Disposition`], the contract's table.
//!
//! Mapping (+ ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// The status class, the disposition, the raw upstream error and the canonical signal, as the
/// contract owns them (DECISIONS #83).
pub use busbar_contract::upstream::{CanonicalSignal, Disposition, RawUpstreamError, StatusClass};

/// Parse a `Retry-After` header (both RFC 9110 forms: delay-seconds, or an HTTP-date read against
/// the wall clock now, floored at zero) — the breaker unit's read, handed the host's clock.
pub fn parse_retry_after(headers: &http::HeaderMap) -> Option<u64> {
    busbar_kernel_breaker::normalize::parse_retry_after(headers, std::time::SystemTime::now())
}

/// Convert a string to StatusClass. Returns None for unknown values.
pub fn status_class_from_str(s: &str) -> Option<StatusClass> {
    StatusClass::parse(s)
}

/// Classify a CanonicalSignal into a disposition — the disposition column of the contract's table.
/// Per ADR-0002: ClientFault never counted; HardDown immediate trip.
pub fn classify(sig: &CanonicalSignal) -> Disposition {
    sig.class.disposition()
}

/// Classify a raw upstream error into a canonical signal using an operator `error_map` — the
/// breaker unit's normalizer, with an unrecognized mapping reported once per value in the host's
/// coded diagnostic.
pub fn normalize_raw_error(
    raw: &RawUpstreamError,
    error_map: &std::collections::HashMap<String, String>,
) -> CanonicalSignal {
    busbar_kernel_breaker::normalize::normalize_raw_error(
        raw,
        error_map,
        &warn_unrecognized_error_map_value,
    )
}

/// Warn (once per distinct value) that an operator `error_map` entry maps to a string that is not a
/// recognized StatusClass. Such a value is silently ignored by `normalize_raw_error` — the error
/// then falls through to HTTP-status classification — so without this signal a typo'd mapping (e.g.
/// `rate_limt`) would never take effect and the operator would have no indication why. Deduped via a
/// process-wide set so a misconfiguration on a hot error path logs once, not per request.
fn warn_unrecognized_error_map_value(value: &str) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    // Poisoning is harmless here (the set only dedupes warnings); recover the guard either way.
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.insert(value.to_string()) {
        crate::diagnostics::diag_warn!(
            crate::diagnostics::CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED,
            error_map_value = value,
            "error_map maps an error to an unrecognized status class; the mapping is IGNORED and \
             classification falls through to HTTP status. Valid classes: rate_limit, overloaded, \
             server_error, timeout, network, auth, billing, client_error, context_length"
        );
    }
}

#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod tests;
