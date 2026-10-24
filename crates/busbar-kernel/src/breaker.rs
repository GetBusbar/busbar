// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker vocabulary the host and the planes share: the status class an operator's
//! `error_map` names, and the class's [`Disposition`] (the contract's table).
//!
//! The kernel reads no far end's error here: no status band, no `Retry-After` header and no
//! vendor's status or dialect's code (Law 1). A plane places its own far end's error in a class
//! (its reading of its dialect, Law 5); the breaker unit acts on the facts it is handed.
//!
//! Mapping (+ ADR-0002):
//!   RateLimit|Overloaded|ServerError|Timeout|Network → TransientUpstream
//!   Auth|Billing → HardDown
//!   ClientError → ClientFault

/// The status class, the disposition, the raw upstream error and the canonical signal, as the
/// contract owns them (DECISIONS #83).
pub use busbar_contract::upstream::{CanonicalSignal, Disposition, RawUpstreamError, StatusClass};

/// Convert a string to StatusClass. Returns None for unknown values.
pub fn status_class_from_str(s: &str) -> Option<StatusClass> {
    StatusClass::parse(s)
}

/// Classify a CanonicalSignal into a disposition — the disposition column of the contract's table.
/// Per ADR-0002: ClientFault never counted; HardDown immediate trip.
pub fn classify(sig: &CanonicalSignal) -> Disposition {
    sig.class.disposition()
}

#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod tests;
