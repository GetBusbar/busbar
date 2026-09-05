// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The disposition-plus-outcome answer the egress unit's `Breaker::classify` port needs, and the
//! pure mapping from a classified upstream error onto it.
//!
//! [`classify`] answers ONLY the disposition (Stage 2 of the two-stage pipeline).
//! The egress port needs one step further: what the classified answer means to THIS unit's own
//! state machine (an [`Outcome`]) and the metric label a caller's dashboard reads. That fold is
//! [`outcome_and_label`] below, ported as data (not as HTTP/telemetry plumbing) from the four-way
//! split in 1.5.5's `classify_error` (`busbar-llm/src/engine/attempt/classify.rs:213-289`):
//! `ClientFault` records nothing and relays; `TransientUpstream` carries the upstream's own
//! `Retry-After` through as the cooldown floor; `HardDown` trips every pool cell for the
//! destination; `ContextLength` records nothing and fails over. [`classify_upstream`] composes that
//! fold with [`crate::classify::normalize_raw_error`] and [`crate::classify::classify`] into the one
//! call a caller needs, and [`crate::BreakerUnit::classify`] is the stateful method that reads the
//! declared per-destination `error_map` and calls it — together the pure function and the method the
//! task asks for.
//!
//! This module takes no dependency beyond [`crate::classify`] and [`crate::Outcome`] — in
//! particular, no `busbar-contract` (this crate's `Cargo.toml` is explicit that `busbar-caps` is the
//! only workspace crate it may name). The egress unit's own `UpstreamStatus` additionally carries
//! the transport's coarse status-class reading (`busbar_contract::StatusClass`); a caller that has
//! that reading folds it into [`UpstreamStatus::code`] itself before calling in — exactly the kind
//! of narrowing an integrator's adapter does, alongside the `DestinationId` width narrowing.

use crate::classify::{self, Disposition};
use crate::Outcome;

/// The upstream answer as this unit classifies it: an HTTP-status-shaped code (`None` when the
/// transport could not put a number on the failure) and the upstream's own requested wait.
///
/// `status.code`, when present, stands in for BOTH the HTTP status and the provider error code an
/// `error_map` entry is keyed on — the config grammar accepts a plain HTTP-status string as a key
/// (`error_map: { "400": client_error }`), which is the one signal a caller that reads no response
/// body (per `// contract:` in `busbar-unit-egress`'s `ports.rs`) can supply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// The upstream's numeric HTTP-shaped status, where one is known.
    pub code: Option<u16>,
    /// The upstream's requested Retry-After, in whole seconds, where it asked for one.
    pub retry_after: Option<u64>,
}

/// What the classifier made of one upstream answer: where the caller sends the request next, what
/// this unit's own state machine should be told, and the metric label for the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    /// Where the caller sends the request next.
    pub disposition: Disposition,
    /// What [`crate::Breaker::observe`] should be told.
    pub outcome: Outcome,
    /// The metric label for this failure.
    pub label: &'static str,
}

/// The metric label literals. These are pinned to the SAME string values as the egress unit's own
/// `ports::disposition` module — the two crates share no dependency to point at one constant, so the
/// values are kept in step by hand, deliberately, rather than through a shared type.
pub mod label {
    /// A transient upstream failure.
    pub const TRANSIENT_UPSTREAM: &str = "transient_upstream";
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = "hard_down";
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = "context_length";
    /// The caller's own fault. Never read as a telemetry label by the reference caller (a
    /// `ClientFault` short-circuits before the label is used) but a real value all the same — never
    /// a placeholder a future caller could mistake for "unset".
    pub const CLIENT_FAULT: &str = "client_fault";
}

/// Fold a classified [`Disposition`] into the [`Outcome`] this unit's state machine acts on and the
/// metric label a caller records the failure under. A pure function: no destination, no lock, no
/// clock.
#[must_use]
pub fn outcome_and_label(disposition: Disposition, retry_after: Option<u64>) -> (Outcome, &'static str) {
    match disposition {
        // The caller's bad input: the destination is healthy either way, so nothing is recorded —
        // folded together with `ContextLength` below, per `Outcome`'s own doc comment.
        Disposition::ClientFault => (Outcome::RecordNothing, label::CLIENT_FAULT),
        // A transient failure: the upstream's own Retry-After (if any) threads through as the
        // cooldown floor `BreakerCell::compute_cooldown_with_retry_after` reads.
        Disposition::TransientUpstream => (Outcome::Transient { retry_after }, label::TRANSIENT_UPSTREAM),
        // A definitive signal about the shared destination: every pool cell trips, not just this
        // one — see `BreakerUnit::hard_down_all`, which `BreakerUnit::observe` dispatches
        // `Outcome::HardDown` to.
        Disposition::HardDown => (Outcome::HardDown, label::HARD_DOWN),
        // Too big for this destination's window: the destination is healthy, record nothing.
        Disposition::ContextLength => (Outcome::RecordNothing, label::CONTEXT_LENGTH),
    }
}

/// Classify one upstream answer against a declared `error_map`, and fold the answer straight
/// through to the [`Outcome`] and label a caller acts on. The pure function
/// [`crate::BreakerUnit::classify`] is implemented over: no lock, no destination, no clock — a
/// caller with its own error-map storage can call this directly.
#[must_use]
pub fn classify_upstream(
    error_map: &std::collections::HashMap<String, String>,
    status: UpstreamStatus,
) -> Classified {
    let raw = classify::RawUpstreamError {
        http_status: status.code.unwrap_or(0),
        provider_code: status.code.map(|c| c.to_string()),
        structured_type: None,
        retry_after_secs: status.retry_after,
    };
    let sig = classify::normalize_raw_error(&raw, error_map, &classify::NoopDiagnostics);
    let disposition = classify::classify(&sig);
    let (outcome, label) = outcome_and_label(disposition, sig.retry_after);
    Classified { disposition, outcome, label }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::BreakerCfg;
    use crate::{Breaker, BreakerUnit, DestinationId, Outcome};
    use std::collections::HashMap;

    fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // ── outcome_and_label: the four-way fold, ported from `classify_error`'s match arms ─────────

    #[test]
    fn client_fault_records_nothing() {
        let (outcome, label) = outcome_and_label(Disposition::ClientFault, Some(30));
        assert_eq!(outcome, Outcome::RecordNothing);
        assert_eq!(label, label::CLIENT_FAULT);
    }

    #[test]
    fn context_length_records_nothing() {
        let (outcome, label) = outcome_and_label(Disposition::ContextLength, None);
        assert_eq!(outcome, Outcome::RecordNothing);
        assert_eq!(label, label::CONTEXT_LENGTH);
    }

    #[test]
    fn transient_upstream_threads_retry_after_through() {
        let (outcome, label) = outcome_and_label(Disposition::TransientUpstream, Some(42));
        assert_eq!(outcome, Outcome::Transient { retry_after: Some(42) });
        assert_eq!(label, label::TRANSIENT_UPSTREAM);
    }

    #[test]
    fn transient_upstream_with_no_retry_after() {
        let (outcome, _) = outcome_and_label(Disposition::TransientUpstream, None);
        assert_eq!(outcome, Outcome::Transient { retry_after: None });
    }

    #[test]
    fn hard_down_is_hard_down() {
        let (outcome, label) = outcome_and_label(Disposition::HardDown, None);
        assert_eq!(outcome, Outcome::HardDown);
        assert_eq!(label, label::HARD_DOWN);
    }

    // ── classify_upstream: error_map precedence over the HTTP-status table, verbatim values from
    //    `busbar-llm/src/engine/tests/forward_pool_integration_tests.rs` (codes 1113 → billing,
    //    1302 → rate_limit) ────────────────────────────────────────────────────────────────────

    #[test]
    fn error_map_code_wins_over_http_status() {
        // Bedrock-shaped: code "1113" carries no intrinsic meaning in the HTTP-status table; the
        // operator's error_map is what turns it into a hard-down billing signal.
        let map = err_map(&[("1113", "billing")]);
        let out = classify_upstream(&map, UpstreamStatus { code: Some(1113), retry_after: None });
        assert_eq!(out.disposition, Disposition::HardDown);
        assert_eq!(out.outcome, Outcome::HardDown);
    }

    #[test]
    fn unmapped_code_falls_through_to_http_status() {
        let map = err_map(&[("1113", "billing")]);
        let out = classify_upstream(&map, UpstreamStatus { code: Some(500), retry_after: None });
        assert_eq!(out.disposition, Disposition::TransientUpstream);
        assert_eq!(out.outcome, Outcome::Transient { retry_after: None });
    }

    #[test]
    fn empty_error_map_still_classifies_by_http_status() {
        let out = classify_upstream(&HashMap::new(), UpstreamStatus { code: Some(429), retry_after: Some(7) });
        assert_eq!(out.disposition, Disposition::TransientUpstream);
        assert_eq!(out.outcome, Outcome::Transient { retry_after: Some(7) });
        assert_eq!(out.label, label::TRANSIENT_UPSTREAM);
    }

    #[test]
    fn auth_status_is_hard_down() {
        let out = classify_upstream(&HashMap::new(), UpstreamStatus { code: Some(401), retry_after: None });
        assert_eq!(out.disposition, Disposition::HardDown);
        assert_eq!(out.outcome, Outcome::HardDown);
    }

    #[test]
    fn client_error_status_is_client_fault_with_no_penalty() {
        let out = classify_upstream(&HashMap::new(), UpstreamStatus { code: Some(422), retry_after: None });
        assert_eq!(out.disposition, Disposition::ClientFault);
        assert_eq!(out.outcome, Outcome::RecordNothing);
    }

    #[test]
    fn no_code_at_all_classifies_as_client_error_via_status_zero() {
        // A caller with no numeric status to report (`status.code: None`) — the same "unexpected
        // non-error status reaching the error path" fallback 1.5.5 took for a 2xx/3xx: no penalty,
        // relay as-is.
        let out = classify_upstream(&HashMap::new(), UpstreamStatus { code: None, retry_after: None });
        assert_eq!(out.disposition, Disposition::ClientFault);
        assert_eq!(out.outcome, Outcome::RecordNothing);
    }

    // ── BreakerUnit::classify: the stateful method, reading the declared per-destination error_map

    #[test]
    fn breaker_unit_classify_reads_the_declared_error_map() {
        let unit: BreakerUnit = BreakerUnit::new();
        unit.set_error_map(DestinationId::new(7), err_map(&[("1113", "billing")]));

        let out = unit.classify(DestinationId::new(7), UpstreamStatus { code: Some(1113), retry_after: None });
        assert_eq!(out.disposition, Disposition::HardDown);

        // A different destination with no declared map falls back to plain HTTP-status
        // classification for the SAME numeric code.
        let out2 = unit.classify(DestinationId::new(8), UpstreamStatus { code: Some(1113), retry_after: None });
        assert_eq!(out2.disposition, Disposition::ClientFault);
    }

    #[test]
    fn breaker_unit_classify_then_observe_trips_every_pool_cell_on_hard_down() {
        let unit: BreakerUnit = BreakerUnit::new();
        unit.set_error_map(DestinationId::new(7), err_map(&[("1113", "billing")]));
        // Touch two pools so `hard_down_all`'s fan-out has more than the default cell to reach.
        let _ = unit.try_admit("pool-a", DestinationId::new(7), 0);
        let _ = unit.try_admit("pool-b", DestinationId::new(7), 0);

        let out = unit.classify(DestinationId::new(7), UpstreamStatus { code: Some(1113), retry_after: None });
        let tripped = unit.observe("pool-a", DestinationId::new(7), out.outcome, &BreakerCfg::default(), 0);
        assert!(tripped, "the first hard-down observation must be a fresh trip");

        assert_eq!(unit.state("pool-a", DestinationId::new(7), 100), crate::LaneState::Suppressed { until: 1800 });
        assert_eq!(unit.state("pool-b", DestinationId::new(7), 100), crate::LaneState::Suppressed { until: 1800 });
    }
}
