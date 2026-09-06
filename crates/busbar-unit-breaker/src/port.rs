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
//!
//! What that narrowing may NOT drop is the numbering the status was spelled in: [`UpstreamCode`]
//! restates the transport contract's namespaced status in this crate's own vocabulary, so an
//! integrator hands over `Grpc(14)` and not the bare `14` an HTTP band-check would fail to place.

use crate::classify::{self, Disposition};
use crate::Outcome;

/// The numbering an upstream status was spelled in, carried WITH the number.
///
/// This unit takes no dependency on the transport contract, so it cannot name that contract's
/// `WireStatus` — but the fact the two types carry is the same one, and an integrator's adapter
/// narrows across (exactly as it already does for the destination's width). What matters is that
/// neither side can hand a bare number over: a `14` read against HTTP's bands matches no band at
/// all, and the destination that just said `UNAVAILABLE` would go unrecorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamCode {
    /// An HTTP status. Classified by band, as 1.5.5 classified every upstream.
    Http(u16),
    /// A `grpc-status` code. Classified through [`crate::classify::GRPC_STATUS_TABLE`], which is
    /// gRPC's own numbering and shares nothing with HTTP's but the fact that it is a number.
    Grpc(u8),
}

/// The upstream answer as this unit classifies it: the numeric status WITH its namespace (`None`
/// when the transport could not put a number on the failure) and the upstream's own requested wait.
///
/// `status.code`, when it is an [`UpstreamCode::Http`], stands in for BOTH the HTTP status and the
/// provider error code an `error_map` entry is keyed on — the config grammar accepts a plain
/// HTTP-status string as a key (`error_map: { "400": client_error }`), which is the one signal a
/// caller that reads no response body (per `// contract:` in `busbar-unit-egress`'s `ports.rs`) can
/// supply. A gRPC code is NOT offered to the `error_map` as a provider code: those keys are
/// HTTP-status strings by the config grammar, and feeding `14` in would let an operator's rule for
/// HTTP `14` — a status that does not exist — silently claim a gRPC `UNAVAILABLE`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// The upstream's numeric status and the numbering that spelled it, where one is known.
    pub code: Option<UpstreamCode>,
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
pub fn outcome_and_label(
    disposition: Disposition,
    retry_after: Option<u64>,
) -> (Outcome, &'static str) {
    match disposition {
        // The caller's bad input: the destination is healthy either way, so nothing is recorded —
        // folded together with `ContextLength` below, per `Outcome`'s own doc comment.
        Disposition::ClientFault => (Outcome::RecordNothing, label::CLIENT_FAULT),
        // A transient failure: the upstream's own Retry-After (if any) threads through as the
        // cooldown floor `BreakerCell::compute_cooldown_with_retry_after` reads.
        Disposition::TransientUpstream => (
            Outcome::Transient { retry_after },
            label::TRANSIENT_UPSTREAM,
        ),
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
///
/// `diagnostics` is the sink an unrecognized `error_map` value is reported to: this
/// function no longer hardcodes [`classify::NoopDiagnostics`] internally, so a real sink bound by
/// the composition root actually reaches the classifier. Pass `&classify::NoopDiagnostics` for
/// today's silently-ignored behavior.
#[must_use]
pub fn classify_upstream(
    error_map: &std::collections::HashMap<String, String>,
    status: UpstreamStatus,
    diagnostics: &dyn classify::Diagnostics,
) -> Classified {
    // Each namespace through its own table. The gRPC leg never enters the HTTP normalizer at all:
    // that normalizer's every branch — the 401/403 arm, the 429 arm, the 5xx band — is a statement
    // about HTTP's numbering, and a gRPC code walking through it lands wherever its digits happen
    // to fall.
    let sig = match status.code {
        Some(UpstreamCode::Grpc(code)) => classify::CanonicalSignal {
            class: classify::grpc_status_class(code),
            provider_signal: None,
            retry_after: status.retry_after,
        },
        http => {
            let http_status = match http {
                Some(UpstreamCode::Http(code)) => Some(code),
                _ => None,
            };
            let raw = classify::RawUpstreamError {
                http_status: http_status.unwrap_or(0),
                provider_code: http_status.map(|c| c.to_string()),
                structured_type: None,
                retry_after_secs: status.retry_after,
            };
            classify::normalize_raw_error(&raw, error_map, diagnostics)
        }
    };
    let disposition = classify::classify(&sig);
    let (outcome, label) = outcome_and_label(disposition, sig.retry_after);
    Classified {
        disposition,
        outcome,
        label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::BreakerCfg;
    use crate::classify::{Diagnostics, NoopDiagnostics, WarnOnceDiagnostics};
    use crate::{Breaker, BreakerUnit, DestinationId, Outcome};
    use busbar_caps::{KernelSeal, Route, UnitToken};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A fresh `UnitToken<Route>` for one `observe`/`state` call — test-only, minted through the
    /// kernel seal exactly as CG-29 says a real deployment would.
    fn route_token() -> UnitToken<Route> {
        UnitToken::mint(&KernelSeal::acquire_for_kernel())
    }

    /// A [`Diagnostics`] sink that records every call it receives, unconditionally (no dedup of
    /// its own) — used underneath [`WarnOnceDiagnostics`] to prove the wrapper is what dedups.
    #[derive(Default)]
    struct RecordingDiagnostics {
        calls: Mutex<Vec<String>>,
    }

    impl Diagnostics for RecordingDiagnostics {
        fn unrecognized_error_map_value(&self, value: &str) {
            self.calls.lock().unwrap().push(value.to_string());
        }
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
        assert_eq!(
            outcome,
            Outcome::Transient {
                retry_after: Some(42)
            }
        );
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
        let out = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::HardDown);
        assert_eq!(out.outcome, Outcome::HardDown);
    }

    #[test]
    fn unmapped_code_falls_through_to_http_status() {
        let map = err_map(&[("1113", "billing")]);
        let out = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(500)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::TransientUpstream);
        assert_eq!(out.outcome, Outcome::Transient { retry_after: None });
    }

    #[test]
    fn empty_error_map_still_classifies_by_http_status() {
        let out = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(429)),
                retry_after: Some(7),
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::TransientUpstream);
        assert_eq!(
            out.outcome,
            Outcome::Transient {
                retry_after: Some(7)
            }
        );
        assert_eq!(out.label, label::TRANSIENT_UPSTREAM);
    }

    #[test]
    fn auth_status_is_hard_down() {
        let out = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(401)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::HardDown);
        assert_eq!(out.outcome, Outcome::HardDown);
    }

    #[test]
    fn client_error_status_is_client_fault_with_no_penalty() {
        let out = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(422)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::ClientFault);
        assert_eq!(out.outcome, Outcome::RecordNothing);
    }

    #[test]
    fn no_code_at_all_classifies_as_client_error_via_status_zero() {
        // A caller with no numeric status to report (`status.code: None`) — the same "unexpected
        // non-error status reaching the error path" fallback 1.5.5 took for a 2xx/3xx: no penalty,
        // relay as-is.
        let out = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: None,
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(out.disposition, Disposition::ClientFault);
        assert_eq!(out.outcome, Outcome::RecordNothing);
    }

    // ── BreakerUnit::classify: the stateful method, reading the declared per-destination error_map

    #[test]
    fn breaker_unit_classify_reads_the_declared_error_map() {
        let unit: BreakerUnit = BreakerUnit::new();
        unit.set_error_map(DestinationId::new(7), err_map(&[("1113", "billing")]));

        let out = unit.classify(
            DestinationId::new(7),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
        );
        assert_eq!(out.disposition, Disposition::HardDown);

        // A different destination with no declared map falls back to plain HTTP-status
        // classification for the SAME numeric code.
        let out2 = unit.classify(
            DestinationId::new(8),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
        );
        assert_eq!(out2.disposition, Disposition::ClientFault);
    }

    #[test]
    fn breaker_unit_classify_then_observe_trips_every_pool_cell_on_hard_down() {
        let unit: BreakerUnit = BreakerUnit::new();
        unit.set_error_map(DestinationId::new(7), err_map(&[("1113", "billing")]));
        // Touch two pools so `hard_down_all`'s fan-out has more than the default cell to reach.
        let _ = unit.try_admit("pool-a", DestinationId::new(7), 0);
        let _ = unit.try_admit("pool-b", DestinationId::new(7), 0);

        let out = unit.classify(
            DestinationId::new(7),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
        );
        let tripped = unit.observe(
            "pool-a",
            DestinationId::new(7),
            out.outcome,
            &BreakerCfg::default(),
            0,
            &route_token(),
        );
        assert!(
            tripped,
            "the first hard-down observation must be a fresh trip"
        );

        assert_eq!(
            unit.state("pool-a", DestinationId::new(7), 100, &route_token()),
            crate::LaneState::Suppressed { until: 1800 }
        );
        assert_eq!(
            unit.state("pool-b", DestinationId::new(7), 100, &route_token()),
            crate::LaneState::Suppressed { until: 1800 }
        );
    }

    // ── CG-43: the diagnostics sink reaches `classify` ──────────────────────────────────────────

    #[test]
    fn an_unrecognized_error_map_value_warns_the_sink_exactly_once() {
        let sink = Arc::new(RecordingDiagnostics::default());
        let warn_once = WarnOnceDiagnostics::new(sink.clone());
        let map = err_map(&[("1113", "not_a_real_class")]);

        // Two calls with the same unrecognized mapped value: the sink is told once.
        let _ = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
            &warn_once,
        );
        let _ = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
            &warn_once,
        );

        assert_eq!(
            *sink.calls.lock().unwrap(),
            vec!["not_a_real_class".to_string()],
            "the second occurrence of the same unrecognized value must not warn again"
        );
    }

    #[test]
    fn noop_diagnostics_stays_silent_on_an_unrecognized_error_map_value() {
        // The default sink: an unrecognized mapping still falls through to HTTP-status
        // classification (the RESULT is unaffected), and NoopDiagnostics records nothing to check
        // against — its only contract is that it never panics and never calls out anywhere.
        let map = err_map(&[("1113", "not_a_real_class")]);
        let out = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        // Falls through to HTTP-status classification: no numeric status recognized as an error
        // (code stood in for the status here), so it lands on the client-fault fallback.
        assert_eq!(out.disposition, Disposition::ClientFault);
    }

    #[test]
    fn breaker_unit_classify_reaches_its_own_diagnostics_sink() {
        // CG-43's binding: `BreakerUnit::classify` must route to the caller-supplied sink, not the
        // hardcoded `NoopDiagnostics` `classify_upstream` used to close over internally.
        let sink = Arc::new(RecordingDiagnostics::default());
        let unit: BreakerUnit<
            crate::journal::NoopJournal,
            WarnOnceDiagnostics<Arc<RecordingDiagnostics>>,
        > = BreakerUnit::with_diagnostics(WarnOnceDiagnostics::new(sink.clone()));
        unit.set_error_map(
            DestinationId::new(1),
            err_map(&[("1113", "not_a_real_class")]),
        );

        let _ = unit.classify(
            DestinationId::new(1),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
        );
        let _ = unit.classify(
            DestinationId::new(1),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(1113)),
                retry_after: None,
            },
        );

        assert_eq!(
            *sink.calls.lock().unwrap(),
            vec!["not_a_real_class".to_string()],
            "the sink must be reached exactly once, through BreakerUnit::classify"
        );
    }

    // ── the two namespaces, each against its own table ──────────────────────────────────────────

    /// Every code gRPC defines, stated as the disposition the walk acts on. Written out rather than
    /// derived from `GRPC_STATUS_TABLE` on purpose: a table that classified itself would agree with
    /// any value it happened to hold, and what needs proving is the money decision behind each row —
    /// which codes penalise the destination, which take it down across every pool, and which are the
    /// caller's own fault and cost the destination nothing.
    const GRPC_DISPOSITIONS: &[(u8, Disposition)] = &[
        (classify::GRPC_OK, Disposition::ClientFault),
        (classify::GRPC_CANCELLED, Disposition::ClientFault),
        (classify::GRPC_UNKNOWN, Disposition::TransientUpstream),
        (classify::GRPC_INVALID_ARGUMENT, Disposition::ClientFault),
        (
            classify::GRPC_DEADLINE_EXCEEDED,
            Disposition::TransientUpstream,
        ),
        (classify::GRPC_NOT_FOUND, Disposition::ClientFault),
        (classify::GRPC_ALREADY_EXISTS, Disposition::ClientFault),
        (classify::GRPC_PERMISSION_DENIED, Disposition::HardDown),
        (
            classify::GRPC_RESOURCE_EXHAUSTED,
            Disposition::TransientUpstream,
        ),
        (classify::GRPC_FAILED_PRECONDITION, Disposition::ClientFault),
        (classify::GRPC_ABORTED, Disposition::TransientUpstream),
        (classify::GRPC_OUT_OF_RANGE, Disposition::ClientFault),
        (classify::GRPC_UNIMPLEMENTED, Disposition::ClientFault),
        (classify::GRPC_INTERNAL, Disposition::TransientUpstream),
        (classify::GRPC_UNAVAILABLE, Disposition::TransientUpstream),
        (classify::GRPC_DATA_LOSS, Disposition::TransientUpstream),
        (classify::GRPC_UNAUTHENTICATED, Disposition::HardDown),
    ];

    #[test]
    fn every_grpc_code_classifies_through_grpcs_own_table() {
        for (code, expected) in GRPC_DISPOSITIONS {
            let got = classify_upstream(
                &HashMap::new(),
                UpstreamStatus {
                    code: Some(UpstreamCode::Grpc(*code)),
                    retry_after: None,
                },
                &NoopDiagnostics,
            );
            assert_eq!(
                got.disposition, *expected,
                "grpc-status {code} must classify as {expected:?}"
            );
        }
    }

    /// The table covers gRPC's whole numbering with no gaps and no repeats, so no code can quietly
    /// fall through to the unknown-code answer.
    #[test]
    fn the_grpc_table_names_every_code_exactly_once() {
        let mut seen: Vec<u8> = classify::GRPC_STATUS_TABLE
            .iter()
            .map(|(c, _)| *c)
            .collect();
        seen.sort_unstable();
        let all: Vec<u8> = (classify::GRPC_OK..=classify::GRPC_UNAUTHENTICATED).collect();
        assert_eq!(seen, all, "every grpc code has exactly one row");
        assert_eq!(
            GRPC_DISPOSITIONS.len(),
            classify::GRPC_STATUS_TABLE.len(),
            "the asserted dispositions cover the whole table"
        );
    }

    /// A number gRPC has never defined is evidence about nobody: it must not invent an outage and
    /// trip a live lane.
    #[test]
    fn an_undefined_grpc_code_records_nothing() {
        let got = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Grpc(200)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(got.disposition, Disposition::ClientFault);
        assert_eq!(got.outcome, Outcome::RecordNothing);
    }

    /// Every HTTP band, at its edges and at the statuses that are read out of their band. Sits
    /// beside the gRPC table so the two namespaces are visibly separate readings of a number — and
    /// so a change that folded them back together fails on both.
    #[test]
    fn every_http_band_classifies_through_https_own_table() {
        let bands: &[(u16, Disposition)] = &[
            (200, Disposition::ClientFault),
            (301, Disposition::ClientFault),
            (400, Disposition::ClientFault),
            (401, Disposition::HardDown),
            (403, Disposition::HardDown),
            (404, Disposition::ClientFault),
            (408, Disposition::TransientUpstream),
            (422, Disposition::ClientFault),
            (429, Disposition::TransientUpstream),
            (499, Disposition::ClientFault),
            (500, Disposition::TransientUpstream),
            (503, Disposition::TransientUpstream),
            (529, Disposition::TransientUpstream),
            (599, Disposition::TransientUpstream),
        ];
        for (status, expected) in bands {
            let got = classify_upstream(
                &HashMap::new(),
                UpstreamStatus {
                    code: Some(UpstreamCode::Http(*status)),
                    retry_after: None,
                },
                &NoopDiagnostics,
            );
            assert_eq!(
                got.disposition, *expected,
                "http {status} must classify as {expected:?}"
            );
        }
    }

    /// The defect this pair of tables replaces, stated as the difference the namespace makes. The
    /// SAME number classifies two ways because it is two different facts, and the gRPC reading is
    /// the one that penalises the destination.
    #[test]
    fn the_same_number_means_different_things_in_the_two_namespaces() {
        let as_grpc = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Grpc(classify::GRPC_UNAVAILABLE)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        let as_http = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Http(u16::from(classify::GRPC_UNAVAILABLE))),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(as_grpc.disposition, Disposition::TransientUpstream);
        assert_eq!(
            as_grpc.outcome,
            Outcome::Transient { retry_after: None },
            "an UNAVAILABLE upstream is recorded against the destination"
        );
        assert_eq!(
            as_http.disposition,
            Disposition::ClientFault,
            "read as an HTTP status the same digits match no band at all — which is exactly the \
             reading that recorded nothing and never failed over"
        );
    }

    /// A gRPC `RESOURCE_EXHAUSTED` carries the upstream's own wait through as the cooldown floor,
    /// the same way an HTTP 429 does — the wait is a fact about the answer, not about HTTP.
    #[test]
    fn a_grpc_resource_exhausted_carries_the_upstreams_wait() {
        let got = classify_upstream(
            &HashMap::new(),
            UpstreamStatus {
                code: Some(UpstreamCode::Grpc(classify::GRPC_RESOURCE_EXHAUSTED)),
                retry_after: Some(9),
            },
            &NoopDiagnostics,
        );
        assert_eq!(
            got.outcome,
            Outcome::Transient {
                retry_after: Some(9)
            }
        );
    }

    /// An operator's `error_map` is keyed on HTTP statuses by the config grammar, so a rule for the
    /// HTTP status `14` — which does not exist — must not reach across and claim a gRPC
    /// `UNAVAILABLE`.
    #[test]
    fn an_http_keyed_error_map_does_not_claim_a_grpc_code() {
        let map = err_map(&[("14", "client_error")]);
        let got = classify_upstream(
            &map,
            UpstreamStatus {
                code: Some(UpstreamCode::Grpc(classify::GRPC_UNAVAILABLE)),
                retry_after: None,
            },
            &NoopDiagnostics,
        );
        assert_eq!(got.disposition, Disposition::TransientUpstream);
    }
}
