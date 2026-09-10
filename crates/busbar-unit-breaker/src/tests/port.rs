//! Tests for `port.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
        0_u128,
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
