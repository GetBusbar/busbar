//! Tests for the breaker unit.
//!
//! The first block ports every classification test from
//! `busbar-substrate::tests::breaker_tests` (1.5.5's
//! `crates/busbar-substrate/src/tests/breaker_tests.rs`) verbatim in assertion, adapted only for
//! this crate's dependency-free signatures (`normalize_raw_error` takes a [`classify::Diagnostics`]
//! sink instead of nothing/`tracing`; `parse_retry_after` takes a `&str` instead of an
//! `axum::http::HeaderMap`). Not ported: `retry_after_accepts_the_http_date_form` and
//! `a_past_http_date_retry_after_floors_at_zero` used the `httpdate` crate to FORMAT a date to feed
//! back in — this crate has no `httpdate` dependency, so those two are reproduced against
//! hand-written IMF-fixdate strings instead of a round-trip through a formatter; the parsing
//! arithmetic under test is identical.
//!
//! The second block is new: state-machine tests the task specifically calls for, driven through
//! the public [`Breaker`] seam rather than 1.5.5's internal `cell_*` free functions (this crate has
//! no direct callers of those internals to mirror — `BreakerUnit` is the whole public surface).

use crate::budget::LifetimeBudget;
use crate::cell::{BreakerCell, BreakerState};
use crate::cfg::{BreakerCfg, TripConfig, TripMode};
use crate::classify::{
    classify, normalize_raw_error, parse_retry_after, status_class_from_str, CanonicalSignal,
    Disposition, NoopDiagnostics, RawUpstreamError, StatusClass, PROVIDER_CODE_CONTEXT_LENGTH,
};
use crate::{Admit, Breaker, BreakerUnit, DestinationId, LaneState, Outcome};
use std::collections::HashMap;

fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

// ── Ported: classification pipeline ─────────────────────────────────────────────────────────────

#[test]
fn test_structured_type_drives_error_map() {
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: None,
        structured_type: Some("model_overloaded".to_string()),
        retry_after_secs: None,
    };
    let map = err_map(&[("model_overloaded", "overloaded")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::Overloaded);
    assert_eq!(sig.provider_signal.as_deref(), Some("model_overloaded"));
}

#[test]
fn test_provider_code_wins_over_structured_type() {
    let raw = RawUpstreamError {
        http_status: 500,
        provider_code: Some("1302".to_string()),
        structured_type: Some("server_error".to_string()),
        retry_after_secs: None,
    };
    let map = err_map(&[("1302", "rate_limit"), ("server_error", "server_error")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::RateLimit);
}

#[test]
fn test_builtin_context_length_on_real_400_classifies_context_length() {
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some(PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new(), &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ContextLength);
    assert_eq!(sig.provider_signal.as_deref(), Some("context_length_exceeded"));
}

#[test]
fn test_builtin_context_length_not_recognized_on_5xx() {
    let raw = RawUpstreamError {
        http_status: 503,
        provider_code: Some(PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new(), &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ServerError);
}

#[test]
fn test_operator_error_map_overrides_builtin_context_length() {
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some(PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[(PROVIDER_CODE_CONTEXT_LENGTH, "client_error")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ClientError);
}

#[test]
fn test_operator_map_context_length_on_5xx_is_penalized() {
    let raw = RawUpstreamError {
        http_status: 503,
        provider_code: Some("1234".to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[("1234", "context_length")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ServerError);
    assert_eq!(classify(&sig), Disposition::TransientUpstream);
}

#[test]
fn test_operator_map_context_length_on_400_still_classifies_context_length() {
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some("1234".to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[("1234", "context_length")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ContextLength);
}

#[test]
fn test_structured_type_context_length_on_5xx_is_penalized() {
    let raw = RawUpstreamError {
        http_status: 502,
        provider_code: None,
        structured_type: Some("ctx_overflow".to_string()),
        retry_after_secs: None,
    };
    let map = err_map(&[("ctx_overflow", "context_length")]);
    let sig = normalize_raw_error(&raw, &map, &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ServerError);
    assert_eq!(classify(&sig), Disposition::TransientUpstream);
}

#[test]
fn test_builtin_context_length_not_recognized_on_non_request_size_4xx() {
    let raw = RawUpstreamError {
        http_status: 403,
        provider_code: Some(PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new(), &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::Auth);
}

#[test]
fn test_builtin_context_length_recognized_on_413() {
    let raw = RawUpstreamError {
        http_status: 413,
        provider_code: Some(PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new(), &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::ContextLength);
}

#[test]
fn test_unmapped_structured_type_falls_through_to_http() {
    let raw = RawUpstreamError {
        http_status: 429,
        provider_code: None,
        structured_type: Some("something_unmapped".to_string()),
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new(), &NoopDiagnostics);
    assert_eq!(sig.class, StatusClass::RateLimit);
}

#[test]
fn retry_after_accepts_the_http_date_form() {
    // A hand-written IMF-fixdate ~120s in the future (see module doc: no `httpdate` dependency to
    // format one, so the string is written out directly).
    let secs = parse_retry_after("Sun, 06 Nov 2286 08:49:37 GMT");
    let n = secs.expect("HTTP-date Retry-After must parse");
    assert!(n > 0);
}

#[test]
fn retry_after_accepts_delay_seconds() {
    assert_eq!(parse_retry_after("120"), Some(120));
}

#[test]
fn a_past_http_date_retry_after_floors_at_zero() {
    assert_eq!(parse_retry_after("Mon, 01 Jan 1990 00:00:00 GMT"), Some(0));
}

#[test]
fn a_missing_retry_after_is_none() {
    assert_eq!(parse_retry_after(""), None);
}

#[test]
fn status_class_from_str_maps_known_values_and_rejects_unknown() {
    assert!(matches!(status_class_from_str("rate_limit"), Some(StatusClass::RateLimit)));
    assert!(matches!(status_class_from_str("overloaded"), Some(StatusClass::Overloaded)));
    assert!(matches!(status_class_from_str("server_error"), Some(StatusClass::ServerError)));
    assert!(matches!(status_class_from_str("timeout"), Some(StatusClass::Timeout)));
    assert!(matches!(status_class_from_str("network"), Some(StatusClass::Network)));
    assert!(matches!(status_class_from_str("auth"), Some(StatusClass::Auth)));
    assert!(status_class_from_str("not_a_class").is_none());
    assert!(status_class_from_str("").is_none());
}

#[test]
fn disposition_table_matches_the_classify_match() {
    for (class, disposition) in crate::classify::DISPOSITION_TABLE {
        let sig = CanonicalSignal {
            class: *class,
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(classify(&sig), *disposition, "table row for {class:?} disagrees with classify()");
    }
}

// ── Not ported ───────────────────────────────────────────────────────────────────────────────────
//
// `crates/busbar-llm/src/engine/tests/{forward_once_pool_cell,probe_guard,probe_release_owner}_tests.rs`:
// every test in those three files dispatches through the LLM engine's `forward_once` (live HTTP
// mocking, pool config parsing, the routing walk) to reach the breaker assertion at the end. None
// of that harness exists in this crate — it is the egress unit's and the LLM plane's, not the
// breaker unit's — so there is nothing to port the SCAFFOLDING into; only the state-machine
// assertions they end on are reproduced, directly against `BreakerCell`/`BreakerUnit`, below and in
// `cell.rs`'s doc-derived arithmetic. Concretely not reproduced: the mock-HTTP-server setup, the
// `PoolConfig`/`ModelCfg` parsing, and any assertion about the SWRR selection order or the
// concurrency semaphore (egress unit scope).

// ── New: state-machine behavior the task calls for ──────────────────────────────────────────────

fn consecutive_cfg(base_cooldown_secs: u64, max_cooldown_secs: u64) -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs,
        max_cooldown_secs,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 1,
            ..TripConfig::default()
        },
        bench_below_trip_threshold: true,
    }
}

#[test]
fn trip_then_cooldown_then_half_open_then_success_closes() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = consecutive_cfg(100, 10_000);
    let now = 1_000;

    // One failure trips a Consecutive(1) cell.
    let tripped = unit.observe("pool", DestinationId::new(1), Outcome::Transient { retry_after: None }, &cfg, now);
    assert!(tripped, "a single failure must trip a consecutive_n=1 cell");
    let LaneState::Suppressed { until } = unit.state("pool", DestinationId::new(1), now) else {
        panic!("expected Suppressed immediately after a trip");
    };
    assert!(until > now, "cooldown must extend into the future");

    // Still cooling: try_admit is refused.
    assert_eq!(unit.try_admit("pool", DestinationId::new(1), now), Err(LaneState::Suppressed { until }));

    // Past the cooldown: the cell is probe-winnable and try_admit wins the single-flight probe.
    let past = until;
    let admit = unit.try_admit("pool", DestinationId::new(1), past).expect("expired cooldown must admit a probe");
    assert!(matches!(admit, Admit { probe_epoch: Some(_) }));
    assert_eq!(unit.state("pool", DestinationId::new(1), past), LaneState::ProbeInFlight);

    // The probe succeeds: the cell recovers to Closed/Ready.
    let re_tripped = unit.observe("pool", DestinationId::new(1), Outcome::Success, &cfg, past);
    assert!(!re_tripped, "a success is never reported as a trip");
    assert_eq!(unit.state("pool", DestinationId::new(1), past), LaneState::Ready);
}

#[test]
fn a_failed_probe_re_trips_with_the_shifted_cooldown() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = consecutive_cfg(200, 100_000);
    let now = 1_000;

    unit.observe("pool", DestinationId::new(1), Outcome::Transient { retry_after: None }, &cfg, now);
    let LaneState::Suppressed { until: first_until } = unit.state("pool", DestinationId::new(1), now) else {
        panic!("expected Suppressed after the first trip");
    };
    let first_cooldown = first_until - now;
    // The consecutive-failure streak is bumped BEFORE the cooldown is computed (matching the
    // ported source exactly — see `cell::BreakerCell::record_failure`'s `ST_CLOSED` arm), so even
    // this FIRST trip computes off streak == 1: duration = (200 << 1) = 400, +/-10% jitter, clamped
    // to >= 200 — i.e. in [360, 440].
    assert!((360..=440).contains(&first_cooldown), "got {first_cooldown}");

    // Win the probe, then fail it: reopens with a FURTHER escalated (streak == 2) cooldown.
    let admit = unit.try_admit("pool", DestinationId::new(1), first_until).unwrap();
    assert!(admit.probe_epoch.is_some());
    unit.observe("pool", DestinationId::new(1), Outcome::Transient { retry_after: None }, &cfg, first_until);
    let LaneState::Suppressed { until: second_until } = unit.state("pool", DestinationId::new(1), first_until) else {
        panic!("expected Suppressed after the re-trip");
    };
    let second_cooldown = second_until - first_until;
    // streak == 2 duration is (200 << 2) = 800 +/- 10%, clamped to >= 400 — strictly larger than
    // any streak == 1 draw above.
    assert!(second_cooldown > first_cooldown, "escalated cooldown ({second_cooldown}) must exceed the first trip's cooldown ({first_cooldown})");
}

#[test]
fn the_oracle_cooldown_pool_draws_a_whole_second_in_one_to_three() {
    // The shadow oracle's `oracle-cd` pool — `base_cooldown_secs: 1, max_cooldown_secs: 5,
    // trip: { mode: consecutive, consecutive_n: 1 }` — is the config the `cooldown|trip-then-serve`
    // cell trips, and that cell's two waits (a refusal INSIDE the cooldown, a serve PAST it) are
    // only meaningful against the exact set of durations this config can draw. Pin the set:
    //   streak is bumped to 1 before the cooldown is computed -> duration = 1 << 1 = 2, capped at 5
    //   jitter_range = max(2 / 10, 1) = 1 -> jittered in [1, 3]
    //   clamped to [max(2 / 2, 1), 5] = [1, 5] -> the clamp cannot widen it
    // so every draw is a whole second in [1, 3]. The script waits 0.3s (below the 1s floor, in the
    // same whole second as the trip) and 4.5s (above the 3s ceiling); a change here that widened
    // the band past either would silently make that cell a coin flip again, which is exactly how it
    // came to record a jitter draw rather than a behaviour.
    let cfg = consecutive_cfg(1, 5);
    // Many independent cells: the jitter seed mixes the cell's own address, so distinct cells are
    // what sample the band (a single cell re-read would return the same draw within a second).
    let cells: Vec<BreakerCell> = (0..256).map(|_| BreakerCell::new()).collect();
    let mut seen = std::collections::BTreeSet::new();
    for cell in &cells {
        // Drive the streak to 1 exactly as a first transient failure does, then read the cooldown
        // the trip armed (`until - now`), so this measures the shipped record path, not a bare
        // arithmetic helper.
        let now = 1_000;
        assert!(cell.record_failure(now, &cfg, None, 86_400), "consecutive_n=1 must trip");
        let BreakerState::Open { until } = cell.state() else {
            panic!("expected Open immediately after the trip");
        };
        let draw = until - now;
        assert!((1..=3).contains(&draw), "oracle-cd cooldown draw out of band: {draw}");
        seen.insert(draw);
    }
    // The band is genuinely sampled — otherwise "in [1, 3]" would also pass for a constant.
    assert!(seen.len() > 1, "jitter never varied across 256 cells: {seen:?}");
}

#[test]
fn retry_after_is_honored_as_a_floor_under_the_computed_cooldown() {
    let cell = BreakerCell::new();
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,
        trip: TripConfig::default(),
        bench_below_trip_threshold: true,
    };
    // A 500s Retry-After floors a would-be-15s cooldown up to (at least) 500s, well past
    // max_cooldown_secs — the server's explicit hint is honored past the configured cap.
    let duration = cell.compute_cooldown_with_retry_after(&cfg, Some(500), 86_400);
    assert!(duration >= 500, "Retry-After floor was not applied: {duration}");

    // The ceiling still applies: a hostile 10_000_000s Retry-After is clamped to
    // max_honored_retry_after_secs, never honored past it.
    let duration = cell.compute_cooldown_with_retry_after(&cfg, Some(10_000_000), 86_400);
    assert_eq!(duration, 86_400);
}

#[test]
fn an_exhausted_destination_budget_is_excluded_not_ordered_last() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;
    unit.set_budget(DestinationId::new(1), 0); // already exhausted

    // The breaker cell itself is perfectly healthy (never observed a failure) — a
    // "budget exhausted" verdict must come from the budget check EXCLUDING the destination before
    // the breaker is even consulted, not from ranking it behind healthy destinations.
    assert_eq!(unit.state("pool", DestinationId::new(1), now), LaneState::BudgetExhausted);
    assert_eq!(unit.try_admit("pool", DestinationId::new(1), now), Err(LaneState::BudgetExhausted));

    // Confirm it really is budget, not the breaker: observing outcomes never touches budget state,
    // and the destination's own cell reads Ready underneath the budget exclusion.
    unit.observe("pool", DestinationId::new(1), Outcome::Success, &cfg, now);
    assert_eq!(unit.state("pool", DestinationId::new(1), now), LaneState::BudgetExhausted);

    // PB-4's soonest-cooldown Retry-After walk must never see this destination as a candidate with
    // a cooldown of 0 (which would wrongly win the "soonest" comparison) — it contributes nothing.
    let retry_after = BreakerUnit::<crate::journal::NoopJournal>::on_exhausted_retry_after(
        [unit.state("pool", DestinationId::new(1), now)],
        now,
    );
    assert_eq!(retry_after, crate::AT_CAPACITY_RETRY_AFTER_SECS);
}

#[test]
fn hard_down_trips_every_pool_cell_for_the_destination() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;

    // Touch three cells for the same destination (the default "" cell, and two named pools) so
    // each exists before the hard-down fan-out.
    assert_eq!(unit.state("", DestinationId::new(1), now), LaneState::Ready);
    assert_eq!(unit.state("pool-a", DestinationId::new(1), now), LaneState::Ready);
    assert_eq!(unit.state("pool-b", DestinationId::new(1), now), LaneState::Ready);

    let fresh = unit.observe("pool-a", DestinationId::new(1), Outcome::HardDown, &cfg, now);
    assert!(fresh, "the first hard-down trip must be reported fresh");

    for pool in ["", "pool-a", "pool-b"] {
        match unit.state(pool, DestinationId::new(1), now) {
            LaneState::Suppressed { until } => assert!(until > now, "pool {pool:?} must carry a sticky cooldown"),
            other => panic!("pool {pool:?} expected Suppressed after hard-down, got {other:?}"),
        }
    }

    // A second hard-down (e.g. a repeated probe failure) is not a FRESH trip.
    let fresh_again = unit.observe("pool-a", DestinationId::new(1), Outcome::HardDown, &cfg, now);
    assert!(!fresh_again);
}

#[test]
fn budget_spend_never_drives_the_counter_negative() {
    let budget = LifetimeBudget::limited(1);
    assert!(budget.spend());
    assert!(!budget.spend(), "a second spend against a budget of 1 must fail, not go negative");
    assert_eq!(budget.remaining(), Some(0));
    budget.refund();
    assert_eq!(budget.remaining(), Some(1));
}
