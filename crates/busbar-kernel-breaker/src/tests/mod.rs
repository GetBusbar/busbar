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
use crate::cell::{BreakerCell, BreakerState, FailureEffect, ProbeAdmit};
use crate::cfg::{BreakerCfg, TripConfig, TripMode};
use crate::classify::{
    classify, normalize_raw_error, status_class_from_str, CanonicalSignal, Disposition,
    NoopDiagnostics, RawUpstreamError, StatusClass, PROVIDER_CODE_CONTEXT_LENGTH,
};
use crate::{BreakerUnit, DestinationId};
use std::collections::HashMap;

/// A fixed "now" for the tests that need one but are not ABOUT it — the kernel supplies this value
/// on the real path, and a unit crate has no other source for it.
const NOW: u64 = 1_700_000_000;

fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The probe fold's one test that takes no token (it reads a crate-private cell census); the ones
/// that drive the `Pass<Route>`-taking seam run in busbar-kernel (`src/tests/members/breaker/`),
/// where the token comes from the kernel's test token helper.
mod probe;

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
    assert_eq!(
        sig.provider_signal.as_deref(),
        Some("context_length_exceeded")
    );
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
fn status_class_from_str_maps_known_values_and_rejects_unknown() {
    assert!(matches!(
        status_class_from_str("rate_limit"),
        Some(StatusClass::RateLimit)
    ));
    assert!(matches!(
        status_class_from_str("overloaded"),
        Some(StatusClass::Overloaded)
    ));
    assert!(matches!(
        status_class_from_str("server_error"),
        Some(StatusClass::ServerError)
    ));
    assert!(matches!(
        status_class_from_str("timeout"),
        Some(StatusClass::Timeout)
    ));
    assert!(matches!(
        status_class_from_str("network"),
        Some(StatusClass::Network)
    ));
    assert!(matches!(
        status_class_from_str("auth"),
        Some(StatusClass::Auth)
    ));
    assert!(status_class_from_str("not_a_class").is_none());
    assert!(status_class_from_str("").is_none());
}

#[test]
fn disposition_table_matches_the_classify_match() {
    for class in crate::classify::StatusClass::ALL {
        let sig = CanonicalSignal {
            class: *class,
            provider_signal: None,
            retry_after: None,
        };
        assert_eq!(
            classify(&sig),
            class.disposition(),
            "table row for {class:?} disagrees with classify()"
        );
    }
}

// ── Not ported ───────────────────────────────────────────────────────────────────────────────────
//
// Some upstream suites reach a breaker assertion only after dispatching through a full routing
// walk (live transport mocking, config parsing, member selection). None of that harness exists in
// this crate — the routing, selection, and transport scaffolding is another unit's, not the
// breaker unit's — so there is nothing to port the SCAFFOLDING into; only the state-machine
// assertions they end on are reproduced, directly against `BreakerCell`/`BreakerUnit`, below and in
// `cell.rs`'s doc-derived arithmetic. Concretely not reproduced: the mock transport setup, the
// config parsing, and any assertion about the selection order or the concurrency semaphore
// (another unit's scope).

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
        assert!(
            cell.record_failure(now, &cfg, None, 86_400).tripped(),
            "consecutive_n=1 must trip"
        );
        let BreakerState::Open { until } = cell.state() else {
            panic!("expected Open immediately after the trip");
        };
        let draw = until - now;
        assert!(
            (1..=3).contains(&draw),
            "oracle-cd cooldown draw out of band: {draw}"
        );
        seen.insert(draw);
    }
    // The band is genuinely sampled — otherwise "in [1, 3]" would also pass for a constant.
    assert!(
        seen.len() > 1,
        "jitter never varied across 256 cells: {seen:?}"
    );
}

/// A CONFIGURATION THAT INVERTS THE COOLDOWN BOUNDS ANSWERS; IT DOES NOT BRING THE NODE DOWN.
///
/// The jitter band is clamped between a floor derived from the duration and the configured ceiling,
/// and `Ord::clamp` panics outright when the floor is above the ceiling. `BreakerCfg` is plain data
/// with public fields and nothing in the tree refuses either shape below, so both are configurations
/// an operator can write — and the panic would land inside `record_failure`, on the response path,
/// at the moment an upstream first fails. The two cases are different routes to the same inversion:
/// a zero ceiling, where the floor is one by construction, and a base cooldown above the ceiling on a
/// FRESH trip, where the escalation branch that would have capped the duration never ran.
#[test]
fn a_cooldown_ceiling_below_the_floor_is_answered_rather_than_panicked_on() {
    for (label, cfg) in [
        (
            "a zero ceiling",
            BreakerCfg {
                base_cooldown_secs: 15,
                max_cooldown_secs: 0,
                honor_retry_after: false,
                trip: TripConfig::default(),
                bench_below_trip_threshold: true,
            },
        ),
        (
            "a base cooldown above the ceiling",
            BreakerCfg {
                base_cooldown_secs: 1_000,
                max_cooldown_secs: 10,
                honor_retry_after: false,
                trip: TripConfig::default(),
                bench_below_trip_threshold: true,
            },
        ),
    ] {
        let cell = BreakerCell::new();
        let duration = cell.compute_cooldown_with_retry_after(NOW, &cfg, None, 86_400);
        assert_eq!(
            duration, cfg.max_cooldown_secs,
            "{label}: the ceiling is what a ceiling means"
        );
    }
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
    let duration = cell.compute_cooldown_with_retry_after(NOW, &cfg, Some(500), 86_400);
    assert!(
        duration >= 500,
        "Retry-After floor was not applied: {duration}"
    );

    // The ceiling still applies: a hostile 10_000_000s Retry-After is clamped to
    // max_honored_retry_after_secs, never honored past it.
    let duration = cell.compute_cooldown_with_retry_after(NOW, &cfg, Some(10_000_000), 86_400);
    assert_eq!(duration, 86_400);
}

/// THE TRIP IS A FUNCTION OF THE `now` IT WAS HANDED, not of the wall clock underneath it.
///
/// A unit crate answers from its arguments. The cooldown's jitter seed used to mix
/// `SystemTime::now()` even though the caller had already handed the trip its `now`, so the same
/// cell, driven from the same `now` with the same cfg, streak and Retry-After, armed a DIFFERENT
/// `cooldown_until` depending on which wall second the process happened to be in — a replayed
/// decision could not be reproduced, and the crate read a clock it is not allowed to read.
///
/// The two trips are deliberately separated by a wall-second boundary, because that is the only
/// thing that distinguishes "seeded from the argument" from "seeded from the clock". The base is
/// large so the jitter band (±10%, ~20001 distinct draws) makes a coincidental match negligible.
#[test]
fn the_armed_cooldown_is_a_function_of_the_now_the_caller_supplied() {
    let cfg = BreakerCfg {
        base_cooldown_secs: 100_000,
        max_cooldown_secs: 1_000_000,
        honor_retry_after: true,
        trip: TripConfig::default(),
        bench_below_trip_threshold: true,
    };
    let cell = BreakerCell::new();
    let now = 1_700_000_000_u64;

    let arm = || {
        cell.open(now, &cfg, Some(7), 86_400);
        let BreakerState::Open { until } = cell.state() else {
            panic!("expected Open immediately after the trip");
        };
        until
    };

    let first = arm();
    // Cross a wall-second boundary: the argument `now` has not changed, so nothing about the
    // decision may change either.
    let start = std::time::SystemTime::now();
    while std::time::SystemTime::now()
        .duration_since(start)
        .unwrap_or_default()
        .as_millis()
        < 1_100
    {
        std::thread::yield_now();
    }
    let second = arm();

    assert_eq!(
        first, second,
        "the same cell armed from the same `now` must arm the same cooldown a second later"
    );
}

// ── The probe journal is a function of what the cell actually did ───────────────────────────────

/// `record_failure` says which arm it took, so a caller never has to guess from a state it read
/// beforehand.
///
/// The three answers are distinct because the consequences are: a fresh trip is what the kernel's
/// trip metric counts, a reopen is what the probe journal records, and a bench is neither.
#[test]
fn record_failure_says_which_arm_it_took() {
    let cfg = consecutive_cfg(100, 10_000);
    let now = 1_000;

    // Closed and at the threshold: a genuine fresh trip.
    let fresh = BreakerCell::new();
    assert_eq!(
        fresh.record_failure(now, &cfg, None, 86_400),
        FailureEffect::Tripped
    );

    // The same cell, now Open: nothing to do, and certainly not a reopen.
    assert_eq!(
        fresh.record_failure(now, &cfg, None, 86_400),
        FailureEffect::Nothing
    );

    // Closed but under the threshold: benched, not tripped and not reopened.
    let mut lenient = consecutive_cfg(100, 10_000);
    lenient.trip.consecutive_n = 5;
    let benched = BreakerCell::new();
    assert_eq!(
        benched.record_failure(now, &lenient, None, 86_400),
        FailureEffect::Benched
    );

    // HalfOpen: the probe failed, so the cell reopens — and that is NOT a fresh trip.
    let probing = BreakerCell::new();
    assert_eq!(
        probing.record_failure(now, &cfg, None, 86_400),
        FailureEffect::Tripped
    );
    let past = now + 100_000;
    assert!(matches!(probing.acquire(past), ProbeAdmit::ProbeWon(_)));
    assert_eq!(
        probing.record_failure(past, &cfg, None, 86_400),
        FailureEffect::Reopened
    );

    // And the boolean the kernel counts trips with is unchanged.
    assert!(FailureEffect::Tripped.tripped());
    assert!(!FailureEffect::Reopened.tripped());
    assert!(!FailureEffect::Benched.tripped());
    assert!(!FailureEffect::Nothing.tripped());
}

/// A reader must never pair a cell's stale cooldown with its freshly stored state.
///
/// Every writer that moves a cell stores the cooldown FIRST and the state SECOND. A reader that
/// loads them in that SAME order can slip between the two stores: it takes the old cooldown (zero,
/// on a cell that has never tripped) and then the new Open state, and decodes a cell that was just
/// tripped for an hour as probe-winnable — an admission the cooldown forbids. Loading state first
/// and cooldown second is the reverse of the write order, which is what makes an observed fresh
/// state imply an at-least-as-fresh cooldown.
#[test]
fn a_verdict_never_pairs_a_stale_cooldown_with_a_fresh_state() {
    use crate::cell::BreakerVerdict;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    const CELLS: usize = 50_000;
    let now = 1_000u64;
    // Each cell is tripped exactly ONCE, from a never-cooled Closed cell to a long Open cooldown,
    // so "probe-winnable" is not a legitimate answer at any point in the cell's life here.
    let cells: Vec<BreakerCell> = (0..CELLS).map(|_| BreakerCell::new()).collect();
    let violations = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            for cell in &cells {
                cell.hard_down(now, 3_600);
            }
        });
        scope.spawn(|| {
            for cell in &cells {
                loop {
                    match cell.verdict(now) {
                        // Not tripped yet from this thread's point of view: keep watching.
                        BreakerVerdict::Ready => continue,
                        BreakerVerdict::ProbeWinnable => {
                            violations.fetch_add(1, AtomicOrdering::Relaxed);
                            break;
                        }
                        _ => break,
                    }
                }
            }
        });
    });

    assert_eq!(
        violations.load(AtomicOrdering::Relaxed),
        0,
        "a cell tripped with an hour of cooldown decoded as probe-winnable"
    );
}

/// A pool cell that a caller can reach is a pool cell a hard-down can reach.
///
/// `cell` published a freshly created cell into the cell map and only afterwards registered its
/// pool name against the destination. In that window the cell was fully reachable — admissions ran
/// through it — while `hard_down_all`, which walks the destination's registered pool names, could
/// not see it: a bad key or an exhausted account would suppress every other pool for that
/// destination and leave this one serving.
///
/// The threads below make the window the whole point. One thread creates the pool under test; a
/// crowd of others create pools of their own, so the registry is under contention and a name
/// published after its cell has to queue behind them. The hard-down waits until the cell under
/// test is reachable and then runs at once. Registering the name before the cell is published is
/// what makes reachability imply hard-downability, whatever the registry is doing.
#[test]
fn a_reachable_pool_cell_is_always_reachable_by_a_hard_down() {
    const NOISE: usize = 8;
    const NOISE_POOLS: usize = 64;
    let destination = DestinationId::new(3);

    let mut missed = 0usize;
    for round in 0..200 {
        let unit: BreakerUnit = BreakerUnit::new();
        let unit = &unit;
        let target = format!("target-{round}");
        let target = target.as_str();
        let started = std::sync::Barrier::new(NOISE + 2);
        let started = &started;
        std::thread::scope(|scope| {
            for n in 0..NOISE {
                scope.spawn(move || {
                    started.wait();
                    for p in 0..NOISE_POOLS {
                        let _ = unit.try_admit(&format!("noise-{n}-{p}"), destination, 1_000);
                    }
                });
            }
            scope.spawn(move || {
                started.wait();
                let _ = unit.try_admit(target, destination, 1_000);
            });
            scope.spawn(move || {
                started.wait();
                while !unit.has_cell(target, destination) {
                    std::hint::spin_loop();
                }
                unit.hard_down_all(destination, 1_000);
            });
        });

        if !matches!(
            unit.cell(target, destination).state(),
            crate::cell::BreakerState::Open { .. }
        ) {
            missed += 1;
        }
    }

    assert_eq!(
        missed, 0,
        "a hard-down skipped a pool cell that was already reachable when it ran"
    );
}

#[test]
fn budget_spend_never_drives_the_counter_negative() {
    let budget = LifetimeBudget::limited(1);
    assert!(budget.spend());
    assert!(
        !budget.spend(),
        "a second spend against a budget of 1 must fail, not go negative"
    );
    assert_eq!(budget.remaining(), Some(0));
    budget.refund();
    assert_eq!(budget.remaining(), Some(1));
}

// ── The DEFAULT trip mode's decision table ───────────────────────────────────────────────────────
//
// Every state-machine case above configures `TripMode::Consecutive`, so the mode a
// `BreakerCfg::default()` cell actually evaluates — `ErrorRate`, with its `min_requests` floor and
// its `>=` threshold comparison — was driven by nothing. These three cases walk the table
// `should_trip`'s `ErrorRate` arm decides from: below the floor, at the floor, at the threshold,
// below the threshold, and outside the window.

/// The Retry-After ceiling the cases below pass: they supply no upstream Retry-After, so the
/// ceiling on one is never reached. Named rather than repeated so a reader is not invited to read
/// meaning into the number.
const MAX_RETRY_AFTER: u64 = 3_600;

#[test]
fn the_default_mode_will_not_trip_below_its_minimum_request_count() {
    let cell = BreakerCell::new();
    let cfg = BreakerCfg::default();
    assert_eq!(cfg.trip.mode, TripMode::ErrorRate, "the default mode");
    assert_eq!(cfg.trip.min_requests, 5, "the floor under test");

    // Four all-error outcomes: the RATIO is 1.0 from the very first one, so the only thing standing
    // between this cell and a trip is the minimum-request floor.
    for i in 1..cfg.trip.min_requests {
        assert_eq!(
            cell.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER),
            FailureEffect::Benched,
            "failure {i} of {} must not trip: the window holds fewer outcomes than the floor",
            cfg.trip.min_requests
        );
        assert!(
            matches!(cell.state(), BreakerState::Closed),
            "the cell must still be Closed after failure {i}"
        );
    }

    // The one that reaches the floor trips, so the loop above is measuring the floor and not some
    // other refusal.
    assert_eq!(
        cell.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER),
        FailureEffect::Tripped,
        "the outcome that reaches min_requests must trip at a 1.0 error rate"
    );
}

#[test]
fn the_default_mode_trips_at_the_threshold_and_not_below_it() {
    let cfg = BreakerCfg::default();
    assert!(
        (cfg.trip.threshold - 0.5).abs() < f64::EPSILON,
        "the threshold under test"
    );

    // AT the threshold: five successes then five failures is exactly 5/10 == 0.5. The comparison is
    // `>=`, so the tenth outcome trips. Each earlier failure is strictly under the threshold
    // (1/6, 2/7, 3/8, 4/9), so nothing trips early and the assertion below is about the boundary.
    let at = BreakerCell::new();
    for _ in 0..5 {
        at.record_success(NOW);
    }
    for i in 1..5 {
        assert_eq!(
            at.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER),
            FailureEffect::Benched,
            "failure {i} sits strictly below the threshold and must not trip"
        );
    }
    assert_eq!(
        at.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER),
        FailureEffect::Tripped,
        "an error rate exactly AT the threshold must trip: the comparison is >=, not >"
    );

    // BELOW the threshold: seven successes then three failures is 3/10 == 0.3. The window already
    // holds more than `min_requests` outcomes, so the floor is not what is refusing here — the
    // ratio is. A numerator that counted OUTCOMES rather than ERRORS would read 1.0 and trip on the
    // first failure.
    let below = BreakerCell::new();
    for _ in 0..7 {
        below.record_success(NOW);
    }
    for i in 1..=3 {
        assert_eq!(
            below.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER),
            FailureEffect::Benched,
            "failure {i} of 3 against 7 successes is a 0.3 error rate and must not trip"
        );
    }
    assert!(
        matches!(below.state(), BreakerState::Closed),
        "a cell under the threshold stays Closed"
    );
}

#[test]
fn outcomes_that_have_aged_out_of_the_window_do_not_count_toward_a_trip() {
    let cell = BreakerCell::new();
    let cfg = BreakerCfg::default();

    // Four failures, then a fifth one placed one second PAST the window's width. The window cut is
    // `ts >= now - window_s`, so at `NOW + window_s + 1` the four old outcomes are outside it and
    // the count is 1 — under the floor.
    for _ in 1..cfg.trip.min_requests {
        cell.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER);
    }
    let later = NOW + cfg.trip.window_s + 1;
    assert_eq!(
        cell.record_failure(later, &cfg, None, MAX_RETRY_AFTER),
        FailureEffect::Benched,
        "aged-out failures must not be counted toward the trip of a much later one"
    );

    // The same fifth failure INSIDE the window does trip — so the case above measures the window
    // cut and not some unrelated refusal.
    let inside = BreakerCell::new();
    for _ in 1..cfg.trip.min_requests {
        inside.record_failure(NOW, &cfg, None, MAX_RETRY_AFTER);
    }
    assert_eq!(
        inside.record_failure(NOW + cfg.trip.window_s, &cfg, None, MAX_RETRY_AFTER),
        FailureEffect::Tripped,
        "an outcome at exactly the window's edge is still inside it"
    );
}

// ── Backoff saturation at a long failure streak ──────────────────────────────────────────────────

#[test]
fn a_long_failure_streak_saturates_the_cooldown_instead_of_wrapping_it_to_zero() {
    // An EVEN base is the whole point: `base << 63` on a u64 discards the set bit and leaves zero,
    // which is a cell that has failed 63 times in a row re-admitting instantly. The u128 shift plus
    // `u64::try_from(..).unwrap_or(u64::MAX)` is what turns that into the ceiling instead.
    let cfg = consecutive_cfg(2, 100);
    let cell = BreakerCell::new();
    let mut now = NOW;

    assert_eq!(
        cell.record_failure(now, &cfg, None, MAX_RETRY_AFTER),
        FailureEffect::Tripped
    );
    let BreakerState::Open { until } = cell.state() else {
        panic!("expected Open after the first failure of a consecutive_n=1 cell");
    };
    // streak == 1: 2 << 1 == 4, +/- a jitter range of max(4/10, 1) == 1, floored at 4/2 == 2.
    assert!(
        (3..=5).contains(&(until - now)),
        "the first cooldown is the un-escalated one; got {}",
        until - now
    );

    // Drive the streak past the 63-bit shift cap through the public transitions only: expire the
    // cooldown, win the single-flight probe, fail it. Each failed probe is a reopen and bumps the
    // streak by one.
    const REOPENS: u32 = 70;
    for i in 0..REOPENS {
        let BreakerState::Open { until } = cell.state() else {
            panic!("expected Open before reopen {i}");
        };
        now = until;
        assert!(
            matches!(cell.acquire(now), ProbeAdmit::ProbeWon(_)),
            "an expired cooldown must yield the probe at reopen {i}"
        );
        assert_eq!(
            cell.record_failure(now, &cfg, None, MAX_RETRY_AFTER),
            FailureEffect::Reopened,
            "a failed probe reopens at reopen {i}"
        );
    }

    // The streak is now past the 63 the shift is capped at. The escalated duration saturates to
    // u64::MAX and is capped at `max_cooldown_secs`, so the armed cooldown sits within one jitter
    // range (max(100/10, 1) == 10) of the ceiling.
    let BreakerState::Open { until } = cell.state() else {
        panic!("expected Open after the last failed probe");
    };
    let saturated = until - now;
    assert!(
        (90..=100).contains(&saturated),
        "a lane failing {} times in a row must be held at the cooldown CEILING, not re-admitted \
         instantly; got {saturated}",
        REOPENS + 1
    );

    // Asked directly, the arithmetic gives the same answer — the armed value above is not an
    // artifact of the transition path.
    let computed = cell.compute_cooldown_with_retry_after(now, &cfg, None, MAX_RETRY_AFTER);
    assert!(
        (90..=100).contains(&computed),
        "the computed cooldown at a saturating streak must be at the ceiling; got {computed}"
    );
}

// ── Item 142: the kernel's admission path runs on this state machine ─────────────────────────

/// The consecutive-failure streak bump happens UNDER the transition lock, serialized with the
/// trip/cooldown read — never before it, where concurrent failures over-counted the streak and
/// inflated the first trip's cooldown. Moved here from the kernel's store tests with the state
/// machine it pins. Deterministic: with the lock held, a racing failure parks at it and the streak
/// cannot move.
#[test]
fn streak_bump_is_serialized_under_the_transition_lock() {
    use std::sync::{Arc, Barrier};
    let cell = Arc::new(BreakerCell::new());
    let cfg = BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 1000,
        honor_retry_after: false,
        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };
    let guard = cell.transition_guard();
    let barrier = Arc::new(Barrier::new(2));
    let handle = {
        let (cell, cfg, barrier) = (Arc::clone(&cell), cfg.clone(), Arc::clone(&barrier));
        std::thread::spawn(move || {
            barrier.wait();
            cell.record_failure(1000, &cfg, None, 3600)
        })
    };
    barrier.wait();
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert_eq!(
        cell.streak(),
        0,
        "while the transition lock is held, a concurrent failure must NOT advance the streak"
    );
    drop(guard);
    assert!(
        !handle.join().expect("record thread").tripped(),
        "streak 1 < n=2 must not trip"
    );
    assert_eq!(cell.streak(), 1);
    assert!(
        cell.record_failure(1000, &cfg, None, 3600).tripped(),
        "streak 2 == n trips"
    );
    assert_eq!(cell.streak(), 2);
    // shift=2 → 40s ±10%; an inflated streak (shift >= 3 → >= 80s) lands well outside.
    let remaining = cell.cooldown_until() - 1000;
    assert!((36..=44).contains(&remaining), "got {remaining}s");
}

/// A cell carried across a rebuild keeps its state, cooldown, streak and error count — and a
/// snapshot taken mid-probe comes back Open, never as a HalfOpen whose probe nobody holds.
#[test]
fn snapshot_restore_round_trips_and_normalizes_a_mid_probe_capture() {
    use crate::cell::CellSnapshot;
    let cfg = BreakerCfg::default();
    let a = BreakerCell::new();
    for _ in 0..5 {
        let _ = a.record_failure(NOW, &cfg, None, 3600);
    }
    let snap = a.snapshot();
    assert_eq!(
        snap.state, 1,
        "five failures trip the default error-rate cell"
    );
    let b = BreakerCell::new();
    b.restore(snap);
    assert_eq!(b.snapshot(), snap);
    assert_eq!(b.err_count(), 5);

    let mid_probe = CellSnapshot { state: 2, ..snap };
    let c = BreakerCell::new();
    c.restore(mid_probe);
    assert_eq!(c.snapshot().state, 1);
    assert!(!c.probe_in_flight());
    assert!(matches!(
        c.acquire(snap.cooldown_until),
        ProbeAdmit::ProbeWon(_)
    ));
}

/// The unit's own budget object is what a holder spends: a spend through the shared handle is a
/// spend the unit sees, and a restored figure never exceeds what it is given nor drops below zero.
#[test]
fn a_shared_budget_is_the_units_budget() {
    let unit = BreakerUnit::new();
    let dest = DestinationId::new(3);
    unit.set_budget(dest, 2);
    let held = unit.budget(dest).expect("declared");
    assert!(held.spend());
    assert_eq!(unit.budget_remaining(dest), Some(1));
    held.restore(-4);
    assert_eq!(unit.budget_remaining(dest), Some(0));
    assert!(!unit.spend_budget(dest));
    let unlimited = LifetimeBudget::unlimited();
    unlimited.restore(7);
    assert_eq!(unlimited.remaining(), None);
}

/// `with_limits` is the path the two `limits.*` knobs take: the unit reports them back, and a
/// hard-down arms exactly the configured sticky cooldown on every pool cell of the destination.
#[test]
fn with_limits_drives_the_hard_down_cooldown() {
    let unit = BreakerUnit::new().with_limits(600, 7200);
    assert_eq!(unit.hard_down_cooldown_secs(), 600);
    assert_eq!(unit.max_honored_retry_after_secs(), 7200);
    let dest = DestinationId::new(1);
    let pooled = unit.cell("pool", dest);
    assert!(unit.hard_down_all(dest, NOW));
    assert_eq!(unit.cell("", dest).cooldown_until(), NOW + 600);
    assert_eq!(pooled.cooldown_until(), NOW + 600);
}
