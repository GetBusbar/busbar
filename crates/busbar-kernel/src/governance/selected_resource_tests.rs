// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const INPUT: &str = "tokens.input";
const OUTPUT: &str = "tokens.output";

fn rates(capacity: usize) -> (Arc<SelectedRates>, Arc<AtomicU64>) {
    let elapsed = Arc::new(AtomicU64::new(0));
    let rates = Arc::new(SelectedRates {
        cells: Sharded::new(),
        clock: RateClock {
            epoch: [1; 16],
            boot_ms: Some(0),
            started: Instant::now(),
            elapsed: Some(elapsed.clone()),
        },
        unavailable: AtomicBool::new(false),
        capacity,
        leases: AtomicUsize::new(0),
        sweep_cursor: AtomicUsize::new(0),
    });
    (rates, elapsed)
}

fn rule(metric: RateMetric, threshold: u64) -> RateTerms {
    RateTerms {
        group_id: "engineering".into(),
        rule_id: match metric {
            RateMetric::Requests => "rpm",
            RateMetric::Tokens => "tpm",
        }
        .into(),
        key_id: "key-a".into(),
        instance: "plane-a".into(),
        resource: "resource-a".into(),
        metric,
        threshold,
        policy_revision: 1,
        activated_minute: 0,
    }
}

fn token(class: &str, amount: Option<i128>, authoritative: bool) -> EffectiveToken<'_> {
    EffectiveToken {
        class,
        quantity: amount.map(|n| Count::from_integer(n).unwrap()),
        authoritative,
    }
}

fn view(amount: i128) -> EffectiveTokenView<'static> {
    EffectiveTokenView(vec![token(INPUT, Some(amount), true)])
}

fn reserve(rates: &Arc<SelectedRates>, terms: Vec<RateTerms>) -> RateHold {
    rates.reserve_terms(terms, &[INPUT]).unwrap()
}

fn inspect(rates: &SelectedRates, term: RateTerms) -> RateSnapshot {
    rates.headroom_terms(vec![term]).unwrap().remove(0)
}

#[test]
fn all_rows_refuse_atomically_and_unsent_drop_releases_only_its_slot() {
    let (rates, _) = rates(16);
    let rpm = rule(RateMetric::Requests, 1);
    let zero = rule(RateMetric::Tokens, 0);
    let denied = rates.reserve_terms(vec![rpm.clone(), zero], &[INPUT]);
    assert_eq!(denied.err().unwrap().kind, RateRefusalKind::Tpm);
    assert_eq!(inspect(&rates, rpm.clone()).provisional_requests, 0);
    let held = reserve(&rates, vec![rpm.clone()]);
    assert_eq!(inspect(&rates, rpm.clone()).provisional_requests, 1);
    assert_eq!(
        rates
            .reserve_terms(vec![rpm.clone()], &[INPUT])
            .err()
            .unwrap()
            .kind,
        RateRefusalKind::Rpm
    );
    drop(held);
    let mut sent = reserve(&rates, vec![rpm.clone()]);
    sent.commit().unwrap();
    drop(sent);
    let snapshot = inspect(&rates, rpm);
    assert_eq!(snapshot.provisional_requests, 0);
    assert_eq!(snapshot.committed_requests, 1);
}

#[test]
fn reservation_expiry_refunds_old_cell_and_never_current_committed_work() {
    let (rates, elapsed) = rates(16);
    let rpm = rule(RateMetric::Requests, 1);
    let mut old = reserve(&rates, vec![rpm.clone()]);
    elapsed.store(60_000, Ordering::Relaxed);
    let mut current = reserve(&rates, vec![rpm.clone()]);
    current.commit().unwrap();
    assert_eq!(
        old.commit().unwrap_err().kind,
        RateRefusalKind::ExpiredReservation
    );
    drop(old);
    let snapshot = inspect(&rates, rpm);
    assert_eq!(snapshot.committed_requests, 1);
    assert_eq!(snapshot.provisional_requests, 0);
    assert_eq!(snapshot.window_start_ms, 60_000);
}

#[test]
fn commit_rechecks_cap_raised_after_reservation_without_double_rpm() {
    let (rates, _) = rates(16);
    let rpm = rule(RateMetric::Requests, 3);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut first = reserve(&rates, vec![rpm.clone(), tpm.clone()]);
    first.commit().unwrap();
    first.observe(&view(99)).unwrap();
    let mut delayed = reserve(&rates, vec![rpm.clone(), tpm.clone()]);
    first.observe(&view(100)).unwrap();
    assert_eq!(delayed.commit().unwrap_err().kind, RateRefusalKind::Tpm);
    let snapshot = inspect(&rates, rpm);
    assert_eq!(snapshot.committed_requests, 1);
    assert_eq!(snapshot.provisional_requests, 0);
}

#[test]
fn commit_rechecks_terminal_unknown_and_arithmetic_exhaustion() {
    for exhausted in [false, true] {
        let (rates, _) = rates(16);
        let rpm = rule(RateMetric::Requests, 4);
        let tpm = rule(RateMetric::Tokens, u64::MAX);
        let mut first = reserve(&rates, vec![rpm.clone(), tpm.clone()]);
        first.commit().unwrap();
        let mut delayed = reserve(&rates, vec![rpm.clone(), tpm.clone()]);
        if exhausted {
            let mut second = reserve(&rates, vec![tpm.clone()]);
            second.commit().unwrap();
            let over = EffectiveTokenView(vec![EffectiveToken {
                class: INPUT,
                quantity: Some(Count::from_micros(i128::MAX)),
                authoritative: true,
            }]);
            first.observe(&over).unwrap();
            assert_eq!(
                second.observe(&view(1)).unwrap_err(),
                RateObservationError::Arithmetic
            );
        } else {
            first.finish(TokenCoverage::Unknown).unwrap();
        }
        assert_eq!(
            delayed.commit().unwrap_err().kind,
            if exhausted {
                RateRefusalKind::ExhaustedArithmetic
            } else {
                RateRefusalKind::Uncertain
            }
        );
        assert_eq!(inspect(&rates, rpm).provisional_requests, 0);
    }
}

#[test]
fn highwater_never_refunds_downward_source_replacement_and_preserves_overshoot() {
    let (rates, _) = rates(16);
    let tpm = rule(RateMetric::Tokens, 25);
    let mut held = reserve(&rates, vec![tpm.clone()]);
    held.commit().unwrap();
    held.observe(&EffectiveTokenView(vec![token(INPUT, Some(20), false)]))
        .unwrap();
    held.observe(&view(14)).unwrap();
    held.observe(&view(14)).unwrap();
    assert_eq!(
        inspect(&rates, tpm.clone()).known_tokens,
        Count::from_integer(20).unwrap()
    );
    held.observe(&view(30)).unwrap();
    held.finish(TokenCoverage::Complete).unwrap();
    assert_eq!(
        inspect(&rates, tpm.clone()).known_tokens,
        Count::from_integer(30).unwrap()
    );
    assert_eq!(
        rates.reserve_terms(vec![tpm], &[INPUT]).err().unwrap().kind,
        RateRefusalKind::Tpm
    );
}

#[test]
fn complete_requires_reported_zero_for_every_declared_physical_class() {
    let (rates, elapsed) = rates(16);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut partial = rates
        .reserve_terms(vec![tpm.clone()], &[INPUT, OUTPUT])
        .unwrap();
    partial.commit().unwrap();
    partial
        .observe(&EffectiveTokenView(vec![
            token(INPUT, Some(0), true),
            token(OUTPUT, None, false),
        ]))
        .unwrap();
    assert_eq!(
        partial.finish(TokenCoverage::Complete).unwrap_err(),
        RateObservationError::Incomplete
    );
    assert!(inspect(&rates, tpm.clone()).uncertain);
    elapsed.store(60_000, Ordering::Relaxed);
    let mut complete = rates
        .reserve_terms(vec![tpm.clone()], &[INPUT, OUTPUT])
        .unwrap();
    complete.commit().unwrap();
    complete
        .observe(&EffectiveTokenView(vec![
            token(INPUT, Some(0), true),
            token(OUTPUT, Some(0), true),
        ]))
        .unwrap();
    complete.finish(TokenCoverage::Complete).unwrap();
    assert!(!inspect(&rates, tpm).uncertain);
}

#[test]
fn one_complete_cross_window_attempt_cannot_clear_another_unknown() {
    let (rates, elapsed) = rates(16);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut first = reserve(&rates, vec![tpm.clone()]);
    let mut second = reserve(&rates, vec![tpm.clone()]);
    first.commit().unwrap();
    second.commit().unwrap();
    elapsed.store(60_000, Ordering::Relaxed);
    assert!(inspect(&rates, tpm.clone()).uncertain);
    first.observe(&view(0)).unwrap();
    first.finish(TokenCoverage::Complete).unwrap();
    assert!(inspect(&rates, tpm.clone()).uncertain);
    second.finish(TokenCoverage::Unknown).unwrap();
    assert!(inspect(&rates, tpm.clone()).uncertain);
    elapsed.store(120_000, Ordering::Relaxed);
    assert!(!inspect(&rates, tpm).uncertain);
}

#[test]
fn capacity_full_cross_window_unknown_retains_its_backing_lease_until_terminal_expiry() {
    let (rates, elapsed) = rates(1);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut held = reserve(&rates, vec![tpm.clone()]);
    held.commit().unwrap();
    elapsed.store(60_000, Ordering::Relaxed);
    drop(held);
    rates.sweep_all();
    assert!(inspect(&rates, tpm.clone()).uncertain);
    assert_eq!(rates.leases.load(Ordering::Relaxed), 1);
    let mut other = tpm.clone();
    other.key_id = "key-b".into();
    assert_eq!(
        rates
            .reserve_terms(vec![other.clone()], &[INPUT])
            .err()
            .unwrap()
            .kind,
        RateRefusalKind::StateCapacity
    );
    elapsed.store(120_000, Ordering::Relaxed);
    rates.sweep_all();
    assert!(!inspect(&rates, tpm).uncertain);
    assert_eq!(rates.leases.load(Ordering::Relaxed), 0);
    drop(reserve(&rates, vec![other]));
}

#[test]
fn churn_and_read_misses_do_not_leave_uncharged_scope_shells_without_maintenance() {
    let (rates, elapsed) = rates(1);
    for minute in 0..32 {
        let mut term = rule(RateMetric::Requests, 1);
        term.key_id = format!("key-{minute}").into();
        drop(reserve(&rates, vec![term.clone()]));
        elapsed.store((minute + 1) * 60_000, Ordering::Relaxed);
        inspect(&rates, term);
        let mut scopes = 0;
        let mut cells = 0;
        for index in 0..super::super::GOV_SHARDS {
            let map = rates.cells.shard_at(index).read();
            scopes += map.len();
            cells += map.values().map(|scope| scope.windows.len()).sum::<usize>();
        }
        assert_eq!(
            (scopes, cells, rates.leases.load(Ordering::Relaxed)),
            (0, 0, 0)
        );
    }
}

#[test]
fn stable_rule_revision_shares_and_structured_scope_keys_do_not_alias() {
    let (rates, _) = rates(16);
    let original = rule(RateMetric::Requests, 1);
    let mut held = reserve(&rates, vec![original.clone()]);
    held.commit().unwrap();
    let mut revised = original.clone();
    revised.policy_revision = 9;
    assert_eq!(
        rates
            .reserve_terms(vec![revised.clone()], &[INPUT])
            .err()
            .unwrap()
            .kind,
        RateRefusalKind::Rpm
    );
    revised.threshold = 2;
    drop(reserve(&rates, vec![revised]));
    let mut a = original.clone();
    let mut b = original;
    a.group_id = "a:b".into();
    a.rule_id = "c".into();
    b.group_id = "a".into();
    b.rule_id = "b:c".into();
    assert_ne!(a.scope_key(), b.scope_key());
}

#[test]
fn independent_processes_do_not_share_rate_cells_and_clock_overflow_fails_closed() {
    let (first, _) = rates(16);
    let (second, _) = rates(16);
    let rpm = rule(RateMetric::Requests, 1);
    let mut a = reserve(&first, vec![rpm.clone()]);
    a.commit().unwrap();
    let mut b = reserve(&second, vec![rpm]);
    b.commit().unwrap();
    let (broken, elapsed) = rates(16);
    elapsed.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        broken
            .reserve_terms(vec![rule(RateMetric::Requests, 1)], &[INPUT])
            .err()
            .unwrap()
            .kind,
        RateRefusalKind::ClockUnavailable
    );
}

#[test]
fn no_matching_rows_are_a_noop_even_without_a_usable_rate_clock() {
    let (rates, elapsed) = rates(1);
    elapsed.store(u64::MAX, Ordering::Relaxed);
    let mut hold = rates.reserve_terms(Vec::new(), &[] as &[&str]).unwrap();
    hold.commit().unwrap();
    hold.finish(TokenCoverage::Complete).unwrap();
    assert!(rates.headroom_terms(Vec::new()).unwrap().is_empty());
    assert_eq!(rates.leases.load(Ordering::Relaxed), 0);
}

#[test]
fn concurrent_reservations_cannot_both_take_the_last_rpm_slot() {
    let (rates, _) = rates(16);
    let start = Arc::new(std::sync::Barrier::new(2));
    let held = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let rates = rates.clone();
            let start = start.clone();
            let held = held.clone();
            std::thread::spawn(move || {
                start.wait();
                let result = rates.reserve_terms(vec![rule(RateMetric::Requests, 1)], &[INPUT]);
                held.wait();
                result.is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        inspect(&rates, rule(RateMetric::Requests, 1)).provisional_requests,
        0
    );
}

#[test]
fn a_later_terminal_latch_survives_earlier_expiry_and_releases_its_lease_once() {
    let (rates, elapsed) = rates(1);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut first = reserve(&rates, vec![tpm.clone()]);
    let mut second = reserve(&rates, vec![tpm.clone()]);
    first.commit().unwrap();
    second.commit().unwrap();
    elapsed.store(60_000, Ordering::Relaxed);
    first.finish(TokenCoverage::Unknown).unwrap();
    elapsed.store(120_000, Ordering::Relaxed);
    second.finish(TokenCoverage::Partial).unwrap();
    rates.sweep_all();
    assert!(inspect(&rates, tpm.clone()).uncertain);
    assert_eq!(rates.leases.load(Ordering::Relaxed), 1);
    elapsed.store(180_000, Ordering::Relaxed);
    rates.sweep_all();
    rates.sweep_all();
    assert!(!inspect(&rates, tpm).uncertain);
    assert_eq!(rates.leases.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_or_duplicate_class_views_do_not_mutate_known_usage() {
    let (rates, _) = rates(16);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut hold = rates
        .reserve_terms(vec![tpm.clone()], &[INPUT, OUTPUT])
        .unwrap();
    hold.commit().unwrap();
    let duplicate = EffectiveTokenView(vec![
        token(INPUT, Some(3), true),
        token(INPUT, Some(4), true),
    ]);
    assert_eq!(
        hold.observe(&duplicate).unwrap_err(),
        RateObservationError::InvalidView
    );
    let negative = EffectiveTokenView(vec![
        token(INPUT, Some(-1), true),
        token(OUTPUT, Some(3), true),
    ]);
    assert_eq!(
        hold.observe(&negative).unwrap_err(),
        RateObservationError::InvalidView
    );
    assert_eq!(inspect(&rates, tpm).known_tokens, Count::ZERO);
}

#[test]
fn fractional_counts_reach_the_cap_without_rounding_or_clipping() {
    let (rates, _) = rates(16);
    let tpm = rule(RateMetric::Tokens, 1);
    let mut hold = reserve(&rates, vec![tpm.clone()]);
    hold.commit().unwrap();
    hold.observe(&EffectiveTokenView(vec![EffectiveToken {
        class: INPUT,
        quantity: Some(Count::from_micros(999_999)),
        authoritative: true,
    }]))
    .unwrap();
    drop(reserve(&rates, vec![tpm.clone()]));
    hold.observe(&view(1)).unwrap();
    assert_eq!(
        rates.reserve_terms(vec![tpm], &[INPUT]).err().unwrap().kind,
        RateRefusalKind::Tpm
    );
}

#[test]
fn retained_scope_key_storage_is_bounded_and_preallocated() {
    let mut term = rule(RateMetric::Tokens, 1);
    term.group_id = "g".repeat(128).into();
    term.rule_id = "r".repeat(128).into();
    term.key_id = "k".repeat(128).into();
    term.instance = "i".repeat(128).into();
    term.resource = "x".repeat(128).into();
    let key = term.scope_key();
    assert_eq!(key.len(), 661);
}

#[test]
fn native_dynamic_physical_classes_survive_their_declaring_storage_and_reject_new_names() {
    use busbar_plugin_abi::plane::{FB_ATTEMPT_USAGE, UNIT_COUNT, UNIT_TOKENS};
    use busbar_ports::codec::fallback_usage::Declaration;
    use busbar_ports::plane::UsageClass;

    let input = format!("tokens.native_input_{}", 41);
    let output = format!("tokens.native_output_{}", 41);
    let session = format!("request.native_{}", 41);
    let classes = vec![
        UsageClass {
            class: input.clone().into_boxed_str(),
            unit: UNIT_TOKENS,
            expected_units: None,
        },
        UsageClass {
            class: output.clone().into_boxed_str(),
            unit: UNIT_TOKENS,
            expected_units: None,
        },
        UsageClass {
            class: session.clone().into_boxed_str(),
            unit: UNIT_COUNT,
            expected_units: None,
        },
    ];
    let attempt_classes = vec![
        input.clone().into_boxed_str(),
        output.clone().into_boxed_str(),
    ];
    let frozen: Box<[Box<str>]> = Declaration::new(FB_ATTEMPT_USAGE, &classes, &attempt_classes)
        .unwrap()
        .physical_classes()
        .map(Box::<str>::from)
        .collect();
    assert_eq!(frozen.len(), 2);
    assert!(!frozen.iter().any(|class| class.as_ref() == session));
    drop(classes);
    drop(attempt_classes);

    let (rates, _) = rates(4);
    let tpm = rule(RateMetric::Tokens, 100);
    let mut hold = rates.reserve_terms(vec![tpm.clone()], &frozen).unwrap();
    drop(frozen);
    hold.commit().unwrap();
    hold.observe(&EffectiveTokenView(vec![
        EffectiveToken {
            class: input.as_str(),
            quantity: Some(Count::from_integer(3).unwrap()),
            authoritative: true,
        },
        EffectiveToken {
            class: output.as_str(),
            quantity: Some(Count::ZERO),
            authoritative: true,
        },
    ]))
    .unwrap();
    let later_generation_class = format!("tokens.native_output_{}", 42);
    assert_eq!(
        hold.observe(&EffectiveTokenView(vec![
            EffectiveToken {
                class: input.as_str(),
                quantity: Some(Count::from_integer(8).unwrap()),
                authoritative: true
            },
            EffectiveToken {
                class: later_generation_class.as_str(),
                quantity: Some(Count::ZERO),
                authoritative: true
            },
        ]))
        .unwrap_err(),
        RateObservationError::InvalidView
    );
    assert_eq!(
        inspect(&rates, tpm).known_tokens,
        Count::from_integer(3).unwrap()
    );
    let finished = hold.finish(TokenCoverage::Complete).unwrap();
    drop(input);
    drop(output);
    assert!(finished
        .highwater
        .iter()
        .any(|(class, amount)| class.as_ref() == "tokens.native_input_41"
            && *amount == Count::from_integer(3).unwrap()));
    assert!(finished
        .highwater
        .iter()
        .any(|(class, amount)| class.as_ref() == "tokens.native_output_41" && amount.is_zero()));
}
