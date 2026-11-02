// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::config::RateEntryCfg;
use busbar_contract::records::{
    VirtualKey, RESERVED_UNITS, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT,
};
use busbar_kernel_ledger::cost::{whole, Money, MoneyError, Tally, STANDARD_TIER_BP};
use std::collections::BTreeMap;

fn bucket_money<'a>(
    model: &CostModel,
    rows: impl IntoIterator<Item = (&'a str, &'a BTreeMap<String, u64>)>,
    billable_requests: u64,
) -> Result<Money, MoneyError> {
    let mut tally = Tally::at_card(model.card());
    for (lane, units) in rows {
        tally.row(lane, 0, STANDARD_TIER_BP, unit_counts(units), whole(0))?;
    }
    tally.fee(0, STANDARD_TIER_BP, whole(billable_requests))?;
    tally.money()
}

fn card(entries: &[(&str, f64, f64)]) -> BTreeMap<String, RateEntryCfg> {
    entries
        .iter()
        .map(|(m, i, o)| {
            (
                m.to_string(),
                RateEntryCfg {
                    input_utok: *i,
                    output_utok: *o,
                    cache_read_utok: 0.0,
                    cache_write_utok: 0.0,
                    ..Default::default()
                },
            )
        })
        .collect()
}

fn resolve_card_fee(
    rate_card: Option<&BTreeMap<String, RateEntryCfg>>,
    per_request_fee: i64,
) -> CostModel {
    CostModel::resolve_parts(rate_card, per_request_fee, &BTreeMap::new())
}

fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

fn group(parent: Option<&str>, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled: true,
        limits,
        ..Default::default()
    }
}

pub(crate) fn key(group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: "vk_1".into(),
        generation_hash: "h".into(),
        name: "k".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: group.map(String::from),
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn toks4(input: u64, output: u64, cache_read: u64, cache_write: u64) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for (k, v) in [
        (UNIT_INPUT, input),
        (UNIT_OUTPUT, output),
        (UNIT_CACHE_READ, cache_read),
        (UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            m.insert(k.to_string(), v);
        }
    }
    m
}

fn toks(input: u64, output: u64) -> BTreeMap<String, u64> {
    toks4(input, output, 0, 0)
}

#[test]
fn absent_rate_card_prices_tokens_at_zero() {
    let cm = resolve_card_fee(None, 3);
    assert!(!cm.pricing_enabled());
    assert!(!cm.model_unpriced("anything"), "no card = nothing to miss");
    let t = toks(1_000_000, 1_000_000);
    let spend = bucket_money(&cm, [("anything", &t)], 5)
        .and_then(Money::minor_i64)
        .expect("the one function prices");
    assert_eq!(spend, 15, "tokens derive to 0; 5 requests x 3c fee remain");
}

#[test]
fn present_rate_card_derives_integer_spend() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.pricing_enabled());
    let t = toks(1_000_000, 1_000_000);
    let spend = bucket_money(&cm, [("gpt-5", &t)], 0)
        .and_then(Money::minor_i64)
        .expect("the one function prices");
    assert_eq!(spend, 1250);

    let micros = bucket_money(&cm, [("gpt-5", &t)], 0)
        .and_then(Money::micros_i64)
        .expect("the one function prices");
    assert_eq!(micros, 12_500_000);
}

#[test]
fn nano_scale_keeps_sub_micro_precision() {
    let c = BTreeMap::from([(
        "m".to_string(),
        RateEntryCfg {
            input_utok: 3.125,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    let t = toks(8, 0);
    assert_eq!(
        bucket_money(&cm, [("m", &t)], 0).and_then(Money::micros_i64),
        Ok(25)
    );
}

#[test]
fn unknown_model_with_card_is_unpriced_and_refuses() {
    let c = card(&[("gpt-5", 1.0, 1.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.model_unpriced("mystery-model"));
    assert!(!cm.model_unpriced("gpt-5"));
    let t = toks(1_000_000, 0);
    assert_eq!(
        bucket_money(&cm, [("mystery-model", &t)], 0).and_then(Money::minor_i64),
        Err(busbar_kernel_ledger::cost::MoneyError::LaneUnpriced {
            card_seq: busbar_kernel_ledger::cost::HistorySeq::OPENING,
            lane: "mystery-model".to_string(),
        })
    );
}

#[test]
fn reprice_on_read_recomputes_derived_spend() {
    let t = toks(1_000_000, 0);
    let wrong = resolve_card_fee(Some(&card(&[("m", 10.0, 0.0)])), 0);
    let fixed = resolve_card_fee(Some(&card(&[("m", 5.0, 0.0)])), 0);
    assert_eq!(
        bucket_money(&wrong, [("m", &t)], 0).and_then(Money::minor_i64),
        Ok(1000)
    );
    assert_eq!(
        bucket_money(&fixed, [("m", &t)], 0).and_then(Money::minor_i64),
        Ok(500),
        "same tokens, corrected rate: derived spend halves on next read"
    );
}

#[test]
fn canonical_money_refuses_an_overflow_never_wraps_or_pins() {
    let cm = resolve_card_fee(Some(&card(&[("m", 1e15, 0.0)])), 0);
    let t = toks(u64::MAX, 0);
    assert_eq!(
        bucket_money(&cm, [("m", &t)], 0).and_then(Money::minor_i64),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "an over-range total is a refusal, never a pinned figure"
    );
    assert_eq!(
        bucket_money(&cm, [("m", &t)], 0).and_then(Money::micros_i64),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow)
    );
}

#[test]
fn rate_card_is_sole_cost_source_and_drives_routing_scalar() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    let r = crate::cost::RateNanos::from_cfg(&c["gpt-5"]);
    assert_eq!(
        (r.input, r.output),
        (2_500, 10_000),
        "nano-unit rates come straight from the card"
    );

    let scalar = crate::config::rate_entry_per_mtok(&c["gpt-5"]);
    assert!((scalar - 6.25).abs() < f64::EPSILON);

    let err = serde_yaml::from_str::<crate::config::PoolCfg>(
        "members:\n  - model: gpt-5\n    cost_per_mtok: 4\n",
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("cost_per_mtok"),
        "the removed member cost key must fail loudly: {err}"
    );
}

#[test]
fn group_limits_resolve_to_per_window_buckets() {
    let groups = BTreeMap::from([(
        "bob".to_string(),
        group(
            None,
            vec![
                limit(LimitMetric::Requests, 10, Some(LimitWindow::Minute)),
                limit(LimitMetric::Tokens, 500, Some(LimitWindow::Minute)),
                limit(LimitMetric::Requests, 1000, Some(LimitWindow::Day)),
                limit(LimitMetric::Budget, 200, Some(LimitWindow::Month)),
                limit(LimitMetric::Concurrent, 5, None),
            ],
        ),
    )]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let g = cm.group_named("bob").expect("resolved");
    assert!(g.enabled);
    assert_eq!(g.concurrent_cap, Some(5));
    assert_eq!(g.buckets.len(), 3, "minute, day, month");
    let minute = g.buckets.iter().find(|b| b.window == "minute").unwrap();
    assert_eq!(minute.bucket_id, "group:bob@minute");
    assert_eq!(minute.requests_cap, Some(10));
    assert_eq!(minute.tokens_cap, Some(500));
    assert_eq!(minute.budget_cap, None);
    let day = g.buckets.iter().find(|b| b.window == "day").unwrap();
    assert_eq!(day.requests_cap, Some(1000));
    let month = g.buckets.iter().find(|b| b.window == "month").unwrap();
    assert_eq!(month.budget_cap, Some(200));
}

#[test]
fn duplicate_metric_same_window_keeps_the_minimum() {
    let groups = BTreeMap::from([(
        "g".to_string(),
        group(
            None,
            vec![
                limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute)),
                limit(LimitMetric::Requests, 7, Some(LimitWindow::Minute)),
                limit(LimitMetric::Concurrent, 9, None),
                limit(LimitMetric::Concurrent, 3, None),
            ],
        ),
    )]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let g = cm.group_named("g").unwrap();
    assert_eq!(g.buckets[0].requests_cap, Some(7));
    assert_eq!(g.concurrent_cap, Some(3));
}

#[test]
fn chain_resolves_key_then_group_window_buckets() {
    let groups = BTreeMap::from([
        (
            "acme".to_string(),
            group(
                None,
                vec![limit(LimitMetric::Budget, 10_000, Some(LimitWindow::Month))],
            ),
        ),
        (
            "growth".to_string(),
            group(
                Some("acme"),
                vec![
                    limit(LimitMetric::Requests, 50, Some(LimitWindow::Minute)),
                    limit(LimitMetric::Budget, 2_000, Some(LimitWindow::Month)),
                ],
            ),
        ),
    ]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let k = key(Some("growth"));
    let chain = cm.chain_for(&k).expect("resolves");
    let got: Vec<(String, &str, Option<u64>, Option<i64>)> = chain
        .iter()
        .map(|b| {
            (
                b.bucket_id.to_string(),
                b.window,
                b.requests_cap,
                b.budget_cap,
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("vk_1".to_string(), "total", None, None),
            ("group:growth@minute".to_string(), "minute", Some(50), None),
            ("group:growth@month".to_string(), "month", None, Some(2_000)),
            ("group:acme@month".to_string(), "month", None, Some(10_000)),
        ]
    );

    let names: Vec<&str> = chain
        .group_indices()
        .iter()
        .map(|&i| cm.groups()[i].name.as_str())
        .collect();
    assert_eq!(names, vec!["growth", "acme"]);

    let solo = key(None);
    let chain = cm.chain_for(&solo).expect("resolves");
    assert_eq!(chain.len(), 1);
    let b = chain.iter().next().unwrap();
    assert!(b.group_name.is_none());
    assert_eq!(b.window, "total");
    assert_eq!(
        (b.requests_cap, b.tokens_cap, b.budget_cap),
        (None, None, None)
    );
    assert!(chain.group_indices().is_empty());
}

#[test]
fn chain_with_missing_group_fails_closed_naming_it() {
    let cm = CostModel::resolve_parts(None, 0, &BTreeMap::new());
    let k = key(Some("ghost"));
    match cm.chain_for(&k) {
        Err(missing) => assert_eq!(missing, "ghost"),
        Ok(_) => panic!("a missing group must fail chain resolution"),
    }
}

#[test]
fn four_tier_card_prices_each_tier_against_its_own_rate() {
    let c = BTreeMap::from([(
        "quad".to_string(),
        RateEntryCfg {
            input_utok: 1.0,
            output_utok: 2.0,
            cache_read_utok: 0.5,
            cache_write_utok: 4.0,
            ..Default::default()
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    let t = toks4(10_000_000, 1_000_000, 2_000_000, 500_000);

    assert_eq!(
        bucket_money(&cm, [("quad", &t)], 0).and_then(Money::minor_i64),
        Ok(1500),
        "each tier must bill against its own rate; a swapped cache_read/cache_write mapping changes this"
    );
    let r = crate::cost::RateNanos::from_cfg(&c["quad"]);
    assert_eq!(
        (r.input, r.output, r.cache_read, r.cache_write),
        (1_000, 2_000, 500, 4_000),
        "nano rates carry all four tiers straight from the card"
    );
}

#[test]
fn cent_derivation_truncates_toward_zero_never_rounds_up() {
    let cm = resolve_card_fee(Some(&card(&[("m", 1.0, 0.0)])), 0);
    let just_under = bucket_money(&cm, [("m", &toks(19_999, 0))], 0)
        .and_then(Money::minor_i64)
        .expect("the one function prices");
    assert_eq!(
        just_under, 1,
        "1.9999 cents must floor to 1, not round up to 2"
    );
    let on_boundary = bucket_money(&cm, [("m", &toks(20_000, 0))], 0)
        .and_then(Money::minor_i64)
        .expect("the one function prices");
    assert_eq!(on_boundary, 2, "exactly 2.0 cents is 2");
    let just_over = bucket_money(&cm, [("m", &toks(20_001, 0))], 0)
        .and_then(Money::minor_i64)
        .expect("the one function prices");
    assert_eq!(just_over, 2, "2.0001 cents still floors to 2");
}

#[test]
fn sub_cent_contributions_across_models_sum_before_flooring() {
    let cm = resolve_card_fee(Some(&card(&[("a", 5.0, 0.0), ("b", 5.0, 0.0)])), 0);
    let ta = toks(1_000, 0);
    let tb = toks(1_000, 0);
    assert_eq!(
        bucket_money(&cm, [("a", &ta)], 0).and_then(Money::minor_i64),
        Ok(0),
        "one 0.5-cent model alone floors to 0"
    );
    assert_eq!(
        bucket_money(&cm, [("a", &ta), ("b", &tb)], 0).and_then(Money::minor_i64),
        Ok(1),
        "two 0.5-cent models sum to a whole cent — nanos accumulate before the single divide"
    );
}

#[test]
fn explicit_zero_rate_model_is_known_and_derives_zero() {
    let c = BTreeMap::from([(
        "freebie".to_string(),
        RateEntryCfg {
            input_utok: 0.0,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.pricing_enabled());
    assert!(
        !cm.model_unpriced("freebie"),
        "an all-zero entry is present, not missing"
    );
    let t = toks4(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(
        bucket_money(&cm, [("freebie", &t)], 0).and_then(Money::minor_i64),
        Ok(0),
        "a zero-rated model bills nothing regardless of volume"
    );
}

#[test]
fn partial_card_prices_known_models_and_refuses_the_missing_one() {
    let c = card(&[("priced", 2.0, 0.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(!cm.model_unpriced("priced"));
    assert!(cm.model_unpriced("absent"));
    let known = toks(1_000_000, 0);
    let absent = toks(9_999_999, 0);
    assert_eq!(
        bucket_money(&cm, [("priced", &known), ("absent", &absent)], 0).and_then(Money::minor_i64),
        Err(busbar_kernel_ledger::cost::MoneyError::LaneUnpriced {
            card_seq: busbar_kernel_ledger::cost::HistorySeq::OPENING,
            lane: "absent".to_string(),
        }),
        "the missing model refuses the derivation; it never derives 0"
    );
    assert_eq!(
        bucket_money(&cm, [("priced", &known)], 0).and_then(Money::minor_i64),
        Ok(200),
        "the priced model alone prices as it always did"
    );
}

#[test]
fn flat_fee_refuses_an_overflow_and_zero_billable_requests_add_nothing() {
    let cm = resolve_card_fee(None, i64::MAX);
    let z = toks(0, 0);
    assert_eq!(
        bucket_money(&cm, [("m", &z)], u64::MAX).and_then(Money::minor_i64),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "i64::MAX fee * u64::MAX requests is refused, never wrapped and never pinned"
    );
    assert_eq!(
        bucket_money(&cm, [("m", &z)], 0).and_then(Money::minor_i64),
        Ok(0),
        "with no billable requests the flat fee contributes nothing"
    );
}

#[test]
fn negative_per_request_fee_clamps_to_zero() {
    let cm = resolve_card_fee(None, -5);
    assert_eq!(cm.request_fee_on(""), 0);
    assert_eq!(
        bucket_money(&cm, [("m", &toks(0, 0))], 100).and_then(Money::minor_i64),
        Ok(0),
        "a negative fee must never credit a bucket: 100 requests at a clamped-0 fee is 0"
    );
}

#[test]
fn micro_projection_fee_is_cents_times_ten_thousand() {
    let cm = resolve_card_fee(None, 3);
    let z = toks(0, 0);

    assert_eq!(
        bucket_money(&cm, [("m", &z)], 5).and_then(Money::micros_i64),
        Ok(150_000)
    );
    assert_eq!(
        bucket_money(&cm, [("m", &z)], 5).and_then(Money::minor_i64),
        Ok(15),
        "the same fee in cents is 15 — the micro projection is exactly 10_000x"
    );
    assert_eq!(
        bucket_money(&cm, [("m", &z)], 0).and_then(Money::micros_i64),
        Ok(0),
        "no billable requests: no fee in the micro projection either"
    );
}

#[test]
fn derived_spend_lands_exactly_on_an_integer_budget_cap() {
    let cm = resolve_card_fee(Some(&card(&[("m", 1.0, 0.0)])), 0);
    assert_eq!(
        bucket_money(&cm, [("m", &toks(1_000_000, 0))], 0).and_then(Money::minor_i64),
        Ok(100),
        "spend lands exactly on the integer cap value the budget check compares against"
    );
    assert_eq!(
        bucket_money(&cm, [("m", &toks(1_010_000, 0))], 0).and_then(Money::minor_i64),
        Ok(101),
        "one full cent more of tokens derives strictly above the cap"
    );
}

#[test]
fn rate_nanos_from_cfg_refuses_a_rate_finer_than_one_nano_unit() {
    let sub_nano = RateEntryCfg {
        input_utok: 0.0015,
        output_utok: 0.0014,
        cache_read_utok: 0.002,
        cache_write_utok: 0.0,
        ..Default::default()
    };
    let raw = sub_nano.raw_tier_rates();
    assert_eq!(
        raw.input, None,
        "1.5 nano-units is refused, never rounded to 2"
    );
    assert_eq!(
        raw.output, None,
        "1.4 nano-units is refused, never rounded to 1"
    );
    assert_eq!(
        raw.cache_read,
        Some(2),
        "a whole nano-rate converts exactly"
    );
    assert_eq!(raw.cache_write, Some(0), "an explicit zero is the free row");
}

#[test]
fn rate_nanos_from_cfg_clamps_a_non_finite_positive_rate_to_zero_not_max() {
    let cfg = RateEntryCfg {
        input_utok: f64::INFINITY,
        output_utok: 0.0,
        cache_read_utok: 0.0,
        cache_write_utok: 0.0,
        ..Default::default()
    };
    let rn = crate::cost::RateNanos::from_cfg(&cfg);
    assert_eq!(
        rn.input, 0,
        "a non-finite (but positive) rate must clamp to 0, not saturate to u64::MAX"
    );
}

fn reserved_rate(rate: &RateNanos, unit: &str) -> u64 {
    match unit {
        busbar_contract::records::UNIT_INPUT => rate.input,
        busbar_contract::records::UNIT_OUTPUT => rate.output,
        busbar_contract::records::UNIT_CACHE_READ => rate.cache_read,
        busbar_contract::records::UNIT_CACHE_WRITE => rate.cache_write,
        other => panic!("`{other}` is not a reserved class"),
    }
}

fn one_nanos(
    rate: &RateNanos,
    units: &BTreeMap<String, u64>,
) -> Result<u128, busbar_kernel_ledger::cost::MoneyError> {
    use busbar_kernel_ledger::cost::{
        nanos_of_exact, whole, LaneClass, RateCard, Tally, STANDARD_TIER_BP,
    };
    let card = RateCard::from_nano_rates(
        RESERVED_UNITS
            .iter()
            .map(|u| (LaneClass::new("m", *u), reserved_rate(rate, u))),
        0,
    );
    let mut tally = Tally::at_card(&card);
    tally.row(
        "m",
        0,
        STANDARD_TIER_BP,
        RESERVED_UNITS
            .iter()
            .filter_map(|u| units.get(*u).map(|n| (*u, whole(*n)))),
        whole(0),
    )?;
    nanos_of_exact(tally.exact()?)
}

const ONE_FUNCTION_MAX_NANOS: u128 = (i128::MAX / 1_000_000) as u128;

fn maxed_units() -> BTreeMap<String, u64> {
    RESERVED_UNITS
        .iter()
        .map(|u| ((*u).to_string(), u64::MAX))
        .collect()
}

const MAX_RATE: RateNanos = RateNanos {
    input: u64::MAX,
    output: u64::MAX,
    cache_read: u64::MAX,
    cache_write: u64::MAX,
};

#[test]
fn four_maximal_products_are_refused_rather_than_wrapped_or_pinned() {
    assert_eq!(
        one_nanos(&MAX_RATE, &maxed_units()),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "four maximal reserved products must be REFUSED, never wrapped and never pinned"
    );
}

#[test]
fn from_raw_clamps_a_finite_but_overflowing_rate_to_zero_not_to_u64_max() {
    let cfg = crate::config::RateEntryCfg {
        input_utok: 1e300,
        output_utok: f64::INFINITY,
        cache_read_utok: -1.0,
        cache_write_utok: f64::NAN,
        ..crate::config::RateEntryCfg::default()
    };
    let raw = cfg.raw_tier_rates();
    assert_eq!(
        (raw.input, raw.output, raw.cache_read, raw.cache_write),
        (None, None, None, None),
        "the intake carries every one of them as a rate the card cannot hold, never a figure"
    );
    let got = RateNanos::from_raw(&raw);
    assert_eq!(
        got.input, 0,
        "a finite-but-overflowing rate must clamp to 0, not saturate to u64::MAX"
    );
    assert_eq!(got.output, 0, "an infinite rate clamps to 0");
    assert_eq!(got.cache_read, 0, "a negative rate clamps to 0");
    assert_eq!(got.cache_write, 0, "a NaN rate clamps to 0");
}

#[test]
fn the_one_function_is_byte_identical_to_the_unguarded_sum_wherever_that_sum_fits() {
    fn unguarded_reference(rate: &RateNanos, units: &BTreeMap<String, u64>) -> Option<u128> {
        RESERVED_UNITS.iter().try_fold(0u128, |acc, u| {
            let n = units.get(*u).copied().unwrap_or(0);
            let product = (n as u128).checked_mul(reserved_rate(rate, u) as u128)?;
            acc.checked_add(product)
        })
    }

    let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let edges: [u64; 10] = [
        0,
        1,
        2,
        1_000,
        1_000_000,
        9_200_000_000_000,
        u32::MAX as u64,
        u64::MAX / 4,
        u64::MAX - 1,
        u64::MAX,
    ];

    let mut agreed_ordinary = 0usize;
    let mut refused = 0usize;

    let mut check = |rate: RateNanos, units: &BTreeMap<String, u64>| {
        let got = one_nanos(&rate, units);
        match unguarded_reference(&rate, units) {
            Some(want) if want <= ONE_FUNCTION_MAX_NANOS => {
                assert_eq!(
                    got,
                    Ok(want),
                    "delegation changed an ORDINARY answer: rate={rate:?} units={units:?}"
                );
                agreed_ordinary += 1;
            }
            _ => {
                assert_eq!(
                    got,
                    Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
                    "an input past the one function's range must be REFUSED: \
                     rate={rate:?} units={units:?}"
                );
                refused += 1;
            }
        }
    };

    for &n in &edges {
        for &r in &edges {
            let rate = RateNanos {
                input: r,
                output: r,
                cache_read: r,
                cache_write: r,
            };
            let all: BTreeMap<String, u64> = RESERVED_UNITS
                .iter()
                .map(|u| ((*u).to_string(), n))
                .collect();
            check(rate, &all);

            for u in RESERVED_UNITS {
                let mut one = BTreeMap::new();
                one.insert(u.to_string(), n);
                check(rate, &one);
            }
        }
    }

    for _ in 0..10_000 {
        let rate = RateNanos {
            input: next() % 100_000_000,
            output: next() % 100_000_000,
            cache_read: next() % 100_000_000,
            cache_write: next() % 100_000_000,
        };
        let units: BTreeMap<String, u64> = RESERVED_UNITS
            .iter()
            .map(|u| ((*u).to_string(), next() % 10_000_000_000))
            .collect();
        check(rate, &units);
    }

    for _ in 0..10_000 {
        let rate = RateNanos {
            input: next(),
            output: next(),
            cache_read: next(),
            cache_write: next(),
        };
        let units: BTreeMap<String, u64> = RESERVED_UNITS
            .iter()
            .map(|u| ((*u).to_string(), next()))
            .collect();
        check(rate, &units);
    }

    println!(
        "one-function equivalence: {agreed_ordinary} ordinary inputs agreed exactly, \
         {refused} inputs past the range refused"
    );
    assert!(
        // The one function's range is an `i128` at scale 15 — narrower than the old fold's `u128`
        // of nano-units — so fewer of the adversarial draws fit; the ordinary ten thousand still do.
        agreed_ordinary > 10_000,
        "expected the ordinary-input agreement arm to run in bulk, ran {agreed_ordinary}"
    );
    assert!(
        refused > 100,
        "expected the refusing arm to be exercised, ran {refused}"
    );
}

#[test]
fn from_raw_is_byte_identical_to_the_unclamped_projection_for_every_in_range_rate() {
    fn unclamped_reference(utok: f64) -> Option<u64> {
        let v = (utok * 1000.0).round();

        (v.is_finite() && v > 0.0 && v < 2.0_f64.powi(64)).then_some(v as u64)
    }

    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let mut agreed = 0usize;
    let mut refused = 0usize;
    for i in 0..10_000 {
        let utok = match i % 4 {
            0 => (next() % 1_000_000) as f64 / 1000.0,
            1 => (next() % 1_000) as f64,
            2 => (next() % 1_000_000_000) as f64 / 1_000_000.0,
            _ => (next() % 100) as f64 / 7.0,
        };
        let cfg = crate::config::RateEntryCfg {
            input_utok: utok,
            output_utok: utok,
            cache_read_utok: utok,
            cache_write_utok: utok,
            ..crate::config::RateEntryCfg::default()
        };
        let Some(want) = unclamped_reference(utok) else {
            continue;
        };
        let decimal = utok.to_string();
        let whole_nanos = decimal
            .split_once('.')
            .is_none_or(|(_, frac)| frac.len() <= 3);
        let raw = cfg.raw_tier_rates();
        if whole_nanos {
            assert_eq!(
                (raw.input, RateNanos::from_cfg(&cfg).input),
                (Some(want), want),
                "the intake moved a rate 1.5.5 priced exactly: utok={utok}"
            );
            agreed += 1;
        } else {
            assert_eq!(
                raw.input, None,
                "utok={utok} is not a whole number of nano-units: REFUSED, never rounded to {want}"
            );
            refused += 1;
        }
    }
    println!("from_raw equivalence: {agreed} rates agreed exactly, {refused} refused");
    assert!(
        agreed > 4_500,
        "expected the whole-nano agreement arm to run in bulk, ran {agreed}"
    );
    assert!(
        refused > 2_000,
        "expected the refusal arm to run in bulk, ran {refused}"
    );
}

#[test]
fn the_one_function_does_not_wrap_an_astronomical_bill_down_to_nearly_free() {
    let rate = RateNanos {
        input: u64::MAX,
        output: 1u64 << 32,
        cache_read: 0,
        cache_write: 0,
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), u64::MAX);
    units.insert(UNIT_OUTPUT.to_string(), 1u64 << 33);

    let product_input = (u64::MAX as u128) * (u64::MAX as u128);
    assert_eq!(
        product_input,
        (1u128 << 127) + ((1u128 << 127) - (1u128 << 65) + 1),
        "the single product is 2^128 - 2^65 + 1, which does fit"
    );

    assert_eq!(
        one_nanos(&rate, &units),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "a total one past the ceiling is REFUSED — never wrapped to 1, never pinned at the top"
    );
}

#[test]
fn a_fractional_cent_rate_prices_exactly_through_the_live_intake() {
    let c = card(&[("m", 0.1, 0.2)]);
    let cm = resolve_card_fee(Some(&c), 0);
    let r = crate::cost::RateNanos::from_cfg(&c["m"]);
    assert_eq!(
        (r.input, r.output),
        (100, 200),
        "the intake carries exact nano-units"
    );
    assert_eq!(
        one_nanos(&r, &toks(1, 1)),
        Ok(300),
        "0.1 + 0.2 is exactly 0.3"
    );
    assert_eq!(one_nanos(&r, &toks(3, 7)), Ok(3 * 100 + 7 * 200));
    assert_eq!(
        bucket_money(&cm, [("m", &toks(1_000_000, 1_000_000))], 0).and_then(Money::micros_i64),
        Ok(300_000),
        "0.1 + 0.2 units per Mtok over a million of each is 300 000 micro-units exactly"
    );
    let drifted = RateEntryCfg {
        input_utok: 0.1 + 0.2,
        ..Default::default()
    };
    assert_eq!(
        drifted.raw_tier_rates().input,
        None,
        "the double 0.30000000000000004 is not a whole nano-rate: refused, never rounded to 300"
    );
}

#[test]
fn a_large_count_times_a_rate_has_no_float_drift() {
    let c = card(&[("m", 0.3, 0.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    let r = crate::cost::RateNanos::from_cfg(&c["m"]);
    let count: u64 = (1 << 53) + 1;
    assert_eq!(
        one_nanos(&r, &toks(count, 0)),
        Ok(u128::from(count) * 300),
        "every token of a count past f64's integer range is billed"
    );
    assert_eq!(
        bucket_money(&cm, [("m", &toks(count, 0))], 0).and_then(Money::micros_i64),
        Ok(i64::try_from(u128::from(count) * 300 / 1_000).expect("fits")),
        "the micro projection truncates the exact figure once"
    );
}

#[test]
fn the_intake_prices_every_money_fixture_rate_at_its_1_5_5_figure() {
    for utok in [
        0.0, 1.0, 100_000.0, 200_000.0, 1e6, 2e6, 1e7, 2e7, 2.5, 10.0, 3.125, 15.0, 0.075, 3.75,
        0.3, 1.25, 0.001,
    ] {
        let v155 = (utok * 1000.0_f64).round() as u64;
        let c = card(&[("m", utok, utok)]);
        let r = crate::cost::RateNanos::from_cfg(&c["m"]);
        assert_eq!(
            (r.input, r.output),
            (v155, v155),
            "{utok} converts as 1.5.5 did"
        );
        assert_eq!(
            one_nanos(&r, &toks(1_234_567, 7_654_321)),
            Ok(u128::from(v155) * (1_234_567 + 7_654_321)),
            "{utok} prices a count as 1.5.5 did"
        );
    }
}
