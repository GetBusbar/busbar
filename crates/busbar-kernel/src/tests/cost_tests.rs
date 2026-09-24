// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the cost + limit model: rate-card derivation (tokens are the ledger, dollars derive)
//! and the resolved `groups:` limit topology (per-(group, window) enforcement buckets, the chain
//! walk, key encoding).

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::config::RateEntryCfg;
use busbar_api::{VirtualKey, RESERVED_UNITS};
use std::collections::BTreeMap;

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

/// A name-keyed reserved-four unit map (test helper) — the M1b replacement for the old
/// `TierTokens` literal. Zero tiers are omitted (sparse map / no-zero-entry invariant).
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

/// ABSENT rate card => token pricing is 0 for every model; only the flat per-request fee
/// counts. This is the all-or-nothing OFF arm.
#[test]
fn absent_rate_card_prices_tokens_at_zero() {
    let cm = resolve_card_fee(None, 3);
    assert!(!cm.pricing_enabled());
    assert!(!cm.model_unpriced("anything"), "no card = nothing to miss");
    let t = toks(1_000_000, 1_000_000);
    let spend = cm
        .derive_spend_cents([("anything", &t)].into_iter(), 5, true)
        .expect("the one function prices");
    assert_eq!(spend, 15, "tokens derive to 0; 5 requests x 3c fee remain");
}

/// PRESENT rate card: derivation is integer nano-unit math over the tier split. gpt-5 at
/// 2.5 utok input / 10 utok output: 1M input + 1M output tokens = 2.5 + 10 units = 1250 cents.
#[test]
fn present_rate_card_derives_integer_spend() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.pricing_enabled());
    let t = toks(1_000_000, 1_000_000);
    let spend = cm
        .derive_spend_cents([("gpt-5", &t)].into_iter(), 0, false)
        .expect("the one function prices");
    assert_eq!(spend, 1250);
    // Micro projection: 12.5 units = 12_500_000 micro-units.
    let micros = cm
        .derive_spend_micros([("gpt-5", &t)].into_iter(), 0, false)
        .expect("the one function prices");
    assert_eq!(micros, 12_500_000);
}

/// Sub-micro precision survives the nano scale: 3.125 utok/token x 8 tokens = 25 micro-units
/// exactly (no truncation at the micro boundary).
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
        cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
        Ok(25)
    );
}

/// Runtime model NOT in a present card => `model_unpriced` (the admission path rejects), and the
/// derive paths REFUSE it (#42, items 25/31/124). They used to price it at 0 — a million tokens as
/// nothing, on the live admission gate and on every customer read.
#[test]
fn unknown_model_with_card_is_unpriced_and_refuses() {
    let c = card(&[("gpt-5", 1.0, 1.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.model_unpriced("mystery-model"));
    assert!(!cm.model_unpriced("gpt-5"));
    let t = toks(1_000_000, 0);
    assert_eq!(
        cm.derive_spend_cents([("mystery-model", &t)].into_iter(), 0, false),
        Err(busbar_kernel_ledger::cost::MoneyError::LaneUnpriced {
            card_seq: busbar_kernel_ledger::cost::HistorySeq::OPENING,
            lane: "mystery-model".to_string(),
        })
    );
}

/// REPRICE-ON-READ: the ledger (tokens) is fixed; deriving under a corrected rate card yields
/// the corrected spend - no stored dollar to migrate.
#[test]
fn reprice_on_read_recomputes_derived_spend() {
    let t = toks(1_000_000, 0);
    let wrong = resolve_card_fee(Some(&card(&[("m", 10.0, 0.0)])), 0);
    let fixed = resolve_card_fee(Some(&card(&[("m", 5.0, 0.0)])), 0);
    assert_eq!(
        wrong.derive_spend_cents([("m", &t)].into_iter(), 0, false),
        Ok(1000)
    );
    assert_eq!(
        fixed.derive_spend_cents([("m", &t)].into_iter(), 0, false),
        Ok(500),
        "same tokens, corrected rate: derived spend halves on next read"
    );
}

/// A total past the range REFUSES (item 28): never a wrap toward 0 (free, the pre-1.5 defect) and
/// never a pin at `i64::MAX` (a bill nobody consumed, the defect the saturation introduced). The
/// door blocks on the refusal; a read fails on it.
#[test]
fn derive_spend_cents_refuses_an_overflow_never_wraps_or_pins() {
    // 1e15 micro-units/token -> 1e18 nano-units/token; x u64::MAX tokens ~= 1.8e37 nanos
    // -> ~1.8e30 cents, far past i64::MAX.
    let cm = resolve_card_fee(Some(&card(&[("m", 1e15, 0.0)])), 0);
    let t = toks(u64::MAX, 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &t)].into_iter(), 0, false),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "an over-range total is a refusal, never a pinned figure"
    );
    assert_eq!(
        cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow)
    );
}

/// rate_card is the ONLY cost source - pool members carry no cost, and the routing
/// scalar (`cheapest` / hook Candidate.cost_per_mtok) derives from a model's card entry as
/// the blended (input + output) / 2 in units/mtok.
#[test]
fn rate_card_is_sole_cost_source_and_drives_routing_scalar() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    let r = cm.rate_for("gpt-5").unwrap();
    assert_eq!(
        (r.input, r.output),
        (2_500, 10_000),
        "nano-unit rates come straight from the card"
    );
    // The routing scalar projection: (2.5 + 10.0) / 2 = 6.25 units/mtok.
    let scalar = crate::config::rate_entry_per_mtok(&c["gpt-5"]);
    assert!((scalar - 6.25).abs() < f64::EPSILON);
    // A pool member no longer parses a cost field at all (fail-closed on the removed key).
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

/// GROUP RESOLUTION: each distinct window a group's limits use becomes ONE enforcement bucket
/// (`group:<name>@<window>`) carrying that window's caps; `concurrent` resolves to the group's
/// instantaneous gauge cap, never a bucket.
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

/// A metric repeated for the same window keeps the MOST RESTRICTIVE amount (AND semantics inside
/// one group, same as across the chain).
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

/// Chain resolution: key attribution bucket first (uncapped, `total`), then EVERY window bucket of
/// each ancestor group, innermost group first; `group_indices` exposes the walked groups for the
/// enabled/concurrent checks. A key with no group is a 1-bucket chain (authed + unlimited).
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
    // The walked group indices resolve to growth (innermost) then acme.
    let names: Vec<&str> = chain
        .group_indices()
        .iter()
        .map(|&i| cm.groups()[i].name.as_str())
        .collect();
    assert_eq!(names, vec!["growth", "acme"]);

    // No group: exactly the key's uncapped attribution bucket.
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

/// A key naming a MISSING group fails closed: chain resolution surfaces the offender.
#[test]
fn chain_with_missing_group_fails_closed_naming_it() {
    let cm = CostModel::resolve_parts(None, 0, &BTreeMap::new());
    let k = key(Some("ghost"));
    match cm.chain_for(&k) {
        Err(missing) => assert_eq!(missing, "ghost"),
        Ok(_) => panic!("a missing group must fail chain resolution"),
    }
}

/// A rate card with ALL FOUR tiers priced distinctly, and four distinct tier-token counts, must
/// price each tier against ITS OWN rate — cache-read tokens at the cache-read rate, cache-write
/// (creation) tokens at the cache-write rate, never swapped. An invoice where cache-read and
/// cache-write were transposed would over- or under-bill every cached request (cache-write is
/// typically 8x cache-read), so this pins the tier→rate mapping with counts chosen so any swap of
/// two tiers changes the total.
#[test]
fn four_tier_card_prices_each_tier_against_its_own_rate() {
    let c = BTreeMap::from([(
        "quad".to_string(),
        RateEntryCfg {
            input_utok: 1.0,       // 1000 nano/token
            output_utok: 2.0,      // 2000
            cache_read_utok: 0.5,  // 500
            cache_write_utok: 4.0, // 4000
            ..Default::default()
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    let t = toks4(
        10_000_000, // 10_000_000_000 nanos
        1_000_000,  //  2_000_000_000
        2_000_000,  //  1_000_000_000
        500_000,    //  2_000_000_000
    );
    // sum 15_000_000_000 nanos / 10_000_000 = 1500 cents exactly.
    assert_eq!(
        cm.derive_spend_cents([("quad", &t)].into_iter(), 0, false),
        Ok(1500),
        "each tier must bill against its own rate; a swapped cache_read/cache_write mapping changes this"
    );
    let r = cm.rate_for("quad").unwrap();
    assert_eq!(
        (r.input, r.output, r.cache_read, r.cache_write),
        (1_000, 2_000, 500, 4_000),
        "nano rates carry all four tiers straight from the card"
    );
}

/// The cent derivation is an INTEGER DIVISION (`nanos / NANOS_PER_CENT`) — it TRUNCATES toward zero,
/// it does not round to nearest. A sub-cent remainder is dropped, never rounded UP. This is the
/// invoice property: the ledger floors fractional spend deterministically (never bills a cent the
/// tokens did not reach). 19_999 input tokens at 1 utok = 19_999_000 nanos = 1.9999 cents and must
/// derive to 1, not 2; the exact boundary 20_000 tokens = 2 cents. A round-to-nearest bug would make
/// the first case 2.
#[test]
fn cent_derivation_truncates_toward_zero_never_rounds_up() {
    let cm = resolve_card_fee(Some(&card(&[("m", 1.0, 0.0)])), 0);
    let just_under = cm
        .derive_spend_cents([("m", &toks(19_999, 0))].into_iter(), 0, false)
        .expect("the one function prices");
    assert_eq!(
        just_under, 1,
        "1.9999 cents must floor to 1, not round up to 2"
    );
    let on_boundary = cm
        .derive_spend_cents([("m", &toks(20_000, 0))].into_iter(), 0, false)
        .expect("the one function prices");
    assert_eq!(on_boundary, 2, "exactly 2.0 cents is 2");
    let just_over = cm
        .derive_spend_cents([("m", &toks(20_001, 0))].into_iter(), 0, false)
        .expect("the one function prices");
    assert_eq!(just_over, 2, "2.0001 cents still floors to 2");
}

/// Two models billed into ONE bucket accumulate NANOS first and divide to cents ONCE, not per model.
/// This matters below the cent: two models each contributing 0.5 cent (5_000_000 nanos) sum to a
/// whole 1 cent — a per-model floor would drop each to 0 and bill 0, silently under-charging every
/// multi-model bucket. Pins the "sum-then-divide" order the ledger depends on.
#[test]
fn sub_cent_contributions_across_models_sum_before_flooring() {
    // 5 utok/token = 5000 nano/token; 1000 tokens = 5_000_000 nanos = 0.5 cent each.
    let cm = resolve_card_fee(Some(&card(&[("a", 5.0, 0.0), ("b", 5.0, 0.0)])), 0);
    let ta = toks(1_000, 0);
    let tb = toks(1_000, 0);
    assert_eq!(
        cm.derive_spend_cents([("a", &ta)].into_iter(), 0, false),
        Ok(0),
        "one 0.5-cent model alone floors to 0"
    );
    assert_eq!(
        cm.derive_spend_cents([("a", &ta), ("b", &tb)].into_iter(), 0, false),
        Ok(1),
        "two 0.5-cent models sum to a whole cent — nanos accumulate before the single divide"
    );
}

/// A model priced EXPLICITLY at zero (all four tiers 0.0 in a present card) is a KNOWN model that
/// derives 0 for any token volume — distinct from an UNKNOWN model (missing entry). Pricing is
/// enabled, the model is NOT unpriced, and even u64::MAX tokens derive exactly 0.
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
        cm.derive_spend_cents([("freebie", &t)].into_iter(), 0, false),
        Ok(0),
        "a zero-rated model bills nothing regardless of volume"
    );
}

/// A PARTIAL card (some models priced, one absent): `model_unpriced` is true ONLY for the missing
/// model, and a mixed derivation REFUSES on the missing one (#42) — it used to skip it, so 9,999,999
/// tokens vanished from the bucket's spend. The known model alone still prices exactly; nothing
/// panics and no model is priced by a sibling's rate.
#[test]
fn partial_card_prices_known_models_and_refuses_the_missing_one() {
    let c = card(&[("priced", 2.0, 0.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(!cm.model_unpriced("priced"));
    assert!(cm.model_unpriced("absent"));
    let known = toks(1_000_000, 0); // 2 utok * 1M = 200 cents
    let absent = toks(9_999_999, 0);
    assert_eq!(
        cm.derive_spend_cents(
            [("priced", &known), ("absent", &absent)].into_iter(),
            0,
            false
        ),
        Err(busbar_kernel_ledger::cost::MoneyError::LaneUnpriced {
            card_seq: busbar_kernel_ledger::cost::HistorySeq::OPENING,
            lane: "absent".to_string(),
        }),
        "the missing model refuses the derivation; it never derives 0"
    );
    assert_eq!(
        cm.derive_spend_cents([("priced", &known)].into_iter(), 0, false),
        Ok(200),
        "the priced model alone prices as it always did"
    );
}

/// The flat per-request fee is `price_per_request_cents * fee_requests`, added ONLY when
/// `include_request_fee`. A product past the range REFUSES (item 28) — never a wrap toward free,
/// never a pinned figure. With the flag off, the fee contributes nothing.
#[test]
fn flat_fee_refuses_an_overflow_and_is_gated_by_the_flag() {
    let cm = resolve_card_fee(None, i64::MAX);
    let z = toks(0, 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), u64::MAX, true),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "i64::MAX fee * u64::MAX requests is refused, never wrapped and never pinned"
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), u64::MAX, false),
        Ok(0),
        "with include_request_fee=false the flat fee contributes nothing"
    );
}

/// A NEGATIVE configured per-request fee is clamped to 0 at resolve (`per_request_fee.max(0)`), so
/// no request can ever be billed a negative amount that would CREDIT a budget bucket back toward
/// headroom. Both the accessor and a fee-inclusive derivation see 0.
#[test]
fn negative_per_request_fee_clamps_to_zero() {
    let cm = resolve_card_fee(None, -5);
    assert_eq!(cm.price_per_request_cents(), 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &toks(0, 0))].into_iter(), 100, true),
        Ok(0),
        "a negative fee must never credit a bucket: 100 requests at a clamped-0 fee is 0"
    );
}

/// The MICRO projection's flat-fee component is `cents * 10_000 * requests` (1 cent = 10_000
/// micro-units), added only when `include_request_fee`. Pins the micro-scale fee against the
/// cent-scale one so the hook-seam projection can never drift from the ledger's cents.
#[test]
fn micro_projection_fee_is_cents_times_ten_thousand() {
    let cm = resolve_card_fee(None, 3);
    let z = toks(0, 0);
    // 3 cents/request * 5 requests = 15 cents = 150_000 micro-units.
    assert_eq!(
        cm.derive_spend_micros([("m", &z)].into_iter(), 5, true),
        Ok(150_000)
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), 5, true),
        Ok(15),
        "the same fee in cents is 15 — the micro projection is exactly 10_000x"
    );
    assert_eq!(
        cm.derive_spend_micros([("m", &z)].into_iter(), 5, false),
        Ok(0),
        "flag off: no fee in the micro projection either"
    );
}

/// BUDGET-CAP BOUNDARY, in the exact cents the admission decision compares (`derived >= cap`): a
/// token count chosen to land the derived spend EXACTLY on an integer cap value derives to precisely
/// that integer (so a request that has reached the cap is recognized as at-cap), and a larger count
/// derives strictly above it. This pins the arithmetic the governance budget check keys off; the
/// comparison itself lives in the metering path (not exercised here).
#[test]
fn derived_spend_lands_exactly_on_an_integer_budget_cap() {
    // 1 utok = 1000 nano/token; 1_000_000 tokens = 1_000_000_000 nanos = 100 cents exactly.
    let cm = resolve_card_fee(Some(&card(&[("m", 1.0, 0.0)])), 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &toks(1_000_000, 0))].into_iter(), 0, false),
        Ok(100),
        "spend lands exactly on the integer cap value the budget check compares against"
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &toks(1_010_000, 0))].into_iter(), 0, false),
        Ok(101),
        "one full cent more of tokens derives strictly above the cap"
    );
}

/// `RateNanos::from_cfg` converts config micro-units to nano-units by `(_utok * 1000).round()` —
/// ROUND TO NEAREST (half away from zero), not truncation. 0.0015 utok = 1.5 nano must round to 2;
/// 0.0014 utok = 1.4 nano must floor to 1. A truncating conversion would make the first case 1,
/// silently under-pricing the finest-grained rates an operator can configure.
#[test]
fn rate_nanos_from_cfg_rounds_to_nearest_at_the_nano_boundary() {
    let half_up = RateEntryCfg {
        input_utok: 0.0015,
        output_utok: 0.0014,
        cache_read_utok: 0.0,
        cache_write_utok: 0.0,
        ..Default::default()
    };
    let rn = crate::cost::RateNanos::from_cfg(&half_up);
    assert_eq!(rn.input, 2, "1.5 nano rounds to 2 (half away from zero)");
    assert_eq!(rn.output, 1, "1.4 nano floors to 1");
}

/// `RateNanos::from_cfg`'s inner `nanos()` clamp is `is_finite() && v > 0.0`, not `||`: a
/// mutated `||` would let a non-finite-but-positive value (e.g. `+inf`, reachable from a huge
/// `_utok` config value * 1000.0) through to `as u64`, which SATURATES to `u64::MAX` on a
/// non-finite float cast in Rust — a garbage billing rate, not the documented "0" defense.
/// NaN alone can't distinguish `&&` from `||` (`NaN > 0.0` is false either way), so this uses
/// `f64::INFINITY` specifically: finite=false, `> 0.0`=true.
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

// -------------------------------------------------------------------------------------------
// MONEY: THE RESERVED-FOUR SUMMATION AND THE RATE PROJECTION IT IS SUMMED AT.
//
// Both of these guard a DELEGATION rather than a local guard. The summation used to live here as
// `RateNanos::reserved_nanos` — a copy of the fold that SATURATED — and it is gone (items 104,
// 25): every figure is `busbar_kernel_ledger::cost::Tally`, THE ONE FUNCTION, which REFUSES an
// overflow (item 28). `one_nanos` below drives it exactly as `CostModel` does, over one model.
// -------------------------------------------------------------------------------------------

/// One reserved class's rate off the four-rate view — the lookup `RateNanos::reserved_rate` used
/// to answer, whose `_ => 0` arm priced an open class as nothing (item 123); a test-side spelling
/// of the four, so these delegation guards keep asking exactly what they asked.
fn reserved_rate(rate: &RateNanos, unit: &str) -> u64 {
    match unit {
        busbar_api::UNIT_INPUT => rate.input,
        busbar_api::UNIT_OUTPUT => rate.output,
        busbar_api::UNIT_CACHE_READ => rate.cache_read,
        busbar_api::UNIT_CACHE_WRITE => rate.cache_write,
        other => panic!("`{other}` is not a reserved class"),
    }
}

/// The one function's figure, in nano-units, for one model's reserved-four counts at these
/// already-quantised rates — the same drive `CostModel::derive_spend_*` performs.
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

/// The largest nano-unit figure the one function holds: its exact accumulator is an `i128` at
/// scale 15, six decimal places finer than a nano-unit.
const ONE_FUNCTION_MAX_NANOS: u128 = (i128::MAX / 1_000_000) as u128;

/// All four reserved units present at the largest count a `u64` holds.
fn maxed_units() -> BTreeMap<String, u64> {
    RESERVED_UNITS
        .iter()
        .map(|u| ((*u).to_string(), u64::MAX))
        .collect()
}

/// The rate card at the largest nano rate a `u64` holds.
const MAX_RATE: RateNanos = RateNanos {
    input: u64::MAX,
    output: u64::MAX,
    cache_read: u64::MAX,
    cache_write: u64::MAX,
};

#[test]
fn four_maximal_products_are_refused_rather_than_wrapped_or_pinned() {
    // ONE product of a u64 count and a u64 rate fits a u128 with a whole bit to spare —
    // (2^64-1)^2 is 2^128 - 2^65 + 1 — and that is the true sentence the old comment made. Their
    // SUM is what it was silent about: four of them reach ~2^130 against a 2^128 ceiling. A plain
    // `+` panics on overflow in a debug build and WRAPS in a release one, and a wrapped total
    // lands back near zero — an astronomical ledger deriving as very nearly free and clearing
    // every budget cap on the way past. Pinning at the top is the only reading that cannot
    // under-bill.
    //
    // The old copy pinned at the top — which cannot under-bill, but bills a ceiling nobody
    // consumed. The one function refuses instead (item 28), and the door blocks on the refusal.
    assert_eq!(
        one_nanos(&MAX_RATE, &maxed_units()),
        Err(busbar_kernel_ledger::cost::MoneyError::Overflow),
        "four maximal reserved products must be REFUSED, never wrapped and never pinned"
    );
}

#[test]
fn from_raw_clamps_a_finite_but_overflowing_rate_to_zero_not_to_u64_max() {
    // 1e300 micro-units per token is a config typo with too many zeros, not a price. Times a
    // thousand it is 1e303: finite, positive, and hugely past `u64::MAX`, so a finiteness test
    // alone lets it through and the float-to-integer cast SATURATES — turning a typo into the
    // largest rate expressible, an astronomical OVERCHARGE, which is the exact opposite of the
    // defence the clamp was there to provide. The ledger's projection refuses it to zero: a rate
    // nobody can price is priced at nothing, and config validation is what is supposed to have
    // caught it one layer earlier.
    let raw = busbar_substrate_values::billing::RawTierRates {
        input: 1e300,
        output: f64::INFINITY,
        cache_read: -1.0,
        cache_write: f64::NAN,
    };
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
    // THE EQUIVALENCE THE DELEGATION OWES. The reference below is the arithmetic this function
    // USED to carry, spelled out with checked operations: multiply in u128, add in u128, no
    // saturation anywhere. Where it does not overflow it is exact, so every input for which it
    // returns an answer is an input on which the delegating implementation must return the SAME
    // answer, bit for bit — that is what "customer-visible behaviour is unchanged" means here.
    // Where it overflows it had no answer to give (it panicked or wrapped), and the delegating
    // implementation pins at the top instead. The two clauses together are a full
    // characterisation, not a spot check.
    fn unguarded_reference(rate: &RateNanos, units: &BTreeMap<String, u64>) -> Option<u128> {
        RESERVED_UNITS.iter().try_fold(0u128, |acc, u| {
            let n = units.get(*u).copied().unwrap_or(0);
            let product = (n as u128).checked_mul(reserved_rate(rate, u) as u128)?;
            acc.checked_add(product)
        })
    }

    // A deterministic generator, so a failure is reproducible by seed rather than by luck.
    let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    // The boundary values a money path actually meets, crossed with themselves: nothing, one,
    // an ordinary request, a large batch, the 32-bit and 64-bit ceilings, and the ceiling of the
    // legacy store wire (#81: an ABI-2 store tops out near 9.2e12 whole units).
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

    // Every (count, rate) pair drawn from the boundary set, applied to all four reserved units
    // at once and to each one alone.
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

    // Then ten thousand ordinary cards and reports: counts and rates in the range a real
    // deployment produces, where the sum has an exact answer and the two implementations must
    // return it identically.
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

    // And ten thousand adversarial ones, drawn from the whole u64 range so the saturating clause
    // is exercised as hard as the ordinary one.
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

    // A filter matching nothing is indistinguishable from a filter matching and passing, and so
    // is a loop that compared nothing. Both arms must have actually run, in bulk. The ten thousand
    // ordinary cards alone guarantee the first figure; the boundary sweep and the in-range tail of
    // the adversarial draw carry it the rest of the way.
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
    // The mirror equivalence for the rate projection. The reference is the conversion this
    // function used to carry: multiply by a thousand, round half away from zero (#44 — card-build
    // quantization is half-away-from-zero, and `f64::round` IS that rule), cast. It is exact for
    // every value that fits a u64, and the delegation must agree with it on all of them; the
    // values it does NOT have an answer for are precisely the ones the missing clamp used to turn
    // into u64::MAX.
    fn unclamped_reference(utok: f64) -> Option<u64> {
        let v = (utok * 1000.0).round();
        // The in-range test is `< 2^64`, NOT `<= u64::MAX as f64`. `u64::MAX` is `2^64 - 1` and no
        // `f64` holds it, so that cast rounds UP to `2^64`; a reference written the second way would
        // claim `v == 2^64` has the answer `v as u64` — which SATURATES to `u64::MAX` — and would
        // then certify the delegation as correct for doing exactly that. An oracle that carries the
        // defect it is meant to detect cannot report it.
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
    for i in 0..10_000 {
        // Real rate cards are small decimals of micro-units per token; sweep that range densely
        // and a few decades either side of it.
        let utok = match i % 4 {
            0 => (next() % 1_000_000) as f64 / 1000.0,
            1 => (next() % 1_000) as f64,
            2 => (next() % 1_000_000_000) as f64 / 1_000_000.0,
            _ => (next() % 100) as f64 / 7.0,
        };
        let raw = busbar_substrate_values::billing::RawTierRates {
            input: utok,
            output: utok,
            cache_read: utok,
            cache_write: utok,
        };
        if let Some(want) = unclamped_reference(utok) {
            assert_eq!(
                RateNanos::from_raw(&raw).input,
                want,
                "delegation changed an ORDINARY rate projection: utok={utok}"
            );
            agreed += 1;
        }
    }
    println!("from_raw equivalence: {agreed} in-range rate projections agreed exactly");
    assert!(
        agreed > 7_000,
        "expected the in-range agreement arm to run in bulk, ran {agreed}"
    );
}

#[test]
fn the_one_function_does_not_wrap_an_astronomical_bill_down_to_nearly_free() {
    // THE RELEASE-BUILD CONSEQUENCE, in exact numbers. A debug build panics on the overflowing
    // add, which is loud. A release build WRAPS, which is silent, and silence is the dangerous
    // half: the total lands back near zero and an enormous ledger derives as very nearly free,
    // clearing every budget cap on the way past.
    //
    // Two products chosen to straddle the ceiling by exactly one:
    //   input      u64::MAX  x  u64::MAX  =  2^128 - 2^65 + 1
    //   output        2^33   x     2^32   =           2^65
    //   true total                        =  2^128 + 1
    // which a wrapping `+` reports as ONE nano-unit. Saturation reports the top instead, and an
    // over-the-top figure is the only reading of an over-the-top bill that cannot under-bill.
    let rate = RateNanos {
        input: u64::MAX,
        output: 1u64 << 32,
        cache_read: 0,
        cache_write: 0,
    };
    let mut units = BTreeMap::new();
    units.insert(UNIT_INPUT.to_string(), u64::MAX);
    units.insert(UNIT_OUTPUT.to_string(), 1u64 << 33);

    // The true sum is 2^128 + 1, one past the accumulator.
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
