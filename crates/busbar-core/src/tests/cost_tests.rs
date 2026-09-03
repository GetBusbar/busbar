// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the cost + limit model: rate-card derivation (tokens are the ledger, dollars derive)
//! and the resolved `groups:` limit topology (per-(group, window) enforcement buckets, the chain
//! walk, key encoding).

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::config::RateEntryCfg;
use busbar_api::VirtualKey;
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

fn toks(input: u64, output: u64) -> TierTokens {
    TierTokens {
        input,
        output,
        cache_read: 0,
        cache_write: 0,
    }
}

/// ABSENT rate card => token pricing is 0 for every model; only the flat per-request fee
/// counts. This is the all-or-nothing OFF arm.
#[test]
fn absent_rate_card_prices_tokens_at_zero() {
    let cm = resolve_card_fee(None, 3);
    assert!(!cm.pricing_enabled());
    assert!(!cm.model_unpriced("anything"), "no card = nothing to miss");
    let t = toks(1_000_000, 1_000_000);
    let spend = cm.derive_spend_cents([("anything", &t)].into_iter(), 5, true);
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
    let spend = cm.derive_spend_cents([("gpt-5", &t)].into_iter(), 0, false);
    assert_eq!(spend, 1250);
    // Micro projection: 12.5 units = 12_500_000 micro-units.
    let micros = cm.derive_spend_micros([("gpt-5", &t)].into_iter(), 0, false);
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
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    let t = toks(8, 0);
    assert_eq!(
        cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
        25
    );
}

/// Runtime model NOT in a present card => `model_unpriced` (the admission path rejects); the
/// derive paths price it at 0 (ledger rows from a previous config).
#[test]
fn unknown_model_with_card_is_unpriced_and_derives_zero() {
    let c = card(&[("gpt-5", 1.0, 1.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.model_unpriced("mystery-model"));
    assert!(!cm.model_unpriced("gpt-5"));
    let t = toks(1_000_000, 0);
    assert_eq!(
        cm.derive_spend_cents([("mystery-model", &t)].into_iter(), 0, false),
        0
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
        1000
    );
    assert_eq!(
        fixed.derive_spend_cents([("m", &t)].into_iter(), 0, false),
        500,
        "same tokens, corrected rate: derived spend halves on next read"
    );
}

/// A cent total past i64::MAX SATURATES at i64::MAX
/// (fail-closed: an astronomical ledger blocks). The pre-fix `as i64` cast wrapped - a large
/// (u64-scale tokens x large configured rate) ledger could land NEGATIVE, be floored to 0 by
/// `.max(0)`, and derive as FREE, bypassing every budget cap.
#[test]
fn derive_spend_cents_saturates_never_wraps_free() {
    // 1e15 micro-units/token -> 1e18 nano-units/token; x u64::MAX tokens ~= 1.8e37 nanos
    // -> ~1.8e30 cents, far past i64::MAX.
    let cm = resolve_card_fee(Some(&card(&[("m", 1e15, 0.0)])), 0);
    let t = toks(u64::MAX, 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &t)].into_iter(), 0, false),
        i64::MAX,
        "an over-i64 cent total must pin at i64::MAX (blocks), never wrap toward 0 (free)"
    );
    // The micro projection already saturated correctly; pin it too.
    assert_eq!(
        cm.derive_spend_micros([("m", &t)].into_iter(), 0, false),
        i64::MAX
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
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    let t = TierTokens {
        input: 10_000_000,     // 10_000_000_000 nanos
        output: 1_000_000,     //  2_000_000_000
        cache_read: 2_000_000, //  1_000_000_000
        cache_write: 500_000,  //  2_000_000_000
    };
    // sum 15_000_000_000 nanos / 10_000_000 = 1500 cents exactly.
    assert_eq!(
        cm.derive_spend_cents([("quad", &t)].into_iter(), 0, false),
        1500,
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
    let just_under = cm.derive_spend_cents([("m", &toks(19_999, 0))].into_iter(), 0, false);
    assert_eq!(
        just_under, 1,
        "1.9999 cents must floor to 1, not round up to 2"
    );
    let on_boundary = cm.derive_spend_cents([("m", &toks(20_000, 0))].into_iter(), 0, false);
    assert_eq!(on_boundary, 2, "exactly 2.0 cents is 2");
    let just_over = cm.derive_spend_cents([("m", &toks(20_001, 0))].into_iter(), 0, false);
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
        0,
        "one 0.5-cent model alone floors to 0"
    );
    assert_eq!(
        cm.derive_spend_cents([("a", &ta), ("b", &tb)].into_iter(), 0, false),
        1,
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
        },
    )]);
    let cm = resolve_card_fee(Some(&c), 0);
    assert!(cm.pricing_enabled());
    assert!(
        !cm.model_unpriced("freebie"),
        "an all-zero entry is present, not missing"
    );
    let t = TierTokens {
        input: u64::MAX,
        output: u64::MAX,
        cache_read: u64::MAX,
        cache_write: u64::MAX,
    };
    assert_eq!(
        cm.derive_spend_cents([("freebie", &t)].into_iter(), 0, false),
        0,
        "a zero-rated model bills nothing regardless of volume"
    );
}

/// A PARTIAL card (some models priced, one absent): `model_unpriced` is true ONLY for the missing
/// model, and a mixed derivation prices the KNOWN model and contributes 0 for the missing one
/// (`rate_for` = None is skipped by the saturating add), so the total is exactly the known model's
/// spend — never a panic, never the missing model priced by a sibling's rate.
#[test]
fn partial_card_prices_known_models_and_zeroes_the_missing_one() {
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
        200,
        "only the priced model contributes; the missing one derives 0"
    );
}

/// The flat per-request fee is `price_per_request_cents * fee_requests`, added ONLY when
/// `include_request_fee`. Both the multiply and the add SATURATE at i64::MAX — an astronomically
/// large billable-request count can never wrap the fee negative (which `.max(0)` would then floor to
/// 0, billing an over-cap bucket as FREE). With the flag off, the fee contributes nothing.
#[test]
fn flat_fee_saturates_and_is_gated_by_the_flag() {
    let cm = resolve_card_fee(None, i64::MAX);
    let z = toks(0, 0);
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), u64::MAX, true),
        i64::MAX,
        "i64::MAX fee * u64::MAX requests must pin at i64::MAX, never wrap toward 0"
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), u64::MAX, false),
        0,
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
        0,
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
        150_000
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &z)].into_iter(), 5, true),
        15,
        "the same fee in cents is 15 — the micro projection is exactly 10_000x"
    );
    assert_eq!(
        cm.derive_spend_micros([("m", &z)].into_iter(), 5, false),
        0,
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
        100,
        "spend lands exactly on the integer cap value the budget check compares against"
    );
    assert_eq!(
        cm.derive_spend_cents([("m", &toks(1_010_000, 0))].into_iter(), 0, false),
        101,
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
    };
    let rn = crate::cost::RateNanos::from_cfg(&cfg);
    assert_eq!(
        rn.input, 0,
        "a non-finite (but positive) rate must clamp to 0, not saturate to u64::MAX"
    );
}

// ── The neutral usage_units one-pricer (1.6.0 M1) ───────────────────────────────────────────────
//
// `cost::price` is the ADDITIVE spine every plane's `Usage` will reach. These oracles pin its
// contract: the reserved four price byte-identically to the unchanged `cost_nanos`; opens price by
// opaque lookup; a present-but-unpriced open is omitted (never a silent $0); and the service-tier
// modifier keeps `CostBreakdown`'s exact-sum invariant (surcharge = a line, discount = folded rate).

use crate::cost::{price, ExtraRates, STANDARD_TIER_BP};
use crate::plane::cost::CostAmount;
use busbar_substrate::billing::Usage as NeutralUsage;

fn rate_2_5() -> crate::cost::RateNanos {
    // input 2 µ/tok → 2000 nano, output 5 µ/tok → 5000 nano.
    crate::cost::RateNanos::from_cfg(&RateEntryCfg {
        input_utok: 2.0,
        output_utok: 5.0,
        cache_read_utok: 0.0,
        cache_write_utok: 0.0,
    })
}

#[test]
fn price_reserved_four_is_byte_identical_to_cost_nanos() {
    let rate = rate_2_5();
    let tt = toks(3, 4); // 3*2000 + 4*5000 = 26_000 nano
    let usage = NeutralUsage {
        tokens: tt,
        ..Default::default()
    };
    let bd = price(&rate, &ExtraRates::new(), STANDARD_TIER_BP, &usage).expect("valid breakdown");
    assert_eq!(
        bd.total(),
        CostAmount(rate.cost_nanos(&tt)),
        "reserved-four pricing must equal the unchanged Copy cost_nanos"
    );
    // Two disjoint top-level lines (Prompt, Output); a zero tier is omitted.
    assert_eq!(
        bd.components().len(),
        2,
        "one line per nonzero reserved tier"
    );
}

#[test]
fn price_open_key_priced_via_opaque_extras_lookup() {
    let rate = rate_2_5();
    let mut extras = ExtraRates::new();
    extras.insert("audio".to_string(), 100); // 100 nano per audio unit
    let mut usage = NeutralUsage {
        tokens: toks(3, 0), // base 6000
        ..Default::default()
    };
    usage.usage_units.insert("audio".to_string(), 7); // 700 nano
    let bd = price(&rate, &extras, STANDARD_TIER_BP, &usage).expect("valid");
    assert_eq!(bd.total(), CostAmount(6000 + 700));
}

#[test]
fn price_present_but_unpriced_open_key_is_omitted_never_silent_zero() {
    let rate = rate_2_5();
    let mut usage = NeutralUsage {
        tokens: toks(3, 0), // base 6000
        ..Default::default()
    };
    usage.usage_units.insert("web_search".to_string(), 3); // no extras entry
    let bd = price(&rate, &ExtraRates::new(), STANDARD_TIER_BP, &usage).expect("valid");
    // The unpriced key adds NO component and NO amount (fail-closed to visible, not to $0).
    assert_eq!(bd.total(), CostAmount(6000));
    assert_eq!(bd.components().len(), 1, "only the priced Prompt line");
}

#[test]
fn price_surcharge_tier_is_a_top_level_line_preserving_exact_sum() {
    let rate = rate_2_5();
    let usage = NeutralUsage {
        tokens: toks(3, 4), // base 26_000
        ..Default::default()
    };
    let bd = price(&rate, &ExtraRates::new(), 12_000, &usage).expect("exact-sum holds");
    // surcharge = 26_000 * (12_000 - 10_000) / 10_000 = 5_200; total = 31_200.
    assert_eq!(bd.total(), CostAmount(31_200));
    assert!(
        bd.components()
            .iter()
            .any(|c| c.label == "service_tier" && c.amount == CostAmount(5_200)),
        "a surcharge tier adds a named top-level service_tier line"
    );
}

#[test]
fn price_discount_tier_folds_into_rate_with_no_named_line() {
    let rate = rate_2_5();
    let usage = NeutralUsage {
        tokens: toks(3, 4), // base 26_000
        ..Default::default()
    };
    let bd = price(&rate, &ExtraRates::new(), 8_000, &usage).expect("exact-sum holds");
    // each per-tier amount scaled ×0.8: Prompt 6000→4800, Output 20000→16000; total 20_800.
    assert_eq!(bd.total(), CostAmount(20_800));
    assert!(
        !bd.components().iter().any(|c| c.label == "service_tier"),
        "a discount folds into effective rate, never a named line"
    );
}
