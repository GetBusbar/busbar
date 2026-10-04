// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/hooks-ranking/src/lib.rs`.

use super::*;

fn cand(
    idx: usize,
    cost: Option<f64>,
    lat: Option<f64>,
    conc: usize,
    budget: Option<i64>,
) -> DecodedCandidate<'static> {
    // Most native tests don't exercise the `usage` signal; default `rate_headroom` to `None`.
    // The `usage` tests build candidates with `cand_rate` to set it explicitly.
    cand_rate(idx, cost, lat, conc, budget, None)
}

fn cand_rate(
    idx: usize,
    cost: Option<f64>,
    lat: Option<f64>,
    conc: usize,
    budget: Option<i64>,
    rate: Option<f64>,
) -> DecodedCandidate<'static> {
    DecodedCandidate {
        idx,
        model: "m".into(),
        provider: "p".into(),
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: cost,
        tags: Vec::new(),
        latency_ms: lat,
        available_concurrency: conc,
        budget_remaining: budget,
        rate_headroom: rate,
        signals: Default::default(),
    }
}

#[test]
fn weighted_native_abstains() {
    let d = rank("weighted", &[cand(0, None, None, 1, None)]).unwrap();
    assert_eq!(d, Verdict::Abstain);
}

#[test]
fn cheapest_orders_by_cost_demoting_unknown() {
    let cands = [
        cand(0, Some(15.0), None, 1, None),
        cand(1, Some(3.0), None, 1, None),
        cand(2, None, None, 1, None), // no cost -> demoted to last
    ];
    let d = rank("cheapest", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![1, 0, 2]));
}

#[test]
fn cheapest_all_unknown_abstains() {
    let cands = [cand(0, None, None, 1, None), cand(1, None, None, 1, None)];
    let d = rank("cheapest", &cands).unwrap();
    assert_eq!(d, Verdict::Abstain);
}

#[test]
fn fastest_orders_by_latency() {
    let cands = [
        cand(0, None, Some(120.0), 1, None),
        cand(1, None, Some(40.0), 1, None),
        cand(2, None, Some(80.0), 1, None),
    ];
    let d = rank("fastest", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![1, 2, 0]));
}

#[test]
fn least_busy_prefers_most_headroom() {
    let cands = [
        cand(0, None, None, 2, None),
        cand(1, None, None, 9, None),
        cand(2, None, None, 5, None),
    ];
    let d = rank("least_busy", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![1, 2, 0]));
}

/// `usage` ranks DESCENDING by `rate_headroom` (most rate-limit headroom first), demoting a
/// candidate with no headroom signal (`None`) to last but keeping it reachable.
#[test]
fn usage_orders_by_rate_headroom_demoting_unknown() {
    let cands = [
        cand_rate(0, None, None, 1, None, Some(0.10)), // nearly at the cap
        cand_rate(1, None, None, 1, None, Some(0.90)), // most headroom
        cand_rate(2, None, None, 1, None, None),       // no signal -> demoted to last
        cand_rate(3, None, None, 1, None, Some(0.50)),
    ];
    let d = rank("usage", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![1, 3, 0, 2]));
}

/// `usage` Abstains when EVERY candidate lacks the rate-headroom signal (no rate limit in play),
/// so selection falls through to the default SWRR.
#[test]
fn usage_all_unknown_abstains() {
    let cands = [
        cand_rate(0, None, None, 1, Some(100), None),
        cand_rate(1, None, None, 1, None, None),
        cand_rate(2, None, None, 1, Some(5000), None),
    ];
    let d = rank("usage", &cands).unwrap();
    assert_eq!(d, Verdict::Abstain);
}

/// Every word this plugin claims ranks; `weighted` is the explicit Abstaining form; anything else
/// is not a strategy of this plugin.
#[test]
fn rank_knows_its_words_and_no_others() {
    let one = [cand(0, Some(1.0), Some(1.0), 1, None)];
    assert!(rank("weighted", &one).is_some());
    for word in WORDS {
        assert!(rank(word, &one).is_some(), "{word}");
    }
    assert!(rank("nonexistent", &one).is_none());
}

/// The claimed words are exactly the four 1.5.5 strategy spellings.
#[test]
fn the_claimed_words_are_the_four_strategies() {
    assert_eq!(WORDS, ["cheapest", "fastest", "least_busy", "usage"]);
}

// ── edge cases: empty pool / single candidate / all-saturated / all-unknown ──────────────────

/// An empty candidate pool yields `Abstain` for every native (no candidates → no opinion → SWRR).
#[test]
fn all_natives_abstain_on_empty_pool() {
    let empty: [DecodedCandidate<'_>; 0] = [];
    for name in ["weighted", "cheapest", "fastest", "least_busy", "usage"] {
        let d = rank(name, &empty).unwrap();
        assert_eq!(
            d,
            Verdict::Abstain,
            "{name} must Abstain on an empty candidate pool"
        );
    }
}

/// A single candidate carrying the relevant signal ranks to a one-element `Prefer` for the
/// signal-bearing natives; the always-present `least_busy` likewise prefers it.
#[test]
fn single_candidate_prefers_it() {
    // cheapest: one candidate with a cost.
    let d = rank("cheapest", &[cand(0, Some(5.0), None, 1, None)]).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0]));
    // fastest: one candidate with a latency sample.
    let d = rank("fastest", &[cand(0, None, Some(30.0), 1, None)]).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0]));
    // least_busy: always has data.
    let d = rank("least_busy", &[cand(0, None, None, 3, None)]).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0]));
    // usage: one candidate with rate headroom.
    let d = rank("usage", &[cand_rate(0, None, None, 1, None, Some(0.5))]).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0]));
}

/// `least_busy` with EVERY candidate saturated (`available_concurrency == 0`) does NOT Abstain —
/// the concurrency signal is always present, so it ranks all lanes (all-zero → ordered by `idx`).
/// The ordered walk + breaker machinery downstream is what skips a truly-unusable lane; the native
/// only ORDERS and must never strand a lane by dropping it.
#[test]
fn least_busy_all_saturated_ranks_by_idx() {
    let cands = [
        cand(0, None, None, 0, None),
        cand(1, None, None, 0, None),
        cand(2, None, None, 0, None),
    ];
    let d = rank("least_busy", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0, 1, 2]));
}

/// `usage` with EVERY candidate at the cap (`rate_headroom == Some(0.0)`) still ranks (the signal
/// is present on all), tie-breaking by `idx` — it does NOT Abstain (Abstain is only for all-`None`).
#[test]
fn usage_all_at_cap_ranks_by_idx() {
    let cands = [
        cand_rate(0, None, None, 1, None, Some(0.0)),
        cand_rate(1, None, None, 1, None, Some(0.0)),
    ];
    let d = rank("usage", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![0, 1]));
}

/// `cheapest` with EVERY candidate at weight-0 / no declared cost Abstains (no cost signal at all
/// → fall through to SWRR). Weight is irrelevant to `cheapest`; it ranks on cost.
#[test]
fn cheapest_all_weight_zero_no_cost_abstains() {
    let mut a = cand(0, None, None, 1, None);
    a.weight = 0;
    let mut b = cand(1, None, None, 1, None);
    b.weight = 0;
    let d = rank("cheapest", &[a, b]).unwrap();
    assert_eq!(d, Verdict::Abstain);
}

/// `fastest` with EVERY candidate lacking a latency sample Abstains (mirrors `cheapest_all_unknown`).
#[test]
fn fastest_all_unknown_latency_abstains() {
    let cands = [cand(0, None, None, 1, None), cand(1, None, None, 1, None)];
    let d = rank("fastest", &cands).unwrap();
    assert_eq!(d, Verdict::Abstain);
}

/// `fastest` demotes a candidate with no latency sample to last (reachable, not dropped), exactly
/// as `cheapest` demotes a no-cost candidate. Mirrors `cheapest_orders_by_cost_demoting_unknown`.
#[test]
fn fastest_orders_by_latency_demoting_unknown() {
    let cands = [
        cand(0, None, Some(120.0), 1, None),
        cand(1, None, None, 1, None), // no latency sample -> demoted to last
        cand(2, None, Some(40.0), 1, None),
    ];
    let d = rank("fastest", &cands).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![2, 0, 1]));
}

/// A NaN cost is not a cheap candidate, an expensive one, or a tie — it is not ORDERABLE, and a
/// comparator that folds it to `Equal` is non-transitive, which is exactly the input `sort_by` is
/// allowed to panic on. It ranks as an ABSENT signal instead: demoted behind every real number,
/// still reachable, and in the same order every run.
#[test]
fn cheapest_treats_a_non_finite_key_as_an_absent_signal() {
    let cands = [
        cand(0, Some(1.0), None, 1, None),
        cand(1, Some(f64::NAN), None, 1, None),
        cand(2, Some(0.5), None, 1, None),
        cand(3, Some(f64::INFINITY), None, 1, None),
    ];
    let expected = Verdict::Prefer(vec![2, 0, 1, 3]);
    // Same answer every run: an order that depends on the comparator's accidents is not an order.
    for _ in 0..16 {
        let d = rank("cheapest", &cands).unwrap();
        assert_eq!(
            d, expected,
            "a non-finite key must rank as absent, every run"
        );
    }
}

/// The same ruling on the descending side, and the abstain boundary with it: when the only signals
/// present are unorderable there is no opinion to express, so the policy abstains to the default
/// SWRR rather than inventing a ranking out of NaNs.
#[test]
fn usage_ranks_a_nan_headroom_last_and_abstains_when_all_are_nan() {
    let ranked = [
        cand_rate(0, None, None, 1, None, Some(f64::NAN)),
        cand_rate(1, None, None, 1, None, Some(0.25)),
    ];
    let d = rank("usage", &ranked).unwrap();
    assert_eq!(d, Verdict::Prefer(vec![1, 0]));

    let all_nan = [
        cand_rate(0, None, None, 1, None, Some(f64::NAN)),
        cand_rate(1, None, None, 1, None, Some(f64::NAN)),
    ];
    let d = rank("usage", &all_nan).unwrap();
    assert_eq!(d, Verdict::Abstain);
}
