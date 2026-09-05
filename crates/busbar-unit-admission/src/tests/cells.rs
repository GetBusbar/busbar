// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The oracle cells for the door, as tables.
//!
//! The parity corpus asks for one cell per cap kind, per window kind including the all-time
//! window, scoped and unscoped, at every chain depth — plus the frozen group, the downgrade
//! cascade, the fee lookahead at a budget boundary, the failed requests that still consume their
//! slots, and the under-sized hold that tops up rather than refusing. They are written as tables
//! here so adding a window word or a cap kind adds a row, not a copied test.

use busbar_caps::{
    step::Admit, Accrual, AdmitToken, Hold, KernelSeal, PrincipalId, ReasonCode, UnitToken,
};

use super::*;
use crate::estimate::{ClassEstimate, Estimate};
use crate::{Admission, AdmissionUnit};

/// Every window word a cap can be written against.
const WINDOWS: [&str; 5] = [MINUTE, HOUR, DAY, MONTH, TOTAL];

/// Build a chain of `depth` nested groups with the cap on the OUTERMOST one, so the test walks the
/// whole chain before it reaches the bucket that blocks. The principal is bound to the innermost.
fn nested(depth: usize, cap: LimitCfg) -> (crate::chain::GroupTable, String) {
    assert!(depth >= 1);
    let mut cfgs: Vec<(String, GroupCfg)> = Vec::new();
    // `g0` is the outermost (it carries the cap); each next one names the previous as parent.
    for i in 0..depth {
        let parent = (i > 0).then(|| format!("g{}", i - 1));
        let limits = if i == 0 {
            vec![cap.clone()]
        } else {
            Vec::new()
        };
        cfgs.push((format!("g{i}"), group_cfg(parent.as_deref(), true, limits)));
    }
    let borrowed: Vec<(&str, GroupCfg)> =
        cfgs.iter().map(|(n, c)| (n.as_str(), c.clone())).collect();
    (table(&borrowed), "g0".to_string())
}

/// The cap kinds a windowed bucket can carry, and how to drive each one to its boundary.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Requests,
    Tokens,
    Budget,
}

impl Kind {
    fn metric(self) -> Metric {
        match self {
            Kind::Requests => Metric::Requests,
            Kind::Tokens => Metric::Tokens,
            Kind::Budget => Metric::Budget,
        }
    }

    fn limit_metric(self) -> LimitMetric {
        match self {
            Kind::Requests => LimitMetric::Requests,
            Kind::Tokens => LimitMetric::Tokens,
            Kind::Budget => LimitMetric::Budget,
        }
    }

    /// The cap amount, and the pricer the case is judged against.
    fn amount(self) -> u64 {
        match self {
            Kind::Requests => 2,
            Kind::Tokens => 100,
            Kind::Budget => 25,
        }
    }

    fn pricer(self) -> Pricer {
        match self {
            // A flat fee of 10 against a 25-cent cap: two admissions spend 20, the third would
            // reach 30. That is the fee LOOKAHEAD doing the work — the third is refused for spend
            // it has not made yet.
            Kind::Budget => no_card(10),
            _ => no_card(0),
        }
    }
}

/// Every cap kind, every window kind including the all-time one, scoped and unscoped, at three
/// chain depths: the bucket that blocks is named exactly, and the retry hint is present for a
/// rolling window and absent for the all-time one.
#[test]
fn cap_kind_by_window_by_scope_by_depth() {
    let now = 1_700_000_000;
    for kind in [Kind::Requests, Kind::Tokens, Kind::Budget] {
        for window in WINDOWS {
            for scope in [None, Some("frontier")] {
                for depth in 1..=3 {
                    let mut cap = match scope {
                        None => limit(kind.limit_metric(), kind.amount(), Some(window)),
                        Some(pool) => pooled(kind.limit_metric(), kind.amount(), window, pool),
                    };
                    cap.per = Some(window);
                    let (t, blocking) = nested(depth, cap);
                    let c = chain(&t, "vk_cell", Some(&format!("g{}", depth - 1)));
                    let d = door();
                    let p = kind.pricer();
                    let pool = scope.unwrap_or("frontier");
                    let case = format!(
                        "{:?} per {window} scope={scope:?} depth={depth}",
                        kind.metric()
                    );

                    match kind {
                        Kind::Requests | Kind::Budget => {
                            for i in 0..2 {
                                d.try_admit(&p, &c, pool, now)
                                    .unwrap_or_else(|e| panic!("{case}: admit {i} refused: {e:?}"));
                            }
                        }
                        Kind::Tokens => {
                            d.try_admit(&p, &c, pool, now)
                                .unwrap_or_else(|e| panic!("{case}: first admit refused: {e:?}"));
                            d.record_usage(&c, pool, "m", &toks(100, 0), now);
                        }
                    }
                    let err = d
                        .try_admit(&p, &c, pool, now)
                        .expect_err(&format!("{case}: the boundary must block"));
                    assert_blocked(err, &blocking, kind.metric(), Some(window), window != TOTAL);
                }
            }
        }
    }
}

/// Each token tier caps its OWN counter and nothing else. The table walks all four: the tier under
/// cap is filled to its boundary and blocks naming itself, while every other tier is filled far
/// past that boundary and never trips it.
#[test]
fn each_token_tier_caps_only_itself() {
    let now = 1_700_000_000;
    let p = no_card(0);
    let cases: [(LimitMetric, Metric, [u64; 4]); 4] = [
        (LimitMetric::Tokens, Metric::Tokens, [50, 0, 0, 0]),
        (LimitMetric::TokensInput, Metric::TokensInput, [50, 0, 0, 0]),
        (
            LimitMetric::TokensOutput,
            Metric::TokensOutput,
            [0, 50, 0, 0],
        ),
        (
            LimitMetric::TokensCacheRead,
            Metric::TokensCacheRead,
            [0, 0, 50, 0],
        ),
    ];
    for (limit_metric, metric, at_cap) in cases {
        let d = door();
        let t = table(&[(
            "g",
            group_cfg(None, true, vec![limit(limit_metric, 50, Some(HOUR))]),
        )]);
        let c = chain(&t, "vk_tier_cell", Some("g"));
        d.try_admit(&p, &c, "", now).expect("nothing ledgered");
        // Every OTHER tier, far past the cap. The aggregate cap is the exception by definition:
        // it sums every tier, so there is no "other tier" that leaves it alone.
        if !matches!(limit_metric, LimitMetric::Tokens) {
            let others: Vec<u64> = at_cap
                .iter()
                .map(|v| if *v == 0 { 10_000 } else { 0 })
                .collect();
            d.record_usage(
                &c,
                "",
                "m",
                &toks_tiers(others[0], others[1], others[2], others[3]),
                now,
            );
            d.try_admit(&p, &c, "", now)
                .unwrap_or_else(|e| panic!("{metric:?}: another tier tripped it: {e:?}"));
        }
        d.record_usage(
            &c,
            "",
            "m",
            &toks_tiers(at_cap[0], at_cap[1], at_cap[2], at_cap[3]),
            now,
        );
        assert_blocked(
            d.try_admit(&p, &c, "", now).unwrap_err(),
            "g",
            metric,
            Some(HOUR),
            true,
        );
    }
}

/// The instantaneous gauge, at every chain depth. It carries no window and no retry hint, and one
/// lease is taken per concurrent-capped GROUP — not per bucket, so a group with a gauge and two
/// windowed caps still takes one.
#[test]
fn concurrent_cap_by_depth() {
    let now = 1_700_000_000;
    for depth in 1..=3 {
        let (t, blocking) = nested(depth, limit(LimitMetric::Concurrent, 2, None));
        let c = chain(&t, "vk_conc", Some(&format!("g{}", depth - 1)));
        let d = door();
        let p = no_card(0);
        let h1 = d.try_admit(&p, &c, "frontier", now).expect("1st in flight");
        let h2 = d.try_admit(&p, &c, "frontier", now).expect("2nd in flight");
        assert_eq!(h1.held(), 1, "one lease per capped group, depth {depth}");
        assert_blocked(
            d.try_admit(&p, &c, "frontier", now).unwrap_err(),
            &blocking,
            Metric::Concurrent,
            None,
            false,
        );
        drop(h1);
        drop(h2);
        assert_eq!(d.gauges().in_flight(&blocking), 0);
    }
}

/// A group carrying a gauge AND two windowed caps takes ONE lease.
#[test]
fn one_lease_per_group_not_per_bucket() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Concurrent, 4, None),
                limit(LimitMetric::Requests, 100, Some(MINUTE)),
                limit(LimitMetric::Requests, 100, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_one", Some("g"));
    let grant = d.try_admit(&p, &c, "", 1_700_000_000).expect("admits");
    assert_eq!(grant.held(), 1);
    assert_eq!(d.gauges().in_flight("g"), 1);
}

/// A frozen group refuses at every depth, before a gauge moves or a counter changes.
#[test]
fn frozen_group_refuses_and_charges_nothing_at_every_depth() {
    let now = 1_700_000_000;
    let p = no_card(0);
    for depth in 1..=3 {
        let mut cfgs: Vec<(String, GroupCfg)> = Vec::new();
        for i in 0..depth {
            let parent = (i > 0).then(|| format!("g{}", i - 1));
            let mut g = group_cfg(
                parent.as_deref(),
                i != 0, // the OUTERMOST group is the frozen one
                vec![limit(LimitMetric::Concurrent, 8, None)],
            );
            g.limits
                .push(limit(LimitMetric::Requests, 100, Some(MINUTE)));
            cfgs.push((format!("g{i}"), g));
        }
        let borrowed: Vec<(&str, GroupCfg)> =
            cfgs.iter().map(|(n, c)| (n.as_str(), c.clone())).collect();
        let t = table(&borrowed);
        let c = chain(&t, "vk_frz", Some(&format!("g{}", depth - 1)));
        let d = door();
        match d.try_admit(&p, &c, "", now).unwrap_err() {
            Blocked::Disabled(name) => assert_eq!(name, "g0"),
            other => panic!("expected Disabled at depth {depth}, got {other:?}"),
        }
        // Nothing moved: no gauge raised, no counter charged, on any group in the chain.
        for i in 0..depth {
            assert_eq!(d.gauges().in_flight(&format!("g{i}")), 0);
            let (requests, _, _) = bucket_usage(&d, &p, &format!("group:g{i}@minute"), MINUTE, now);
            assert_eq!(requests, 0, "a frozen chain mutates nothing");
        }
    }
}

/// The downgrade cascade, driven the way the caller drives it: a budget block that names a
/// downgrade target is re-attempted against that pool, and the charge follows the pool actually
/// attempted. A pool that was only passed over — never attempted — draws nothing.
#[test]
fn downgrade_cascade_charges_the_attempted_pool_only() {
    let d = door();
    let p = no_card(10);
    let mut frontier = pooled(LimitMetric::Budget, 25, DAY, "frontier");
    frontier.downgrade_to = Some("middle".to_string());
    let mut middle = pooled(LimitMetric::Budget, 25, DAY, "middle");
    middle.downgrade_to = Some("value".to_string());
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![
                frontier,
                middle,
                pooled(LimitMetric::Budget, 1_000, DAY, "value"),
            ],
        ),
    )]);
    let c = chain(&t, "vk_casc", Some("team"));
    let now = 1_700_000_000;
    // Fill frontier and middle to their boundaries.
    for pool in ["frontier", "middle"] {
        d.try_admit(&p, &c, pool, now).expect("1st");
        d.try_admit(&p, &c, pool, now).expect("2nd");
    }
    // Now one more request through frontier cascades: frontier blocks naming middle, middle blocks
    // naming value, value admits.
    let mut attempt = "frontier".to_string();
    let mut hops = Vec::new();
    let grant = loop {
        match d.try_admit(&p, &c, &attempt, now) {
            Ok(g) => break g,
            Err(Blocked::Limit {
                downgrade_to: Some(to),
                ..
            }) => {
                hops.push(attempt.clone());
                attempt = to;
            }
            Err(other) => panic!("cascade should have reached a pool with headroom: {other:?}"),
        }
    };
    drop(grant);
    assert_eq!(hops, vec!["frontier".to_string(), "middle".to_string()]);
    assert_eq!(attempt, "value", "the cascade ended at the reachable pool");
    // The charge landed on the pool ATTEMPTED, and only there: the two exhausted pools still hold
    // exactly the two admissions each that filled them.
    for pool in ["frontier", "middle"] {
        let (requests, _, _) =
            bucket_usage(&d, &p, &format!("group:team@day#pool:{pool}"), DAY, now);
        assert_eq!(requests, 2, "a hop that only blocked drew nothing more");
    }
    let (value_requests, _, _) = bucket_usage(&d, &p, "group:team@day#pool:value", DAY, now);
    assert_eq!(value_requests, 1, "the attempted pool is the one charged");
}

/// A scoped cap on a pool the request never routed through stays untouched — the pool predicate is
/// equality on the effective pool name and nothing else.
#[test]
fn scoped_cap_on_a_non_selected_pool_is_unchanged() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![pooled(LimitMetric::Requests, 1, DAY, "frontier")],
        ),
    )]);
    let c = chain(&t, "vk_ns", Some("team"));
    let now = 1_700_000_000;
    for _ in 0..5 {
        d.try_admit(&p, &c, "value", now).expect("another pool");
    }
    let (requests, _, _) = bucket_usage(&d, &p, "group:team@day#pool:frontier", DAY, now);
    assert_eq!(requests, 0, "the unselected pool's bucket never moved");
    // And frontier's own cap of 1 is still whole.
    d.try_admit(&p, &c, "frontier", now).expect("frontier 1st");
    assert_blocked(
        d.try_admit(&p, &c, "frontier", now).unwrap_err(),
        "team",
        Metric::Requests,
        Some(DAY),
        true,
    );
}

/// The fee lookahead AT the boundary: a bucket whose derived spend is exactly one fee short of the
/// cap still refuses, because the prospective post-charge spend is what is compared. The cap is
/// 30, the fee 10, so the fourth request would reach exactly 40 — and the third, at 30, is already
/// at the cap.
#[test]
fn fee_lookahead_at_a_budget_boundary() {
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 30, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_look", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("spend 0, +10 <= 30");
    d.try_admit(&p, &c, "", now).expect("spend 10, +10 <= 30");
    d.try_admit(&p, &c, "", now).expect("spend 20, +10 <= 30");
    // Spend is now exactly 30: at the cap, so it blocks on the at-or-over arm without the
    // lookahead ever being needed.
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Budget,
        Some(DAY),
        true,
    );

    // And the lookahead alone: a cap of 25 with a fee of 10 blocks the third at a spend of 20,
    // which is UNDER the cap. Nothing has been spent past 25; the refusal is for spend the request
    // would make.
    let d2 = door();
    let t2 = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 25, Some(DAY))]),
    )]);
    let c2 = chain(&t2, "vk_look", Some("g"));
    d2.try_admit(&p, &c2, "", now).expect("1st");
    d2.try_admit(&p, &c2, "", now).expect("2nd");
    let (_, _, spend) = bucket_usage(&d2, &p, "group:g@day", DAY, now);
    assert_eq!(spend, 20, "under the cap");
    assert_blocked(
        d2.try_admit(&p, &c2, "", now).unwrap_err(),
        "g",
        Metric::Budget,
        Some(DAY),
        true,
    );
}

/// N failed requests consume N slots and bill no fee. The requests counter is never refunded, so
/// failures cannot be used to escape a requests cap; the billable counter is, so the fee bills
/// successes only.
#[test]
fn n_failed_requests_consume_n_slots_and_bill_no_fee() {
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 5, Some(DAY)),
                limit(LimitMetric::Budget, 10_000, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_fail", Some("g"));
    let now = 1_700_000_000;
    for _ in 0..5 {
        d.try_admit(&p, &c, "", now).expect("admits");
        d.refund_request(&c, "", now); // every one of them failed
    }
    let (requests, _, spend) = bucket_usage(&d, &p, "group:g@day", DAY, now);
    assert_eq!(requests, 5, "five slots consumed");
    assert_eq!(spend, 0, "no fee billed on any of them");
    // And the cap is spent: a sixth request is refused even though every prior one failed.
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Requests,
        Some(DAY),
        true,
    );
    // The attribution bucket counted them too, uncapped and unable to block.
    let (attributed, _, _) = bucket_usage(&d, &p, "vk_fail", TOTAL, now);
    assert_eq!(attributed, 5);
}

// ── the sealed shape, and the hold it carries ───────────────────────────────────────────────────

/// An estimate of `quantity` at `price` nano-units, with no fee.
fn estimate(quantity: u64, price: u64) -> Estimate {
    Estimate {
        per_class: vec![ClassEstimate {
            class: "tokens_in".to_string(),
            quantity,
            max_unit_price_nanos: price,
        }],
        fee_nanos: 0,
    }
}

/// The door's answer through the sealed shape: a pass carries the unit's own hold, sized from the
/// estimate against the chain's tier.
#[test]
fn admit_yields_a_hold_sized_from_the_estimate() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit_token: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let unit_token: UnitToken<Admit> = UnitToken::mint(&seal);
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_hold", Some("g"));
    let now = 1_700_000_000;
    let principal = PrincipalId::new("vk_hold");
    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    let decision = unit.admit(
        &estimate(1_000, 7),
        &principal,
        &c,
        &admit_token,
        &unit_token,
    );
    let admission = decision.into_result(&seal).expect("admitted");
    match admission {
        busbar_caps::Admission::Own(hold) => {
            assert_eq!(hold.reserved(), 7_000, "quantity x price, tier 1.0");
            assert_eq!(hold.principal().as_str(), "vk_hold");
            std::mem::forget(hold); // the ledger settles it; nothing to settle in a unit test
        }
        other => panic!("expected the unit's own hold, got {other:?}"),
    }
    assert!(unit.take_grant().is_some(), "the grant comes back");

    // The refusal carries the closed reason, and the blocking bucket rides alongside it because
    // the reason code cannot name a bucket.
    let mut unit2 = AdmissionUnit::new(&d, &p, "", now);
    let refused = unit2.admit(
        &estimate(1_000, 7),
        &principal,
        &c,
        &admit_token,
        &unit_token,
    );
    let refusal = refused.into_result(&seal).expect_err("over the cap");
    assert_eq!(refusal.reason(), ReasonCode::RateLimited);
    assert!(refusal.retry_after_secs().is_some());
    assert_blocked(
        unit2.blocked().cloned().expect("a blocking bucket"),
        "g",
        Metric::Requests,
        Some(MINUTE),
        true,
    );
}

/// A tier other than one times the multiplier scales the hold once over the whole sum, rounded up,
/// and does not touch the decision.
#[test]
fn tier_scales_the_hold_and_not_the_decision() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit_token: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let unit_token: UnitToken<Admit> = UnitToken::mint(&seal);
    let d = door();
    let p = no_card(0);
    let mut g = group_cfg(None, true, vec![limit(LimitMetric::Requests, 4, Some(DAY))]);
    g.tier_bp = 15_000; // 1.5x
    let t = table(&[("g", g)]);
    let c = chain(&t, "vk_tier", Some("g"));
    assert_eq!(c.tier_bp(), 15_000);
    let principal = PrincipalId::new("vk_tier");
    let mut unit = AdmissionUnit::new(&d, &p, "", 1_700_000_000);
    let decision = unit.admit(&estimate(3, 1), &principal, &c, &admit_token, &unit_token);
    match decision.into_result(&seal).expect("admitted") {
        busbar_caps::Admission::Own(hold) => {
            // 3 x 1 = 3 pre-tier; 3 x 15000 / 10000 = 4.5, rounded UP once.
            assert_eq!(hold.reserved(), 5);
            std::mem::forget(hold);
        }
        other => panic!("expected a hold, got {other:?}"),
    }
}

/// A unit whose estimate is zero gets no hold at all, which is why a zero-priced unit can run when
/// everything else is at its ceiling.
#[test]
fn a_zero_estimate_holds_nothing() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit_token: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let unit_token: UnitToken<Admit> = UnitToken::mint(&seal);
    let d = door();
    let p = no_card(0);
    let t = table(&[("g", group_cfg(None, true, vec![]))]);
    let c = chain(&t, "vk_zero", Some("g"));
    let principal = PrincipalId::new("vk_zero");
    let mut unit = AdmissionUnit::new(&d, &p, "", 1_700_000_000);
    let decision = unit.admit(&Estimate::zero(), &principal, &c, &admit_token, &unit_token);
    match decision.into_result(&seal).expect("admitted") {
        busbar_caps::Admission::ZeroHold => {}
        other => panic!("expected no hold, got {other:?}"),
    }
}

/// An UNDER-SIZED hold tops up and never refuses. The hold is accounting: it reports that the
/// reservation ran out, the unit draws more, and the request carries on. Nothing here can turn a
/// unit the door admitted into a refusal.
#[test]
fn an_undersized_hold_tops_up_and_never_refuses() {
    let seal = KernelSeal::acquire_for_kernel();
    let admit_token: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let principal = PrincipalId::new("vk_top");
    let mut hold = Hold::open(&admit_token, principal, 100);
    // Spend inside the reservation.
    assert_eq!(hold.accrue(60), Accrual::Within { remaining: 40 });
    // Spend past it: the hold says how far past, and says nothing about refusing.
    match hold.accrue(60) {
        Accrual::Exhausted { shortfall } => assert_eq!(shortfall, 20),
        other => panic!("expected the reservation to be used up, got {other:?}"),
    }
    // One top-up from the slice, and the unit continues.
    assert_eq!(hold.top_up(50), 30);
    assert_eq!(hold.accrue(10), Accrual::Within { remaining: 20 });
    // If the top-up had been refused the unit would still finish and post the excess.
    hold.record_overdraft(20);
    assert_eq!(hold.overdraft(), 20);
    std::mem::forget(hold);
}

/// The chain's own boot rule: one tier per chain. A mixed chain is refused at build time, so no
/// request ever walks one.
#[test]
fn a_mixed_tier_chain_is_a_boot_refusal() {
    let mut parent = group_cfg(None, true, vec![]);
    parent.tier_bp = 10_000;
    let mut child = group_cfg(Some("parent"), true, vec![]);
    child.tier_bp = 15_000;
    let t = table(&[("parent", parent), ("child", child)]);
    let err = t.validate_tiers().expect_err("mixed tiers are refused");
    match err {
        crate::chain::ChainError::TierMismatch {
            expected, found, ..
        } => {
            assert_eq!(expected, 15_000);
            assert_eq!(found, 10_000);
        }
    }
}
