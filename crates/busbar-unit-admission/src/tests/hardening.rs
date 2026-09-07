// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams the ported suite reaches through but never looks at.
//!
//! Every case here was written because a deliberate change to production code left the whole suite
//! green: a read-back accessor answering the same thing for every request, the refusal vocabulary
//! saying a different word, the cycle clamp on the chain walk never counting. None of them is about
//! the decision itself — the ported cases cover that thoroughly — and all of them are about what the
//! decision HANDS BACK, which is what a caller acts on.

use busbar_caps::{step::Admit, AdmitToken, KernelSeal, PrincipalId, UnitToken};

use super::*;
use crate::chain::{ChainBucket, GroupBucket, GroupRuntime, GroupTable, STANDARD_TIER_BP};
use crate::{Admission as _, AdmissionUnit, Estimate};

/// The three tokens the sealed shape is lent, minted once per case.
fn tokens() -> (KernelSeal, AdmitToken<Admit>, UnitToken<Admit>) {
    let seal = KernelSeal::acquire_for_kernel();
    let admit = AdmitToken::mint(&seal);
    let unit = UnitToken::mint(&seal);
    (seal, admit, unit)
}

/// A group with a concurrency cap and the interned name the composition root would have handed the
/// door, so the read-back seam has something to read back.
fn leased(name: &str, lease_id: &'static str, cap: u64, parent: Option<usize>) -> GroupRuntime {
    GroupRuntime {
        name: name.to_string(),
        lease_id: Some(lease_id),
        enabled: true,
        concurrent_cap: Some(cap),
        tier_bp: STANDARD_TIER_BP,
        buckets: Vec::new(),
        parent,
    }
}

// ---------------------------------------------------------------------------------------------
// What the unit hands back after the decision.
// ---------------------------------------------------------------------------------------------

/// The grant the unit hands back is THE grant the decision took, and a refused unit has none.
///
/// The suite asserted only that a yes hands something back. That is satisfied by handing back a
/// fresh empty grant, and the two failures that hides are the two that matter: a refused unit would
/// hand back a grant it never earned, and — because the real grant is then never moved out of the
/// unit and never dropped by the caller — the gauge it raised would come down only when the unit
/// itself is dropped, or not at all if the unit outlives the request. The gauge is the one piece of
/// door state a leak is permanent in: it is never reset, so a leaked count caps the group lower for
/// the rest of the process's life.
#[test]
fn the_grant_handed_back_is_the_one_the_decision_took_and_a_refusal_has_none() {
    let (seal, admit_token, unit_token) = tokens();
    let d = door();
    let p = no_card(0);
    let t = GroupTable::new(vec![leased("tenant", "tenant", 8, None)]);
    let c = chain(&t, "vk_g", Some("tenant"));
    let now = 1_700_000_000;

    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    let decision = unit.admit(
        &Estimate::zero(),
        &PrincipalId::new("vk_g"),
        &c,
        &admit_token,
        &unit_token,
    );
    std::mem::forget(decision.into_result(&seal).expect("admitted"));
    assert_eq!(d.gauges().in_flight("tenant"), 1, "the gauge is raised");

    let grant = unit.take_grant().expect("the grant comes back");
    assert_eq!(
        grant.held(),
        1,
        "the grant handed back holds the gauge the decision raised"
    );
    assert!(
        unit.take_grant().is_none(),
        "it was MOVED out; the unit no longer holds it"
    );
    drop(grant);
    assert_eq!(
        d.gauges().in_flight("tenant"),
        0,
        "dropping the handed-back grant releases the gauge — the leak this seam exists to prevent"
    );

    // A refusal counted nothing, so it has nothing to hand back.
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 0, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_r", Some("g"));
    let mut refused = AdmissionUnit::new(&d, &p, "", now);
    let decision = refused.admit(
        &Estimate::zero(),
        &PrincipalId::new("vk_r"),
        &c,
        &admit_token,
        &unit_token,
    );
    decision.into_result(&seal).expect_err("over the cap");
    assert!(
        refused.take_grant().is_none(),
        "a refused unit was never admitted, so it holds no grant at all"
    );
}

/// The unit names the groups the decision counted it against, and a refused unit names none.
///
/// The kernel writes these onto the unit's slot so the sweep can release a lease for a task that
/// has gone away — the one thing the grant's own RAII release cannot do. A seam that answered the
/// same thing for every unit would have the sweep releasing leases the unit never took, or leaving
/// the ones it did.
#[test]
fn the_unit_names_the_groups_it_was_counted_against() {
    let (seal, admit_token, unit_token) = tokens();
    let d = door();
    let p = no_card(0);
    let t = GroupTable::new(vec![
        leased("tenant", "tenant", 8, None),
        leased("team", "team", 4, Some(0)),
    ]);
    let c = chain(&t, "vk_g", Some("team"));
    let now = 1_700_000_000;

    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    assert!(
        unit.group_leases().is_empty(),
        "before the decision, nothing has been counted"
    );
    let decision = unit.admit(
        &Estimate::zero(),
        &PrincipalId::new("vk_g"),
        &c,
        &admit_token,
        &unit_token,
    );
    std::mem::forget(decision.into_result(&seal).expect("admitted"));
    assert_eq!(
        unit.group_leases(),
        ["team", "tenant"],
        "every capped group, innermost first — the chain's own order"
    );

    // A frozen group refuses before a gauge moves, so the unit counted nothing and names nothing.
    let frozen = table(&[("g", group_cfg(None, false, Vec::new()))]);
    let fc = chain(&frozen, "vk_f", Some("g"));
    let mut refused = AdmissionUnit::new(&d, &p, "", now);
    let decision = refused.admit(
        &Estimate::zero(),
        &PrincipalId::new("vk_f"),
        &fc,
        &admit_token,
        &unit_token,
    );
    decision.into_result(&seal).expect_err("frozen");
    assert!(
        refused.group_leases().is_empty(),
        "a refused unit counted nothing, so it names nothing"
    );
}

/// The unit's refund reaches the door's refund — it is not a no-op.
///
/// The refund returns the FLAT FEE for a request that produced no usable result, by decrementing the
/// billable count the budget cap derives spend from. A refund that quietly did nothing would leave
/// the fee for every failed request on the cell for the rest of the window, and a principal whose
/// requests all fail would be blocked on a budget it never actually spent.
#[test]
fn the_units_refund_returns_the_fee_and_leaves_the_request_slot_consumed() {
    let (seal, admit_token, unit_token) = tokens();
    let d = door();
    // A 25-cent flat fee and no token rates, so the derived spend is the fee times the billable
    // count and nothing else.
    let p = card(25, &[]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 10, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_rf", Some("g"));
    let now = 1_700_000_000;

    let mut unit = AdmissionUnit::new(&d, &p, "", now);
    let decision = unit.admit(
        &Estimate::zero(),
        &PrincipalId::new("vk_rf"),
        &c,
        &admit_token,
        &unit_token,
    );
    std::mem::forget(decision.into_result(&seal).expect("admitted"));

    let (requests, _, spend) = bucket_usage(&d, &p, "group:g@minute", MINUTE, now);
    assert_eq!(requests, 1);
    assert_eq!(spend, 25, "one request, one fee");

    unit.refund(&c);

    let (requests, _, spend) = bucket_usage(&d, &p, "group:g@minute", MINUTE, now);
    assert_eq!(
        spend, 0,
        "the fee came back — the refund is not a no-op at the unit seam"
    );
    assert_eq!(
        requests, 1,
        "the request slot stays consumed: a caller must not escape a requests cap by failing"
    );
}

// ---------------------------------------------------------------------------------------------
// The refusal's own vocabulary.
// ---------------------------------------------------------------------------------------------

/// Each metric's operator-facing word, pinned.
///
/// The word IS the wire: it is what the refusal prints and what an operator greps their logs for.
/// The suite matched on the `Metric` variants and never on the strings, so every metric could have
/// reported the same word — or no word — without a single case failing.
#[test]
fn every_metric_prints_its_own_operator_facing_word() {
    let table = [
        (Metric::Requests, "requests"),
        (Metric::Tokens, "tokens"),
        (Metric::TokensInput, "tokens_input"),
        (Metric::TokensOutput, "tokens_output"),
        (Metric::TokensCacheRead, "tokens_cache_read"),
        (Metric::TokensCacheWrite, "tokens_cache_write"),
        (Metric::Budget, "budget"),
        (Metric::Concurrent, "concurrent"),
    ];
    for (metric, word) in table {
        assert_eq!(metric.as_str(), word, "{metric:?}");
        assert!(!word.is_empty());
    }
    // And no two metrics share a word: a refusal names exactly one counter.
    for (a, wa) in table {
        for (b, wb) in table {
            assert_eq!(wa == wb, a == b, "{a:?} and {b:?} must be told apart");
        }
    }
}

/// The spend cap is the only quota, and the rest are rate limits.
///
/// One dialect answers an over-quota block with a different status than a rate-limit block, and it
/// keys off exactly this. Read only in the negative — "these are not quotas" — a constant `false`
/// satisfies every existing case, and every over-budget caller silently starts getting the
/// rate-limit status instead.
#[test]
fn the_spend_cap_is_the_only_quota() {
    assert!(Metric::Budget.is_quota(), "the spend cap is a quota");
    for m in [
        Metric::Requests,
        Metric::Tokens,
        Metric::TokensInput,
        Metric::TokensOutput,
        Metric::TokensCacheRead,
        Metric::TokensCacheWrite,
        Metric::Concurrent,
    ] {
        assert!(!m.is_quota(), "{m:?} is a rate limit, not a quota");
    }
}

/// The grant's `Debug` reports how many gauges it holds.
///
/// It is hand-written — the gauges are `Arc`s with nothing readable in them — precisely so an
/// operator's log says how many leases a unit is holding. A rendering that produced nothing would
/// take that with it.
#[test]
fn the_grants_debug_rendering_says_how_many_gauges_it_holds() {
    let d = door();
    let p = no_card(0);
    let t = GroupTable::new(vec![
        leased("tenant", "tenant", 8, None),
        leased("team", "team", 4, Some(0)),
    ]);
    let c = chain(&t, "vk_g", Some("team"));
    let grant = d.try_admit(&p, &c, "", 0).expect("admitted");
    let rendered = format!("{grant:?}");
    assert!(rendered.contains("AdmitGrant"), "{rendered}");
    assert!(rendered.contains("gauges"), "{rendered}");
    assert!(rendered.contains('2'), "{rendered}");
}

// ---------------------------------------------------------------------------------------------
// The chain's own shape, read back.
// ---------------------------------------------------------------------------------------------

/// A bucket is uncapped exactly when it carries NO cap of any kind — including the spend cap.
///
/// This is the predicate the check pass skips a bucket on, and the skip is what makes the
/// `expect("only group buckets carry caps")` below it safe: a bucket that reached the cap tests is a
/// bucket with a cap, and only a group bucket has one. A predicate that answered "capped" for the
/// attribution bucket would walk it into the tests it has no name to be refused under; one that
/// answered "uncapped" for a spend-capped bucket would skip the budget cap entirely, and the door
/// would stop enforcing the one limit that costs money.
#[test]
fn a_bucket_is_uncapped_only_when_it_carries_no_cap_at_all() {
    let attribution = ChainBucket::attribution("vk_a");
    assert!(
        attribution.is_uncapped(),
        "the principal's own bucket carries nothing and never blocks"
    );

    // Every cap in turn, on its own, makes the bucket capped — the spend cap included, which is the
    // one an enumeration written from the token metrics alone would leave out.
    /// A named cap-setter: the word the cap is known by, and the field it sets.
    type SetCap = (&'static str, fn(&mut ChainBucket));
    let each: [SetCap; 7] = [
        ("requests", |b| b.requests_cap = Some(1)),
        ("tokens", |b| b.tokens_cap = Some(1)),
        ("tokens_input", |b| b.tokens_input_cap = Some(1)),
        ("tokens_output", |b| b.tokens_output_cap = Some(1)),
        ("tokens_cache_read", |b| b.tokens_cache_read_cap = Some(1)),
        ("tokens_cache_write", |b| b.tokens_cache_write_cap = Some(1)),
        ("budget", |b| b.budget_cap = Some(1)),
    ];
    for (word, set) in each {
        let mut b = ChainBucket::attribution("vk_a");
        set(&mut b);
        assert!(
            !b.is_uncapped(),
            "a bucket carrying a {word} cap is not uncapped"
        );
    }
}

/// The chain reports the buckets and the groups it was resolved with.
///
/// Both are read-back accessors with no caller inside this crate, so nothing here fails if either
/// starts answering "nothing at all" — and a caller reading the chain back to render it, or to
/// reconcile what it charged, would see an empty deployment.
#[test]
fn the_chain_reports_the_buckets_and_groups_it_was_resolved_with() {
    let t = table(&[
        (
            "tenant",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
            ),
        ),
        (
            "team",
            group_cfg(
                Some("tenant"),
                true,
                vec![limit(LimitMetric::Tokens, 500, Some(DAY))],
            ),
        ),
    ]);
    let c = chain(&t, "vk_c", Some("team"));

    let ids: Vec<&str> = c.buckets().iter().map(|b| b.bucket_id.as_str()).collect();
    assert_eq!(
        ids,
        ["vk_c", "group:team@day", "group:tenant@minute"],
        "the attribution bucket, then each ancestor's, innermost first"
    );
    let names: Vec<&str> = c.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["team", "tenant"], "groups innermost first");

    // And the table's own read-back, which likewise has no caller in this crate.
    let table_names: Vec<&str> = t.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(table_names, ["team", "tenant"]);
}

/// A parent CYCLE in the group table ends both walks instead of running forever.
///
/// The clamp is a distinct-node counter: a walk that has visited as many nodes as the table holds
/// must have revisited one. A cycle is a validation error and should never reach here, but "should
/// never" is not a guarantee the walk gets to assume — a table assembled from a config the resolver
/// did not reject would hang the whole node on the request path, holding the cell lock, with no
/// error and no way out. Neither walk was ever handed a cyclic table, so the counter that makes the
/// clamp work was free to never count.
#[test]
fn a_cyclic_group_table_clamps_both_walks_instead_of_looping() {
    // Two groups, each the other's parent.
    let cyclic = GroupTable::new(vec![
        GroupRuntime {
            name: "a".to_string(),
            lease_id: None,
            enabled: true,
            concurrent_cap: None,
            tier_bp: STANDARD_TIER_BP,
            buckets: vec![GroupBucket::new("group:a@minute".to_string(), MINUTE)],
            parent: Some(1),
        },
        GroupRuntime {
            name: "b".to_string(),
            lease_id: None,
            enabled: true,
            concurrent_cap: None,
            tier_bp: STANDARD_TIER_BP,
            buckets: vec![GroupBucket::new("group:b@minute".to_string(), MINUTE)],
            parent: Some(0),
        },
    ]);

    // The chain walk terminates, and visits each node at most once.
    let c = cyclic
        .chain_for("vk_cyc", Some("a"))
        .expect("group resolves");
    let names: Vec<&str> = c.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(
        names,
        ["a", "b"],
        "the walk stops at the table's own size rather than revisiting"
    );

    // And so does the boot-time tier check, which walks the same edges.
    assert!(
        cyclic.validate_tiers().is_ok(),
        "one tier throughout, and the walk that checks it terminates"
    );

    // A dangling parent index ends the walk too, rather than ending the process.
    let dangling = GroupTable::new(vec![GroupRuntime {
        name: "a".to_string(),
        lease_id: None,
        enabled: true,
        concurrent_cap: None,
        tier_bp: STANDARD_TIER_BP,
        buckets: Vec::new(),
        parent: Some(99),
    }]);
    let c = dangling
        .chain_for("vk_d", Some("a"))
        .expect("group resolves");
    let names: Vec<&str> = c.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["a"]);
    assert!(dangling.validate_tiers().is_ok());
}
