// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 decision tests, ported.
//!
//! Every case here existed at the tag against the governance limit engine, and every assertion is
//! the one it made there. They are the reason to believe the claim this crate is built on: not
//! that the new code looks like the old code, but that the old code's own tests still pass against
//! it, unchanged in what they assert.
//!
//! Two cases from the original file are not here, and both for the same reason — they exercise
//! something other than the decision. The hydrate half of the accrual case drives a store flush
//! and a fresh process reading it back, which is the ledger's write-behind, not the door's; the
//! accrual half is ported below. The headroom case reads a chain's remaining fraction for the
//! routing policy, which is a projection over the same counters rather than a decision about them.

use super::*;

/// Requests per MINUTE: N admissions charge and pass; N+1 in the same window is refused naming
/// (group, requests, minute) with a retry hint to the minute roll; the NEXT window admits again.
#[test]
fn requests_per_minute_enforced_and_window_rolls() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "bob",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 3, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_r", Some("bob"));
    let now = 1_700_000_000; // mid-minute
    for _ in 0..3 {
        d.try_admit(&p, &c, "", now).expect("under the cap");
    }
    let err = d.try_admit(&p, &c, "", now).unwrap_err();
    assert_blocked(err, "bob", Metric::Requests, Some(MINUTE), true);
    // The next minute window is fresh.
    d.try_admit(&p, &c, "", now + 60)
        .expect("new window admits");
}

/// Every windowed granularity resolves and enforces independently: an HOUR cap and a DAY cap on
/// one group live in separate buckets and the tighter one blocks first.
#[test]
fn hour_and_day_windows_enforce_independently() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 2, Some(HOUR)),
                limit(LimitMetric::Requests, 3, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_hd", Some("g"));
    let day0 = 1_700_006_400 / crate::window::SECS_PER_DAY * crate::window::SECS_PER_DAY;
    d.try_admit(&p, &c, "", day0).expect("1st");
    d.try_admit(&p, &c, "", day0).expect("2nd");
    // Hour cap (2) trips first.
    assert_blocked(
        d.try_admit(&p, &c, "", day0).unwrap_err(),
        "g",
        Metric::Requests,
        Some(HOUR),
        true,
    );
    // Next hour: the hour bucket is fresh but the DAY bucket already holds 2; one more is the
    // day's 3rd and passes, the next blocks on the day cap.
    let next_hour = day0 + 3600;
    d.try_admit(&p, &c, "", next_hour).expect("day's 3rd");
    assert_blocked(
        d.try_admit(&p, &c, "", next_hour).unwrap_err(),
        "g",
        Metric::Requests,
        Some(DAY),
        true,
    );
}

/// `total` never rolls: the refusal carries NO retry hint.
#[test]
fn total_window_blocks_without_retry_after() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(TOTAL))],
        ),
    )]);
    let c = chain(&t, "vk_t", Some("g"));
    d.try_admit(&p, &c, "", 100).expect("first");
    assert_blocked(
        d.try_admit(&p, &c, "", 100_000_000).unwrap_err(),
        "g",
        Metric::Requests,
        Some(TOTAL),
        false,
    );
}

/// `tokens` per window is BEST-EFFORT post-paid: admission passes until the LEDGERED total crosses
/// the cap, then the next request is refused naming (group, tokens, window).
#[test]
fn tokens_cap_blocks_after_ledger_crosses() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Tokens, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_tok", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now)
        .expect("no tokens ledgered yet");
    d.record_usage(&c, "", "m", &toks(60, 39), now); // 99 < 100
    d.try_admit(&p, &c, "", now).expect("still under");
    d.record_usage(&c, "", "m", &toks(1, 0), now); // exactly 100 = at the cap
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Tokens,
        Some(MINUTE),
        true,
    );
    // A fresh window forgets the tokens.
    d.try_admit(&p, &c, "", now + 60).expect("fresh window");
}

/// `tokens_input` is best-effort post-paid on the UNCACHED-INPUT tier ONLY: admission passes until
/// the ledgered input crosses the cap. Output tokens on the same cell do NOT trip it — the tiers
/// are budgeted independently.
#[test]
fn tokens_input_cap_blocks_on_input_tier_only() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::TokensInput, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_ti", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now)
        .expect("no tokens ledgered yet");
    d.record_usage(&c, "", "m", &toks(99, 0), now); // input 99 < 100
    d.try_admit(&p, &c, "", now).expect("still under on input");
    // A request that only produces OUTPUT tokens must not trip the input cap.
    d.record_usage(&c, "", "m", &toks(0, 10_000), now);
    d.try_admit(&p, &c, "", now)
        .expect("output tokens do not count against tokens_input");
    d.record_usage(&c, "", "m", &toks(1, 0), now); // input now exactly 100 = at the cap
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::TokensInput,
        Some(MINUTE),
        true,
    );
    d.try_admit(&p, &c, "", now + 60).expect("fresh window");
}

/// CACHED-READ tokens live in their own tier, not the input tier: they must never count against a
/// `tokens_input` cap.
#[test]
fn cached_read_tokens_do_not_count_against_tokens_input() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::TokensInput, 100, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_tcr", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("nothing ledgered");
    // Well over the 100 input cap in cache reads, but zero uncached input.
    d.record_usage(&c, "", "m", &toks_tiers(0, 0, 10_000, 0), now);
    d.try_admit(&p, &c, "", now)
        .expect("cache_read tokens do not fill the tokens_input bucket");
    // And the input cap still bites once real input crosses it.
    d.record_usage(&c, "", "m", &toks_tiers(100, 0, 0, 0), now);
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::TokensInput,
        Some(MINUTE),
        true,
    );
}

/// Each per-tier cap enforces on its OWN tier, and the refusal names that exact tier.
#[test]
fn tokens_cache_write_cap_blocks_on_its_tier() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::TokensCacheWrite, 50, Some(HOUR))],
        ),
    )]);
    let c = chain(&t, "vk_tcw", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("nothing ledgered");
    // Other tiers do not trip a cache_write cap.
    d.record_usage(&c, "", "m", &toks_tiers(1_000, 1_000, 1_000, 0), now);
    d.try_admit(&p, &c, "", now)
        .expect("input/output/cache_read do not count against tokens_cache_write");
    d.record_usage(&c, "", "m", &toks_tiers(0, 0, 0, 50), now); // cache_write = 50 = at cap
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::TokensCacheWrite,
        Some(HOUR),
        true,
    );
}

/// `budget` derives spend from the token ledger times the rate card plus the flat fee times
/// requests, and blocks at or over the cap.
#[test]
fn budget_cap_derives_from_ledger_and_rate_card() {
    let d = door();
    // 10 micro-units/token input; cap 100 cents per month. 100_000 input tokens = 100 cents = AT
    // the cap.
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Budget, 100, Some(MONTH))],
        ),
    )]);
    let c = chain(&t, "vk_b", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("nothing spent");
    d.record_usage(&c, "", "m", &toks(99_000, 0), now); // 99 cents
    d.try_admit(&p, &c, "", now).expect("under the cap");
    d.record_usage(&c, "", "m", &toks(1_000, 0), now); // 100 cents = at the cap
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Budget,
        Some(MONTH),
        true,
    );
}

/// The flat per-request fee is part of a bucket's derived spend: with a fee of 10 and a 25-cent
/// budget, the 3rd admission's prospective spend (2 charged x 10 + 10 = 30) exceeds the cap.
#[test]
fn per_request_fee_counts_into_group_budget() {
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 25, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_fee", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("fee 10 <= 25");
    d.try_admit(&p, &c, "", now).expect("fee 20 <= 25");
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Budget,
        Some(DAY),
        true,
    );
    // A refund returns the fee, re-opening the cap (the fee bills successes only).
    d.refund_request(&c, "", now);
    d.try_admit(&p, &c, "", now)
        .expect("refund re-opened the cap");
}

/// A REFUND must return the fee without returning the request-LIMIT slot. Otherwise a caller
/// escapes the requests cap by hammering failures: each refunds its own slot and the cap only ever
/// counts successes.
#[test]
fn refund_returns_the_fee_but_never_the_requests_limit_slot() {
    let d = door();
    let p = no_card(10); // fee 10 cents/request
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 2, Some(DAY)),
                limit(LimitMetric::Budget, 1_000, Some(DAY)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_split", Some("g"));
    let now = 1_700_000_000;
    // Two admissions, both refunded (two failures).
    d.try_admit(&p, &c, "", now).expect("1st admits");
    d.refund_request(&c, "", now);
    d.try_admit(&p, &c, "", now).expect("2nd admits");
    d.refund_request(&c, "", now);
    // The requests LIMIT saw 2 admissions and was NOT refunded: the 3rd is refused on the requests
    // cap even though both prior requests failed.
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Requests,
        Some(DAY),
        true,
    );
    // The FEE, meanwhile, was refunded: derived spend on the bucket is 0.
    let (requests, _tokens, spend) = bucket_usage(&d, &p, "group:g@day", DAY, now);
    assert_eq!(requests, 2, "admission count is never refunded");
    assert_eq!(spend, 0, "both fees were refunded");
}

/// `concurrent` is an INSTANTANEOUS in-flight gauge: holds live on the returned grant and release
/// on drop; a full gauge refuses naming (group, concurrent) with no window and no retry hint.
#[test]
fn concurrent_gauge_holds_and_releases() {
    let d = door();
    let p = no_card(0);
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Concurrent, 2, None)]),
    )]);
    let c = chain(&t, "vk_c", Some("g"));
    let now = 1_700_000_000;
    let g1 = d.try_admit(&p, &c, "", now).expect("1st in flight");
    let g2 = d.try_admit(&p, &c, "", now).expect("2nd in flight");
    assert_eq!(g1.held(), 1);
    assert_eq!(d.gauges().in_flight("g"), 2);
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "g",
        Metric::Concurrent,
        None,
        false,
    );
    drop(g1);
    assert_eq!(d.gauges().in_flight("g"), 1);
    let g3 = d.try_admit(&p, &c, "", now).expect("slot freed");
    drop(g2);
    drop(g3);
    assert_eq!(d.gauges().in_flight("g"), 0, "all holds released");
}

/// A refused admission must NOT leak a concurrent hold: an inner gauge taken before an outer
/// (parent) limit blocks is rolled back with the refusal.
#[test]
fn rejected_admission_releases_concurrent_holds() {
    let d = door();
    let p = no_card(0);
    let t = table(&[
        (
            "parent",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 1, Some(MINUTE))],
            ),
        ),
        (
            "child",
            group_cfg(
                Some("parent"),
                true,
                vec![limit(LimitMetric::Concurrent, 10, None)],
            ),
        ),
    ]);
    let c = chain(&t, "vk_leak", Some("child"));
    let now = 1_700_000_000;
    let held = d.try_admit(&p, &c, "", now).expect("first admits");
    // Second: the child's gauge increments, then the parent's requests cap blocks — the gauge must
    // be released with the refusal.
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "parent",
        Metric::Requests,
        Some(MINUTE),
        true,
    );
    drop(held);
    assert_eq!(
        d.gauges().in_flight("child"),
        0,
        "no hold leaked by the refused admission"
    );
}

/// CHAIN AND across levels: the parent's cap blocks the child's principals even when the child's
/// own caps have headroom, and NOTHING is charged on a blocked admission.
#[test]
fn chain_and_parent_blocks_child_and_charges_nothing() {
    let d = door();
    let p = no_card(0);
    let t = table(&[
        (
            "acme",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 2, Some(MINUTE))],
            ),
        ),
        (
            "growth",
            group_cfg(
                Some("acme"),
                true,
                vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
            ),
        ),
    ]);
    let c = chain(&t, "vk_child", Some("growth"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("1st");
    d.try_admit(&p, &c, "", now).expect("2nd");
    // Parent cap (2) blocks despite the child's 100-cap headroom.
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "acme",
        Metric::Requests,
        Some(MINUTE),
        true,
    );
    // ALL-OR-NOTHING: the child's minute bucket holds exactly the 2 admitted charges.
    let (requests, _, _) = bucket_usage(&d, &p, "group:growth@minute", MINUTE, now);
    assert_eq!(requests, 2);
}

/// A per-user leaf ADDED at runtime enforces exactly like a boot-resolved tree: the team ceiling
/// ANDs ABOVE the leaf, so a generous personal budget can never let the user spend past the team
/// cap. This is the over-allocation safety property the whole self-service story rests on.
#[test]
fn runtime_added_user_leaf_is_capped_by_the_team_ceiling() {
    let d = door();
    let p = no_card(0);
    // Runtime add of `user:bob` under team with a deliberately LOOSER personal cap.
    let t = table(&[
        (
            "team",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 2, Some(MINUTE))],
            ),
        ),
        (
            "user:bob",
            group_cfg(
                Some("team"),
                true,
                vec![limit(LimitMetric::Requests, 5, Some(MINUTE))],
            ),
        ),
    ]);
    let c = chain(&t, "vk_bob", Some("user:bob"));
    let now = 1_700_000_000;
    // Two admissions fit under the team ceiling; the third is blocked by TEAM, not bob's 5-cap.
    d.try_admit(&p, &c, "", now).expect("1st");
    d.try_admit(&p, &c, "", now).expect("2nd");
    assert_blocked(
        d.try_admit(&p, &c, "", now).unwrap_err(),
        "team",
        Metric::Requests,
        Some(MINUTE),
        true,
    );
}

/// A frozen group refuses every request through it, directly or via a descendant, before anything
/// is charged; history is kept.
#[test]
fn disabled_group_freezes_the_chain() {
    let d = door();
    let p = no_card(0);
    let build = |parent_enabled: bool| {
        table(&[
            (
                "parent",
                group_cfg(
                    None,
                    parent_enabled,
                    vec![limit(LimitMetric::Requests, 100, Some(MINUTE))],
                ),
            ),
            ("child", group_cfg(Some("parent"), true, vec![])),
        ])
    };
    let now = 1_700_000_000;
    // Accrue history under the enabled config first.
    let live = build(true);
    d.try_admit(&p, &chain(&live, "vk_frozen", Some("child")), "", now)
        .expect("enabled admits");
    // Freeze the ANCESTOR: the child's principals are refused too — the freeze walks the chain.
    let frozen = build(false);
    match d
        .try_admit(&p, &chain(&frozen, "vk_frozen", Some("child")), "", now)
        .unwrap_err()
    {
        Blocked::Disabled(name) => assert_eq!(name, "parent"),
        other => panic!("expected Disabled, got {other:?}"),
    }
    // History kept: the parent's minute bucket still holds the pre-freeze charge.
    let (requests, _, _) = bucket_usage(&d, &p, "group:parent@minute", MINUTE, now);
    assert_eq!(requests, 1, "freezing keeps history");
    // Unfreeze: admission resumes.
    d.try_admit(
        &p,
        &chain(&build(true), "vk_frozen", Some("child")),
        "",
        now,
    )
    .expect("unfrozen admits");
}

/// A principal with NO group is authed and UNLIMITED: every admission passes and only its own
/// attribution bucket is charged.
#[test]
fn key_with_no_group_is_unlimited() {
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
    let c = chain(&t, "vk_free", None);
    let now = 1_700_000_000;
    for _ in 0..100 {
        d.try_admit(&p, &c, "", now).expect("no group = no caps");
    }
    let (requests, _, _) = bucket_usage(&d, &p, "vk_free", TOTAL, now);
    assert_eq!(requests, 100);
    // The configured, unrelated group's buckets saw nothing.
    let (other, _, _) = bucket_usage(&d, &p, "group:g@minute", MINUTE, now);
    assert_eq!(other, 0);
}

/// A principal bound to a group MISSING from this node's config fails CLOSED at admission.
#[test]
fn missing_group_fails_closed() {
    let t = table(&[]);
    match chain_for(&t, "vk_ghost", Some("ghost")).unwrap_err() {
        Blocked::MissingGroup(name) => assert_eq!(name, "ghost"),
        other => panic!("expected MissingGroup, got {other:?}"),
    }
}

/// Accrual lands the SAME response's tokens on EVERY bucket of the chain — each window counts all
/// the traffic through it.
#[test]
fn accrual_covers_every_chain_bucket() {
    let d = door();
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Budget, 1_000, Some(DAY)),
                limit(LimitMetric::Budget, 10_000, Some(MONTH)),
            ],
        ),
    )]);
    let c = chain(&t, "vk_acc", Some("g"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "", now).expect("admits");
    d.record_usage(&c, "", "m", &toks(500, 0), now);
    for (bucket, window) in [
        ("vk_acc", TOTAL),
        ("group:g@day", DAY),
        ("group:g@month", MONTH),
    ] {
        let (_, tokens, _) = bucket_usage(&d, &p, bucket, window, now);
        assert_eq!(tokens, 500, "bucket {bucket} accrued the tokens");
    }
}

/// The pool-split budget: two pool-qualified budgets on ONE group account independently.
/// Exhausting one blocks only that pool's traffic (and the refusal names the pool); the other
/// still admits against its own untouched bucket; a pool neither limit names is capped by neither.
#[test]
fn pool_scoped_budgets_account_independently() {
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![
                pooled(LimitMetric::Budget, 25, DAY, "frontier"),
                pooled(LimitMetric::Budget, 25, DAY, "value"),
            ],
        ),
    )]);
    let c = chain(&t, "vk_ps", Some("team"));
    let now = 1_700_000_000;
    // fee=10: two frontier admissions spend 20; the 3rd would reach 30 > 25.
    d.try_admit(&p, &c, "frontier", now).expect("frontier 1st");
    d.try_admit(&p, &c, "frontier", now).expect("frontier 2nd");
    match d.try_admit(&p, &c, "frontier", now).unwrap_err() {
        Blocked::Limit {
            group,
            metric: Metric::Budget,
            window: Some(DAY),
            pool: Some(pool),
            downgrade_to: None,
            retry_after: Some(_),
        } => {
            assert_eq!(group, "team");
            assert_eq!(pool, "frontier", "the refusal names the exhausted pool");
        }
        other => panic!("expected the frontier budget to block, got {other:?}"),
    }
    // The value pool's own bucket is untouched.
    d.try_admit(&p, &c, "value", now).expect("value 1st");
    d.try_admit(&p, &c, "value", now).expect("value 2nd");
    assert_blocked(
        d.try_admit(&p, &c, "value", now).unwrap_err(),
        "team",
        Metric::Budget,
        Some(DAY),
        true,
    );
    // A pool neither limit names is capped by neither bucket.
    d.try_admit(&p, &c, "other", now)
        .expect("unqualified pool is not pool-capped");
}

/// A group-wide limit still ANDs across every pool: pool-qualified budgets carve the spend, the
/// group-wide requests ceiling counts ALL traffic regardless of pool.
#[test]
fn group_wide_limit_ands_with_pool_scoped() {
    let d = door();
    let p = no_card(1);
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 3, Some(DAY)),
                pooled(LimitMetric::Budget, 100, DAY, "frontier"),
            ],
        ),
    )]);
    let c = chain(&t, "vk_gw", Some("team"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "frontier", now).expect("1st");
    d.try_admit(&p, &c, "value", now)
        .expect("2nd (different pool, same requests ceiling)");
    d.try_admit(&p, &c, "frontier", now).expect("3rd");
    assert_blocked(
        d.try_admit(&p, &c, "value", now).unwrap_err(),
        "team",
        Metric::Requests,
        Some(DAY),
        true,
    );
}

/// Accrual mirrors admission: tokens ledgered under pool A land ONLY in A's bucket, so they
/// exhaust A's budget without touching B's; and the REFUND of a pool-A admission erodes only the
/// buckets that admission charged.
#[test]
fn pool_scoped_accrual_and_refund_mirror_the_charge() {
    let d = door();
    // 10 micro-units/token: 100_000 input tokens = 100 cents = AT a 100-cent cap. No flat fee.
    let p = card(0, &[("m", 10.0, 0.0)]);
    let t = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![
                pooled(LimitMetric::Budget, 100, MONTH, "frontier"),
                pooled(LimitMetric::Budget, 100, MONTH, "value"),
            ],
        ),
    )]);
    let c = chain(&t, "vk_pa", Some("team"));
    let now = 1_700_000_000;
    // Tokens served through the value pool fill ONLY value's bucket.
    d.record_usage(&c, "value", "m", &toks(100_000, 0), now);
    d.try_admit(&p, &c, "frontier", now)
        .expect("frontier bucket is untouched by value-pool tokens");
    match d.try_admit(&p, &c, "value", now).unwrap_err() {
        Blocked::Limit {
            pool: Some(pool), ..
        } => assert_eq!(pool, "value"),
        other => panic!("expected value's budget to block, got {other:?}"),
    }
    // Refund mirror: a frontier admission's refund re-opens frontier, never value.
    let d2 = door();
    let p2 = no_card(10);
    let t2 = table(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![pooled(LimitMetric::Budget, 25, DAY, "frontier")],
        ),
    )]);
    let c2 = chain(&t2, "vk_pa", Some("team"));
    d2.try_admit(&p2, &c2, "frontier", now).expect("1st");
    d2.try_admit(&p2, &c2, "frontier", now).expect("2nd");
    assert!(d2.try_admit(&p2, &c2, "frontier", now).is_err(), "at cap");
    d2.refund_request(&c2, "frontier", now);
    d2.try_admit(&p2, &c2, "frontier", now)
        .expect("the refunded fee re-opened frontier's bucket");
}

/// A request that straddles a window boundary is charged on the LIVE cell, and its refund has to
/// reach that same cell.
///
/// `now` is the arrival epoch, pinned when the request came in. A concurrent admission can roll the
/// cell forward between then and the charge, and the charge deliberately lands in place on the
/// rolled cell rather than resetting it — the check reads that same cell for exactly this reason.
/// The refund is the other half of that charge, so it resolves the cell the same way: at or past
/// this request's window. Anything else keeps the flat fee for a request that failed, and the
/// derived spend the budget cap reads stays one fee too high for the rest of the window.
#[test]
fn a_refund_reaches_the_cell_a_straddling_charge_reached() {
    let d = door();
    let p = no_card(10);
    let t = table(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Budget, 1_000, Some(MINUTE))],
        ),
    )]);
    let c = chain(&t, "vk_straddle", Some("g"));

    // A minute boundary, with `earlier` in the minute before `later`.
    let later = 1_700_000_100;
    let earlier = 1_700_000_099;
    assert_ne!(
        crate::window::budget_window(MINUTE, earlier),
        crate::window::budget_window(MINUTE, later),
        "the two epochs have to be in different minutes for this to be a straddle at all"
    );

    // A concurrent admission has already rolled the cell into the newer minute.
    d.try_admit(&p, &c, "", later).expect("the roller admits");
    let bucket = "group:g@minute";
    let rolled = d.cells().snapshot(bucket).expect("the cell exists");
    assert_eq!(rolled.billable_requests, 1);

    // Our request arrived just before the boundary; its charge lands IN PLACE on the rolled cell.
    d.try_admit(&p, &c, "", earlier).expect("the straddler admits");
    assert_eq!(
        d.cells().snapshot(bucket).expect("cell").billable_requests,
        2,
        "the straddling charge landed on the live cell, not on a fresh one"
    );

    // It failed. The refund must reach the cell the charge reached.
    d.refund_request(&c, "", earlier);
    assert_eq!(
        d.cells().snapshot(bucket).expect("cell").billable_requests,
        1,
        "the fee for a failed request must come back off the cell it was charged to"
    );
}

/// The previous release kept that fee, and this records what it did.
///
/// The tag resolved a refund on `window_start == window` while resolving a charge on
/// `window > window_start`, so the two halves of one request could land on different cells and the
/// flat fee for a failed straddling request was never returned. That asymmetry is what the
/// improvement closes; naming it here keeps the change a deliberate divergence rather than a silent
/// one.
#[test]
fn the_previous_release_kept_the_fee_a_straddling_refund_could_not_reach() {
    // The rules, stated as the predicates they actually were.
    let charge_lands_in_place =
        |cell_window: u64, request_window: u64| request_window <= cell_window;
    let old_refund_reaches = |cell_window: u64, request_window: u64| cell_window == request_window;
    let new_refund_reaches = |cell_window: u64, request_window: u64| cell_window >= request_window;

    let request_window = crate::window::budget_window(MINUTE, 1_700_000_099);
    let rolled_cell = crate::window::budget_window(MINUTE, 1_700_000_100);
    assert!(rolled_cell > request_window);

    assert!(
        charge_lands_in_place(rolled_cell, request_window),
        "the charge reached the rolled cell"
    );
    assert!(
        !old_refund_reaches(rolled_cell, request_window),
        "and the previous release's refund did not: the fee stayed on the cell"
    );
    assert!(
        new_refund_reaches(rolled_cell, request_window),
        "the improvement makes the refund the exact inverse of the charge"
    );

    // A cell genuinely OLDER than the request's window is still a no-op under both rules: that is
    // not a straddle, it is a window that has already been left behind.
    let stale_cell = crate::window::budget_window(MINUTE, 1_700_000_000);
    assert!(!old_refund_reaches(stale_cell, request_window));
    assert!(!new_refund_reaches(stale_cell, request_window));
}

/// A budget block whose limit declared a downgrade NAMES the downgrade pool in the refusal, so the
/// caller can re-admit there; the most restrictive of two merged budgets is the one whose
/// behaviour governs; and a plain budget block still carries no downgrade.
#[test]
fn budget_block_carries_downgrade_target() {
    let d = door();
    let p = no_card(10);
    let mut teach = pooled(LimitMetric::Budget, 25, DAY, "frontier");
    teach.downgrade_to = Some("value".to_string());
    let t = table(&[("team", group_cfg(None, true, vec![teach]))]);
    let c = chain(&t, "vk_dg", Some("team"));
    let now = 1_700_000_000;
    d.try_admit(&p, &c, "frontier", now).expect("1st");
    d.try_admit(&p, &c, "frontier", now).expect("2nd");
    match d.try_admit(&p, &c, "frontier", now).unwrap_err() {
        Blocked::Limit {
            metric: Metric::Budget,
            downgrade_to: Some(to),
            ..
        } => assert_eq!(to, "value", "the block names where the traffic should go"),
        other => panic!("expected a downgrade-carrying budget block, got {other:?}"),
    }
    // The downgrade pool itself admits — its buckets are untouched.
    d.try_admit(&p, &c, "value", now)
        .expect("the value pool is not capped here");

    // MERGE rule: two budgets on one (window, pool) — the tighter declares the downgrade, the
    // looser does not; the tighter cap is the one that blocks, so its downgrade governs.
    let d2 = door();
    let mut tight = pooled(LimitMetric::Budget, 25, DAY, "frontier");
    tight.downgrade_to = Some("value".to_string());
    let loose = pooled(LimitMetric::Budget, 100, DAY, "frontier");
    let t2 = table(&[("team", group_cfg(None, true, vec![loose, tight]))]);
    let c2 = chain(&t2, "vk_dg", Some("team"));
    d2.try_admit(&p, &c2, "frontier", now).expect("1st");
    d2.try_admit(&p, &c2, "frontier", now).expect("2nd");
    match d2.try_admit(&p, &c2, "frontier", now).unwrap_err() {
        Blocked::Limit {
            downgrade_to: Some(to),
            ..
        } => assert_eq!(to, "value"),
        other => panic!("the tighter budget's downgrade governs, got {other:?}"),
    }
}
