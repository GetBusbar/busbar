// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::cost::CostModel;
use std::collections::BTreeMap;

fn gov() -> GovState {
    GovState::new(crate::real_store::store(), None).expect("memory store constructs")
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

fn group_cfg(parent: Option<&str>, enabled: bool, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled,
        limits,
        ..Default::default()
    }
}

fn model(groups: &[(&str, GroupCfg)]) -> CostModel {
    let map: BTreeMap<String, GroupCfg> = groups
        .iter()
        .map(|(n, g)| (n.to_string(), g.clone()))
        .collect();
    CostModel::resolve_parts(None, 0, &map)
}

fn model_with_card(groups: &[(&str, GroupCfg)], fee: i64, card: &[(&str, f64, f64)]) -> CostModel {
    let map: BTreeMap<String, GroupCfg> = groups
        .iter()
        .map(|(n, g)| (n.to_string(), g.clone()))
        .collect();
    let card: BTreeMap<String, crate::config::RateEntryCfg> = card
        .iter()
        .map(|(m, i, o)| {
            (
                m.to_string(),
                crate::config::RateEntryCfg {
                    input_utok: *i,
                    output_utok: *o,
                    cache_read_utok: 0.0,
                    cache_write_utok: 0.0,
                    ..Default::default()
                },
            )
        })
        .collect();
    CostModel::resolve_parts((!card.is_empty()).then_some(&card), fee, &map)
}

fn key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h:{id}"),
        name: id.to_string(),
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

fn toks(input: u64, output: u64) -> std::collections::BTreeMap<String, u64> {
    toks_tiers(input, output, 0, 0)
}

#[track_caller]
fn assert_blocked(
    err: LimitBlocked,
    group: &str,
    metric: &str,
    window: Option<&str>,
    has_retry: bool,
) {
    match err {
        LimitBlocked::Limit {
            group: g,
            metric: m,
            window: w,
            pool: _,
            downgrade_to: _,
            retry_after,
        } => {
            assert_eq!(g, group, "blocking group");
            assert_eq!(m, metric, "blocking metric");
            assert_eq!(w, window, "blocking window");
            assert_eq!(retry_after.is_some(), has_retry, "retry-after presence");
        }
        other => panic!("expected a Limit rejection, got {other:?}"),
    }
}

#[test]
fn requests_per_minute_enforced_and_window_rolls() {
    let g = gov();
    let cm = model(&[(
        "bob",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 3, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_r", Some("bob"));
    let now = 1_700_000_000;
    for _ in 0..3 {
        g.try_admit(&cm, &k, "", now).expect("under the cap");
    }
    let err = g.try_admit(&cm, &k, "", now).unwrap_err();
    assert_blocked(err, "bob", "requests", Some("minute"), true);

    g.try_admit(&cm, &k, "", now + 60)
        .expect("new window admits");
}

#[test]
fn hour_and_day_windows_enforce_independently() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![
                limit(LimitMetric::Requests, 2, Some(LimitWindow::Hour)),
                limit(LimitMetric::Requests, 3, Some(LimitWindow::Day)),
            ],
        ),
    )]);
    let k = key("vk_hd", Some("g"));
    let day0 = 1_700_006_400 / super::SECS_PER_DAY * super::SECS_PER_DAY;
    g.try_admit(&cm, &k, "", day0).expect("1st");
    g.try_admit(&cm, &k, "", day0).expect("2nd");

    assert_blocked(
        g.try_admit(&cm, &k, "", day0).unwrap_err(),
        "g",
        "requests",
        Some("hour"),
        true,
    );

    let next_hour = day0 + 3600;
    g.try_admit(&cm, &k, "", next_hour).expect("day's 3rd");
    assert_blocked(
        g.try_admit(&cm, &k, "", next_hour).unwrap_err(),
        "g",
        "requests",
        Some("day"),
        true,
    );
}

#[test]
fn total_window_blocks_without_retry_after() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Total))],
        ),
    )]);
    let k = key("vk_t", Some("g"));
    g.try_admit(&cm, &k, "", 100).expect("first");
    assert_blocked(
        g.try_admit(&cm, &k, "", 100_000_000).unwrap_err(),
        "g",
        "requests",
        Some("total"),
        false,
    );
}

#[test]
fn tokens_cap_blocks_after_ledger_crosses() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Tokens, 100, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_tok", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now)
        .expect("no tokens ledgered yet");
    g.record_usage(&cm, &k, "", "m", &toks(60, 39), now);
    g.try_admit(&cm, &k, "", now).expect("still under");
    g.record_usage(&cm, &k, "", "m", &toks(1, 0), now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens",
        Some("minute"),
        true,
    );

    g.try_admit(&cm, &k, "", now + 60).expect("fresh window");
}

fn toks_tiers(
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    for (k, v) in [
        (busbar_contract::records::UNIT_INPUT, input),
        (busbar_contract::records::UNIT_OUTPUT, output),
        (busbar_contract::records::UNIT_CACHE_READ, cache_read),
        (busbar_contract::records::UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            m.insert(k.to_string(), v);
        }
    }
    m
}

#[test]
fn tokens_input_cap_blocks_on_input_tier_only() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::TokensInput,
                100,
                Some(LimitWindow::Minute),
            )],
        ),
    )]);
    let k = key("vk_ti", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now)
        .expect("no tokens ledgered yet");
    g.record_usage(&cm, &k, "", "m", &toks(99, 0), now);
    g.try_admit(&cm, &k, "", now).expect("still under on input");

    g.record_usage(&cm, &k, "", "m", &toks(0, 10_000), now);
    g.try_admit(&cm, &k, "", now)
        .expect("output tokens do not count against tokens_input");
    g.record_usage(&cm, &k, "", "m", &toks(1, 0), now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens_input",
        Some("minute"),
        true,
    );

    g.try_admit(&cm, &k, "", now + 60).expect("fresh window");
}

#[test]
fn cached_read_tokens_do_not_count_against_tokens_input() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::TokensInput,
                100,
                Some(LimitWindow::Minute),
            )],
        ),
    )]);
    let k = key("vk_tcr", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("nothing ledgered");

    g.record_usage(&cm, &k, "", "m", &toks_tiers(0, 0, 10_000, 0), now);
    g.try_admit(&cm, &k, "", now)
        .expect("cache_read tokens do not fill the tokens_input bucket");

    g.record_usage(&cm, &k, "", "m", &toks_tiers(100, 0, 0, 0), now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens_input",
        Some("minute"),
        true,
    );
}

#[test]
fn tokens_cache_write_cap_blocks_on_its_tier() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::TokensCacheWrite,
                50,
                Some(LimitWindow::Hour),
            )],
        ),
    )]);
    let k = key("vk_tcw", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("nothing ledgered");

    g.record_usage(&cm, &k, "", "m", &toks_tiers(1_000, 1_000, 1_000, 0), now);
    g.try_admit(&cm, &k, "", now)
        .expect("input/output/cache_read do not count against tokens_cache_write");
    g.record_usage(&cm, &k, "", "m", &toks_tiers(0, 0, 0, 50), now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens_cache_write",
        Some("hour"),
        true,
    );
}

#[test]
fn budget_cap_derives_from_ledger_and_rate_card() {
    let g = gov();

    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 100, Some(LimitWindow::Month))],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_b", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("nothing spent");
    g.record_usage(&cm, &k, "", "m", &toks(99_000, 0), now);
    g.try_admit(&cm, &k, "", now).expect("under the cap");
    g.record_usage(&cm, &k, "", "m", &toks(1_000, 0), now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("month"),
        true,
    );
}

#[test]
fn per_request_fee_counts_into_group_budget() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 25, Some(LimitWindow::Day))],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_fee", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("fee 10 <= 25");
    let second = g.try_admit(&cm, &k, "", now).expect("fee 20 <= 25");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("day"),
        true,
    );

    g.refund_charge(second.charge());
    g.try_admit(&cm, &k, "", now)
        .expect("refund re-opened the cap");
}

#[test]
fn refund_returns_the_fee_but_never_the_requests_limit_slot() {
    let g = gov();

    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Requests, 2, Some(LimitWindow::Day)),
                    limit(LimitMetric::Budget, 1_000, Some(LimitWindow::Day)),
                ],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_split", Some("g"));
    let now = 1_700_000_000;

    let first = g.try_admit(&cm, &k, "", now).expect("1st admits");
    g.refund_charge(first.charge());
    let second = g.try_admit(&cm, &k, "", now).expect("2nd admits");
    g.refund_charge(second.charge());

    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "requests",
        Some("day"),
        true,
    );

    let u = g
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .unwrap();
    assert_eq!(u.requests, 2, "admission count is never refunded");
    assert_eq!(
        u.spend_cents, 0,
        "both fees were refunded (2xx-only billing)"
    );
}

#[test]
fn a_refund_after_a_window_roll_reaches_the_cell_the_charge_reached() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 25, Some(LimitWindow::Minute))],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_straddle", Some("g"));

    let after = 1_700_000_100;
    let before = after - 1;
    assert_ne!(
        crate::governance::budget_window("minute", before),
        crate::governance::budget_window("minute", after),
        "the two epochs have to be in different minutes for this to be a straddle at all"
    );

    g.try_admit(&cm, &k, "", after).expect("the roller admits");
    let straddler = (g.try_admit(&cm, &k, "", before)).expect("the straddler admits");
    assert_blocked(
        g.try_admit(&cm, &k, "", after).unwrap_err(),
        "g",
        "budget",
        Some("minute"),
        true,
    );

    g.refund_charge(straddler.charge());
    let u = g
        .derived_bucket_usage(&cm, "group:g@minute", "minute", true, after)
        .expect("the rolled cell reads");
    assert_eq!(
        u.spend_cents, 10,
        "one fee remains: the failed straddler's came off the cell it was charged to"
    );
    g.try_admit(&cm, &k, "", after)
        .expect("the returned fee re-opened the budget the failed straddler was holding");
}

#[test]
fn concurrent_gauge_holds_and_releases() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Concurrent, 2, None)]),
    )]);
    let k = key("vk_c", Some("g"));
    let now = 1_700_000_000;
    let g1 = g.try_admit(&cm, &k, "", now).expect("1st in flight");
    let g2 = g.try_admit(&cm, &k, "", now).expect("2nd in flight");
    assert_eq!(g1.held(), 1);
    assert_eq!(g.concurrent_in_flight("g"), 2);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "concurrent",
        None,
        false,
    );
    drop(g1);
    assert_eq!(g.concurrent_in_flight("g"), 1);
    let _g3 = g.try_admit(&cm, &k, "", now).expect("slot freed");
    drop(g2);
    drop(_g3);
    assert_eq!(g.concurrent_in_flight("g"), 0, "all holds released");
}

#[test]
fn rejected_admission_releases_concurrent_holds() {
    let g = gov();
    let cm = model(&[
        (
            "parent",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Minute))],
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
    let k = key("vk_leak", Some("child"));
    let now = 1_700_000_000;
    let held = g.try_admit(&cm, &k, "", now).expect("first admits");

    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "parent",
        "requests",
        Some("minute"),
        true,
    );
    drop(held);
    assert_eq!(
        g.concurrent_in_flight("child"),
        0,
        "no hold leaked by the rejected admission"
    );
}

#[test]
fn chain_and_parent_blocks_child_and_charges_nothing() {
    let g = gov();
    let cm = model(&[
        (
            "acme",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
            ),
        ),
        (
            "growth",
            group_cfg(
                Some("acme"),
                true,
                vec![limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute))],
            ),
        ),
    ]);
    let k = key("vk_child", Some("growth"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("1st");
    g.try_admit(&cm, &k, "", now).expect("2nd");

    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "acme",
        "requests",
        Some("minute"),
        true,
    );

    let child = g
        .derived_bucket_usage(&cm, "group:growth@minute", "minute", true, now)
        .unwrap();
    assert_eq!(child.requests, 2);
}

#[test]
fn runtime_added_user_leaf_is_capped_by_the_team_ceiling() {
    let g = gov();

    let base = model(&[(
        "team",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
        ),
    )]);

    let mut map: BTreeMap<String, GroupCfg> = BTreeMap::new();
    map.insert(
        "team".into(),
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 2, Some(LimitWindow::Minute))],
        ),
    );
    map.insert(
        "user:bob".into(),
        group_cfg(
            Some("team"),
            true,
            vec![limit(LimitMetric::Requests, 5, Some(LimitWindow::Minute))],
        ),
    );
    let cm = base.with_groups(&map);
    let k = key("vk_bob", Some("user:bob"));
    let now = 1_700_000_000;

    g.try_admit(&cm, &k, "", now).expect("1st");
    g.try_admit(&cm, &k, "", now).expect("2nd");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "team",
        "requests",
        Some("minute"),
        true,
    );
}

#[test]
fn disabled_group_freezes_the_chain() {
    let g = gov();
    let build = |parent_enabled: bool| {
        model(&[
            (
                "parent",
                group_cfg(
                    None,
                    parent_enabled,
                    vec![limit(LimitMetric::Requests, 100, Some(LimitWindow::Minute))],
                ),
            ),
            ("child", group_cfg(Some("parent"), true, vec![])),
        ])
    };
    let k = key("vk_frozen", Some("child"));
    let now = 1_700_000_000;

    let cm = build(true);
    g.try_admit(&cm, &k, "", now).expect("enabled admits");

    let frozen = build(false);
    match g.try_admit(&frozen, &k, "", now).unwrap_err() {
        LimitBlocked::Disabled(name) => assert_eq!(name, "parent"),
        other => panic!("expected Disabled, got {other:?}"),
    }

    let hist = g
        .derived_bucket_usage(&frozen, "group:parent@minute", "minute", true, now)
        .unwrap();
    assert_eq!(hist.requests, 1, "freezing keeps history");

    g.try_admit(&build(true), &k, "", now)
        .expect("unfrozen admits");
}

#[test]
fn key_with_no_group_is_unlimited() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_free", None);
    let now = 1_700_000_000;
    for _ in 0..100 {
        g.try_admit(&cm, &k, "", now).expect("no group = no caps");
    }
    let usage = g.usage_for(&cm, "vk_free", now).unwrap();

    assert!(usage.is_none());
    let bucket = g
        .derived_bucket_usage(&cm, "vk_free", super::WINDOW_TOTAL, true, now)
        .unwrap();
    assert_eq!(bucket.requests, 100);

    let other = g
        .derived_bucket_usage(&cm, "group:g@minute", "minute", true, now)
        .unwrap();
    assert_eq!(other.requests, 0);
}

#[test]
fn missing_group_fails_closed() {
    let g = gov();
    let cm = model(&[]);
    let k = key("vk_ghost", Some("ghost"));
    match g.try_admit(&cm, &k, "", 1_700_000_000).unwrap_err() {
        LimitBlocked::MissingGroup(name) => assert_eq!(name, "ghost"),
        other => panic!("expected MissingGroup, got {other:?}"),
    }
}

#[test]
fn accrual_and_hydrate_cover_every_chain_bucket() {
    let store = crate::real_store::store();
    let g = GovState::new(store.clone(), None).unwrap();
    let cm = model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Budget, 1_000, Some(LimitWindow::Day)),
                    limit(LimitMetric::Budget, 10_000, Some(LimitWindow::Month)),
                ],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_acc", Some("g"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "", now).expect("admits");
    g.record_usage(&cm, &k, "", "m", &toks(500, 0), now);
    for bucket in ["vk_acc", "group:g@day", "group:g@month"] {
        let window = if bucket == "vk_acc" {
            super::WINDOW_TOTAL
        } else if bucket.ends_with("@day") {
            super::WINDOW_DAY
        } else {
            super::WINDOW_MONTH
        };
        let u = g
            .derived_bucket_usage(&cm, bucket, window, true, now)
            .unwrap();
        assert_eq!(u.tokens, 500, "bucket {bucket} accrued the tokens");
    }

    assert!(g.flush_budgets() >= 1);
    let g2 = GovState::new(store, None).unwrap();
    g2.hydrate_budgets(&cm, now).unwrap();
    let day = g2
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .unwrap();
    assert_eq!(day.tokens, 500, "hydrate restored the day bucket");
    let month = g2
        .derived_bucket_usage(&cm, "group:g@month", "month", true, now)
        .unwrap();
    assert_eq!(month.tokens, 500, "hydrate restored the month bucket");
}

#[test]
fn rate_headroom_reads_the_chain() {
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 4, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_head", Some("g"));
    let now = 1_700_000_000;
    assert_eq!(
        g.rate_headroom(&cm, &k, None, now),
        Some(1.0),
        "untouched = full"
    );
    g.try_admit(&cm, &k, "", now).unwrap();
    g.try_admit(&cm, &k, "", now).unwrap();
    let h = g.rate_headroom(&cm, &k, None, now).unwrap();
    assert!((h - 0.5).abs() < 1e-9, "2 of 4 used = 0.5, got {h}");

    assert_eq!(g.rate_headroom(&cm, &key("vk_none", None), None, now), None);
}

fn pooled(metric: LimitMetric, amount: u64, per: LimitWindow, pool: &str) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: Some(ScopeRef::pool(pool)),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

#[test]
fn pool_scoped_budgets_account_independently() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    pooled(LimitMetric::Budget, 25, LimitWindow::Day, "frontier"),
                    pooled(LimitMetric::Budget, 25, LimitWindow::Day, "value"),
                ],
            ),
        )],
        10,
        &[],
    );
    let k = key("vk_ps", Some("team"));
    let now = 1_700_000_000;

    g.try_admit(&cm, &k, "frontier", now).expect("frontier 1st");
    g.try_admit(&cm, &k, "frontier", now).expect("frontier 2nd");
    match g.try_admit(&cm, &k, "frontier", now).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("day"),
            pool: Some(pool),
            downgrade_to: None,
            retry_after: Some(_),
        } => {
            assert_eq!(group, "team");
            assert_eq!(pool, "frontier", "the rejection names the exhausted pool");
        }
        other => panic!("expected the frontier budget to block, got {other:?}"),
    }

    g.try_admit(&cm, &k, "value", now).expect("value 1st");
    g.try_admit(&cm, &k, "value", now).expect("value 2nd");
    assert_blocked(
        g.try_admit(&cm, &k, "value", now).unwrap_err(),
        "team",
        "budget",
        Some("day"),
        true,
    );

    g.try_admit(&cm, &k, "other", now)
        .expect("unqualified pool is not pool-capped");
}

#[test]
fn group_wide_limit_ands_with_pool_scoped() {
    let g = gov();
    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    limit(LimitMetric::Requests, 3, Some(LimitWindow::Day)),
                    pooled(LimitMetric::Budget, 100, LimitWindow::Day, "frontier"),
                ],
            ),
        )],
        1,
        &[],
    );
    let k = key("vk_gw", Some("team"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "frontier", now).expect("1st");
    g.try_admit(&cm, &k, "value", now)
        .expect("2nd (different pool, same requests ceiling)");
    g.try_admit(&cm, &k, "frontier", now).expect("3rd");
    assert_blocked(
        g.try_admit(&cm, &k, "value", now).unwrap_err(),
        "team",
        "requests",
        Some("day"),
        true,
    );
}

#[test]
fn pool_scoped_accrual_and_refund_mirror_the_charge() {
    let g = gov();

    let cm = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![
                    pooled(LimitMetric::Budget, 100, LimitWindow::Month, "frontier"),
                    pooled(LimitMetric::Budget, 100, LimitWindow::Month, "value"),
                ],
            ),
        )],
        0,
        &[("m", 10.0, 0.0)],
    );
    let k = key("vk_pa", Some("team"));
    let now = 1_700_000_000;

    g.record_usage(&cm, &k, "value", "m", &toks(100_000, 0), now);
    g.try_admit(&cm, &k, "frontier", now)
        .expect("frontier bucket is untouched by value-pool tokens");
    match g.try_admit(&cm, &k, "value", now).unwrap_err() {
        LimitBlocked::Limit {
            pool: Some(pool), ..
        } => assert_eq!(pool, "value"),
        other => panic!("expected value's budget to block, got {other:?}"),
    }

    let g2 = gov();
    let cm2 = model_with_card(
        &[(
            "team",
            group_cfg(
                None,
                true,
                vec![pooled(
                    LimitMetric::Budget,
                    25,
                    LimitWindow::Day,
                    "frontier",
                )],
            ),
        )],
        10,
        &[],
    );
    g2.try_admit(&cm2, &k, "frontier", now).expect("1st");
    let second = g2.try_admit(&cm2, &k, "frontier", now).expect("2nd");
    assert!(g2.try_admit(&cm2, &k, "frontier", now).is_err(), "at cap");
    g2.refund_charge(second.charge());
    g2.try_admit(&cm2, &k, "frontier", now)
        .expect("the refunded fee re-opened frontier's bucket");
}

#[test]
fn budget_block_carries_downgrade_target() {
    let g = gov();
    let mut teach = pooled(LimitMetric::Budget, 25, LimitWindow::Day, "frontier");
    teach.on_exhaust = Some(crate::config::groups::OnExhaust::Downgrade);
    teach.downgrade_to = Some(ScopeRef::pool("value"));
    let cm = model_with_card(&[("team", group_cfg(None, true, vec![teach]))], 10, &[]);
    let k = key("vk_dg", Some("team"));
    let now = 1_700_000_000;
    g.try_admit(&cm, &k, "frontier", now).expect("1st");
    g.try_admit(&cm, &k, "frontier", now).expect("2nd");
    match g.try_admit(&cm, &k, "frontier", now).unwrap_err() {
        LimitBlocked::Limit {
            metric: "budget",
            downgrade_to: Some(to),
            ..
        } => assert_eq!(to, "value", "the block names where the traffic should go"),
        other => panic!("expected a downgrade-carrying budget block, got {other:?}"),
    }

    g.try_admit(&cm, &k, "value", now)
        .expect("the value pool is not capped here");

    let g2 = gov();
    let mut tight = pooled(LimitMetric::Budget, 25, LimitWindow::Day, "frontier");
    tight.on_exhaust = Some(crate::config::groups::OnExhaust::Downgrade);
    tight.downgrade_to = Some(ScopeRef::pool("value"));
    let loose = pooled(LimitMetric::Budget, 100, LimitWindow::Day, "frontier");
    let cm2 = model_with_card(
        &[("team", group_cfg(None, true, vec![loose, tight]))],
        10,
        &[],
    );
    g2.try_admit(&cm2, &k, "frontier", now).expect("1st");
    g2.try_admit(&cm2, &k, "frontier", now).expect("2nd");
    match g2.try_admit(&cm2, &k, "frontier", now).unwrap_err() {
        LimitBlocked::Limit {
            downgrade_to: Some(to),
            ..
        } => assert_eq!(to, "value"),
        other => panic!("the tighter budget's downgrade governs, got {other:?}"),
    }
}

#[test]
fn an_open_class_priced_in_config_is_charged_and_capped_end_to_end() {
    let card: BTreeMap<String, crate::config::RateEntryCfg> =
        serde_yaml::from_str("rerank: { input_utok: 1, units: { search_units: 2000 } }\n")
            .expect("an open class parses under units:");
    let groups: BTreeMap<String, GroupCfg> = [(
        "g".to_string(),
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Budget, 100, Some(LimitWindow::Day))],
        ),
    )]
    .into();
    let cm = CostModel::resolve_parts(Some(&card), 0, &groups);
    let g = gov();
    let k = key("vk_rerank", Some("g"));
    let now = 1_700_000_000;
    let search = |n: u64| BTreeMap::from([("search_units".to_string(), n)]);

    g.try_admit(&cm, &k, "", now).expect("nothing spent");
    g.record_usage(&cm, &k, "", "rerank", &search(499), now);
    let read = g
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .expect("the read prices");
    assert_eq!(
        read.spend_cents, 99,
        "CHARGED: 499 × 0.2 cents, truncated once"
    );
    assert_eq!(
        read.tokens, 0,
        "a search unit is priced, never counted as a token"
    );
    g.try_admit(&cm, &k, "", now).expect("under the cap");

    g.record_usage(&cm, &k, "", "rerank", &search(1), now);
    let read = g
        .derived_bucket_usage(&cm, "group:g@day", "day", true, now)
        .expect("the read prices");
    assert_eq!(read.spend_cents, 100, "500 search units = the whole budget");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("day"),
        true,
    );
}

#[test]
fn an_open_class_the_present_card_does_not_price_refuses_and_absent_reads_zero() {
    let groups: BTreeMap<String, GroupCfg> = [(
        "g".to_string(),
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Budget, 100, Some(LimitWindow::Day))],
        ),
    )]
    .into();
    let units = BTreeMap::from([("search_units".to_string(), 1u64)]);
    let now = 1_700_000_000;
    let k = key("vk_rerank", Some("g"));

    let silent: BTreeMap<String, crate::config::RateEntryCfg> =
        serde_yaml::from_str("rerank: { input_utok: 1 }\n").expect("parses");
    let cm = CostModel::resolve_parts(Some(&silent), 0, &groups);
    let usage = busbar_contract::billing::Usage {
        usage_units: units.clone(),
    };
    let entry =
        busbar_kernel_ledger::cost::LedgerEntry::new("rerank", 0).with_whole("search_units", 1);
    let priced = busbar_kernel_ledger::cost::price_ledger(
        &[entry],
        &busbar_kernel_ledger::cost::History::opening(cm.card().clone(), 0),
    );
    assert!(
        matches!(
            priced,
            Err(busbar_kernel_ledger::cost::MoneyError::ClassUnpriced { ref class, .. })
                if class == "search_units"
        ),
        "a present card silent about a hit class refuses (#42)"
    );
    let g = gov();
    g.record_usage(&cm, &k, "", "rerank", &units, now);
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "budget",
        Some("day"),
        true,
    );

    let absent = CostModel::resolve_parts(None, 0, &groups);
    assert_eq!(
        absent.price_usage_nanos("rerank", &usage),
        Some(0),
        "billing off reads 0"
    );
}

static TOKEN_FAMILY_PLANE: crate::plane_driver::registry::PlaneDecl =
    crate::plane_driver::registry::PlaneDecl {
        declaration: crate::plane_driver::registry::PlaneDeclaration {
            key: "token-family-plane",
            fallback: false,
            config_section: "streams",
            scope_kinds: &[],
            subject_noun: "stream",
            admin_noun: "stream",
            audit_kind: "stream",
            card_signing_domain: None,
            card_kid_prefix: None,
            owned_config_sections: &[],
            billable_classes: &[
                crate::plane_driver::registry::BillableClass {
                    class: "audio_tokens_in",
                    family: crate::plane_driver::registry::TOKEN_FAMILY,
                },
                crate::plane_driver::registry::BillableClass {
                    class: "audio_tokens_out",
                    family: crate::plane_driver::registry::TOKEN_FAMILY,
                },
                crate::plane_driver::registry::BillableClass {
                    class: "audio_seconds_in",
                    family: "duration",
                },
            ],
            fee_units: &[],
            metric_families: &[],
            record_kinds: &[],
            required_config_sections: &[],
            trust_keys: &[],
            served_op_classes: &[],
            caller_credential_refusal: None,
        },
        wire_format_names: |_| &[],
        provider_dialects: |_| &[],
        claims: |_| Vec::new(),
        admission: |_| None,
        build: |_, _| None,
        routes: None,
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        viewer: None,
        retain_verify_gates: None,
        default_section: None,
        resolve_provider: None,
        door: None,
    };

#[test]
fn tokens_cap_counts_every_token_family_class_a_plane_declares() {
    let _iso =
        busbar_kernel::test_support::planes::TestRegistryIsolation::seeded(&[&TOKEN_FAMILY_PLANE]);
    let g = gov();
    let cm = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Tokens, 100, Some(LimitWindow::Minute))],
        ),
    )]);
    let k = key("vk_audio", Some("g"));
    let now = 1_700_000_000;
    let units = |pairs: &[(&str, u64)]| -> BTreeMap<String, u64> {
        pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
    };
    g.try_admit(&cm, &k, "", now).expect("nothing ledgered");
    g.record_usage(
        &cm,
        &k,
        "",
        "realtime",
        &units(&[("audio_tokens_in", 60), ("audio_seconds_in", 1000)]),
        now,
    );
    g.try_admit(&cm, &k, "", now)
        .expect("60 audio tokens < 100; seconds are not tokens");
    g.record_usage(
        &cm,
        &k,
        "",
        "realtime",
        &units(&[("audio_tokens_out", 40)]),
        now,
    );
    let read = g
        .derived_bucket_usage(&cm, "group:g@minute", "minute", true, now)
        .expect("the read derives");
    assert_eq!(read.tokens, 100, "audio tokens in + out are tokens");
    assert_blocked(
        g.try_admit(&cm, &k, "", now).unwrap_err(),
        "g",
        "tokens",
        Some("minute"),
        true,
    );
}

fn era_now() -> u64 {
    crate::rate_apply::effective_from_at(crate::store::now_ms())
}

fn metered(g: &GovState, key_id: &str, model: &str, n: u64, now: u64) {
    g.store
        .add_metering(&busbar_contract::records::MeteringDelta {
            key_id: key_id.to_string(),
            bucket: crate::governance::metering_bucket(now),
            model: model.to_string(),
            provider: String::new(),
            tokens_input: n,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: era_now(),
            usage_units: Default::default(),
        })
        .expect("the memory store accepts a metering delta");
}

#[test]
fn an_adjust_moves_the_key_group_and_metrics_reads_of_the_budget_book() {
    use busbar_contract::records::UNIT_INPUT;
    let g = gov();
    let day = limit(LimitMetric::Budget, 100_000, Some(LimitWindow::Day));
    let cm = model_with_card(
        &[("g", group_cfg(None, true, vec![day]))],
        0,
        &[("m", 2.5, 0.0)],
    );
    let k = key("vk_q51_adjust_reads", Some("g"));
    g.store.put_key(&k).expect("key persists");
    let now = crate::store::now();
    g.record_usage(&cm, &k, "", "m", &toks(1_000_000, 0), now);
    metered(&g, &k.id, "m", 1_000_000, now);
    let read = |g: &GovState| {
        let key = g.usage_for(&cm, &k.id, now).unwrap().unwrap();
        let group = (g.derived_bucket_usage(&cm, "group:g@day", "day", true, now)).unwrap();
        let gauge = g.bucket_model_tokens(&k.id, super::WINDOW_TOTAL, now);
        (
            key.spend_cents,
            key.tokens,
            group.spend_cents,
            gauge[0].1[UNIT_INPUT],
        )
    };
    assert_eq!(read(&g), (250, 1_000_000, 250, 1_000_000), "as recorded");
    let delta = BTreeMap::from([(UNIT_INPUT.to_string(), -200_000i64)]);
    let adjustment = super::Adjustment {
        key_id: &k.id,
        pool: "",
        model: "m",
        entry_era: era_now(),
        card_epoch_ms: now * 1_000,
        delta: &delta,
        now,
    };
    g.adjust_usage(&cm, &adjustment)
        .expect("the store reads")
        .expect("the correction applies");
    assert_eq!(read(&g), (200, 800_000, 200, 800_000), "as corrected");
}

#[test]
fn an_adjust_larger_than_its_segment_is_refused_and_moves_nothing() {
    use busbar_contract::records::UNIT_INPUT;
    let g = gov();
    let day = limit(LimitMetric::Budget, 100_000, Some(LimitWindow::Day));
    let cm = model_with_card(
        &[("g", group_cfg(None, true, vec![day]))],
        0,
        &[("m", 2.5, 0.0)],
    );
    let k = key("vk_adjust_exceeds", Some("g"));
    g.store.put_key(&k).expect("key persists");
    let now = crate::store::now();
    g.record_usage(&cm, &k, "", "m", &toks(1_000, 0), now);
    metered(&g, &k.id, "m", 1_000, now);
    let read = |g: &GovState| {
        let key = g.usage_for(&cm, &k.id, now).unwrap().unwrap();
        let group = (g.derived_bucket_usage(&cm, "group:g@day", "day", true, now)).unwrap();
        (key.tokens, group.tokens)
    };
    assert_eq!(read(&g), (1_000, 1_000));
    let delta = BTreeMap::from([(UNIT_INPUT.to_string(), -1_001i64)]);
    let adjustment = super::Adjustment {
        key_id: &k.id,
        pool: "",
        model: "m",
        entry_era: era_now(),
        card_epoch_ms: now * 1_000,
        delta: &delta,
        now,
    };
    match g.adjust_usage(&cm, &adjustment).expect("the store reads") {
        Err(super::AdjustRefused::Exceeds { count, delta, .. }) => {
            assert_eq!((count, delta), (1_000, -1_001));
        }
        other => panic!("a correction past the count is refused, got {other:?}"),
    }
    assert_eq!(read(&g), (1_000, 1_000), "nothing was applied anywhere");

    let other_lane = super::Adjustment {
        model: "never-served",
        delta: &BTreeMap::from([(UNIT_INPUT.to_string(), -1i64)]),
        ..adjustment
    };
    assert!(matches!(
        g.adjust_usage(&cm, &other_lane).expect("the store reads"),
        Err(super::AdjustRefused::NotMetered { .. })
    ));

    let unknown = super::Adjustment {
        key_id: "vk_nobody",
        ..adjustment.clone()
    };
    assert_eq!(
        g.adjust_usage(&cm, &unknown).expect("the store reads"),
        Err(super::AdjustRefused::UnknownKey)
    );
    let empty = BTreeMap::from([(UNIT_INPUT.to_string(), 0i64)]);
    let nothing = super::Adjustment {
        delta: &empty,
        ..adjustment
    };
    assert_eq!(
        g.adjust_usage(&cm, &nothing).expect("the store reads"),
        Err(super::AdjustRefused::Empty)
    );
}

fn admit_after_adjust(id: &'static str, recorded: u64, corrected: u64) -> (bool, i64) {
    use busbar_contract::records::UNIT_INPUT;
    let g = gov();
    let day = limit(LimitMetric::Budget, 300, Some(LimitWindow::Day));
    let group = id.trim_start_matches("vk_");
    let cm = model_with_card(
        &[(group, group_cfg(None, true, vec![day]))],
        0,
        &[("m", 2.5, 0.0)],
    );
    let k = key(id, Some(group));
    g.store.put_key(&k).expect("key persists");
    let now = crate::store::now();
    g.record_usage(&cm, &k, "", "m", &toks(recorded, 0), now);
    metered(&g, &k.id, "m", recorded, now);
    let signed = |n: u64| i64::try_from(n).expect("the fixture's counts fit i64");
    let delta = BTreeMap::from([(UNIT_INPUT.to_string(), signed(corrected) - signed(recorded))]);
    let adjustment = super::Adjustment {
        key_id: &k.id,
        pool: "",
        model: "m",
        entry_era: era_now(),
        card_epoch_ms: now * 1_000,
        delta: &delta,
        now,
    };
    g.adjust_usage(&cm, &adjustment)
        .expect("the store reads")
        .expect("the correction applies");
    let bucket = format!("group:{group}@day");
    let read = (g.derived_bucket_usage(&cm, &bucket, "day", true, now))
        .expect("the read derives")
        .spend_cents;
    (g.try_admit(&cm, &k, "", now).is_ok(), read)
}

#[test]
fn an_upward_adjust_past_the_cap_is_enforced_at_admission() {
    assert_eq!(
        admit_after_adjust("vk_q51_door_up", 1_000_000, 1_400_000),
        (false, 350),
        "the book reads 350 of 300 cents, so admission refuses"
    );
}

#[test]
fn a_downward_adjust_under_the_cap_admits_at_admission() {
    assert_eq!(
        admit_after_adjust("vk_q51_door_down", 1_300_000, 800_000),
        (true, 200),
        "the book reads 200 of 300 cents, so admission admits"
    );
}

fn q64_two_pools(id: &'static str, group: &'static str) -> (GovState, CostModel, VirtualKey, u64) {
    let g = gov();
    let limits = vec![
        limit(LimitMetric::Budget, 100_000, Some(LimitWindow::Day)),
        pooled(LimitMetric::Budget, 100_000, LimitWindow::Day, "pool-a"),
        pooled(LimitMetric::Budget, 100_000, LimitWindow::Day, "pool-b"),
    ];
    let cm = model_with_card(
        &[(group, group_cfg(None, true, limits))],
        0,
        &[("m", 2.5, 0.0)],
    );
    let k = key(id, Some(group));
    g.store.put_key(&k).expect("key persists");
    let now = crate::store::now();
    g.record_usage(&cm, &k, "pool-a", "m", &toks(1_000_000, 0), now);
    g.record_usage(&cm, &k, "pool-b", "m", &toks(1_000_000, 0), now);
    metered(&g, &k.id, "m", 2_000_000, now);
    (g, cm, k, now)
}

fn q64_adjust(g: &GovState, cm: &CostModel, id: &str, now: u64, pool: Option<&str>) {
    use busbar_contract::records::UNIT_INPUT;
    let delta = BTreeMap::from([(UNIT_INPUT.to_string(), -200_000i64)]);
    let adjustment = super::Adjustment {
        key_id: id,
        pool: pool.unwrap_or(""),
        model: "m",
        entry_era: era_now(),
        card_epoch_ms: now * 1_000,
        delta: &delta,
        now,
    };
    g.adjust_usage(cm, &adjustment)
        .expect("the store reads")
        .expect("the correction applies");
}

fn q64_read(
    g: &GovState,
    cm: &CostModel,
    k: &VirtualKey,
    group: &str,
    now: u64,
) -> [(i64, u64); 4] {
    let key = g.usage_for(cm, &k.id, now).unwrap().unwrap();
    let bucket = |suffix: &str| {
        let id = format!("group:{group}@day{suffix}");
        let spend = (g.derived_bucket_usage(cm, &id, "day", true, now))
            .unwrap()
            .spend_cents;
        let gauge = g.bucket_model_tokens(&id, "day", now);
        (spend, gauge[0].1[busbar_contract::records::UNIT_INPUT])
    };
    [
        (key.spend_cents, key.tokens),
        bucket(""),
        bucket("#pool:pool-a"),
        bucket("#pool:pool-b"),
    ]
}

#[test]
fn a_pooled_adjust_moves_its_own_pool_bucket_and_no_other() {
    let (g, cm, k, now) = q64_two_pools("vk_q64_pooled", "q64p");
    let read = || q64_read(&g, &cm, &k, "q64p", now);
    let recorded = [
        (500, 2_000_000),
        (500, 2_000_000),
        (250, 1_000_000),
        (250, 1_000_000),
    ];
    assert_eq!(read(), recorded, "as recorded");
    q64_adjust(&g, &cm, "vk_q64_pooled", now, Some("pool-a"));
    assert_eq!(
        read(),
        [
            (450, 1_800_000),
            (450, 1_800_000),
            (200, 800_000),
            (250, 1_000_000),
        ],
        "as corrected: pool-a follows the key, pool-b is untouched"
    );
}

#[test]
fn an_adjust_naming_no_pool_moves_no_pool_bucket() {
    let (g, cm, k, now) = q64_two_pools("vk_q64_unscoped", "q64u");
    q64_adjust(&g, &cm, "vk_q64_unscoped", now, None);
    assert_eq!(
        q64_read(&g, &cm, &k, "q64u", now),
        [
            (450, 1_800_000),
            (450, 1_800_000),
            (250, 1_000_000),
            (250, 1_000_000),
        ],
    );
}

fn estimate_budget(admission: Option<crate::config::groups::AdmissionMode>) -> LimitCfg {
    let mut l = pooled(LimitMetric::Budget, 25, LimitWindow::Day, "frontier");
    l.admission = admission;
    l
}

fn estimate_card(limits: Vec<LimitCfg>) -> CostModel {
    model_with_card(
        &[("team", group_cfg(None, true, limits))],
        10,
        &[("m-cheap", 1.0, 0.0), ("m-dear", 2.0, 0.0)],
    )
}

fn expected_input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), n)])
}

#[test]
fn an_estimate_budget_refuses_at_the_dearest_destination_and_charges_nothing() {
    let g = gov();
    let cm = estimate_card(vec![estimate_budget(Some(
        crate::config::groups::AdmissionMode::Estimate,
    ))]);
    let k = key("vk_est", Some("team"));
    let now = 1_700_000_000;
    let want = expected_input(100_000);

    match g
        .try_admit_estimated(&cm, &k, "frontier", now, &["m-cheap", "m-dear"], &want)
        .unwrap_err()
    {
        LimitBlocked::Limit {
            metric: "budget", ..
        } => {}
        other => panic!("the estimate refuses on the budget, got {other:?}"),
    }

    g.try_admit_estimated(&cm, &k, "frontier", now, &["m-cheap"], &want)
        .expect("the cheap destination's estimate fits");

    g.try_admit(&cm, &k, "frontier", now)
        .expect("the refused unit left no fee behind");
    assert!(
        g.try_admit(&cm, &k, "frontier", now).is_err(),
        "three fees exceed 25"
    );
}

#[test]
fn an_exact_budget_ignores_the_estimate() {
    let g = gov();
    let cm = estimate_card(vec![estimate_budget(None)]);
    let k = key("vk_exact", Some("team"));
    g.try_admit_estimated(
        &cm,
        &k,
        "frontier",
        1_700_000_000,
        &["m-dear"],
        &expected_input(10_000_000),
    )
    .expect("exact refuses only a budget already exhausted");
}

#[test]
fn an_estimate_miss_downgrades_where_the_limit_declares_it() {
    let g = gov();
    let mut l = estimate_budget(Some(crate::config::groups::AdmissionMode::Estimate));
    l.on_exhaust = Some(crate::config::groups::OnExhaust::Downgrade);
    l.downgrade_to = Some(ScopeRef::pool("value"));
    let cm = estimate_card(vec![l]);
    let k = key("vk_est_dg", Some("team"));
    match g
        .try_admit_estimated(
            &cm,
            &k,
            "frontier",
            1_700_000_000,
            &["m-dear"],
            &expected_input(100_000),
        )
        .unwrap_err()
    {
        LimitBlocked::Limit {
            metric: "budget",
            downgrade_to: Some(to),
            ..
        } => assert_eq!(to, "value"),
        other => panic!("an estimate miss downgrades, got {other:?}"),
    }
}

#[test]
fn an_unpriceable_estimate_blocks_and_never_downgrades() {
    let g = gov();
    let mut l = estimate_budget(Some(crate::config::groups::AdmissionMode::Estimate));
    l.on_exhaust = Some(crate::config::groups::OnExhaust::Downgrade);
    l.downgrade_to = Some(ScopeRef::pool("value"));
    let cm = estimate_card(vec![l]);
    let k = key("vk_est_unpriced", Some("team"));
    match g
        .try_admit_estimated(
            &cm,
            &k,
            "frontier",
            1_700_000_000,
            &["m-unknown"],
            &expected_input(1),
        )
        .unwrap_err()
    {
        LimitBlocked::Limit {
            metric: "budget",
            downgrade_to: None,
            ..
        } => {}
        other => panic!("an unpriceable estimate blocks without a downgrade, got {other:?}"),
    }
}

#[test]
fn the_estimate_is_never_billed_or_held() {
    let g = gov();
    let cm = estimate_card(vec![estimate_budget(Some(
        crate::config::groups::AdmissionMode::Estimate,
    ))]);
    let k = key("vk_est_bill", Some("team"));
    let now = 1_700_000_000;
    g.try_admit_estimated(
        &cm,
        &k,
        "frontier",
        now,
        &["m-cheap"],
        &expected_input(100_000),
    )
    .expect("fits");
    let spend: Vec<i64> = g
        .budget_state(&cm, &k, now)
        .into_iter()
        .filter(|b| b.budget_group.is_some())
        .map(|b| b.spend_micros_at_current_rate)
        .collect();
    assert_eq!(
        spend,
        vec![10 * busbar_kernel_ledger::cost::MICROS_PER_CENT],
        "the fee alone, never the estimate"
    );
}

struct FlakyStore {
    inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    down: std::sync::atomic::AtomicBool,
    meter_down: std::sync::atomic::AtomicBool,
    era_down: std::sync::atomic::AtomicBool,
    before_add: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    lose_correction_reply: std::sync::atomic::AtomicBool,
    correction_calls: std::sync::Mutex<Vec<busbar_contract::records::correction::Request>>,
}

impl FlakyStore {
    fn new() -> Self {
        Self {
            inner: crate::real_store::store(),
            down: std::sync::atomic::AtomicBool::new(false),
            meter_down: std::sync::atomic::AtomicBool::new(false),
            era_down: std::sync::atomic::AtomicBool::new(false),
            before_add: std::sync::Mutex::new(None),
            lose_correction_reply: std::sync::atomic::AtomicBool::new(false),
            correction_calls: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn set_down(&self, down: bool) {
        self.down.store(down, std::sync::atomic::Ordering::SeqCst);
    }
}

impl RecordStore for FlakyStore {
    fn supports_usage_correction(&self) -> bool {
        true
    }
    fn apply_usage_correction(
        &self,
        request: &busbar_contract::records::correction::Request,
    ) -> RecordStoreResult<busbar_contract::records::correction::Decision> {
        self.correction_calls.lock().unwrap().push(request.clone());
        let hook = self.before_add.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RecordStoreError("planted correction write failure".into()));
        }
        let result = self.inner.apply_usage_correction(request);
        if self
            .lose_correction_reply
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(RecordStoreError("planted lost correction reply".into()));
        }
        result
    }
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(&self, bucket_id: &str, window: u64, l: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window, l)
    }
    fn add_usage(&self, bucket_id: &str, window: u64, d: &UsageDelta) -> RecordStoreResult<()> {
        if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RecordStoreError("the store is down".to_string()));
        }
        let hook = self.before_add.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if self.down.load(std::sync::atomic::Ordering::SeqCst)
            || (bucket_id.starts_with(super::ERA_BUCKET_PREFIX)
                && self.era_down.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Err(RecordStoreError("planted usage write failure".to_string()));
        }
        self.inner.add_usage(bucket_id, window, d)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        if self.meter_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RecordStoreError("the metering store is down".to_string()));
        }
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

#[path = "ledger_ownership_cases.rs"]
mod ledger_ownership_cases;

#[path = "ledger_correction_cases.rs"]
mod ledger_correction_cases;

#[path = "large_flush_cases.rs"]
mod large_flush_cases;

fn minute_fee_model() -> CostModel {
    model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(
                    LimitMetric::Budget,
                    1_000_000,
                    Some(LimitWindow::Minute),
                )],
            ),
        )],
        10,
        &[("m", 1.0, 1.0)],
    )
}

fn minute_row(store: &dyn RecordStore, bucket: &str, at: u64) -> (u64, u64, u64, u64) {
    let row = store
        .get_usage(bucket, crate::governance::budget_window("minute", at))
        .expect("the store reads");
    let m = row.models.iter().find(|m| m.model == "m");
    let unit = |u: &str| m.and_then(|m| m.usage_units.get(u).copied()).unwrap_or(0);
    (
        row.requests,
        row.billable_requests,
        unit(busbar_contract::records::UNIT_INPUT),
        unit(busbar_contract::records::UNIT_OUTPUT),
    )
}

#[test]
fn a_window_roll_before_the_flush_keeps_the_old_windows_counts() {
    let store = crate::real_store::store();
    let g = GovState::new(store.clone(), None).expect("memory store constructs");
    let cm = minute_fee_model();
    let k = key("vk_roll_delta", Some("g"));
    let w = 1_700_000_040;
    let w1 = w + 60;
    let bucket = "group:g@minute";

    g.try_admit(&cm, &k, "", w).expect("W admits");
    g.record_usage(&cm, &k, "", "m", &toks(1_000, 200), w);
    g.try_admit(&cm, &k, "", w1)
        .expect("W+1 admits and rolls the cell");
    g.flush_budgets();

    assert_eq!(
        minute_row(store.as_ref(), bucket, w),
        (1, 1, 1_000, 200),
        "W's request, fee and tokens reach W's durable row"
    );
    assert_eq!(
        minute_row(store.as_ref(), bucket, w1),
        (1, 1, 0, 0),
        "W+1 holds only its own request"
    );
    g.flush_budgets();
    assert_eq!(
        minute_row(store.as_ref(), bucket, w),
        (1, 1, 1_000, 200),
        "a second flush writes nothing twice"
    );
}

#[test]
fn a_store_outage_across_a_window_roll_retries_the_old_windows_delta() {
    let store = Arc::new(FlakyStore::new());
    let g = GovState::new(store.clone(), None).expect("store constructs");
    let cm = minute_fee_model();
    let k = key("vk_roll_outage", Some("g"));
    let w = 1_700_000_040;
    let w1 = w + 60;
    let bucket = "group:g@minute";

    store.set_down(true);
    g.try_admit(&cm, &k, "", w).expect("W admits");
    g.record_usage(&cm, &k, "", "m", &toks(500, 50), w);
    g.flush_budgets();
    g.try_admit(&cm, &k, "", w1)
        .expect("W+1 admits and rolls the cell");
    g.flush_budgets();
    store.set_down(false);
    g.flush_budgets();

    assert_eq!(minute_row(store.as_ref(), bucket, w), (1, 1, 500, 50));
    assert_eq!(minute_row(store.as_ref(), bucket, w1), (1, 1, 0, 0));
}

#[test]
fn a_stale_cell_still_owing_the_store_survives_the_sweep_and_is_written() {
    let store = Arc::new(FlakyStore::new());
    let g = GovState::new(store.clone(), None).expect("store constructs");
    let w = 1_700_000_040;
    let now = w + 32 * super::SECS_PER_DAY;
    let window = crate::governance::budget_window("minute", w);
    let owed = "group:gone@minute";

    {
        let mut map = g.budget.write("vk_sweep_owed");
        let mut cell = BudgetCell::fresh(window);
        cell.park(
            window,
            UsageDelta {
                requests: 1,
                billable_requests: 1,
                ..UsageDelta::default()
            },
        );
        cell.dirty = true;
        map.insert(owed.to_string(), cell);
    }

    g.budget.sweep_ticker_for("vk_sweep_owed").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        std::sync::atomic::Ordering::Relaxed,
    );
    g.try_admit(&minute_fee_model(), &key("vk_sweep_owed", None), "", now)
        .expect("the key admits");
    g.flush_budgets();

    assert_eq!(
        minute_row(store.as_ref(), owed, w),
        (1, 1, 0, 0),
        "the old window's parked counts reach its durable row"
    );
}

#[test]
fn a_window_roll_during_an_in_flight_flush_writes_the_old_window_once() {
    let store = Arc::new(FlakyStore::new());
    let g = Arc::new(GovState::new(store.clone(), None).expect("store constructs"));
    let cm = minute_fee_model();
    let k = key("vk_roll_inflight", Some("g"));
    let w = 1_700_000_040;
    let w1 = w + 60;
    let bucket = "group:g@minute";

    g.try_admit(&cm, &k, "", w).expect("W admits");
    g.record_usage(&cm, &k, "", "m", &toks(300, 30), w);
    let (roller, cm2, k2) = (g.clone(), minute_fee_model(), k.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        roller
            .try_admit(&cm2, &k2, "", w1)
            .expect("W+1 admits mid-flush");
    }));
    g.flush_budgets();
    g.flush_budgets();
    g.flush_budgets();

    assert_eq!(minute_row(store.as_ref(), bucket, w), (1, 1, 300, 30));
    assert_eq!(minute_row(store.as_ref(), bucket, w1), (1, 1, 0, 0));
}

#[test]
fn a_refund_after_a_roll_returns_the_fee_from_the_window_it_was_charged_in() {
    let store = crate::real_store::store();
    let g = GovState::new(store.clone(), None).expect("memory store constructs");
    let cm = minute_fee_model();
    let k = key("vk_refund_charged", Some("g"));
    let w = 1_700_000_040;
    let w1 = w + 60;
    let bucket = "group:g@minute";

    let a = (g.try_admit(&cm, &k, "", w)).expect("A admits in W, on W's cell");
    g.try_admit(&cm, &k, "", w1)
        .expect("B admits in W+1 and rolls the cell");
    g.refund_charge(a.charge());

    let live = (g.derived_bucket_usage(&cm, bucket, "minute", true, w1)).expect("W+1 reads");
    assert_eq!(live.spend_cents, 10, "B's fee stays on W+1");
    g.flush_budgets();
    assert_eq!(
        minute_row(store.as_ref(), bucket, w),
        (1, 0, 0, 0),
        "W keeps A's request slot; A's fee came back from W"
    );
    assert_eq!(minute_row(store.as_ref(), bucket, w1), (1, 1, 0, 0));
}

fn captured<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let r = tracing::subscriber::with_default(subscriber, f);
    (r, cap.messages())
}

#[test]
fn metering_overflow_coalescing_warns_once_per_window_naming_the_count() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let pending = PendingMetering::new();
    let ((), lines) = captured(|| {
        for i in 0..(MAX_PENDING_METERING_PER_SHARD + 3) {
            let key: MeterKey = (
                "vk_over".into(),
                1,
                format!("m{i}"),
                "p".into(),
                0,
                String::new(),
                String::new(),
            );
            pending.accrue(key, MeterCounts::default());
        }
    });
    let warns: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("metering accumulator at cap"))
        .collect();
    assert_eq!(
        warns.len(),
        1,
        "exactly one line for three coalesces: {lines:?}"
    );
    assert!(
        warns[0].contains("coalesced=1") || warns[0].contains("1 cell"),
        "the line names how many cells were coalesced: {}",
        warns[0]
    );
    assert!(
        crate::diagnostics::METERING_PENDING_OVERFLOW_COALESCED.severity
            == crate::diagnostics::Severity::Actionable
    );
}

#[test]
fn deleting_a_group_keeps_its_unflushed_spend_until_the_flush() {
    let store = crate::real_store::store();
    let g = GovState::new(store.clone(), None).expect("memory store constructs");
    let cm = minute_fee_model();
    let k = key("vk_reclaim", Some("g"));
    let w = 1_700_000_040;
    g.try_admit(&cm, &k, "", w).expect("admits");
    g.record_usage(&cm, &k, "", "m", &toks(1_000, 200), w);

    g.reclaim_group_cells("g");
    g.flush_budgets();

    assert_eq!(
        minute_row(store.as_ref(), "group:g@minute", w),
        (1, 1, 1_000, 200),
        "the deleted group's usage row is complete"
    );
}

#[test]
fn a_shutdown_flush_against_a_down_store_names_what_is_unrecorded() {
    let store = Arc::new(FlakyStore::new());
    let g = GovState::new(store.clone(), None).expect("store constructs");
    let cm = minute_fee_model();
    let k = key("vk_shutdown", Some("g"));
    let w = 1_700_000_040;
    g.try_admit(&cm, &k, "", w).expect("admits");
    g.record_usage(&cm, &k, "", "m", &toks(10, 2), w);
    store.set_down(true);
    store
        .meter_down
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let (_, lines) = captured(|| {
        g.flush_budgets_final();
        g.flush_metering_final();
    });
    let errs: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("shutdown") && l.contains("group:g@minute"))
        .collect();
    assert_eq!(
        errs.len(),
        1,
        "one shutdown error naming the bucket: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("will retry next tick")),
        "the shutdown path never promises a retry: {lines:?}"
    );

    let (_, lines) = captured(|| {
        g.flush_budgets();
    });
    assert!(
        lines.iter().any(|l| l.contains("will retry next tick")),
        "{lines:?}"
    );
}
