// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the cost + limit model: rate-card derivation (tokens are the ledger, dollars derive)
//! and the resolved `groups:` limit topology (per-(group, window) enforcement buckets, the chain
//! walk, key encoding).

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::config::RateEntryCfg;
use busbar_api::VirtualKey;
use busbar_contract::ids::{DIM_TOKENS_IN, DIM_TOKENS_OUT};
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

/// rate_card is the ONLY cost source - pool members carry no cost, and the routing
/// scalar (`cheapest` / hook Candidate.cost_per_mtok) derives from a model's card entry as
/// the blended (input + output) / 2 in units/mtok.
#[test]
fn rate_card_is_sole_cost_source_and_drives_routing_scalar() {
    let c = card(&[("gpt-5", 2.5, 10.0)]);
    let cm = resolve_card_fee(Some(&c), 0);
    let r = cm.card().lane_rates("gpt-5", CurrencyCode::USD).unwrap();
    assert_eq!(
        (
            r.nanos_per_unit(DIM_TOKENS_IN),
            r.nanos_per_unit(DIM_TOKENS_OUT)
        ),
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
    // The walked groups are growth (innermost) then acme.
    let names: Vec<&str> = chain.groups().iter().map(|g| g.name.as_str()).collect();
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
    assert!(chain.groups().is_empty());
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

/// **THE ADMISSION PATH ALLOCATES NOTHING TO RESOLVE A CHAIN.**
///
/// The group half of an enforcement chain is decided by the group a key names and by nothing else,
/// and the model is immutable once resolved — so the admission unit's walk runs ONCE PER GROUP when
/// the model is built, and a request reads the result. That claim is the whole reason the retiring
/// engine could take the unit's OWNED `BucketChain` (`String` ids, `String` group names, `String`
/// scopes) without paying a heap allocation per bucket per request, so it is pinned here rather
/// than asserted in a comment.
///
/// The proof is IDENTITY, not equality: two different keys bound to the same group must read chains
/// at the SAME ADDRESS. A walk that rebuilt per request would return equal values at different
/// addresses and pass an `assert_eq!`; only the pointer comparison can tell the two apart. The
/// attribution bucket is the one per-request part and it is the key's own id, borrowed — asserted
/// here by reading it back off each chain.
#[test]
fn chain_read_is_a_borrow_not_a_build() {
    let groups = BTreeMap::from([(
        "growth".to_string(),
        group(
            None,
            vec![limit(LimitMetric::Requests, 50, Some(LimitWindow::Minute))],
        ),
    )]);
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let mut a = key(Some("growth"));
    a.id = "vk_a".into();
    let mut b = key(Some("growth"));
    b.id = "vk_b".into();

    let ca = cm.chain_for(&a).expect("resolves");
    let cb = cm.chain_for(&b).expect("resolves");

    let ptr_a = ca
        .iter()
        .nth(1)
        .expect("growth carries window buckets")
        .bucket_id
        .as_ptr();
    let ptr_b = cb
        .iter()
        .nth(1)
        .expect("growth carries window buckets")
        .bucket_id
        .as_ptr();
    assert_eq!(
        ptr_a, ptr_b,
        "two keys of one group read two DIFFERENT chains — the walk is running per request, and \
         every bucket of it is a fresh heap allocation on the admission path"
    );

    // The one per-request part is the key's own id, and it is borrowed from the key rather than
    // copied into a bucket the read had to build.
    let attribution_a = ca.iter().next().expect("always present");
    let attribution_b = cb.iter().next().expect("always present");
    assert_eq!(attribution_a.bucket_id, "vk_a");
    assert_eq!(attribution_b.bucket_id, "vk_b");
    assert!(std::ptr::eq(
        attribution_a.bucket_id.as_ptr(),
        a.id.as_ptr()
    ));
}
