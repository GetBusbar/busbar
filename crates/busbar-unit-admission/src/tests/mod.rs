// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test support: the spec values the tests resolve chains from, plus the assertions every test
//! shares.
//!
//! The projection is the cost unit's own `GroupTable::resolve`, driven from the same spec values the
//! composition root relays at boot. It used to be a third copy of that projection, kept here so the
//! ported cases read the way they read at the tag; a copy of the money topology's projection in a
//! test is a copy that can agree with itself and disagree with the one that ships, so the cases now
//! walk the buckets the shipped resolver materialises.

use std::collections::BTreeMap;

use busbar_unit_cost::{GroupSpec, LimitMetric, LimitSpec, ScopeSpec};

use crate::chain::{ChainWalk, GroupRuntime, GroupTable, STANDARD_TIER_BP};
use crate::decide::{Blocked, Door, Metric};
use crate::price::{Pricer, RateNanos};
use crate::window::{WINDOW_DAY, WINDOW_HOUR, WINDOW_MINUTE, WINDOW_MONTH, WINDOW_TOTAL};
use crate::{BucketChain, InMemoryCells};

mod cells;
mod hold;
mod leases;
mod ported;
mod price;

/// A pool-kind scope reference, the only kind the configuration grammar produces.
pub(crate) fn pool(name: &str) -> ScopeSpec {
    ScopeSpec {
        kind: "pool".to_string(),
        value: name.to_string(),
    }
}

/// A windowed limit with no pool scope.
pub(crate) fn limit(metric: LimitMetric, amount: u64, per: Option<&'static str>) -> LimitSpec {
    LimitSpec {
        metric,
        amount,
        window: per,
        scope: None,
        downgrade_to: None,
    }
}

/// A windowed limit qualified to a pool.
pub(crate) fn pooled(
    metric: LimitMetric,
    amount: u64,
    per: &'static str,
    scope: &str,
) -> LimitSpec {
    LimitSpec {
        metric,
        amount,
        window: Some(per),
        scope: Some(pool(scope)),
        downgrade_to: None,
    }
}

/// One configured group: the cost unit's spec, plus the tier multiplier the resolver does not read
/// from configuration and these tests set by hand.
#[derive(Debug, Clone)]
pub(crate) struct GroupCfg {
    pub spec: GroupSpec,
    pub tier_bp: u32,
}

/// A group with a parent, a freeze flag and a set of limits.
pub(crate) fn group_cfg(parent: Option<&str>, enabled: bool, limits: Vec<LimitSpec>) -> GroupCfg {
    GroupCfg {
        spec: GroupSpec {
            lease_id: None,
            parent: parent.map(str::to_string),
            enabled,
            limits,
        },
        tier_bp: STANDARD_TIER_BP,
    }
}

/// The configured groups, resolved by the COST UNIT into the table the chain walk chases — the one
/// projection in the tree, so every decision below is judged over the buckets the resolver really
/// materialises. The tier multiplier is the one field the resolver does not take from
/// configuration; it is written onto the resolved group afterwards, per test.
pub(crate) fn table(groups: &[(&str, GroupCfg)]) -> GroupTable {
    let specs: BTreeMap<String, GroupSpec> = groups
        .iter()
        .map(|(n, c)| (n.to_string(), c.spec.clone()))
        .collect();
    let mut resolved: Vec<GroupRuntime> = GroupTable::resolve(&specs).groups().to_vec();
    for g in &mut resolved {
        let (_, cfg) = groups
            .iter()
            .find(|(n, _)| *n == g.name)
            .expect("resolved from this set");
        g.tier_bp = cfg.tier_bp;
    }
    GroupTable::new(resolved)
}

/// The chain for a principal id bound to a group, or the fail-closed error.
pub(crate) fn chain_for(
    t: &GroupTable,
    id: &str,
    group: Option<&str>,
) -> Result<BucketChain, Blocked> {
    t.chain_for(id, group)
        .map_err(|m| Blocked::MissingGroup(m.0))
}

/// The chain for a principal, panicking if the group is missing.
pub(crate) fn chain(t: &GroupTable, id: &str, group: Option<&str>) -> BucketChain {
    chain_for(t, id, group).expect("group resolves")
}

/// A door over a fresh in-memory cell store.
pub(crate) fn door() -> Door<InMemoryCells> {
    Door::new(InMemoryCells::new())
}

/// A pricer with a flat fee and no rate card.
pub(crate) fn no_card(fee: i64) -> Pricer {
    Pricer::flat(fee)
}

/// A pricer with a flat fee and a card of (model, input micro-units/token, output
/// micro-units/token) entries.
pub(crate) fn card(fee: i64, entries: &[(&str, f64, f64)]) -> Pricer {
    let rates: BTreeMap<String, RateNanos> = entries
        .iter()
        .map(|(m, i, o)| {
            (
                (*m).to_string(),
                RateNanos::from_micros_per_token(*i, *o, 0.0, 0.0),
            )
        })
        .collect();
    if rates.is_empty() {
        Pricer::flat(fee)
    } else {
        Pricer::with_card(fee, rates)
    }
}

/// A four-key token map; a zero count is omitted, exactly as the ledger stores it.
pub(crate) fn toks_tiers(
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for (k, v) in [
        (busbar_contract::ids::DIM_TOKENS_IN, input),
        (busbar_contract::ids::DIM_TOKENS_OUT, output),
        (busbar_contract::ids::DIM_CACHE_READ, cache_read),
        (busbar_contract::ids::DIM_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            m.insert(k.to_string(), v);
        }
    }
    m
}

/// An input/output token map.
pub(crate) fn toks(input: u64, output: u64) -> BTreeMap<String, u64> {
    toks_tiers(input, output, 0, 0)
}

/// The exact blocking bucket must be NAMED: group, metric, window, and a retry hint for a rolling
/// window.
#[track_caller]
pub(crate) fn assert_blocked(
    err: Blocked,
    group: &str,
    metric: Metric,
    window: Option<&str>,
    has_retry: bool,
) {
    match err {
        Blocked::Limit {
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
        other => panic!("expected a Limit refusal, got {other:?}"),
    }
}

/// A bucket's request count and derived spend, the way an admin read would see it.
pub(crate) fn bucket_usage(
    d: &Door<InMemoryCells>,
    pricer: &Pricer,
    bucket_id: &str,
    window_word: &str,
    now: u64,
) -> (u64, u64, i64) {
    let window = crate::window::budget_window(window_word, now);
    match d.cells().snapshot(bucket_id) {
        Some(cell) if cell.window_start == window => (
            cell.requests,
            cell.total_tokens(),
            pricer.derive_spend_cents(cell.model_views(), cell.billable_requests, true),
        ),
        _ => (0, 0, 0),
    }
}

// Re-exported window words, so the ported cases spell them the way the config does.
pub(crate) const MINUTE: &str = WINDOW_MINUTE;
pub(crate) const HOUR: &str = WINDOW_HOUR;
pub(crate) const DAY: &str = WINDOW_DAY;
pub(crate) const MONTH: &str = WINDOW_MONTH;
pub(crate) const TOTAL: &str = WINDOW_TOTAL;
