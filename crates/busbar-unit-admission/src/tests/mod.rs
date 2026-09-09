// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test support: the small config projection the tests build chains from, plus the assertions
//! every test shares.
//!
//! The projection here mirrors the one the resolver runs at boot — a limit materialises a bucket
//! per (window, pool) on first use, a metric repeated for the same window and pool keeps the most
//! restrictive amount, and for a spend cap the most restrictive one's exhaustion behaviour governs
//! because it is the cap that actually blocks. It lives in the tests rather than the library
//! because the door is handed a chain already resolved; it is here so the ported cases read the
//! way they read at the tag.

use std::collections::BTreeMap;

use crate::chain::{GroupBucket, GroupRuntime, GroupTable, STANDARD_TIER_BP};
use crate::decide::{Blocked, Door, Metric};
use crate::price::{Pricer, RateNanos};
use crate::window::{WINDOW_DAY, WINDOW_HOUR, WINDOW_MINUTE, WINDOW_MONTH, WINDOW_TOTAL};
use crate::{BucketChain, InMemoryCells};

mod cells;
mod hold;
mod leases;
mod ported;
mod price;

/// Which counter a limit caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitMetric {
    Requests,
    Tokens,
    TokensInput,
    TokensOutput,
    TokensCacheRead,
    TokensCacheWrite,
    Budget,
    Concurrent,
}

/// One configured limit.
#[derive(Debug, Clone)]
pub(crate) struct LimitCfg {
    pub metric: LimitMetric,
    pub amount: u64,
    pub per: Option<&'static str>,
    pub scope: Option<String>,
    pub downgrade_to: Option<String>,
}

/// One configured group.
#[derive(Debug, Clone)]
pub(crate) struct GroupCfg {
    pub parent: Option<String>,
    pub enabled: bool,
    pub tier_bp: u32,
    pub limits: Vec<LimitCfg>,
}

/// A windowed limit with no pool scope.
pub(crate) fn limit(metric: LimitMetric, amount: u64, per: Option<&'static str>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
        scope: None,
        downgrade_to: None,
    }
}

/// A windowed limit qualified to a pool.
pub(crate) fn pooled(metric: LimitMetric, amount: u64, per: &'static str, pool: &str) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: Some(pool.to_string()),
        downgrade_to: None,
    }
}

/// A group with a parent, a freeze flag and a set of limits.
pub(crate) fn group_cfg(parent: Option<&str>, enabled: bool, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled,
        tier_bp: STANDARD_TIER_BP,
        limits,
    }
}

/// Project a set of configured groups into the resolved table the chain walk chases.
pub(crate) fn table(groups: &[(&str, GroupCfg)]) -> GroupTable {
    let mut names: Vec<&str> = groups.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    let idx: BTreeMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let resolved: Vec<GroupRuntime> = names
        .iter()
        .map(|name| {
            let cfg = &groups
                .iter()
                .find(|(n, _)| n == name)
                .expect("named group exists")
                .1;
            let mut buckets: Vec<GroupBucket> = Vec::new();
            let mut concurrent_cap: Option<u64> = None;
            for l in &cfg.limits {
                match (l.metric, l.per) {
                    (LimitMetric::Concurrent, _) => {
                        concurrent_cap =
                            Some(concurrent_cap.map_or(l.amount, |c: u64| c.min(l.amount)));
                    }
                    (metric, Some(w)) => {
                        let pos = buckets
                            .iter()
                            .position(|b| b.window == w && b.scope == l.scope);
                        let bucket = match pos {
                            Some(i) => &mut buckets[i],
                            None => {
                                let bucket_id = match &l.scope {
                                    Some(s) => format!("group:{name}@{w}#pool:{s}"),
                                    None => format!("group:{name}@{w}"),
                                };
                                let mut b = GroupBucket::new(bucket_id, w);
                                b.scope = l.scope.clone();
                                buckets.push(b);
                                buckets.last_mut().expect("just pushed")
                            }
                        };
                        let min_u =
                            |cur: Option<u64>| Some(cur.map_or(l.amount, |c: u64| c.min(l.amount)));
                        match metric {
                            LimitMetric::Requests => {
                                bucket.requests_cap = min_u(bucket.requests_cap)
                            }
                            LimitMetric::Tokens => bucket.tokens_cap = min_u(bucket.tokens_cap),
                            LimitMetric::TokensInput => {
                                bucket.tokens_input_cap = min_u(bucket.tokens_input_cap)
                            }
                            LimitMetric::TokensOutput => {
                                bucket.tokens_output_cap = min_u(bucket.tokens_output_cap)
                            }
                            LimitMetric::TokensCacheRead => {
                                bucket.tokens_cache_read_cap = min_u(bucket.tokens_cache_read_cap)
                            }
                            LimitMetric::TokensCacheWrite => {
                                bucket.tokens_cache_write_cap = min_u(bucket.tokens_cache_write_cap)
                            }
                            LimitMetric::Budget => {
                                let amount = i64::try_from(l.amount).unwrap_or(i64::MAX);
                                if bucket.budget_cap.is_none_or(|c| amount < c) {
                                    bucket.downgrade_to = l.downgrade_to.clone();
                                }
                                bucket.budget_cap =
                                    Some(bucket.budget_cap.map_or(amount, |c: i64| c.min(amount)));
                            }
                            LimitMetric::Concurrent => unreachable!("matched above"),
                        }
                    }
                    (_, None) => {}
                }
            }
            GroupRuntime {
                name: (*name).to_string(),
                // The interned name is the composition root's to hand over, and this harness is
                // not the root: a table built here names no lease, which is the shape every
                // decision test below is written against.
                lease_id: None,
                enabled: cfg.enabled,
                concurrent_cap,
                tier_bp: cfg.tier_bp,
                buckets,
                parent: cfg.parent.as_deref().and_then(|p| idx.get(p).copied()),
            }
        })
        .collect();
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
        (crate::price::UNIT_INPUT, input),
        (crate::price::UNIT_OUTPUT, output),
        (crate::price::UNIT_CACHE_READ, cache_read),
        (crate::price::UNIT_CACHE_WRITE, cache_write),
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

// ── 1.6.0: the `week` window ─────────────────────────────────────────────────────────────────────

/// A week is aligned to UTC MONDAY midnight, and the arithmetic has to say so explicitly because
/// epoch day 0 (1970-01-01) is a THURSDAY -- a naive `now / SECS_PER_WEEK` would put every boundary
/// on a Thursday, which is not a week anybody writes a budget against.
#[test]
fn the_week_window_starts_on_monday_midnight_utc() {
    use crate::window::{budget_window, window_end, WINDOW_WEEK};
    const DAY: u64 = 86_400;

    // 2026-09-08 is a Tuesday. Days from epoch to 2026-09-07 (Monday) = 20_703.
    let monday = 20_703 * DAY;
    let tuesday_noon = monday + DAY + 12 * 3_600;

    assert_eq!(
        budget_window(WINDOW_WEEK, tuesday_noon),
        monday,
        "a Tuesday belongs to the Monday that opened its week"
    );
    // The boundary itself belongs to its own week, not to the one before it.
    assert_eq!(budget_window(WINDOW_WEEK, monday), monday);
    // One second earlier is the PREVIOUS week.
    assert_eq!(budget_window(WINDOW_WEEK, monday - 1), monday - 7 * DAY);
    // And it rolls exactly seven days on.
    assert_eq!(
        window_end(WINDOW_WEEK, tuesday_noon),
        Some(monday + 7 * DAY)
    );
}

/// The week is a KNOWN window word, so it never falls through the corrupt-row backstop that
/// enforces an unrecognized word as all-time. A `per: week` cap that silently enforced as `total`
/// would be a cap that never resets.
#[test]
fn the_week_window_is_a_known_word_and_never_falls_back_to_all_time() {
    use crate::window::{budget_window, is_known_window, ALL_WINDOWS, WINDOW_WEEK};
    assert!(is_known_window(WINDOW_WEEK));
    assert_eq!(ALL_WINDOWS.len(), 6);
    assert!(ALL_WINDOWS.contains(&WINDOW_WEEK));
    // The fall-safe answer is 0; a real week is not 0 (except in the epoch's own first week).
    assert_ne!(budget_window(WINDOW_WEEK, 20_703 * 86_400), 0);
}

/// Every window word the vocabulary lists resolves to a window start that CONTAINS the instant it
/// was asked about, and (except for the never-rolling all-time window) to an end after it. This is
/// the property a new window is most likely to break, and it is checked over the whole vocabulary
/// rather than over the new entry alone.
#[test]
fn every_window_word_brackets_the_instant_it_is_asked_about() {
    use crate::window::{budget_window, window_end, ALL_WINDOWS, WINDOW_TOTAL};
    let now = 20_703 * 86_400 + 45_296;
    for w in ALL_WINDOWS {
        let start = budget_window(w, now);
        assert!(start <= now, "{w}: the window start is at or before now");
        match window_end(w, now) {
            Some(end) => assert!(end > now, "{w}: the window ends after now"),
            None => assert_eq!(w, WINDOW_TOTAL, "only the all-time window never rolls"),
        }
    }
}
