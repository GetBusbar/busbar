// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The decision.
//!
//! This is the function that says yes or no, and it is 1.5.5's function, moved rather than
//! rewritten. Every comparison, every truncation and every ordering is the one at the tag. Where
//! the shape had to change — the ledger cells now arrive through a trait instead of through a
//! field — the change is mechanical and the arithmetic either side of it is untouched.
//!
//! The order of enforcement, and the reason for each position:
//!
//! 1. The chain is resolved. A principal bound to a group this node does not have fails closed:
//!    a chain whose caps cannot be read cannot be enforced, so nothing is admitted under it.
//! 2. The chain is filtered to the buckets this request's pool participates in. ONCE, here, so the
//!    check pass, the charge pass and the lock set can never disagree about what is in play.
//! 3. Freeze. Any disabled group anywhere in the chain refuses, before a gauge moves or a counter
//!    changes, so a frozen chain mutates nothing at all.
//! 4. The instantaneous in-flight gauges, innermost first, each taken by compare-and-swap so N
//!    racing admissions can never jointly overshoot. A full gauge rolls back the ones already
//!    taken and names its group.
//! 5. The windowed caps, both passes under one set of held locks: check every bucket and return on
//!    the FIRST that blocks, charging nothing; then, only if all of them passed, charge every one
//!    of them. All-or-nothing, and indivisible against a concurrent admission.
//!
//! Per-metric semantics, which differ and are meant to:
//!
//! - Requests is precise: the plus-one charge is synchronous with the check.
//! - Tokens is best-effort and post-paid. Tokens land after the response, so the cap blocks the
//!   NEXT request once the ledgered total has crossed it; the tokens of requests already in flight
//!   are invisible to admissions racing them. A hard token cap would need an admit-time
//!   reservation, and that would refuse requests the tag admitted.
//! - Budget is derived at check time from the cell's token ledger against the current rate table,
//!   plus the flat fee times the billable request count. The prospective post-charge spend — one
//!   more fee — must stay within the cap, and a bucket already at or over the cap blocks. The fee
//!   component is hard; token overshoot past a cap is bounded by the tokens of the requests already
//!   admitted and in flight.
//!
//! Synchronous and infallible: in-memory cells, no store round-trip, no await.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};

use crate::cells::{CellStore, Cells, LedgerCell};
use crate::chain::{BucketChain, ChainBucket};
use crate::price::Pricer;
use crate::window::{budget_window, window_end, WINDOW_TOTAL};

/// Which counter blocked. The word is the operator-facing metric name, and it is what the refusal
/// prints, so the vocabulary is closed here rather than assembled at the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// The request-count cap.
    Requests,
    /// The total-token cap.
    Tokens,
    /// The uncached-input token cap.
    TokensInput,
    /// The output token cap.
    TokensOutput,
    /// The cache-read token cap.
    TokensCacheRead,
    /// The cache-write token cap.
    TokensCacheWrite,
    /// The derived-spend cap.
    Budget,
    /// The instantaneous in-flight gauge.
    Concurrent,
}

impl Metric {
    /// The metric as the refusal spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Metric::Requests => "requests",
            Metric::Tokens => "tokens",
            Metric::TokensInput => "tokens_input",
            Metric::TokensOutput => "tokens_output",
            Metric::TokensCacheRead => "tokens_cache_read",
            Metric::TokensCacheWrite => "tokens_cache_write",
            Metric::Budget => "budget",
            Metric::Concurrent => "concurrent",
        }
    }

    /// Whether this metric is a spend cap. The one dialect that answers an over-quota block with a
    /// different status than a rate-limit block keys off exactly this, so it is a property of the
    /// metric rather than a decision the renderer makes.
    pub fn is_quota(self) -> bool {
        matches!(self, Metric::Budget)
    }
}

/// Why an admission was refused, carried out whole so the renderer can name the exact blocking
/// bucket. Built only on the refusal path, so the owned strings are off the admitting path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// A specific bucket blocked.
    Limit {
        /// The group that owns the bucket.
        group: String,
        /// Which counter blocked.
        metric: Metric,
        /// The window word — `None` for the instantaneous gauge, which has no window.
        window: Option<&'static str>,
        /// The pool the bucket is qualified to, when a pool-qualified bucket blocked. Only that
        /// pool's traffic is capped, and saying so tells the caller the actionable part.
        pool: Option<String>,
        /// For a budget block whose limit declared a downgrade: the pool the caller should be
        /// re-admitted through instead of refused.
        downgrade_to: Option<String>,
        /// Seconds until the window rolls. `None` for the all-time window, which never rolls, and
        /// for the gauge.
        retry_after: Option<u64>,
    },
    /// A group in the chain is frozen. Every request charging through it is refused while its
    /// history is kept.
    Disabled(String),
    /// The principal names a group this node's config does not have — fail-closed.
    MissingGroup(String),
}

/// The in-flight holds an admission acquires on every concurrent-capped group in the chain.
///
/// Releasing on drop is what makes the gauge impossible to leak: the grant rides with the request
/// and comes back however the request ends, including every error path and every unwind.
#[derive(Default)]
pub struct AdmitGrant {
    gauges: Vec<Arc<AtomicI64>>,
}

impl AdmitGrant {
    /// How many gauges this grant holds. One per concurrent-capped GROUP in the chain — a group
    /// with a concurrent cap and two windowed caps takes one, not three.
    pub fn held(&self) -> usize {
        self.gauges.len()
    }
}

impl Drop for AdmitGrant {
    fn drop(&mut self) {
        for g in &self.gauges {
            g.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for AdmitGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitGrant")
            .field("gauges", &self.gauges.len())
            .finish()
    }
}

/// The per-group in-flight gauges. Node-local and in-memory: an instantaneous count of what is
/// running here right now, which is what "concurrent" means and all it can mean.
#[derive(Debug, Default)]
pub struct Gauges {
    map: RwLock<std::collections::HashMap<String, Arc<AtomicI64>>>,
}

impl Gauges {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The gauge for a group, materialised on first sight. A read lock on the common path; the
    /// write lock is taken only to insert a missing gauge, once per group per process lifetime.
    fn gauge(&self, group: &str) -> Arc<AtomicI64> {
        if let Some(g) = self
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
        {
            return g.clone();
        }
        self.map
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(group.to_string())
            .or_default()
            .clone()
    }

    /// The current in-flight count for a group.
    pub fn in_flight(&self, group: &str) -> i64 {
        self.map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// The door.
///
/// Holds the two pieces of node-local state the decision needs — the in-flight gauges, and the
/// store the ledger cells come through — and nothing else. The rate table and the chain arrive per
/// request, because both can change under a config reload and a request must be judged against the
/// table current when it arrived.
#[derive(Debug)]
pub struct Door<S: CellStore> {
    cells: S,
    gauges: Gauges,
}

impl<S: CellStore> Door<S> {
    /// A door over a cell store.
    pub fn new(cells: S) -> Self {
        Door {
            cells,
            gauges: Gauges::new(),
        }
    }

    /// The cell store, for the ledger's own reads.
    pub fn cells(&self) -> &S {
        &self.cells
    }

    /// The in-flight gauges.
    pub fn gauges(&self) -> &Gauges {
        &self.gauges
    }

    /// Check and charge the whole chain for one request. `Ok` means admitted AND charged: one
    /// request landed on every bucket of the pool-filtered chain, the uncapped attribution bucket
    /// included, and the returned grant holds the in-flight gauges until it is dropped.
    ///
    /// `now` must be the pinned arrival epoch the rest of the request will use, not a fresh clock
    /// read, so a request straddling a window boundary can never split its charges across two
    /// windows.
    pub fn try_admit(
        &self,
        pricer: &Pricer,
        chain: &BucketChain,
        pool: &str,
        now: u64,
    ) -> Result<AdmitGrant, Blocked> {
        // Pool-scoped buckets participate only when THIS request's pool matches; filtered once
        // here so the check pass, the charge pass and the lock set can never disagree.
        let buckets: Vec<&ChainBucket> = chain.pool_filtered(pool);

        // 1. FREEZE check: any disabled group in the chain refuses — checked before any gauge or
        // charge, so a frozen chain mutates nothing.
        for g in chain.groups() {
            if !g.enabled {
                return Err(Blocked::Disabled(g.name.clone()));
            }
        }

        // 2. CONCURRENT holds, innermost first. The update is a compare-and-swap loop: the
        // increment lands only while strictly under the cap, so N racing admissions can never
        // jointly overshoot. On a full gauge, roll back the holds already taken by dropping the
        // grant, and name the group.
        let mut grant = AdmitGrant::default();
        for g in chain.groups() {
            let Some(cap) = g.concurrent_cap else {
                continue;
            };
            let gauge = self.gauges.gauge(&g.name);
            let cap = i64::try_from(cap).unwrap_or(i64::MAX);
            let admitted = gauge
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    (v < cap).then_some(v + 1)
                })
                .is_ok();
            if !admitted {
                drop(grant); // release the holds taken so far
                return Err(Blocked::Limit {
                    group: g.name.clone(),
                    metric: Metric::Concurrent,
                    window: None,
                    pool: None,
                    downgrade_to: None,
                    retry_after: None,
                });
            }
            grant.gauges.push(gauge);
        }

        // 3. WINDOWED limits. One locked view over every bucket in play, held across BOTH passes.
        let fee = pricer.price_per_request_cents();
        let ids: Vec<&str> = buckets.iter().map(|b| b.bucket_id.as_str()).collect();
        let mut cells = self.cells.lock(&ids);

        // PASS 1 — CHECK every bucket under the held view: resolve its cell for ITS OWN current
        // window (missing or stale cells read as empty) and test each configured cap. The blocking
        // bucket is named exactly, and the first one in chain order is the one that answers.
        for bucket in buckets.iter() {
            if bucket.is_uncapped() {
                continue; // an attribution bucket is charged, and never blocks
            }
            let window = budget_window(bucket.window, now);
            // Read the LIVE cell when it holds this window OR a NEWER one. That second case is the
            // straddle: `now` is the pinned arrival epoch, so a request admitted just before a
            // boundary can arrive after a concurrent admission already rolled the cell forward —
            // its charge lands on the live cell in pass 2, so the check must read that same cell
            // rather than treat it as a fresh window. Only a genuinely older or absent cell reads
            // as empty.
            //
            // A per-tier counter is read only when its own cap is set, the same best-effort
            // post-paid shape as the total. The input tier reads uncached input alone, so a cached
            // prompt read never counts against an input cap.
            let (requests, tokens, t_input, t_output, t_cache_read, t_cache_write, derived) =
                match cells.get(&bucket.bucket_id) {
                    Some(cell) if cell.window_start >= window => (
                        cell.requests,
                        if bucket.tokens_cap.is_some() {
                            cell.total_tokens()
                        } else {
                            0
                        },
                        if bucket.tokens_input_cap.is_some() {
                            cell.total_input()
                        } else {
                            0
                        },
                        if bucket.tokens_output_cap.is_some() {
                            cell.total_output()
                        } else {
                            0
                        },
                        if bucket.tokens_cache_read_cap.is_some() {
                            cell.total_cache_read()
                        } else {
                            0
                        },
                        if bucket.tokens_cache_write_cap.is_some() {
                            cell.total_cache_write()
                        } else {
                            0
                        },
                        if bucket.budget_cap.is_some() {
                            pricer.derive_spend_cents(
                                cell.model_views(),
                                cell.billable_requests,
                                true,
                            )
                        } else {
                            0
                        },
                    ),
                    // stale or absent cell = fresh window = nothing used
                    _ => (0, 0, 0, 0, 0, 0, 0),
                };
            let blocked_metric = if bucket
                .requests_cap
                .is_some_and(|cap| requests.saturating_add(1) > cap)
            {
                Some(Metric::Requests)
            } else if bucket.tokens_cap.is_some_and(|cap| tokens >= cap) {
                Some(Metric::Tokens)
            } else if bucket.tokens_input_cap.is_some_and(|cap| t_input >= cap) {
                Some(Metric::TokensInput)
            } else if bucket.tokens_output_cap.is_some_and(|cap| t_output >= cap) {
                Some(Metric::TokensOutput)
            } else if bucket
                .tokens_cache_read_cap
                .is_some_and(|cap| t_cache_read >= cap)
            {
                Some(Metric::TokensCacheRead)
            } else if bucket
                .tokens_cache_write_cap
                .is_some_and(|cap| t_cache_write >= cap)
            {
                Some(Metric::TokensCacheWrite)
            } else if bucket
                .budget_cap
                .is_some_and(|cap| derived >= cap || derived.saturating_add(fee) > cap)
            {
                Some(Metric::Budget)
            } else {
                None
            };
            if let Some(metric) = blocked_metric {
                drop(cells); // release the view before the cold refusal build
                drop(grant); // release the concurrent holds — nothing was admitted
                return Err(Blocked::Limit {
                    group: bucket
                        .group_name
                        .clone()
                        .expect("only group buckets carry caps"),
                    metric,
                    window: Some(bucket.window),
                    pool: bucket.scope.clone(),
                    // A downgrade is declared on, and validated against, the BUDGET metric only;
                    // a requests or tokens block on the same bucket still blocks.
                    downgrade_to: if metric == Metric::Budget {
                        bucket.downgrade_to.clone()
                    } else {
                        None
                    },
                    retry_after: window_end(bucket.window, now)
                        .map(|end| end.saturating_sub(now).max(1)),
                });
            }
        }

        // PASS 2 — CHARGE every bucket under the SAME held view: one request and one billable
        // request each, atomic all-or-nothing with the checks above. Straddle-safe cell
        // resolution, mirroring accrual: reset ONLY a genuinely stale cell (this window strictly
        // newer); a cell holding the same or a newer window is charged in place.
        for bucket in buckets.iter() {
            let window = budget_window(bucket.window, now);
            let cell = resolve_for_charge(&mut cells, &bucket.bucket_id, window);
            cell.requests = cell.requests.saturating_add(1);
            cell.billable_requests = cell.billable_requests.saturating_add(1);
            cell.dirty = true;
            cell.last_touch = now;
        }
        Ok(grant)
    }

    /// Refund the request charged at admission across every bucket of the chain, for a request
    /// that produced no usable result.
    ///
    /// What comes back is the FEE, and only the fee: the flat fee bills successes only, and it
    /// derives from the billable count, so decrementing that returns it. The admission count is
    /// never touched, so a failed request still consumed its request slot — otherwise a caller
    /// escapes a requests cap by hammering failures, each one refunding its own slot, and the cap
    /// only ever counts successes.
    ///
    /// `now` must be the same pinned epoch the admission charge used, so the refund lands in the
    /// same window per bucket; a bucket whose window has since rolled is a no-op. Floored at zero:
    /// a refund can never drive a counter negative.
    pub fn refund_request(&self, chain: &BucketChain, pool: &str, now: u64) {
        // Refund EXACTLY the buckets the admission charged: the same pool predicate, so a
        // pool-qualified bucket another pool's request never charged is never eroded by its refund.
        for bucket in chain.pool_filtered(pool) {
            self.refund_bucket(&bucket.bucket_id, bucket.window, now);
        }
    }

    /// The fail-closed twin of [`Door::refund_request`], for a request whose chain could not be
    /// resolved. The charge failed closed on the missing group, so nothing was charged; the
    /// principal's own bucket is refunded defensively and floors at zero on the no-op.
    pub fn refund_unchained(&self, attribution_bucket_id: &str, now: u64) {
        self.refund_bucket(attribution_bucket_id, WINDOW_TOTAL, now);
    }

    fn refund_bucket(&self, bucket_id: &str, period: &str, now: u64) {
        let window = budget_window(period, now);
        let mut cells = self.cells.lock(&[bucket_id]);
        if let Some(cell) = cells.get_mut(bucket_id) {
            if cell.window_start == window {
                cell.billable_requests = cell.billable_requests.saturating_sub(1);
                cell.dirty = true;
            }
        }
    }

    /// Ledger one response's tokens onto every bucket of the chain this request's pool
    /// participates in. Accrual mirrors the charge exactly — same chain, same pool predicate — so
    /// what a bucket counts is precisely the traffic it admitted.
    ///
    /// Straddle-safe like the charge: a cell holding the same or a newer window is credited in
    /// place, so a straddling request's tokens attribute to the live window rather than being
    /// dropped.
    pub fn record_usage(
        &self,
        chain: &BucketChain,
        pool: &str,
        model: &str,
        units: &BTreeMap<String, u64>,
        now: u64,
    ) {
        if units.values().all(|v| *v == 0) {
            return; // nothing to ledger
        }
        for bucket in chain.pool_filtered(pool) {
            self.accrue_bucket(&bucket.bucket_id, bucket.window, model, units, now);
        }
    }

    /// Ledger tokens to the principal's own bucket alone. A missing group cannot block accrual —
    /// the request was already admitted and served — so the tokens degrade to here rather than
    /// being lost.
    pub fn record_usage_unchained(
        &self,
        attribution_bucket_id: &str,
        model: &str,
        units: &BTreeMap<String, u64>,
        now: u64,
    ) {
        if units.values().all(|v| *v == 0) {
            return;
        }
        self.accrue_bucket(attribution_bucket_id, WINDOW_TOTAL, model, units, now);
    }

    fn accrue_bucket(
        &self,
        bucket_id: &str,
        period: &str,
        model: &str,
        units: &BTreeMap<String, u64>,
        now: u64,
    ) {
        let window = budget_window(period, now);
        let mut cells = self.cells.lock(&[bucket_id]);
        let cell = resolve_for_charge(&mut cells, bucket_id, window);
        cell.accrue(model, units);
        cell.dirty = true;
        cell.last_touch = now;
    }
}

/// Straddle-safe cell resolution, shared by the charge and the accrual so the two can never drift:
/// reset only a genuinely stale cell, credit a same-or-newer one in place, insert a fresh one when
/// the bucket has none.
///
/// The two lookups are the price of reaching the cells through a trait rather than a field; the
/// outcome is the same one either way.
fn resolve_for_charge<'c, C: Cells + ?Sized>(
    cells: &'c mut C,
    bucket_id: &str,
    window: u64,
) -> &'c mut LedgerCell {
    match cells.get(bucket_id).map(|c| c.window_start) {
        Some(existing) if window > existing => {
            let cell = cells.get_mut(bucket_id).expect("just observed");
            *cell = LedgerCell::fresh(window);
            cell
        }
        Some(_) => cells.get_mut(bucket_id).expect("just observed"),
        None => cells.insert_fresh(bucket_id, window),
    }
}
