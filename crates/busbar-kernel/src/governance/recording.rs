// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RECORDING COUNTS OFF THE REQUEST PATH, on the governance book (MONEY-DESIGN §3c, §3d): the
//! book's side of the [`Recorder`] (it takes the shards' pending deltas), strict mode's gate, and
//! the fleet snapshot admission reads without a lock or an await.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};
use std::time::Duration;

use busbar_contract::records::MeteringDelta;

use super::{budget_window, GovState};
use crate::posting::record::{sibling_bucket, CellCount};
use crate::posting::recorder::{Closed, Ledger, PostStore, Recorder};

/// A capped bucket's snapshot older than this, whose last read FAILED, raises strict mode's 503.
pub const SNAPSHOT_STALE_MS: u64 = 5_000;

/// The snapshot tick's cadence.
pub const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// Capped buckets touched within this are kept fresh.
pub const SNAPSHOT_TOUCHED_MS: u64 = 10 * 60 * 1_000;

/// How many buckets one tick reads at most (round-robin across ticks).
pub const SNAPSHOT_BUDGET: usize = 256;

/// One capped bucket's fleet reading.
#[derive(Debug, Clone, Default)]
pub struct Foreign {
    /// The window read.
    pub window: u64,
    /// Other nodes' counts in it (never negative).
    pub counts: CellCount,
    /// The last successful read, wall-clock ms.
    pub read_ms: u64,
    /// When reads began failing, if the last one failed.
    pub failing_since: Option<u64>,
}

/// THE FLEET SNAPSHOT: immutable, swapped whole by the tick.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    rows: HashMap<String, Foreign>,
    /// The round-robin cursor of the next tick.
    cursor: usize,
}

impl Snapshot {
    /// The reading for `bucket`, if any.
    #[must_use]
    pub fn get(&self, bucket: &str) -> Option<&Foreign> {
        self.rows.get(bucket)
    }

    /// How many buckets it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// The book as the recorder sees it (weakly: the book owns the recorder).
struct BookLedger(Weak<GovState>);

impl Ledger for BookLedger {
    fn take_pending(&self, mark: &dyn Fn(&str)) -> Vec<CellCount> {
        self.0
            .upgrade()
            .map(|g| g.take_pending(mark))
            .unwrap_or_default()
    }

    fn take_metering(&self) -> Vec<MeteringDelta> {
        self.0.upgrade().map(|g| g.take_metering()).unwrap_or_default()
    }

    fn landed(&self, cells: &[CellCount]) {
        if let Some(g) = self.0.upgrade() {
            g.landed(cells);
        }
    }

    fn unposted(&self, cells: &[CellCount]) {
        if let Some(g) = self.0.upgrade() {
            // Only the positive parts were ever added (at the take); they leave.
            let out: Vec<CellCount> = cells.iter().map(|c| c.signed_part(true).negated()).collect();
            g.adjust_posted(&out);
        }
    }

    fn reposted(&self, cells: &[CellCount]) {
        if let Some(g) = self.0.upgrade() {
            // READY: the whole signed delta is in the store now.
            g.adjust_posted(cells);
        }
    }
}

impl GovState {
    /// The [`Ledger`] the recorder takes from: this book, held weakly.
    #[must_use]
    pub fn ledger(self: &Arc<Self>) -> Arc<dyn Ledger> {
        Arc::new(BookLedger(Arc::downgrade(self)))
    }

    /// Keep the configured store's recorder, once. `false` when one was already kept.
    pub fn attach_recorder(&self, recorder: Arc<Recorder>) -> bool {
        self.recorder.set(recorder).is_ok()
    }

    /// The configured store's recorder, once attached.
    #[must_use]
    pub fn recorder(&self) -> Option<Arc<Recorder>> {
        self.recorder.get().cloned()
    }

    /// `advanced.strict_spend_recording` (read by every admission; set at every config apply).
    pub fn set_strict_spend_recording(&self, on: bool) {
        self.strict
            .store(on, std::sync::atomic::Ordering::Relaxed);
        if let Some(r) = self.recorder.get() {
            r.stamps().set_strict(on);
        }
    }

    /// Whether `bucket` has deltas in the recorder's accumulator or an unresolved carve: its cell
    /// is not evicted by the sweep.
    pub(crate) fn unrecorded(&self, bucket: &str) -> bool {
        self.recorder
            .get()
            .is_some_and(|r| r.stamps().unrecorded(bucket))
    }

    /// STRICT MODE's gate at `now_ms`: `None` with strict mode off (nothing on the request path
    /// changes), or when spend can be recorded; else why not. The shared stamps only, never the
    /// store.
    pub(crate) fn recording_gate(&self, now_ms: u64) -> Option<Closed> {
        if !self.strict.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.recorder
            .get()
            .and_then(|r| r.stamps().check(now_ms).err())
    }

    /// Other nodes' counts for capped `bucket` in `window`, from the snapshot, with no lock and no
    /// await. A bucket with no reading for this window reads 0 and wakes the snapshot task; under
    /// strict mode a reading whose last read failed over 5 s ago flags `strict`.
    pub(crate) fn foreign_for(
        &self,
        bucket: &str,
        window: u64,
        now_ms: u64,
        strict: &mut Option<Closed>,
    ) -> Option<CellCount> {
        let snap = self.foreign.load();
        let Some(f) = snap.get(bucket).filter(|f| f.window == window) else {
            if self.recorder.get().is_some() {
                self.snapshot_wake.notify_one();
            }
            return None;
        };
        if self.strict.load(std::sync::atomic::Ordering::Relaxed)
            && f
                .failing_since
                .is_some_and(|since| now_ms.saturating_sub(since) > SNAPSHOT_STALE_MS)
            && strict.is_none()
        {
            *strict = Some(Closed::SnapshotStale);
        }
        (!f.counts.is_zero()).then(|| f.counts.clone())
    }

    /// The fleet snapshot as it stands.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.foreign.load_full()
    }

    /// `cells`' amounts added to `posted_hi` (signed; another window's entry is skipped).
    pub(crate) fn adjust_posted(&self, cells: &[CellCount]) {
        for delta in cells {
            let mut guard = self.budget.write(&delta.bucket);
            guard.posted_add(delta);
        }
    }

    /// The capped buckets this node touched within [`SNAPSHOT_TOUCHED_MS`], with their windows.
    fn touched_capped(&self, cost: &crate::cost::CostModel, now: u64) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for shard in self.budget.shards.iter() {
            let map = shard.map.read().unwrap_or_else(|p| p.into_inner());
            for (id, cell) in map.iter() {
                if cell.last_touch.saturating_mul(1_000).saturating_add(SNAPSHOT_TOUCHED_MS)
                    >= now.saturating_mul(1_000)
                    && cost.bucket_enforces_a_cap(id)
                {
                    out.push((id.clone(), cell.window_start));
                }
            }
        }
        out.sort();
        out
    }

    /// ONE SNAPSHOT TICK: read (plain row first, then sibling) up to [`SNAPSHOT_BUDGET`] touched
    /// capped buckets, round-robin, and publish what other nodes hold beyond this node's
    /// `posted_hi`. A failed read keeps the previous reading and marks it failing.
    pub async fn refresh_snapshot(&self, cost: &crate::cost::CostModel, store: &dyn PostStore) {
        let now = crate::store::now();
        let now_ms = crate::store::now_ms();
        let touched = self.touched_capped(cost, now);
        let old = self.foreign.load_full();
        let mut next = Snapshot {
            rows: HashMap::new(),
            cursor: 0,
        };
        for (id, window) in &touched {
            if let Some(f) = old.rows.get(id).filter(|f| f.window == *window) {
                next.rows.insert(id.clone(), f.clone());
            }
        }
        if touched.is_empty() {
            self.foreign.store(Arc::new(next));
            return;
        }
        let start = old.cursor % touched.len();
        let n = touched.len().min(SNAPSHOT_BUDGET);
        for k in 0..n {
            let (id, window) = &touched[(start + k) % touched.len()];
            let read = async {
                let plain = store.get_usage(id, *window).await?;
                let sibling = store.get_usage(&sibling_bucket(id), *window).await?;
                Ok::<_, busbar_contract::store_calls::StoreFailure>((plain, sibling))
            }
            .await;
            match read {
                Ok((plain, sibling)) => {
                    let stored = super::state_rows(plain, sibling, *window);
                    let posted = self.posted_hi(id, *window).unwrap_or_default();
                    next.rows.insert(
                        id.clone(),
                        Foreign {
                            window: *window,
                            counts: foreign_of(&stored, &posted),
                            read_ms: now_ms,
                            failing_since: None,
                        },
                    );
                }
                Err(e) => {
                    tracing::debug!(bucket = %id, error = %e, "money: a fleet snapshot read failed; the previous reading stands");
                    let mut f = next.rows.get(id).cloned().unwrap_or(Foreign {
                        window: *window,
                        ..Foreign::default()
                    });
                    f.failing_since.get_or_insert(now_ms);
                    next.rows.insert(id.clone(), f);
                }
            }
        }
        next.cursor = (start + n) % touched.len().max(1);
        let stale = next
            .rows
            .values()
            .filter(|f| f.failing_since.is_some())
            .count();
        // Exported only once a read has failed (and back to 0 after), so a healthy node's scrape is
        // unchanged.
        static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if stale > 0 || SHOWN.load(std::sync::atomic::Ordering::Relaxed) {
            SHOWN.store(stale > 0, std::sync::atomic::Ordering::Relaxed);
            metrics::gauge!(crate::snapshot::MONEY_SNAPSHOT_FAILING).set(stale as f64);
        }
        self.foreign.store(Arc::new(next));
    }

    /// Run the snapshot tick for the process lifetime: every [`SNAPSHOT_EVERY`], and at once when a
    /// capped bucket is touched with no reading. `cost` answers the generation's cost model.
    pub fn spawn_snapshot(
        self: &Arc<Self>,
        store: Arc<dyn PostStore>,
        cost: impl Fn() -> Arc<crate::cost::CostModel> + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let gov = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(g) = gov.upgrade() else {
                    return;
                };
                let wake = async {
                    tokio::select! {
                        () = g.snapshot_wake.notified() => {}
                        () = tokio::time::sleep(SNAPSHOT_EVERY) => {}
                    }
                };
                wake.await;
                g.refresh_snapshot(&cost(), store.as_ref()).await;
            }
        })
    }

    /// The cell a VIEW prices: `cell` plus the snapshot's foreign counts for its window.
    pub(super) fn viewed(&self, bucket: &str, cell: super::BudgetCell) -> super::BudgetCell {
        match self.foreign.load().get(bucket) {
            Some(f) if f.window == cell.window_start && !f.counts.is_zero() => {
                cell.with_foreign(&f.counts)
            }
            _ => cell,
        }
    }

    /// The window of `period` at `now` (a convenience for the views).
    #[must_use]
    pub fn window_of(period: &str, now: u64) -> u64 {
        budget_window(period, now)
    }
}

/// WHAT OTHER NODES HOLD (MONEY-DESIGN §3d) in a stored row pair, given this node's `posted_hi`:
/// per segment `max(0, sibling - posted)`; per count the total `max(0, plain - posted_total)`; the
/// remainder (segment `""`) is the total minus the segments, and when the segments sum above the
/// total they are scaled down in proportion, rounding down, the residue going to the remainder.
#[must_use]
pub fn foreign_of(stored: &CellCount, posted: &CellCount) -> CellCount {
    let mut out = CellCount::new(&stored.bucket, stored.window);
    out.requests = (stored.requests - posted.requests).max(0);
    // The fee base, then each (model, class), as (segment -> stored, segment -> posted).
    let fee = |c: &CellCount| -> BTreeMap<String, i64> { c.billable.clone() };
    for (seg, n) in split(&fee(stored), &fee(posted)) {
        out.add_billable(&seg, n);
    }
    let mut keys: Vec<(String, String)> = Vec::new();
    for c in [stored, posted] {
        for models in c.units.values() {
            for (model, classes) in models {
                for class in classes.keys() {
                    let k = (model.clone(), class.clone());
                    if !keys.contains(&k) {
                        keys.push(k);
                    }
                }
            }
        }
    }
    for (model, class) in keys {
        let of = |c: &CellCount| -> BTreeMap<String, i64> {
            c.units
                .iter()
                .filter_map(|(seg, models)| {
                    models
                        .get(&model)
                        .and_then(|m| m.get(&class))
                        .map(|n| (seg.clone(), *n))
                })
                .collect()
        };
        for (seg, n) in split(&of(stored), &of(posted)) {
            out.add_unit(&seg, &model, &class, n);
        }
    }
    out.tidy();
    out
}

/// One count's foreign split: `stored` and `posted` by segment (`""` the remainder).
fn split(stored: &BTreeMap<String, i64>, posted: &BTreeMap<String, i64>) -> Vec<(String, i64)> {
    let total = |m: &BTreeMap<String, i64>| m.values().fold(0i64, |a, n| a.saturating_add(*n));
    let foreign_total = (total(stored) - total(posted)).max(0);
    let mut segs: Vec<(String, i64)> = stored
        .iter()
        .filter(|(seg, _)| !seg.is_empty())
        .map(|(seg, n)| (seg.clone(), (n - posted.get(seg).copied().unwrap_or(0)).max(0)))
        .filter(|(_, n)| *n > 0)
        .collect();
    let sum: i64 = segs.iter().map(|(_, n)| *n).sum();
    if sum > foreign_total {
        // Scale down in proportion, rounding down; the residue goes to the remainder.
        for (_, n) in &mut segs {
            *n = i64::try_from(i128::from(*n) * i128::from(foreign_total) / i128::from(sum.max(1)))
                .unwrap_or(0);
        }
    }
    let used: i64 = segs.iter().map(|(_, n)| *n).sum();
    let rem = (foreign_total - used).max(0);
    if rem > 0 {
        segs.push((String::new(), rem));
    }
    segs
}

#[cfg(test)]
#[path = "tests/recording_tests.rs"]
mod tests;
