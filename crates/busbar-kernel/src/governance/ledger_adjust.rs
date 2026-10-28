// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE LEDGER'S ADMIN READ AND ITS ONE CORRECTION (MONEY-DESIGN §4, Busbar PR-C).
//!
//! Money is the ledger's counts x the rate card, computed in core. The ledger is these usage rows:
//! a bucket's cell in RAM, its durable row behind it. There is no second book, so the admin ledger
//! views price exactly what [`GovState::derived_bucket_usage`] prices, and an operator's
//! correction is a SIGNED DELTA on those same counts:
//!
//! - it names the unit it corrects by its CARD EPOCH (`card_epoch_ms`, the unit's arrival instant)
//!   and the card entry its counts were earned under (`entry_era`), which must be the entry they
//!   were dated with at that epoch;
//! - IT LANDS WHERE ITS UNIT WAS LEDGERED, never where the correction is made (Q128 arch u32 #18,
//!   carried onto the one ledger: money is the counts x the card in effect at the ledgered unit's
//!   time): in each bucket, the window holding the epoch, and in that window the unit's lane in the
//!   latest era not after the epoch (a new segment at the entry in force then when the window holds
//!   none of that lane), and on the metering day holding the epoch;
//! - it lands on every bucket an accrual of the unit would have landed on (the key's own, and each
//!   group bucket its pool participates in), all or nothing;
//! - it is applied in RAM at once — to the live cell's `cur` when the cell still holds the epoch's
//!   window, else parked under that window ([`BudgetCell::park`]) like a rolled window's counts — so
//!   every view and every admission sees it, and the write-behind flush carries it to the store as a
//!   signed `add_usage` delta under that window — today's path, until the poster replaces it (PR-B2);
//! - FAIL CLOSED: a correction whose card cannot be resolved (no entry covers its epoch, or it names
//!   another entry than the one its counts were dated with), whose epoch's window holds none of its
//!   counts for a downward delta to move, or that would take any count of its segment below zero is
//!   REFUSED, with the reason, and nothing is applied, so no store floors the row while RAM goes
//!   negative (MONEY-REVIEW review 17, NB5) and no correction is ever moved onto another window's
//!   counts;
//! - it reaches THE METERED VIEW (`GET /api/v1/admin/usage`) as an ADJUSTMENT ROW: the metering rows
//!   carry unsigned counts, so the signed delta is kept beside them on two usage rows of the day
//!   ([`ADJUST_UP_BUCKET`], [`ADJUST_DOWN_BUCKET`]), each only ever added to, and the usage read
//!   folds them into the day's metering rows of the same key, lane and era
//!   ([`GovState::usage_adjustments`]). The view prices the counts AS ADJUSTED, through the same one
//!   function; it carries no money of its own. An adjustment the epoch day's metering rows cannot
//!   carry (no row of that key, lane and era, or a count it would take below zero) is refused too.
//!
//! A child module of `state`, so it reaches that module's private helpers (`bucket_cell`,
//! `durable_cell`) exactly as a method written there would.

use super::*;

/// The usage row a day's UPWARD adjustments accumulate on: per slot ([`adjustment_slot`]), per
/// class, the sum of every positive delta. Only ever added to.
pub const ADJUST_UP_BUCKET: &str = "adjust:usage+";

/// The usage row a day's DOWNWARD adjustments accumulate on: per slot, per class, the sum of every
/// negative delta's magnitude. Only ever added to. Up minus down is the day's signed adjustment.
pub const ADJUST_DOWN_BUCKET: &str = "adjust:usage-";

/// The separator of an adjustment slot's three parts. Not [`PLANE_LANE_SEP`], which a lane carries.
const SLOT_SEP: char = '\u{1e}';

/// The model name an adjustment row keeps one (key, lane, era) under.
fn adjustment_slot(key_id: &str, lane: &str, era: u64) -> String {
    format!("{key_id}{SLOT_SEP}{lane}{SLOT_SEP}{era}")
}

/// A metering row's LANE: a non-fallback plane's row is that plane's lane (`<plane><sep><model>`),
/// every other row its model — the lane its counts were accrued on in the budget book.
#[must_use]
pub fn metering_lane<'a>(model: &'a str, provider: &str) -> std::borrow::Cow<'a, str> {
    match crate::plane_driver::registry::plane_decl_for(provider) {
        Some(decl) if !decl.fallback => {
            std::borrow::Cow::Owned(format!("{}{}{model}", decl.key, PLANE_LANE_SEP))
        }
        _ => std::borrow::Cow::Borrowed(model),
    }
}

/// One day's net adjustment of one (key, lane, era): what the usage read folds into the day's
/// metering rows of that key, lane and era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageAdjustment {
    /// The key whose counts were adjusted.
    pub key_id: String,
    /// The lane, as [`metering_lane`] names a metering row's.
    pub lane: String,
    /// The era (`priced_from_ms`) of the metering rows it lands on.
    pub era: u64,
    /// The signed net delta per class. Zero nets are left off.
    pub delta: BTreeMap<String, i64>,
}

/// One class's count on a metering row: the four token columns under their reserved spellings,
/// every other class from the row's `usage_units`.
fn metered_count(row: &MeteringRow, class: &str) -> u64 {
    match class {
        busbar_contract::records::UNIT_INPUT => row.tokens_input,
        busbar_contract::records::UNIT_OUTPUT => row.tokens_output,
        busbar_contract::records::UNIT_CACHE_READ => row.tokens_cache_read,
        busbar_contract::records::UNIT_CACHE_WRITE => row.tokens_cache_write,
        other => row.usage_units.get(other).copied().unwrap_or(0),
    }
}

/// One bucket's current window, priced by the one function: what the admin ledger views serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedBucket {
    /// The window the cell holds, as the unix second it opens at (`0` = the all-time window).
    pub window_start: u64,
    /// Admitted requests in the window.
    pub requests: u64,
    /// Billable requests in the window: the fee base.
    pub billable_requests: u64,
    /// The cell's counts priced at the card each era was earned under, fee included, or the one
    /// function's refusal (a card silent about a lane or class, no card in force, out of range).
    pub spend: Result<busbar_kernel_ledger::cost::Money, MoneyError>,
}

/// One operator correction to a unit's counts, as signed deltas.
#[derive(Debug, Clone)]
pub struct Adjustment<'a> {
    /// The key whose counts are corrected.
    pub key_id: &'a str,
    /// The pool the unit was dispatched through (Q64/Q67): a group bucket takes the correction only
    /// if its pool participates, as the accrual did.
    pub pool: &'a str,
    /// The lane (model) the counts were earned on.
    pub model: &'a str,
    /// THE ENTRY: the `effective_from` of the card entry the counts were priced with. It must be the
    /// entry they were dated with at [`Self::card_epoch_ms`] (the latest era the epoch day's
    /// metering of the key and lane carries at or before it); any other is refused.
    pub entry_era: u64,
    /// THE CARD EPOCH: the corrected unit's arrival instant in milliseconds, whose card its counts
    /// price at. It picks each bucket's window (the one holding it), the segment in that window,
    /// and the metering day — never the instant the correction is made.
    pub card_epoch_ms: u64,
    /// The signed delta per class. Zero deltas are ignored.
    pub delta: &'a BTreeMap<String, i64>,
    /// The instant the correction is made, wall seconds: the touched cells' last touch, and nothing
    /// else.
    pub now: u64,
}

/// Why an adjustment was refused. Nothing was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjustRefused {
    /// No key by that id.
    UnknownKey,
    /// The correction carries no non-zero delta.
    Empty,
    /// The day's metering rows hold no count of that key, lane and era to adjust.
    NotMetered {
        /// The metering day (its UTC-day start, unix seconds).
        day: u64,
    },
    /// The delta would take a count of its segment below zero (or past `u64`).
    Exceeds {
        /// The bucket it would have landed on.
        bucket: String,
        /// The class.
        class: String,
        /// What the segment holds now.
        count: u64,
        /// The delta asked for.
        delta: i64,
    },
    /// No rate-card entry covers the corrected unit's epoch: its card cannot be resolved.
    NoCardInForce {
        /// The epoch, unix milliseconds.
        at: u64,
    },
    /// The entry the correction names is not the one its unit's counts were dated with: it begins
    /// after the epoch, or the epoch day's metering of the key and lane is dated with a later
    /// entry at or before the epoch.
    NotInForce {
        /// The `effective_from` of the entry named.
        named: u64,
        /// The `effective_from` of the entry the counts were dated with at the epoch.
        in_force: u64,
    },
    /// The window holding the unit's epoch holds no count of its lane and card entry for a
    /// downward delta to move: the segment is gone, and the correction is never moved onto another
    /// window's counts.
    Unplaced {
        /// The bucket.
        bucket: String,
        /// The window holding the epoch (its start, unix seconds).
        window: u64,
        /// The class.
        class: String,
    },
}

impl std::fmt::Display for AdjustRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdjustRefused::UnknownKey => f.write_str("no key by that id"),
            AdjustRefused::Empty => f.write_str("the adjustment moves no count"),
            AdjustRefused::NotMetered { day } => write!(
                f,
                "no usage of that key, lane and card entry is metered on day {day}"
            ),
            AdjustRefused::Exceeds {
                bucket,
                class,
                count,
                delta,
            } => write!(
                f,
                "bucket `{bucket}` holds {count} `{class}` in that segment, and {delta} would take \
                 it out of range"
            ),
            AdjustRefused::NoCardInForce { at } => write!(
                f,
                "the corrected unit's card cannot be resolved: {}",
                MoneyError::NoCardInForce { at: *at }
            ),
            AdjustRefused::NotInForce { named, in_force } => write!(
                f,
                "the card entry named (effective from {named}) is not the one the corrected unit's \
                 counts were dated with at its epoch (effective from {in_force})"
            ),
            AdjustRefused::Unplaced {
                bucket,
                window,
                class,
            } => write!(
                f,
                "bucket `{bucket}` holds none of that lane and card entry in window {window}, the \
                 window holding the corrected unit's epoch, so the correction has nowhere to land: \
                 a correction may not take the {class:?} count below zero"
            ),
        }
    }
}

impl std::error::Error for AdjustRefused {}

impl GovState {
    /// **ONE BUCKET'S CURRENT WINDOW, PRICED** — the live cell, else the durable row read as the
    /// cell hydrated from it, priced at the card each era was earned under, the fee included. The
    /// same cell and the same function [`GovState::derived_bucket_usage`] answers from, kept in
    /// the money type rather than projected to whole minor units.
    ///
    /// # Errors
    ///
    /// The store could not read the durable row.
    pub fn priced_bucket(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> RecordStoreResult<PricedBucket> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell(bucket_id, window)?;
        Ok(PricedBucket {
            window_start: cell.window_start,
            requests: cell.requests,
            billable_requests: cell.billable_requests,
            spend: cell.spend(cost, true),
        })
    }

    /// **APPLY ONE OPERATOR CORRECTION** to the usage counts WHERE ITS UNIT WAS LEDGERED (Q128 arch
    /// u32 #18): every bucket an accrual of the unit lands on (the key's own, and each group bucket
    /// of its chain the pool participates in; the key's own alone when its group is missing, as
    /// accrual degrades), in the window holding `card_epoch_ms`, on `model` in the latest era not
    /// after it. Checked under every bucket's shard lock, taken in ascending shard order, and applied
    /// under the same locks: all of it or none of it.
    ///
    /// FAIL CLOSED: a card epoch no rate-card entry covers, an `entry_era` other than the entry the
    /// unit's counts were dated with, an epoch window holding none of the counts a downward delta
    /// moves, or a count taken below zero refuses the whole correction with its reason, and nothing
    /// moves.
    ///
    /// The delta reaches the store through the write-behind flush, as a signed `add_usage` delta
    /// under the epoch's window.
    ///
    /// # Errors
    ///
    /// The store could not read a key or a durable row (outer); the correction was refused and
    /// nothing was applied (inner).
    pub fn adjust_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let delta: BTreeMap<&str, i64> = adj
            .delta
            .iter()
            .filter(|(_, d)| **d != 0)
            .map(|(class, d)| (class.as_str(), *d))
            .collect();
        if delta.is_empty() {
            return Ok(Err(AdjustRefused::Empty));
        }
        let Some(key) = self.store.get_key(adj.key_id)? else {
            return Ok(Err(AdjustRefused::UnknownKey));
        };
        // THE UNIT'S CARD: the entry in force at its epoch, resolved or refused. A dated history
        // with no entry covering the epoch cannot say what the unit's counts are worth.
        let at = adj.card_epoch_ms;
        if let Some(history) = crate::rate_apply::dated_history() {
            if history.current().entry_at(at).is_none() {
                return Ok(Err(AdjustRefused::NoCardInForce { at }));
            }
        }
        // An entry that begins after the unit cannot be the one its counts were dated with.
        if adj.entry_era > at {
            return Ok(Err(AdjustRefused::NotInForce {
                named: adj.entry_era,
                in_force: crate::rate_apply::effective_from_at(at),
            }));
        }
        // THE UNIT'S TIME, in wall seconds: its metering day and each bucket's window are the ones
        // holding it, never the ones current when the correction is made.
        let epoch = at / 1_000;
        // THE METERED VIEW must carry it: checked against the epoch day's rows before anything moves.
        let day = crate::governance::metering_bucket(epoch);
        if let Err(refused) = self.metered_check(adj, &delta, day)? {
            return Ok(Err(refused));
        }
        // The buckets, as `record_usage` picks them, each at the window holding the epoch.
        let mut buckets: Vec<(String, u64)> = match cost.chain_for(&key) {
            Ok(chain) => chain
                .iter()
                .filter(|b| b.applies_to_pool(adj.pool))
                .map(|b| (b.bucket_id.to_string(), budget_window(b.window, epoch)))
                .collect(),
            Err(_) => vec![(
                adj.key_id.to_string(),
                budget_window(super::super::WINDOW_TOTAL, epoch),
            )],
        };
        buckets.sort();
        buckets.dedup();
        // The budget book is checked first and moved last: the adjustment row is durable before
        // RAM moves, so a store that refuses the row leaves nothing applied. A refusal on the
        // second, applying pass (a concurrent charge moved a count between the two) writes the
        // opposite row, so the metered view never keeps an adjustment the book refused.
        if let Err(refused) = self.budget_pass(&buckets, adj, &delta, false)? {
            return Ok(Err(refused));
        }
        self.write_usage_adjustment(adj, &delta, day, 1)?;
        match self.budget_pass(&buckets, adj, &delta, true)? {
            Ok(()) => Ok(Ok(())),
            Err(refused) => {
                self.write_usage_adjustment(adj, &delta, day, -1)?;
                Ok(Err(refused))
            }
        }
    }

    /// The day's metering rows of the adjustment's key, lane and era, with the day's earlier
    /// adjustments of that slot folded in: refused when the day's rows of the key and lane are
    /// dated with a later entry at or before the unit's epoch, when no such row exists, or when a
    /// delta would take a class below zero.
    fn metered_check(
        &self,
        adj: &Adjustment<'_>,
        delta: &BTreeMap<&str, i64>,
        day: u64,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let lane_rows: Vec<MeteringRow> = self
            .store
            .list_metering(day)?
            .into_iter()
            .filter(|r| r.key_id == adj.key_id && metering_lane(&r.model, &r.provider) == adj.model)
            .collect();
        // THE UNIT'S ENTRY, as its counts were dated: the latest era this day's rows of the key and
        // lane were dated with at or before the unit's epoch. A later one there means the named
        // entry was not the one in force when the unit was served (refused); the dates the rows
        // carry are what the budget book's segments carry too, so a rate-card amendment appended
        // since does not move them.
        let dated = (lane_rows.iter())
            .map(|r| r.priced_from_ms)
            .filter(|era| *era > adj.entry_era && *era <= adj.card_epoch_ms)
            .max();
        if let Some(in_force) = dated {
            return Ok(Err(AdjustRefused::NotInForce {
                named: adj.entry_era,
                in_force,
            }));
        }
        let rows: Vec<&MeteringRow> = (lane_rows.iter())
            .filter(|r| r.priced_from_ms == adj.entry_era)
            .collect();
        if rows.is_empty() {
            return Ok(Err(AdjustRefused::NotMetered { day }));
        }
        let earlier = self
            .usage_adjustments(day)?
            .into_iter()
            .find(|a| a.key_id == adj.key_id && a.lane == adj.model && a.era == adj.entry_era);
        for (class, d) in delta {
            let metered: i128 = rows
                .iter()
                .map(|r| i128::from(metered_count(r, class)))
                .sum::<i128>()
                + earlier
                    .as_ref()
                    .and_then(|a| a.delta.get(*class))
                    .map_or(0, |e| i128::from(*e));
            if metered + i128::from(*d) < 0 {
                return Ok(Err(AdjustRefused::Exceeds {
                    bucket: format!("metering@{day}"),
                    class: (*class).to_string(),
                    count: u64::try_from(metered).unwrap_or(0),
                    delta: *d,
                }));
            }
        }
        Ok(Ok(()))
    }

    /// Put `sign` x the delta on the day's adjustment rows: its positive part on
    /// [`ADJUST_UP_BUCKET`], its negative part's magnitude on [`ADJUST_DOWN_BUCKET`].
    fn write_usage_adjustment(
        &self,
        adj: &Adjustment<'_>,
        delta: &BTreeMap<&str, i64>,
        day: u64,
        sign: i64,
    ) -> RecordStoreResult<()> {
        let slot = adjustment_slot(adj.key_id, adj.model, adj.entry_era);
        let mut up = BTreeMap::new();
        let mut down = BTreeMap::new();
        for (class, d) in delta {
            let d = d.saturating_mul(sign);
            if d > 0 {
                up.insert((*class).to_string(), d);
            } else if d < 0 {
                down.insert((*class).to_string(), d.saturating_neg());
            }
        }
        for (bucket, units) in [(ADJUST_UP_BUCKET, up), (ADJUST_DOWN_BUCKET, down)] {
            if units.is_empty() {
                continue;
            }
            let row = UsageDelta {
                requests: 0,
                billable_requests: 0,
                models: vec![busbar_contract::records::ModelTokensDelta {
                    model: slot.clone(),
                    usage_units: units,
                }],
            };
            self.store.add_usage(bucket, day, &row)?;
        }
        Ok(())
    }

    /// **THE DAY'S ADJUSTMENTS**, net per (key, lane, era): what the usage read folds into the
    /// day's metering rows. Read from the two adjustment rows of `day`.
    ///
    /// # Errors
    ///
    /// The store could not read an adjustment row.
    pub fn usage_adjustments(&self, day: u64) -> RecordStoreResult<Vec<UsageAdjustment>> {
        let mut net: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        for (bucket, sign) in [(ADJUST_UP_BUCKET, 1i64), (ADJUST_DOWN_BUCKET, -1i64)] {
            for m in self.store.get_usage(bucket, day)?.models {
                let slot = net.entry(m.model).or_default();
                for (class, n) in m.usage_units {
                    let n = i64::try_from(n).unwrap_or(i64::MAX).saturating_mul(sign);
                    let e = slot.entry(class).or_insert(0);
                    *e = e.saturating_add(n);
                }
            }
        }
        Ok(net
            .into_iter()
            .filter_map(|(slot, mut delta)| {
                delta.retain(|_, d| *d != 0);
                let mut parts = slot.splitn(3, SLOT_SEP);
                let key_id = parts.next()?.to_string();
                let lane = parts.next()?.to_string();
                let era = parts.next()?.parse().ok()?;
                (!delta.is_empty()).then_some(UsageAdjustment {
                    key_id,
                    lane,
                    era,
                    delta,
                })
            })
            .collect())
    }

    /// The budget book's half of an adjustment: every bucket's segment in the window holding the
    /// unit's epoch, checked under every bucket's shard lock, taken in ascending shard order, and —
    /// when `apply` — moved under the same locks: all of it or none of it.
    ///
    /// Where a bucket's counts of that window live decides where the delta goes:
    ///
    /// - the live cell holds the window: its segment of the unit's lane in the latest era not after
    ///   the epoch ([`segment_at`]), or a new segment at the entry in force then when the window
    ///   holds none of that lane (an upward delta only: a downward one has nothing to move);
    /// - the live cell has moved past the window (it rolled away): the window's durable row plus
    ///   what the cell still has parked under it ([`rolled_count`]), and the delta is parked under
    ///   the window ([`BudgetCell::park`]) for the flusher to write there, as a rolled window's own
    ///   counts are;
    /// - no live cell, or an older one: the window is hydrated from its durable row, as boot would,
    ///   and is the live cell.
    ///
    /// Never the current window when it is not the epoch's: a correction with nowhere to land in
    /// its own window is refused ([`AdjustRefused::Unplaced`]).
    fn budget_pass(
        &self,
        buckets: &[(String, u64)],
        adj: &Adjustment<'_>,
        delta: &BTreeMap<&str, i64>,
        apply: bool,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        // A bucket whose live cell does not hold the epoch's window has that window's durable row
        // read first, OUTSIDE the locks, as the cell boot would hydrate from it: the store already
        // holds those counts, so the flush baselines start level and only the correction is
        // written. It is installed when no cell holds that window or a newer one, and it is the
        // rolled-away window's stored count when one does.
        let mut durable: HashMap<String, BudgetCell> = HashMap::new();
        for (bucket_id, window) in buckets {
            let holds = (self.budget.read(bucket_id).get(bucket_id.as_str()))
                .is_some_and(|c| c.window_start == *window);
            if !holds {
                let mut cell = self.stored_cell(bucket_id, *window)?;
                cell.last_touch = adj.now;
                durable.insert(bucket_id.clone(), cell);
            }
        }
        // Every bucket's shard, write-locked in ascending index order (the admission charge's
        // canonical order, so the two cannot deadlock), held across the check and the apply.
        let mut order: Vec<usize> = buckets
            .iter()
            .map(|(bucket_id, _)| self.budget.shard_index(bucket_id))
            .collect();
        order.sort_unstable();
        order.dedup();
        let mut guards: Vec<(
            usize,
            std::sync::RwLockWriteGuard<'_, HashMap<String, BudgetCell>>,
        )> = order
            .iter()
            .map(|&sh| {
                let map = self
                    .budget
                    .shard_at(sh)
                    .map
                    .write()
                    .unwrap_or_else(|p| p.into_inner());
                (sh, map)
            })
            .collect();
        let map_of = |bucket_id: &str| -> usize {
            let sh = self.budget.shard_index(bucket_id);
            guards
                .iter()
                .position(|(s, _)| *s == sh)
                .expect("every bucket's shard is locked")
        };
        let at: Vec<usize> = buckets.iter().map(|(b, _)| map_of(b)).collect();
        // Install the hydrated cells where nothing as new appeared while the store was read.
        for ((bucket_id, window), i) in buckets.iter().zip(&at) {
            let map = &mut guards[*i].1;
            let stale = map
                .get(bucket_id.as_str())
                .is_none_or(|c| c.window_start < *window);
            if stale {
                if let Some(cell) = durable.remove(bucket_id) {
                    match map.get_mut(bucket_id.as_str()) {
                        // An older window's cell rolls first, so what it still owes is kept.
                        Some(old) => {
                            old.roll(*window);
                            let parked = std::mem::take(&mut old.rolled);
                            *old = cell;
                            old.rolled = parked;
                            old.dirty = !old.rolled.is_empty();
                        }
                        None => {
                            map.insert(bucket_id.clone(), cell);
                        }
                    }
                }
            }
        }
        // THE CHECK, every bucket first: a downward delta with no count of its own window to move,
        // or a count of the segment taken out of range, refuses the whole.
        for ((bucket_id, window), i) in buckets.iter().zip(&at) {
            let cell = guards[*i].1.get(bucket_id.as_str());
            for (class, d) in delta {
                let held = match cell {
                    Some(c) if c.window_start == *window => {
                        segment_at(&c.models, adj.model, adj.card_epoch_ms)
                            .map(|s| i128::from(c.models[s].cur.get(*class).copied().unwrap_or(0)))
                    }
                    Some(c) if c.window_start > *window => {
                        rolled_count(durable.get(bucket_id), c, *window, adj.model, class)
                    }
                    // Neither held nor read (the cell went between the read and the lock): there
                    // is nothing to place the correction against, so it is refused.
                    _ => None,
                };
                let unplaced = match cell {
                    Some(c) => held.is_none() && (*d < 0 || c.window_start < *window),
                    None => true,
                };
                if unplaced {
                    return Ok(Err(AdjustRefused::Unplaced {
                        bucket: bucket_id.clone(),
                        window: *window,
                        class: (*class).to_string(),
                    }));
                }
                let count = held.unwrap_or(0);
                let next = count + i128::from(*d);
                if next < 0 || u64::try_from(next).is_err() {
                    return Ok(Err(AdjustRefused::Exceeds {
                        bucket: bucket_id.clone(),
                        class: (*class).to_string(),
                        count: u64::try_from(count).unwrap_or(0),
                        delta: *d,
                    }));
                }
            }
        }
        if !apply {
            return Ok(Ok(()));
        }
        // THE APPLY, under the same locks. The check left every bucket a cell holding the epoch's
        // window or a newer one.
        for ((bucket_id, window), i) in buckets.iter().zip(&at) {
            let map = &mut guards[*i].1;
            let cell = map
                .get_mut(bucket_id.as_str())
                .expect("checked under the same lock");
            if cell.window_start == *window {
                let segment = match segment_at(&cell.models, adj.model, adj.card_epoch_ms) {
                    Some(p) => &mut cell.models[p],
                    None => {
                        cell.models.push(ModelCell {
                            model: std::sync::Arc::from(adj.model),
                            era: adj.entry_era,
                            cur: BTreeMap::new(),
                            flushed: BTreeMap::new(),
                        });
                        cell.models.last_mut().expect("just pushed")
                    }
                };
                for (class, d) in delta {
                    let count = segment.cur.get(*class).copied().unwrap_or(0);
                    let next = moved(count, *d).expect("checked under the same lock");
                    if next == 0 {
                        segment.cur.remove(*class);
                    } else {
                        segment.cur.insert((*class).to_string(), next);
                    }
                }
            } else {
                // The window rolled away: parked under it for the flusher to write there, never
                // folded into the newer window the cell holds.
                let usage_units = (delta.iter())
                    .map(|(class, d)| ((*class).to_string(), *d))
                    .collect();
                cell.park(
                    *window,
                    UsageDelta {
                        requests: 0,
                        billable_requests: 0,
                        models: vec![busbar_contract::records::ModelTokensDelta {
                            model: adj.model.to_string(),
                            usage_units,
                        }],
                    },
                );
            }
            cell.dirty = true;
            cell.last_touch = adj.now;
        }
        Ok(Ok(()))
    }
}

/// THE SEGMENT A CORRECTION LANDS ON in a window's cell: `lane` in the latest era not after the
/// unit's epoch `at_ms` — the era the unit's counts accrued under, as dev's read-time fold placed
/// it (Q128 arch u32 #18). `None` when the window holds none of that lane by then.
fn segment_at(models: &[ModelCell], lane: &str, at_ms: u64) -> Option<usize> {
    (models.iter().enumerate())
        .filter(|(_, m)| *m.model == *lane && m.era <= at_ms)
        .max_by_key(|(_, m)| m.era)
        .map(|(i, _)| i)
}

/// What a ROLLED-AWAY `window` holds of `lane`'s `class`: its durable row (`stored`, read before
/// the locks; it carries no era) plus what the live cell still has parked under it. `None` when
/// neither holds that lane at all — the window's segment is gone, or was not read.
fn rolled_count(
    stored: Option<&BudgetCell>,
    live: &BudgetCell,
    window: u64,
    lane: &str,
    class: &str,
) -> Option<i128> {
    let mut held: Option<i128> = None;
    for m in (stored.into_iter().flat_map(|c| c.models.iter())).filter(|m| *m.model == *lane) {
        let n = i128::from(m.cur.get(class).copied().unwrap_or(0));
        held = Some(held.unwrap_or(0) + n);
    }
    let parked = (live.rolled.iter())
        .filter(|(w, _)| *w == window)
        .flat_map(|(_, d)| d.models.iter())
        .filter(|m| m.model == lane);
    for m in parked {
        let n = i128::from(m.usage_units.get(class).copied().unwrap_or(0));
        held = Some(held.unwrap_or(0) + n);
    }
    held
}

/// `count` moved by `delta`, or `None` when that leaves `u64`.
fn moved(count: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        count.checked_add(delta.unsigned_abs())
    } else {
        count.checked_sub(delta.unsigned_abs())
    }
}
