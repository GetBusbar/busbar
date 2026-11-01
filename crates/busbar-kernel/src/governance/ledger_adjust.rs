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
//! - its affected raw rows, captured local debt and metering adjustment commit atomically, after
//!   comparing their exact shared pre-state. No compensation write or unconditional negative
//!   flush can accept a correction. RAM adopts the acknowledged branch only after that decision;
//!   ordinary operations update both possible branches while the result is unknown;
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
pub use busbar_contract::records::correction::ADJUST_UP_BUCKET;

/// The usage row a day's DOWNWARD adjustments accumulate on: per slot, per class, the sum of every
/// negative delta's magnitude. Only ever added to. Up minus down is the day's signed adjustment.
pub use busbar_contract::records::correction::ADJUST_DOWN_BUCKET;

/// The separator of an adjustment slot's three parts. Not [`PLANE_LANE_SEP`], which a lane carries.
use busbar_contract::records::correction::SLOT_SEP;

#[path = "ledger_correction.rs"]
mod correction_impl;

pub(in crate::governance) use correction_impl::PendingCorrection;

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
    /// The exact signed difference of two raw `u64` counters per class. Zero nets are left off.
    pub delta: BTreeMap<String, i128>,
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
    /// after it. Local raw facts are captured under ordered shard locks; the store compares all
    /// exact durable pre-states and commits all replacements and its receipt atomically.
    ///
    /// FAIL CLOSED: a card epoch no rate-card entry covers, an `entry_era` other than the entry the
    /// unit's counts were dated with, an epoch window holding none of the counts a downward delta
    /// moves, or a count taken below zero refuses the whole correction with its reason, and nothing
    /// moves.
    ///
    /// The store accepts exact raw row replacements and the applied receipt atomically. The
    /// immutable operation and both raw branches survive an unknown answer for exact replay.
    ///
    /// # Errors
    ///
    /// A store error can have an unknown commit outcome (outer): the exact operation and both
    /// raw branches remain owned for replay, including through another call of this API. A named
    /// refusal (inner) accepted no correction.
    pub fn adjust_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let _claim = self.correction_claims.claim(adj.key_id.to_string());
        if self.resume_usage_correction(adj)? {
            return Ok(Ok(()));
        }
        if !self.store.supports_usage_correction() {
            return Err(RecordStoreError("usage corrections unsupported".into()));
        }
        let delta: BTreeMap<&str, i64> = adj
            .delta
            .iter()
            .filter(|(_, d)| **d != 0)
            .map(|(class, d)| (class.as_str(), *d))
            .collect();
        if delta.is_empty() {
            return Ok(Err(AdjustRefused::Empty));
        }
        if self.store.get_key(adj.key_id)?.is_none() {
            return Ok(Err(AdjustRefused::UnknownKey));
        }
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
        self.correct_usage(cost, adj, &delta, day)
    }

    /// **THE DAY'S ADJUSTMENTS**, net per (key, lane, era): what the usage read folds into the
    /// day's metering rows. Read from the two adjustment rows of `day`.
    ///
    /// # Errors
    ///
    /// The store could not read an adjustment row.
    pub fn usage_adjustments(&self, day: u64) -> RecordStoreResult<Vec<UsageAdjustment>> {
        if self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|pending| pending.unresolved_day() == Some(day))
        {
            return Err(RecordStoreError(
                "usage correction outcome unresolved".into(),
            ));
        }
        let mut net: BTreeMap<String, BTreeMap<String, i128>> = BTreeMap::new();
        for (bucket, sign) in [(ADJUST_UP_BUCKET, 1i128), (ADJUST_DOWN_BUCKET, -1i128)] {
            for model in self.store.get_usage(bucket, day)?.models {
                for (class, count) in model.usage_units {
                    *net.entry(model.model.clone())
                        .or_default()
                        .entry(class)
                        .or_default() += i128::from(count) * sign;
                }
            }
        }
        let mut result = Vec::new();
        for (slot, counts) in net {
            let mut parts = slot.splitn(3, SLOT_SEP);
            let (Some(key), Some(lane), Some(era)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(era) = era.parse() else {
                continue;
            };
            let delta: BTreeMap<_, _> = counts
                .into_iter()
                .filter(|(_, count)| *count != 0)
                .collect();
            if !delta.is_empty() {
                result.push(UsageAdjustment {
                    key_id: key.into(),
                    lane: lane.into(),
                    era,
                    delta,
                });
            }
        }
        Ok(result)
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

/// `count` moved by `delta`, or `None` when that leaves `u64`.
fn moved(count: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        count.checked_add(delta.unsigned_abs())
    } else {
        count.checked_sub(delta.unsigned_abs())
    }
}

#[cfg(test)]
#[path = "ledger_adjust_view_tests.rs"]
mod view_tests;
