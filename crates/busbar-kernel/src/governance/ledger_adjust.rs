// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

pub use busbar_contract::records::correction::ADJUST_UP_BUCKET;

pub use busbar_contract::records::correction::ADJUST_DOWN_BUCKET;

#[path = "ledger_correction.rs"]
mod correction_impl;

pub(in crate::governance) use correction_impl::PendingCorrection;

use crate::off_path::governance::ledger as ledger_off_path;

fn adjustment_slot(key_id: &str, lane: &str, era: impl Into<RawRateEra>) -> String {
    ledger_off_path::ledger_adjust_slot(key_id, lane, &era_tag(era.into()))
}

#[must_use]
pub fn metering_lane<'a>(model: &'a str, provider: &str) -> std::borrow::Cow<'a, str> {
    if model.contains(PLANE_LANE_SEP) {
        return std::borrow::Cow::Borrowed(model);
    }
    match crate::plane_driver::registry::plane_decl_for(provider) {
        Some(decl) if !decl.fallback => {
            std::borrow::Cow::Owned(ledger_off_path::ledger_adjust_plane_lane(decl.key, model))
        }
        _ => std::borrow::Cow::Borrowed(model),
    }
}

/// Whether a metering row of `model` served by `provider` is on `lane`, as [`metering_lane`]
/// names a row's lane. Compared where the parts lie: a named plane's lane (`plane SEP model`) is
/// not built for each row a correction checks.
fn on_lane(model: &str, provider: &str, lane: &str) -> bool {
    if model.contains(PLANE_LANE_SEP) {
        return model == lane;
    }
    match crate::plane_driver::registry::plane_decl_for(provider) {
        Some(decl) if !decl.fallback => {
            let plane: &str = decl.key;
            lane.strip_prefix(plane)
                .and_then(|rest| rest.strip_prefix(PLANE_LANE_SEP))
                == Some(model)
        }
        _ => model == lane,
    }
}

/// One day's net adjustment of one (key, lane, era): what the usage read folds into the day's
/// metering rows of that key, lane and era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageAdjustment<T = i128> {
    /// The key whose counts were adjusted.
    pub key_id: String,
    /// The lane, as [`metering_lane`] names a metering row's.
    pub lane: String,
    /// The era (`priced_from_ms`) of the metering rows it lands on.
    pub era: u64,
    /// The exact entry identity where it was captured, absent for historical timestamp rows.
    pub entry_id: Option<EntryId>,
    /// The exact signed difference of two nonnegative `i128` quantity counters per class. Zero nets are left off.
    pub delta: BTreeMap<String, T>,
}

fn metered_count(row: &MeteringRow, class: &str) -> RecordStoreResult<Count> {
    let raw = match class {
        busbar_contract::records::UNIT_INPUT => row.tokens_input,
        busbar_contract::records::UNIT_OUTPUT => row.tokens_output,
        busbar_contract::records::UNIT_CACHE_READ => row.tokens_cache_read,
        busbar_contract::records::UNIT_CACHE_WRITE => row.tokens_cache_write,
        other => row.usage_units.get(other).copied().unwrap_or(0),
    };
    Count::from_stored(raw, row.scale).map_err(crate::governance::store_error)
}

/// One bucket's current window, priced by the one function: what the admin ledger views serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedBucket {
    /// The window the cell holds, as the unix second it opens at (`0` = the all-time window).
    pub window_start: u64,
    /// Admitted requests in the window.
    pub requests: u64,
    /// Billable requests in the window: legacy flat requests plus named-plane request fees.
    pub billable_requests: u64,
    /// The cell's counts priced at the card each era was earned under, fee included, or the one
    /// function's refusal (a card silent about a lane or class, no card in force, out of range).
    pub spend: Result<busbar_kernel_ledger::cost::Money, MoneyError>,
}

/// One operator correction to a unit's counts, as signed deltas.
#[derive(Debug, Clone)]
pub struct Adjustment<'a, T = i64> {
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
    /// Exact raw rate entry, when known. A missing identity retains legacy dating semantics.
    pub entry_id: Option<crate::cost::EntryId>,
    /// THE CARD EPOCH: the corrected unit's arrival instant in milliseconds, whose card its counts
    /// price at. It picks each bucket's window (the one holding it), the segment in that window,
    /// and the metering day — never the instant the correction is made.
    pub card_epoch_ms: u64,
    /// The signed delta per class. Zero deltas are ignored.
    pub delta: &'a BTreeMap<String, T>,
    /// The instant the correction is made, wall seconds: the touched cells' last touch, and nothing
    /// else.
    pub now: u64,
}

/// Why an adjustment was refused. Nothing was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjustRefused {
    /// The engine could not prepare a complete correction before claiming any raw cells or
    /// submitting a conditional store mutation. The effect is definitively not applied.
    Preparation { reason: String },
    /// The corrected unit has not arrived.
    FutureEpoch { at: u64, now: u64 },
    /// No key by that id.
    UnknownKey,
    /// The correction carries no non-zero delta.
    Empty,
    /// The day's metering rows hold no count of that key, lane and era to adjust.
    NotMetered {
        /// The metering day (its UTC-day start, unix seconds).
        day: u64,
    },
    /// The delta would take a count of its segment below zero (or past the signed-i128 Count range).
    Exceeds {
        /// The bucket it would have landed on.
        bucket: String,
        /// The class.
        class: String,
        /// What the segment holds now.
        count: Count,
        /// The delta asked for.
        delta: Count,
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
            AdjustRefused::Preparation { reason } => {
                write!(
                    f,
                    "correction preparation failed before any effect: {reason}"
                )
            }
            AdjustRefused::FutureEpoch { at, now } => write!(
                f,
                "the corrected unit epoch {at} is later than the current instant {now}"
            ),
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

// Named-plane admission records request fees on the plane's synthetic fee lane instead of
// the legacy flat counter. Only that lane's per-request class belongs in this projection;
// provider usage and session fees are separate facts, even when their class names overlap.
fn billable_request_count(cell: &BudgetCell) -> Result<u64, busbar_contract::count::CountError> {
    use busbar_kernel_ledger::cost::{split_plane_lane, PER_REQUEST};
    cell.models
        .iter()
        .filter(|model| {
            let (plane, lane) = split_plane_lane(&model.model);
            !plane.is_empty() && lane.is_empty()
        })
        .try_fold(cell.billable_requests, |total, model| {
            let requests = model.cur.get(PER_REQUEST).copied().unwrap_or_default();
            total
                .checked_add(requests.whole_u64()?)
                .ok_or(busbar_contract::count::CountError::OutOfRange)
        })
}

impl GovState {
    pub async fn priced_bucket_async(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> RecordStoreResult<PricedBucket> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell_async(bucket_id, window).await?;
        Ok(PricedBucket {
            window_start: cell.window_start,
            requests: cell.requests,
            billable_requests: billable_request_count(&cell)
                .map_err(crate::cold::governance::ledger::ledger_adjust_billable_count_refusal)?,
            spend: cell.spend(cost, true),
        })
    }

    pub async fn adjust_usage_async(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let delta = ledger_off_path::ledger_adjust_whole_delta(adj.delta);
        self.adjust_usage_exact_async(
            cost,
            &Adjustment {
                key_id: adj.key_id,
                pool: adj.pool,
                model: adj.model,
                entry_era: adj.entry_era,
                entry_id: adj.entry_id,
                card_epoch_ms: adj.card_epoch_ms,
                delta: &delta,
                now: adj.now,
            },
        )
        .await
    }

    pub async fn adjust_usage_exact_async(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        self.adjust_usage_exact_action_async(cost, adj, None).await
    }

    /// The action id also travels in retained correction custody, linking HTTP reconciliation
    /// to the raw conditional operation without changing the Store request ABI.
    pub async fn adjust_usage_exact_action_async(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
        action_id: Option<&str>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let _claim = self.correction_claims.claim_async(adj.key_id.into()).await;
        if self.resume_usage_correction(adj, action_id).await? {
            return Ok(Ok(()));
        }
        if let Err(refused) = check_epoch(adj.card_epoch_ms, crate::store::now_ms()) {
            return Ok(Err(refused));
        }
        if nonzero(adj.delta).next().is_none() {
            return Ok(Err(AdjustRefused::Empty));
        }
        match self.core_store()?.identity().get_key(adj.key_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(Err(AdjustRefused::UnknownKey)),
            Err(error) => {
                return Ok(Err(AdjustRefused::Preparation {
                    reason: crate::governance::rendered_error(std::convert::identity, error),
                }));
            }
        }

        let at = adj.card_epoch_ms;
        if let Some(history) = crate::rate_apply::dated_history() {
            if history.current().entry_at(at).is_none() {
                return Ok(Err(AdjustRefused::NoCardInForce { at }));
            }
        }

        if adj.entry_era > at {
            return Ok(Err(AdjustRefused::NotInForce {
                named: adj.entry_era,
                in_force: crate::rate_apply::effective_from_at(at),
            }));
        }

        let epoch = at / 1_000;

        let day = crate::governance::metering_bucket(epoch);
        self.correct_usage(cost, adj, day, action_id).await
    }

    pub async fn usage_adjustments_async(
        &self,
        day: u64,
    ) -> RecordStoreResult<Vec<UsageAdjustment>> {
        ledger_off_path::ledger_adjust_whole_adjustments(
            self.usage_adjustments_exact_async(day).await?,
        )
    }

    pub async fn usage_adjustments_exact_async(
        &self,
        day: u64,
    ) -> RecordStoreResult<Vec<UsageAdjustment<Count>>> {
        let unresolved = ledger_off_path::ledger_corrections_any(
            &*self.corrections.lock().unwrap_or_else(|p| p.into_inner()),
            |pending| pending.unresolved_day() == Some(day),
        );
        if unresolved {
            return Err(RecordStoreError(
                "usage correction outcome unresolved".into(),
            ));
        }
        let (up, down) = self
            .core_store()?
            .ledger()
            .get_usage_pair(ADJUST_UP_BUCKET, ADJUST_DOWN_BUCKET, day)
            .await?;
        ledger_off_path::ledger_adjust_net_adjustments(up, down, parse_era_tag)
    }
}

/// The classes a correction actually moves: its non-zero deltas, in class order. Read off the
/// correction's own map each time it is walked; nothing is collected.
fn nonzero(delta: &BTreeMap<String, Count>) -> impl Iterator<Item = (&str, Count)> + Clone + '_ {
    delta
        .iter()
        .filter(|(_, count)| **count != Count::ZERO)
        .map(|(class, count)| (class.as_str(), *count))
}

fn check_epoch(at: u64, now: u64) -> Result<(), AdjustRefused> {
    if at > now {
        Err(AdjustRefused::FutureEpoch { at, now })
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/ledger_adjust_epoch_tests.rs"]
mod epoch_tests;

fn segment_at(models: &[ModelCell], lane: &str, at_ms: u64) -> Option<usize> {
    (models.iter().enumerate())
        .filter(|(_, m)| {
            *m.model == *lane && m.era.entry_id.is_none() && m.era.effective_from <= at_ms
        })
        .max_by_key(|(_, m)| m.era.effective_from)
        .map(|(i, _)| i)
}

fn moved(count: Count, delta: Count) -> Option<Count> {
    count.checked_add(delta).ok().filter(|n| !n.is_negative())
}

#[cfg(test)]
#[path = "ledger_adjust_view_tests.rs"]
mod view_tests;

#[cfg(test)]
#[path = "tests/ledger_adjust_billable_request_count_tests.rs"]
mod billable_request_count_tests;
