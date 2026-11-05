// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

pub use busbar_contract::records::correction::ADJUST_UP_BUCKET;

pub use busbar_contract::records::correction::ADJUST_DOWN_BUCKET;

use busbar_contract::records::correction::SLOT_SEP;

#[path = "ledger_correction.rs"]
mod correction_impl;

pub(in crate::governance) use correction_impl::PendingCorrection;

fn adjustment_slot(key_id: &str, lane: &str, era: impl Into<RawRateEra>) -> String {
    format!("{key_id}{SLOT_SEP}{lane}{SLOT_SEP}{}", era_tag(era.into()))
}

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
    Count::from_stored(raw, row.scale).map_err(|e| RecordStoreError(e.to_string()))
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
            billable_requests: billable_request_count(&cell)
                .map_err(|e| RecordStoreError(format!("billable request count: {e}")))?,
            spend: cell.spend(cost, true),
        })
    }

    pub fn adjust_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let delta = adj
            .delta
            .iter()
            .map(|(class, value)| {
                (
                    class.clone(),
                    Count::from_integer(i128::from(*value)).expect("i64 whole count fits"),
                )
            })
            .collect();
        self.adjust_usage_exact(
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
    }

    pub fn adjust_usage_exact(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        self.adjust_usage_exact_action(cost, adj, None)
    }

    /// The action id also travels in retained correction custody, linking HTTP reconciliation
    /// to the raw conditional operation without changing the Store request ABI.
    pub fn adjust_usage_exact_action(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
        action_id: Option<&str>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let _claim = self.correction_claims.claim(adj.key_id.to_string());
        if self.resume_usage_correction(adj, action_id)? {
            return Ok(Ok(()));
        }
        if let Err(refused) = check_epoch(adj.card_epoch_ms, crate::store::now_ms()) {
            return Ok(Err(refused));
        }
        if !self.store.supports_usage_correction() {
            return Err(RecordStoreError("usage corrections unsupported".into()));
        }
        let delta: BTreeMap<&str, Count> = adj
            .delta
            .iter()
            .filter(|(_, d)| **d != Count::ZERO)
            .map(|(class, d)| (class.as_str(), *d))
            .collect();
        if delta.is_empty() {
            return Ok(Err(AdjustRefused::Empty));
        }
        if self.store.get_key(adj.key_id)?.is_none() {
            return Ok(Err(AdjustRefused::UnknownKey));
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
        self.correct_usage(cost, adj, &delta, day, action_id)
    }

    pub fn usage_adjustments(&self, day: u64) -> RecordStoreResult<Vec<UsageAdjustment>> {
        self.usage_adjustments_exact(day)?
            .into_iter()
            .map(|row| {
                let delta = row
                    .delta
                    .into_iter()
                    .map(|(class, count)| {
                        if count.micros() % 1_000_000 != 0 {
                            return Err(RecordStoreError(
                                "fractional whole-unit adjustment".into(),
                            ));
                        }
                        Ok((class, count.micros() / 1_000_000))
                    })
                    .collect::<RecordStoreResult<_>>()?;
                Ok(UsageAdjustment {
                    key_id: row.key_id,
                    lane: row.lane,
                    era: row.era,
                    entry_id: row.entry_id,
                    delta,
                })
            })
            .collect()
    }

    pub fn usage_adjustments_exact(
        &self,
        day: u64,
    ) -> RecordStoreResult<Vec<UsageAdjustment<Count>>> {
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
                    let count = Count::from_stored(count, model.scale)
                        .map_err(|e| RecordStoreError(e.to_string()))?;
                    if count.is_negative() {
                        return Err(RecordStoreError("negative adjustment magnitude".into()));
                    }
                    let slot = net
                        .entry(model.model.clone())
                        .or_default()
                        .entry(class)
                        .or_default();
                    *slot = slot
                        .checked_add(count.micros() * sign)
                        .ok_or_else(|| RecordStoreError("adjustment total overflow".into()))?;
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
            let Some(era) = parse_era_tag(era)? else {
                continue;
            };
            let delta: BTreeMap<_, _> = counts
                .into_iter()
                .filter(|(_, count)| *count != 0)
                .map(|(class, count)| (class, Count::from_micros(count)))
                .collect();
            if !delta.is_empty() {
                result.push(UsageAdjustment {
                    key_id: key.into(),
                    lane: lane.into(),
                    era: era.effective_from,
                    entry_id: era.entry_id,
                    delta,
                });
            }
        }
        Ok(result)
    }
}

fn check_epoch(at: u64, now: u64) -> Result<(), AdjustRefused> {
    if at > now {
        Err(AdjustRefused::FutureEpoch { at, now })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    #[test]
    fn arrival_comparison_preserves_millisecond_precision_and_equality() {
        let now = 1_234_567;
        assert_eq!(check_epoch(now - 1, now), Ok(()));
        assert_eq!(check_epoch(now, now), Ok(()));
        assert_eq!(
            check_epoch(now + 1, now),
            Err(AdjustRefused::FutureEpoch { at: now + 1, now })
        );
    }
}

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
mod billable_request_count_tests {
    use super::*;
    use busbar_contract::count::CountError;
    use busbar_kernel_ledger::cost::{plane_fee_lane, PER_REQUEST, PER_SESSION};

    #[test]
    fn ledger_request_fees_include_only_legacy_and_named_request_fee_rows() {
        let mut cell = BudgetCell::fresh(0);
        cell.billable_requests = 2;
        cell.accrue(
            &plane_fee_lane("decisions"),
            1,
            &BTreeMap::from([(PER_REQUEST.into(), 3)]),
        );
        cell.accrue(
            &plane_fee_lane("decisions"),
            2,
            &BTreeMap::from([(PER_REQUEST.into(), 4)]),
        );
        cell.accrue(
            &plane_fee_lane("voice"),
            2,
            &BTreeMap::from([(PER_SESSION.into(), 9)]),
        );
        cell.accrue(
            "decisions\u{1f}model",
            2,
            &BTreeMap::from([(PER_REQUEST.into(), 100)]),
        );
        cell.accrue(
            "legacy-model",
            2,
            &BTreeMap::from([(PER_REQUEST.into(), 100)]),
        );
        assert_eq!(billable_request_count(&cell), Ok(9));
    }

    #[test]
    fn ledger_request_fees_refuse_fraction_negative_and_overflow_without_rounding() {
        for (count, error) in [
            (Count::parse("0.5").unwrap(), CountError::NotWhole),
            (Count::from_micros(-1_000_000), CountError::Negative),
            (
                Count::from_integer(i128::from(u64::MAX) + 1).unwrap(),
                CountError::OutOfRange,
            ),
        ] {
            let mut cell = BudgetCell::fresh(0);
            cell.accrue(
                &plane_fee_lane("decisions"),
                0,
                &BTreeMap::from([(PER_REQUEST.into(), 1)]),
            );
            cell.models[0].cur.insert(PER_REQUEST.into(), count);
            assert_eq!(billable_request_count(&cell), Err(error));
        }
        let mut cell = BudgetCell::fresh(0);
        cell.billable_requests = u64::MAX;
        cell.accrue(
            &plane_fee_lane("decisions"),
            0,
            &BTreeMap::from([(PER_REQUEST.into(), 1)]),
        );
        assert_eq!(billable_request_count(&cell), Err(CountError::OutOfRange));
    }
}
