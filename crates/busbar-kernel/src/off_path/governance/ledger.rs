// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::ledger` off-path code (see `crate::off_path::governance`): operator-issued usage
//! adjustments and their correction custody (`ledger_adjust`, `ledger_correction`,
//! `ledger_correction_recovery`), the admin usage-adjustment and priced-bucket views, and the
//! retained-correction replay at boot or recovery. None of it runs per request.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::count::{Count, COUNT_SCALE};
use busbar_contract::records::correction::{UsageAddress, UsageChange, SLOT_SEP};
use busbar_contract::records::{MeteringRow, RecordStoreError, RecordStoreResult, UsageLedger};
use busbar_kernel_ledger::cost::{EntryId, RawRateEra};

use crate::governance::recovery::RecoveryChild;
use crate::governance::UsageAdjustment;

/// `ledger_adjust`: an adjustment's raw slot name, `key SEP lane SEP era`, rendered once per
/// operator adjustment or adjustment-view row.
pub(crate) fn ledger_adjust_slot(key_id: &str, lane: &str, era_tag: &str) -> String {
    format!("{key_id}{SLOT_SEP}{lane}{SLOT_SEP}{era_tag}")
}

/// `ledger_adjust`: a named plane's metering lane, `plane SEP model` (operator adjustments and the
/// admin usage view).
pub(crate) fn ledger_adjust_plane_lane(plane: &str, model: &str) -> String {
    format!("{plane}{}{model}", crate::governance::PLANE_LANE_SEP)
}

/// `ledger_adjust`: an operator's whole-unit delta as exact counts.
pub(crate) fn ledger_adjust_whole_delta(delta: &BTreeMap<String, i64>) -> BTreeMap<String, Count> {
    delta
        .iter()
        .map(|(class, value)| {
            (
                class.clone(),
                Count::from_integer(i128::from(*value)).expect("i64 whole count fits"),
            )
        })
        .collect()
}

/// `ledger_adjust`: the classes a correction actually moves (its non-zero deltas).
pub(crate) fn ledger_adjust_nonzero_delta(
    delta: &BTreeMap<String, Count>,
) -> BTreeMap<&str, Count> {
    delta
        .iter()
        .filter(|(_, count)| **count != Count::ZERO)
        .map(|(class, count)| (class.as_str(), *count))
        .collect()
}

/// `ledger_adjust`: the admin usage-adjustment view in whole units; a fractional net is refused.
pub(crate) fn ledger_adjust_whole_adjustments(
    rows: Vec<UsageAdjustment<Count>>,
) -> RecordStoreResult<Vec<UsageAdjustment>> {
    rows.into_iter()
        .map(|row| {
            let delta = row
                .delta
                .into_iter()
                .map(|(class, count)| {
                    if count.micros() % 1_000_000 != 0 {
                        return Err(RecordStoreError("fractional whole-unit adjustment".into()));
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

/// `ledger_adjust`: one day's net adjustment per (key, lane, era) from its up and down rows (the
/// admin usage-adjustment view). `parse_era` reads a slot's era tag.
pub(crate) fn ledger_adjust_net_adjustments(
    up: UsageLedger,
    down: UsageLedger,
    parse_era: impl Fn(&str) -> RecordStoreResult<Option<RawRateEra>>,
) -> RecordStoreResult<Vec<UsageAdjustment<Count>>> {
    let mut net: BTreeMap<String, BTreeMap<String, i128>> = BTreeMap::new();
    for (row, sign) in [(up, 1i128), (down, -1i128)] {
        for model in row.models {
            for (class, count) in model.usage_units {
                let count = Count::from_stored(count, model.scale)
                    .map_err(crate::governance::store_error)?;
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
        let (Some(key), Some(lane), Some(era)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Some(era) = parse_era(era)? else {
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

/// `ledger_correction`: the retained correction `owns` picks, scanned out of the few unresolved
/// corrections (recovery, operator verdicts and correction custody only).
pub(crate) fn ledger_corrections_find<T: Clone>(
    corrections: &foldhash::HashMap<String, T>,
    owns: impl Fn(&T) -> bool,
) -> Option<T> {
    corrections.values().find(|pending| owns(pending)).cloned()
}

/// `ledger_correction`: whether any retained correction matches (the admin usage-adjustment view).
pub(crate) fn ledger_corrections_any<T>(
    corrections: &foldhash::HashMap<String, T>,
    matches: impl Fn(&T) -> bool,
) -> bool {
    corrections.values().any(matches)
}

/// `ledger_correction`: a snapshot of every retained correction, for the flush tick's retry pass.
pub(crate) fn ledger_corrections_snapshot<T: Clone>(
    corrections: &foldhash::HashMap<String, T>,
) -> Vec<T> {
    corrections.values().cloned().collect()
}

/// `ledger_correction`: the wall seconds a fresh correction operation is sent at (its durable
/// first-send time). Read once per sent operation; a condition-conflict retry sends a new
/// operation.
pub(crate) fn ledger_correction_sent_clock() -> u64 {
    crate::store::now()
}

/// `ledger_correction`: a settled correction's selected raw cuts, keyed by (bucket, window).
pub(crate) fn ledger_correction_cuts_by_target<C>(
    cuts: Vec<(String, u64, C)>,
) -> BTreeMap<(String, u64), C> {
    cuts.into_iter()
        .map(|(bucket, window, cell)| ((bucket, window), cell))
        .collect()
}

/// `ledger_correction`: the budget shards a correction's targets live on, in lock order (ascending,
/// each once).
pub(crate) fn ledger_correction_shard_order(shards: impl Iterator<Item = usize>) -> Vec<usize> {
    let mut order: Vec<usize> = shards.collect();
    order.sort();
    order.dedup();
    order
}

/// `ledger_correction`: hold each shard of `order`, in that order, for one correction step.
pub(crate) fn ledger_correction_hold_shards<G>(
    order: &[usize],
    mut hold: impl FnMut(usize) -> G,
) -> Vec<(usize, G)> {
    order.iter().map(|shard| (*shard, hold(*shard))).collect()
}

/// `ledger_correction`: a correction step's staging buffer, sized once to what the step can stage
/// (one entry per target, per pending correction or per moved unit) so filling it never
/// reallocates.
pub(crate) fn ledger_correction_staging<T>(len: usize) -> Vec<T> {
    Vec::with_capacity(len)
}

/// `ledger_correction`: the (bucket, window) targets a correction lands on, ordered and each once,
/// recording each group bucket's owning groups in `owners`.
pub(crate) fn ledger_correction_targets<'a>(
    chain: impl Iterator<Item = (&'a str, u64, Option<&'a str>)>,
    owners: &mut BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, u64)> {
    let mut targets: Vec<(String, u64)> = chain
        .map(|(bucket, window, group)| {
            if let Some(group) = group {
                owners
                    .entry(bucket.into())
                    .or_default()
                    .insert(group.into());
            }
            (bucket.into(), window)
        })
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

/// `ledger_correction`: the corrected key's metering rows of the day.
pub(crate) fn ledger_correction_key_metering(
    rows: impl IntoIterator<Item = MeteringRow>,
    key_id: &str,
) -> Vec<MeteringRow> {
    rows.into_iter()
        .filter(|row| row.key_id == key_id)
        .collect()
}

/// `ledger_correction`: the candidate replacement rows, starting as copies of the expected rows.
pub(crate) fn ledger_correction_replacements(
    snapshots: &BTreeMap<UsageAddress, UsageLedger>,
) -> BTreeMap<UsageAddress, UsageLedger> {
    snapshots.clone()
}

/// `ledger_correction`: the conditional request's usage changes, in address order: each expected
/// row with its canonical replacement.
pub(crate) fn ledger_correction_usage_changes(
    snapshots: BTreeMap<UsageAddress, UsageLedger>,
    replacements: &mut BTreeMap<UsageAddress, UsageLedger>,
) -> Result<Vec<UsageChange>, &'static str> {
    snapshots
        .into_iter()
        .map(|(address, expected)| {
            let mut replacement = replacements.remove(&address).expect("same raw row set");

            busbar_contract::records::correction::canonical_ledger(&mut replacement)?;
            Ok::<_, &'static str>(UsageChange {
                address,
                expected,
                replacement,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

/// `ledger_correction`: drop a window's rolled debt from a correction branch (it is re-staged or
/// has moved into the correction).
pub(crate) fn ledger_correction_release_window<T>(windows: &mut Vec<(u64, T)>, window: u64) {
    windows.retain(|(at, _)| *at != window);
}

/// `ledger_correction`: a fee split's dated counts by era, for a correction's fee differences.
pub(crate) fn ledger_correction_fee_eras(dated: &[(RawRateEra, u64)]) -> BTreeMap<RawRateEra, u64> {
    dated.iter().copied().collect()
}

/// `ledger_correction`: the flush baselines (plain and dated) of a model a correction cut adds to a
/// cell: both start at the cut's counts.
pub(crate) fn ledger_correction_baselines(
    cur: &BTreeMap<String, Count>,
) -> (BTreeMap<String, Count>, BTreeMap<String, Count>) {
    (cur.clone(), cur.clone())
}

/// `ledger_correction`: a raw row model's counts normalized to the exact scale; a bad stored scale
/// or a negative count is refused.
pub(crate) fn ledger_correction_normalized_units(
    units: &BTreeMap<String, i128>,
    scale: u32,
) -> Result<BTreeMap<String, i128>, &'static str> {
    units
        .iter()
        .map(|(k, n)| {
            let count = Count::from_stored(*n, scale).map_err(|_| "invalid stored count scale")?;
            if count.is_negative() {
                return Err("negative stored usage count");
            }
            Ok((k.clone(), count.micros()))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

/// `ledger_correction`: a new raw model's unit counts, holding one unit.
pub(crate) fn ledger_correction_unit_map(unit: &str, count: i128) -> BTreeMap<String, i128> {
    let mut units = BTreeMap::new();
    units.insert(unit.into(), count);
    units
}

/// `ledger_correction_recovery`: a retained correction's custody record, encoded for its recovery
/// event.
pub(crate) fn ledger_correction_recovery_encode<T: serde::Serialize>(
    custody: &T,
) -> Option<Vec<u8>> {
    busbar_contract::json::to_vec(custody).ok()
}

/// `ledger_correction_recovery`: the child operation `owns` picks among a custody's handoffs.
pub(crate) fn ledger_correction_recovery_handoff(
    handoffs: &[RecoveryChild],
    owns: impl Fn(&RecoveryChild) -> bool,
) -> Option<&RecoveryChild> {
    handoffs.iter().find(|child| owns(child))
}

/// `ledger_correction_recovery`: the custody's copy of a cell's group owners.
pub(crate) fn ledger_correction_recovery_owners(owners: &BTreeSet<String>) -> BTreeSet<String> {
    owners.clone()
}

/// `ledger_correction_recovery`: one live model cell, borrowed for its custody copy.
pub(crate) struct ModelRef<'a> {
    pub(crate) model: &'a str,
    pub(crate) era: RawRateEra,
    pub(crate) current: &'a BTreeMap<String, Count>,
    pub(crate) flushed: &'a BTreeMap<String, Count>,
    pub(crate) flushed_era: &'a BTreeMap<String, Count>,
}

/// `ledger_correction_recovery`: the custody's copy of a cell's models.
pub(crate) fn ledger_correction_recovery_models<'a>(
    models: impl Iterator<Item = ModelRef<'a>>,
) -> Vec<RawModel> {
    models
        .map(|model| RawModel {
            model: model.model.to_owned(),
            era: model.era.into(),
            current: model.current.clone(),
            flushed: model.flushed.clone(),
            flushed_era: model.flushed_era.clone(),
        })
        .collect()
}

/// `ledger_correction_recovery`: the custody's copy of a fee split's non-zero dated eras.
pub(crate) fn ledger_correction_recovery_fee_eras(
    dated: &[(RawRateEra, u64)],
) -> Vec<(RawEra, u64)> {
    dated
        .iter()
        .filter(|(_, count)| *count != 0)
        .map(|(era, count)| ((*era).into(), *count))
        .collect()
}

/// `ledger_correction_recovery`: a custody fee split read back, or `None` when an era repeats, is
/// legacy zero, or holds no count.
pub(crate) fn ledger_correction_recovery_fee_rows(
    rows: Vec<(RawEra, u64)>,
) -> Option<Vec<(RawRateEra, u64)>> {
    let mut identities = BTreeSet::new();
    rows.into_iter()
        .map(|(era, count)| {
            let era: RawRateEra = era.into();
            if !identities.insert(era) || era == RawRateEra::legacy(0) || count == 0 {
                return None;
            }
            Some((era, count))
        })
        .collect()
}

/// `ledger_correction_recovery`: the custody's copy of a cell's rolled windows' debts.
pub(crate) fn ledger_correction_recovery_capture_rolled<D>(
    rolled: &[(u64, D)],
    capture: impl Fn(&D) -> RecordStoreResult<RawDebt>,
) -> RecordStoreResult<Vec<(u64, RawDebt)>> {
    rolled
        .iter()
        .map(|(window, debt)| Ok((*window, capture(debt)?)))
        .collect()
}

/// `ledger_correction_recovery`: a custody cell's rolled windows' debts read back.
pub(crate) fn ledger_correction_recovery_restore_rolled<D>(
    rolled: Vec<(u64, RawDebt)>,
    restore: impl Fn(RawDebt) -> RecordStoreResult<D>,
) -> RecordStoreResult<Vec<(u64, D)>> {
    rolled
        .into_iter()
        .map(|(window, debt)| Ok((window, restore(debt)?)))
        .collect()
}

/// `ledger_correction_recovery`: a custody cell's models read back, without the unnamed-lane rows
/// that hold no count (`None`), and how many of those were dropped.
pub(crate) fn ledger_correction_recovery_named_models<M>(
    models: impl Iterator<Item = RecordStoreResult<Option<M>>>,
) -> RecordStoreResult<(Vec<M>, usize)> {
    let mut dropped = 0usize;
    let models = models
        .filter_map(|row| match row {
            Ok(None) => {
                dropped += 1;
                None
            }
            Ok(Some(row)) => Some(Ok(row)),
            Err(e) => Some(Err(e)),
        })
        .collect::<RecordStoreResult<_>>()?;
    Ok((models, dropped))
}

/// `ledger_correction_recovery`: a custody's targets captured from the live cells, in target order.
pub(crate) fn ledger_correction_recovery_capture_targets(
    targets: &[(String, u64)],
    capture: impl Fn(&String, u64) -> RecordStoreResult<RawTarget>,
) -> RecordStoreResult<Vec<RawTarget>> {
    targets
        .iter()
        .map(|(bucket, window)| capture(bucket, *window))
        .collect()
}

/// `ledger_correction_recovery`: a restored custody's (bucket, window) targets, each target's two
/// cells first checked by `check`.
pub(crate) fn ledger_correction_recovery_restore_targets(
    targets: Vec<RawTarget>,
    check: impl Fn(RawCell, &str) -> RecordStoreResult<()>,
) -> RecordStoreResult<Vec<(String, u64)>> {
    targets
        .into_iter()
        .map(|target| {
            check(target.before, &target.bucket)?;
            check(target.accepted, &target.bucket)?;
            Ok((target.bucket, target.window))
        })
        .collect()
}

/// `ledger_correction_recovery`: a settled custody's selected cut per target (the accepted cells
/// when `applied`, else the original ones), read back by `restore`.
pub(crate) fn ledger_correction_recovery_cuts<C>(
    targets: Vec<RawTarget>,
    applied: bool,
    restore: impl Fn(RawCell, &str) -> RecordStoreResult<C>,
) -> RecordStoreResult<Vec<(String, u64, C)>> {
    targets
        .into_iter()
        .map(|target| {
            let cut = if applied {
                target.accepted
            } else {
                target.before
            };
            let cell = restore(cut, &target.bucket)?;
            Ok((target.bucket, target.window, cell))
        })
        .collect()
}

/// A count era as correction custody stores it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEra {
    effective_from: u64,
    entry_id: Option<[u8; 12]>,
}

impl From<RawRateEra> for RawEra {
    fn from(era: RawRateEra) -> Self {
        Self {
            effective_from: era.effective_from,
            entry_id: era.entry_id.map(|id| id.0),
        }
    }
}

impl From<RawEra> for RawRateEra {
    fn from(era: RawEra) -> Self {
        Self {
            effective_from: era.effective_from,
            entry_id: era.entry_id.map(EntryId),
        }
    }
}

/// One model of a custody cell.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawModel {
    pub(crate) model: String,
    pub(crate) era: RawEra,
    pub(crate) current: BTreeMap<String, Count>,
    pub(crate) flushed: BTreeMap<String, Count>,
    pub(crate) flushed_era: BTreeMap<String, Count>,
}

/// A signed raw debt as custody stores it: decimal counts at `scale`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawDebt {
    #[serde(default)]
    scale: u32,
    requests: String,
    billable_requests: String,
    models: BTreeMap<String, BTreeMap<String, String>>,
}

impl RawDebt {
    /// A debt's custody record from its signed totals and per-model unit counts (exact micros),
    /// or `None` when a model repeats.
    pub(crate) fn of_models<'a>(
        requests: i128,
        billable_requests: i128,
        models: impl Iterator<Item = (&'a str, &'a BTreeMap<String, i128>)>,
    ) -> Option<Self> {
        let mut rows = BTreeMap::new();
        for (model, usage_units) in models {
            let units = usage_units
                .iter()
                .map(|(unit, count)| (unit.clone(), count.to_string()))
                .collect();
            if rows.insert(model.to_owned(), units).is_some() {
                return None;
            }
        }
        Some(Self {
            scale: COUNT_SCALE,
            requests: requests.to_string(),
            billable_requests: billable_requests.to_string(),
            models: rows,
        })
    }

    /// The debt read back: its signed totals and one `model(name, units)` per model (exact
    /// micros), or `invalid`'s error for the first count that does not parse or scale.
    pub(crate) fn restore_with<M, E>(
        self,
        invalid: impl Fn(&dyn std::fmt::Display) -> E,
        model: impl Fn(String, BTreeMap<String, i128>) -> M,
    ) -> Result<(i128, i128, Vec<M>), E> {
        let signed = |count: &str| {
            count
                .parse::<i128>()
                .map_err(|_| invalid(&"invalid signed raw debt in custody"))
        };
        let requests = signed(&self.requests)?;
        let billable_requests = signed(&self.billable_requests)?;
        let scale = self.scale;
        let models = self
            .models
            .into_iter()
            .map(|(name, units)| {
                let usage_units = units
                    .into_iter()
                    .map(|(unit, count)| {
                        Ok((
                            unit,
                            Count::from_stored(signed(&count)?, scale)
                                .map_err(|e| invalid(&e))?
                                .micros(),
                        ))
                    })
                    .collect::<Result<_, E>>()?;
                Ok(model(name, usage_units))
            })
            .collect::<Result<_, E>>()?;
        Ok((requests, billable_requests, models))
    }
}

/// A budget cell as correction custody stores it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCell {
    pub(crate) group_owners: BTreeSet<String>,
    pub(crate) window_start: u64,
    pub(crate) requests: u64,
    pub(crate) billable_requests: u64,
    pub(crate) flushed_requests: u64,
    pub(crate) flushed_billable_requests: u64,
    pub(crate) models: Vec<RawModel>,
    pub(crate) fee_eras: Vec<(RawEra, u64)>,
    pub(crate) flushed_fee_eras: Vec<(RawEra, u64)>,
    pub(crate) rolled: Vec<(u64, RawDebt)>,
    pub(crate) rolled_eras: Vec<(u64, RawDebt)>,
    pub(crate) last_touch: u64,
}

/// One correction target as custody stores it: both raw branches of the cell, and any negative
/// debt the quarantined correction absorbed.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTarget {
    pub(crate) bucket: String,
    pub(crate) window: u64,
    pub(crate) before: RawCell,
    pub(crate) accepted: RawCell,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) absorbed_plain: Option<RawDebt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) absorbed_dated: Option<RawDebt>,
}

/// Operator provenance (actor, reason) copied into a recovery verdict or its retained resolution:
/// once per operator-issued recovery decision, never per request.
pub(crate) fn operator_provenance(actor: &str, reason: &str) -> (String, String) {
    (actor.to_owned(), reason.to_owned())
}
