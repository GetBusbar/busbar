// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw branch custody for a conditional correction. This contains no priced projection.

use super::*;

fn change_unit(debt: &mut ExactUsageDelta, model: &str, unit: &str, change: i128) {
    if change == 0 {
        return;
    }
    if let Some(row) = debt.models.iter_mut().find(|row| row.model == model) {
        *row.usage_units.entry(unit.into()).or_default() += change;
    } else {
        debt.models
            .push(crate::governance::exact_debt::ExactModelDelta {
                model: model.into(),
                usage_units: BTreeMap::from([(unit.into(), change)]),
            });
    }
}

fn absorb_with_capacity(
    plain: &mut ExactUsageDelta,
    dated: &mut ExactUsageDelta,
    plain_capacity: &ExactUsageDelta,
    dated_capacity: &ExactUsageDelta,
    held_plain: &ExactUsageDelta,
    held_dated: &ExactUsageDelta,
) -> RecordStoreResult<(ExactUsageDelta, ExactUsageDelta)> {
    use crate::governance::exact_debt::SegmentedUsage;
    let mut capacity = SegmentedUsage::of(plain_capacity, dated_capacity)?.positive();
    capacity.merge(&SegmentedUsage::of(held_plain, held_dated)?);
    let mut remaining = SegmentedUsage::of(plain, dated)?;
    let taken = remaining.take_negatives(Some(&capacity.positive()));
    (*plain, *dated) = remaining.deltas();
    Ok(taken.deltas())
}

fn negate(mut debt: ExactUsageDelta) -> ExactUsageDelta {
    debt.requests = -debt.requests;
    debt.billable_requests = -debt.billable_requests;
    for row in &mut debt.models {
        for count in row.usage_units.values_mut() {
            *count = -*count;
        }
    }
    debt
}

fn window_debt(cell: &BudgetCell, window: u64, dated: bool) -> ExactUsageDelta {
    let mut debt = ExactUsageDelta::default();
    for (_, part) in if dated {
        &cell.rolled_eras
    } else {
        &cell.rolled
    }
    .iter()
    .filter(|(at, _)| *at == window)
    {
        debt.merge(part);
    }
    debt
}

/// Resolve the signed dated segments before taking their positive parts. Taking positive parts
/// after plain aggregation would hide a +5 in one era behind a -3 in another era.
fn positive_rolled(
    plain: &ExactUsageDelta,
    dated: &ExactUsageDelta,
) -> RecordStoreResult<(ExactUsageDelta, ExactUsageDelta)> {
    Ok(
        crate::governance::exact_debt::SegmentedUsage::of(plain, dated)?
            .positive()
            .deltas(),
    )
}

pub(super) fn take_positives(
    cell: &mut BudgetCell,
    window: u64,
) -> RecordStoreResult<Option<(ExactUsageDelta, ExactUsageDelta)>> {
    take_positives_mode(cell, window, false)
}

fn take_positives_mode(
    cell: &mut BudgetCell,
    window: u64,
    common_only: bool,
) -> RecordStoreResult<Option<(ExactUsageDelta, ExactUsageDelta)>> {
    let Some(branch) = cell
        .correction
        .as_ref()
        .filter(|branch| branch.window == window)
    else {
        return Ok(None);
    };
    let mut before = cell.clone();
    before.correction = None;
    let mut accepted = branch.accepted.clone();
    let (plain, dated) = if accepted.window_start == window {
        if accepted.rolled.iter().any(|(at, _)| *at == window)
            || accepted.rolled_eras.iter().any(|(at, _)| *at == window)
            || before.rolled.iter().any(|(at, _)| *at == window)
            || before.rolled_eras.iter().any(|(at, _)| *at == window)
        {
            return Err(unresolved("current common debt overlaps a rolled window"));
        }
        positive_current(&mut before, &mut accepted, common_only)?
    } else {
        let (mut plain, mut dated) = positive_rolled(
            &window_debt(&accepted, window, false),
            &window_debt(&accepted, window, true),
        )?;
        if common_only {
            use crate::governance::exact_debt::SegmentedUsage;
            let (before_plain, before_dated) = positive_rolled(
                &window_debt(&before, window, false),
                &window_debt(&before, window, true),
            )?;
            let mut negative_before =
                SegmentedUsage::of(&negate(before_plain), &negate(before_dated))?;
            let common = negative_before.take_negatives(Some(&SegmentedUsage::of(&plain, &dated)?));
            let (common_plain, common_dated) = common.deltas();
            plain = negate(common_plain);
            dated = negate(common_dated);
        }
        for branch in [&mut before, &mut accepted] {
            for (dated_kind, sent) in [(false, &plain), (true, &dated)] {
                let mut remaining = window_debt(branch, window, dated_kind);
                remaining.merge(&negate(sent.clone()));
                let windows = if dated_kind {
                    &mut branch.rolled_eras
                } else {
                    &mut branch.rolled
                };
                windows.retain(|(at, _)| *at != window);
                if !remaining.is_zero() {
                    windows.push((window, remaining));
                }
            }
        }
        (plain, dated)
    };
    if plain.is_zero() && dated.is_zero() {
        return Ok(Some((plain, dated)));
    }
    let op_id = branch.op_id;
    before.dirty = true;
    accepted.dirty = true;
    before.correction = Some(Box::new(CorrectionBranch {
        op_id,
        window,
        accepted,
    }));
    *cell = before;
    Ok(Some((plain, dated)))
}

fn positive_current(
    before: &mut BudgetCell,
    accepted: &mut BudgetCell,
    common_only: bool,
) -> RecordStoreResult<(ExactUsageDelta, ExactUsageDelta)> {
    let mut plain = ExactUsageDelta::default();
    let mut dated = ExactUsageDelta::default();
    let mut transfers = Vec::new();
    for model in &accepted.models {
        if model.era != RawRateEra::legacy(0) && model.flushed != model.flushed_era {
            return Err(unresolved("common raw model baselines diverged"));
        }
        for (unit, current) in &model.cur {
            let flushed = model.flushed.get(unit).copied().unwrap_or(0);
            let mut amount = current.saturating_sub(flushed);
            if common_only {
                amount = amount.min(
                    before
                        .models
                        .iter()
                        .find(|raw| raw.model == model.model && raw.era == model.era)
                        .map_or(0, |raw| {
                            raw.cur
                                .get(unit)
                                .copied()
                                .unwrap_or(0)
                                .saturating_sub(raw.flushed.get(unit).copied().unwrap_or(0))
                        }),
                );
            }
            if amount == 0 {
                continue;
            }
            change_unit(&mut plain, &model.model, unit, i128::from(amount));
            if model.era != RawRateEra::legacy(0) {
                change_unit(
                    &mut dated,
                    &era_model(model.era, &model.model),
                    unit,
                    i128::from(amount),
                );
            }
            transfers.push((model.model.clone(), model.era, unit.clone(), amount));
        }
    }
    plain.requests = i128::from(accepted.requests.saturating_sub(accepted.flushed_requests));
    if common_only {
        plain.requests = plain.requests.min(i128::from(
            before.requests.saturating_sub(before.flushed_requests),
        ));
    }
    let fees: BTreeMap<_, _> = accepted.fee_eras.dated().iter().copied().collect();
    let flushed: BTreeMap<_, _> = accepted.flushed_fee_eras.dated().iter().copied().collect();
    let mut legacy_fee =
        i128::from(accepted.billable_requests) - i128::from(accepted.flushed_billable_requests);
    let mut fee_transfers = BTreeMap::new();
    let before_fees: BTreeMap<_, _> = before.fee_eras.dated().iter().copied().collect();
    let before_flushed: BTreeMap<_, _> = before.flushed_fee_eras.dated().iter().copied().collect();
    let before_legacy_fee = i128::from(before.billable_requests)
        - i128::from(before.flushed_billable_requests)
        - before_fees
            .values()
            .map(|count| i128::from(*count))
            .sum::<i128>()
        + before_flushed
            .values()
            .map(|count| i128::from(*count))
            .sum::<i128>();
    for era in fees
        .keys()
        .chain(flushed.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        let count = i128::from(fees.get(&era).copied().unwrap_or(0))
            - i128::from(flushed.get(&era).copied().unwrap_or(0));
        legacy_fee -= count;
        let common_count = if common_only {
            count.min(
                i128::from(before_fees.get(&era).copied().unwrap_or(0))
                    - i128::from(before_flushed.get(&era).copied().unwrap_or(0)),
            )
        } else {
            count
        };
        if common_count > 0 {
            plain.billable_requests += common_count;
            change_unit(&mut dated, &era_tag(era), ERA_FEE_UNIT, common_count);
            fee_transfers.insert(era, common_count);
        }
    }
    plain.billable_requests += if common_only {
        legacy_fee.min(before_legacy_fee).max(0)
    } else {
        legacy_fee.max(0)
    };
    for branch in [before, accepted] {
        branch.flushed_requests = exact(checked_move(branch.flushed_requests, plain.requests))?;
        branch.flushed_billable_requests = exact(checked_move(
            branch.flushed_billable_requests,
            plain.billable_requests,
        ))?;
        for (model, era, unit, amount) in &transfers {
            let raw = branch
                .models
                .iter_mut()
                .find(|raw| raw.model == *model && raw.era == *era)
                .ok_or_else(|| unresolved("common raw model missing from one branch"))?;
            let baseline = raw.flushed.entry(unit.clone()).or_default();
            *baseline = exact(checked_move(*baseline, i128::from(*amount)))?;
            if *era != RawRateEra::legacy(0) {
                let baseline = raw.flushed_era.entry(unit.clone()).or_default();
                *baseline = exact(checked_move(*baseline, i128::from(*amount)))?;
            }
        }
        let mut baseline: BTreeMap<_, _> =
            branch.flushed_fee_eras.dated().iter().copied().collect();
        for (era, amount) in &fee_transfers {
            let count = baseline.entry(*era).or_default();
            *count = exact(checked_move(*count, *amount))?;
        }
        branch.flushed_fee_eras = RawFeeEras::of(baseline);
    }
    Ok((plain, dated))
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEra {
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    model: String,
    era: RawEra,
    current: BTreeMap<String, u64>,
    flushed: BTreeMap<String, u64>,
    flushed_era: BTreeMap<String, u64>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDebt {
    // Decimal strings preserve the complete signed range, including values beyond JSON u64.
    requests: String,
    billable_requests: String,
    models: BTreeMap<String, BTreeMap<String, String>>,
}

impl RawDebt {
    fn capture(debt: &ExactUsageDelta) -> RecordStoreResult<Self> {
        let mut models = BTreeMap::new();
        for model in &debt.models {
            if models
                .insert(
                    model.model.clone(),
                    model
                        .usage_units
                        .iter()
                        .map(|(unit, count)| (unit.clone(), count.to_string()))
                        .collect(),
                )
                .is_some()
            {
                return Err(unresolved("duplicate raw debt model in custody"));
            }
        }
        Ok(Self {
            requests: debt.requests.to_string(),
            billable_requests: debt.billable_requests.to_string(),
            models,
        })
    }

    fn restore(self) -> RecordStoreResult<ExactUsageDelta> {
        let signed = |count: &str| {
            count
                .parse::<i128>()
                .map_err(|_| unresolved("invalid signed raw debt in custody"))
        };
        Ok(ExactUsageDelta {
            requests: signed(&self.requests)?,
            billable_requests: signed(&self.billable_requests)?,
            models: self
                .models
                .into_iter()
                .map(|(model, units)| {
                    Ok(crate::governance::exact_debt::ExactModelDelta {
                        model,
                        usage_units: units
                            .into_iter()
                            .map(|(unit, count)| Ok((unit, signed(&count)?)))
                            .collect::<RecordStoreResult<_>>()?,
                    })
                })
                .collect::<RecordStoreResult<_>>()?,
        })
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCell {
    group_owners: std::collections::BTreeSet<String>,
    window_start: u64,
    requests: u64,
    billable_requests: u64,
    flushed_requests: u64,
    flushed_billable_requests: u64,
    models: Vec<RawModel>,
    fee_eras: Vec<(RawEra, u64)>,
    flushed_fee_eras: Vec<(RawEra, u64)>,
    rolled: Vec<(u64, RawDebt)>,
    rolled_eras: Vec<(u64, RawDebt)>,
    last_touch: u64,
}

impl RawCell {
    fn capture(cell: &BudgetCell) -> RecordStoreResult<Self> {
        Ok(Self {
            group_owners: cell.group_owners.clone(),
            window_start: cell.window_start,
            requests: cell.requests,
            billable_requests: cell.billable_requests,
            flushed_requests: cell.flushed_requests,
            flushed_billable_requests: cell.flushed_billable_requests,
            models: cell
                .models
                .iter()
                .map(|model| RawModel {
                    model: model.model.to_string(),
                    era: model.era.into(),
                    current: model.cur.clone(),
                    flushed: model.flushed.clone(),
                    flushed_era: model.flushed_era.clone(),
                })
                .collect(),
            fee_eras: cell
                .fee_eras
                .dated()
                .iter()
                .filter(|(_, count)| *count != 0)
                .map(|(era, count)| ((*era).into(), *count))
                .collect(),
            flushed_fee_eras: cell
                .flushed_fee_eras
                .dated()
                .iter()
                .filter(|(_, count)| *count != 0)
                .map(|(era, count)| ((*era).into(), *count))
                .collect(),
            rolled: cell
                .rolled
                .iter()
                .map(|(window, debt)| Ok((*window, RawDebt::capture(debt)?)))
                .collect::<RecordStoreResult<_>>()?,
            rolled_eras: cell
                .rolled_eras
                .iter()
                .map(|(window, debt)| Ok((*window, RawDebt::capture(debt)?)))
                .collect::<RecordStoreResult<_>>()?,
            last_touch: cell.last_touch,
        })
    }

    fn restore(self) -> RecordStoreResult<BudgetCell> {
        let mut identities = std::collections::BTreeSet::new();
        let models = self
            .models
            .into_iter()
            .map(|model| {
                let era = model.era.into();
                if !identities.insert((model.model.clone(), era)) {
                    return Err(unresolved("duplicate raw model era in custody"));
                }
                Ok(ModelCell {
                    model: model.model.into(),
                    era,
                    cur: model.current,
                    flushed: model.flushed,
                    flushed_era: model.flushed_era,
                })
            })
            .collect::<RecordStoreResult<_>>()?;
        let fees = |rows: Vec<(RawEra, u64)>| -> RecordStoreResult<RawFeeEras> {
            let mut identities = std::collections::BTreeSet::new();
            let rows = rows
                .into_iter()
                .map(|(era, count)| {
                    let era: RawRateEra = era.into();
                    if !identities.insert(era) || era == RawRateEra::legacy(0) || count == 0 {
                        return Err(unresolved("invalid raw fee era in custody"));
                    }
                    Ok((era, count))
                })
                .collect::<RecordStoreResult<Vec<_>>>()?;
            Ok(RawFeeEras::of(rows))
        };
        let mut cell = BudgetCell {
            group_owners: self.group_owners,
            window_start: self.window_start,
            requests: self.requests,
            billable_requests: self.billable_requests,
            flushed_requests: self.flushed_requests,
            flushed_billable_requests: self.flushed_billable_requests,
            models,
            fee_eras: fees(self.fee_eras)?,
            flushed_fee_eras: fees(self.flushed_fee_eras)?,
            rolled: self
                .rolled
                .into_iter()
                .map(|(window, debt)| Ok((window, debt.restore()?)))
                .collect::<RecordStoreResult<_>>()?,
            rolled_eras: self
                .rolled_eras
                .into_iter()
                .map(|(window, debt)| Ok((window, debt.restore()?)))
                .collect::<RecordStoreResult<_>>()?,
            last_touch: self.last_touch,
            ..Default::default()
        };
        // Runtime flight locks are not durable ownership. The recovery coordinator restores
        // any still-unresolved additive flights before admission; their payloads own that debt.
        cell.dirty = has_debt(&cell);
        Ok(cell)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    bucket: String,
    window: u64,
    before: RawCell,
    accepted: RawCell,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    absorbed_plain: Option<RawDebt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    absorbed_dated: Option<RawDebt>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Custody {
    version: u32,
    request: Request,
    intent: Intent,
    sent_at: u64,
    decision: Option<RawDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<RecoveryOrigin>,
    #[serde(default)]
    handoffs: Vec<RecoveryChild>,
    #[serde(default)]
    terminal: bool,
    #[serde(default)]
    age_unknown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repost_operation_id: Option<[u8; 16]>,
    #[serde(default)]
    intent_applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit: Option<OperatorAudit>,
    targets: Vec<RawTarget>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorAudit {
    pub(super) actor: String,
    pub(super) reason: String,
    pub(super) expected_revision: u64,
    pub(super) landed: bool,
    pub(super) sender_quiesced: bool,
    pub(super) backend_quiesced: bool,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawDecision {
    Applied,
    ConditionConflict,
}

impl From<Decision> for RawDecision {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Applied => Self::Applied,
            Decision::ConditionConflict => Self::ConditionConflict,
        }
    }
}

impl From<RawDecision> for Decision {
    fn from(decision: RawDecision) -> Self {
        match decision {
            RawDecision::Applied => Self::Applied,
            RawDecision::ConditionConflict => Self::ConditionConflict,
        }
    }
}

impl Custody {
    pub(super) fn release_common_positives(&mut self) -> RecordStoreResult<bool> {
        if self.terminal || self.decision.is_some() {
            return Ok(false);
        }
        let mut changed = false;
        for target in &mut self.targets {
            let mut before = target.before.clone_raw()?;
            before.correction = Some(Box::new(CorrectionBranch {
                op_id: self.request.op_id,
                window: target.window,
                accepted: target.accepted.clone_raw()?,
            }));
            let Some((plain, dated)) = take_positives_mode(&mut before, target.window, true)?
            else {
                return Err(unresolved(
                    "stored common positive has no exact branch custody",
                ));
            };
            let Some(child) =
                GovState::usage_recovery_child(&target.bucket, target.window, plain, dated)?
            else {
                continue;
            };
            target.accepted = RawCell::capture(
                &before
                    .correction
                    .as_ref()
                    .expect("temporary branch retained")
                    .accepted,
            )?;
            target.before = RawCell::capture(&before)?;
            self.handoffs.push(child);
            changed = true;
        }
        Ok(changed)
    }

    pub(super) fn mark_age_unknown(&mut self) {
        self.age_unknown = true;
    }

    pub(super) fn stage_settlement(
        gov: &GovState,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<Self> {
        let mut custody = Self::capture(gov, pending)?;
        custody.transfer_selected(decision, true)?;
        Ok(custody)
    }

    pub(super) fn transfer_selected(
        &mut self,
        decision: Decision,
        include_absorbed: bool,
    ) -> RecordStoreResult<()> {
        if self.terminal {
            return Ok(());
        }
        for target in &mut self.targets {
            let selected = if decision == Decision::Applied {
                &target.accepted
            } else {
                &target.before
            };
            let selected = selected.clone_raw()?;
            let window = target.window;
            let mut plain = window_debt(&selected, window, false);
            let mut dated = window_debt(&selected, window, true);
            if selected.window_start == window {
                plain.merge(&ExactUsageDelta::of(&selected, false));
                dated.merge(&ExactUsageDelta::of(&selected, true));
            }
            if include_absorbed {
                if let Some(held) = target.absorbed_plain.take() {
                    plain.merge(&held.restore()?);
                }
                if let Some(held) = target.absorbed_dated.take() {
                    dated.merge(&held.restore()?);
                }
            }
            if let Some(child) =
                GovState::usage_recovery_child(&target.bucket, window, plain, dated)?
            {
                self.handoffs.push(child);
            }
        }
        self.decision = Some(decision.into());
        self.intent_applied = decision == Decision::Applied;
        self.terminal = true;
        Ok(())
    }

    pub(super) fn attach_repost(&mut self, child: RecoveryChild) -> RecordStoreResult<()> {
        if !self.terminal || child.kind != RecoveryKind::Correction || self.intent_applied {
            return Err(unresolved(
                "conditional successor does not follow an unlanded raw cut",
            ));
        }
        self.repost_operation_id = Some(child.operation_id);
        self.handoffs.push(child);
        Ok(())
    }

    pub(super) fn repost_operation_id(&self) -> Option<[u8; 16]> {
        self.repost_operation_id
    }

    pub(super) fn repost_descriptor(&self) -> Option<&RecoveryChild> {
        self.repost_operation_id.and_then(|operation_id| {
            self.handoffs.iter().find(|child| {
                child.operation_id == operation_id && child.kind == RecoveryKind::Correction
            })
        })
    }

    pub(super) fn intent_applied(&self) -> bool {
        self.intent_applied
    }

    pub(super) fn finish_repost(&mut self) -> RecordStoreResult<()> {
        if !self.terminal || self.repost_operation_id.is_none() {
            return Err(unresolved(
                "no conditional successor owns the revalidated correction",
            ));
        }
        for target in &mut self.targets {
            let plain = target
                .absorbed_plain
                .take()
                .map(RawDebt::restore)
                .transpose()?
                .unwrap_or_default();
            let dated = target
                .absorbed_dated
                .take()
                .map(RawDebt::restore)
                .transpose()?
                .unwrap_or_default();
            if let Some(child) =
                GovState::usage_recovery_child(&target.bucket, target.window, plain, dated)?
            {
                self.handoffs.push(child);
            }
        }
        self.intent_applied = true;
        Ok(())
    }

    pub(super) fn verdict_matches(&self, resolution: &RecoveryResolution) -> bool {
        self.audit.as_ref().is_some_and(|audit| {
            audit.actor == resolution.actor
                && audit.reason == resolution.reason
                && audit.landed == (resolution.verdict == RecoveryVerdict::Landed)
                && audit.sender_quiesced == resolution.sender_quiesced
                && audit.backend_quiesced == resolution.backend_quiesced
        })
    }

    pub(super) fn retained_resolution(
        &self,
        event: &RecoveryEvent,
    ) -> RecordStoreResult<RecoveryResolution> {
        let audit = self
            .audit
            .as_ref()
            .ok_or_else(|| unresolved("audited correction has no operator provenance"))?;
        if !audit.sender_quiesced || !audit.backend_quiesced {
            return Err(unresolved(
                "audited correction has no explicit quiescence attestations",
            ));
        }
        Ok(RecoveryResolution {
            operation_id: event.operation_id,
            body_fingerprint: event.body_fingerprint,
            expected_revision: audit.expected_revision,
            verdict: if audit.landed {
                RecoveryVerdict::Landed
            } else {
                RecoveryVerdict::NotLanded
            },
            actor: audit.actor.clone(),
            reason: audit.reason.clone(),
            sender_quiesced: audit.sender_quiesced,
            backend_quiesced: audit.backend_quiesced,
        })
    }

    pub(super) fn validate_event(&self, event: &RecoveryEvent) -> RecordStoreResult<()> {
        if self.request.op_id.0 != event.operation_id
            || self.request.fingerprint() != event.body_fingerprint
            || self.sent_at.checked_mul(1_000) != event.first_sent_at_ms
            || event.kind != RecoveryKind::Correction
        {
            return Err(unresolved("raw correction custody event identity mismatch"));
        }
        let decision: Option<Decision> = self.decision.map(Into::into);
        let valid = match event.state {
            RecoveryState::Intent | RecoveryState::LandedUnknown => {
                decision.is_none() && !self.terminal
            }
            RecoveryState::Applied => decision == Some(Decision::Applied) && !self.terminal,
            RecoveryState::ConditionConflict => {
                decision == Some(Decision::ConditionConflict) && !self.terminal
            }
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded => {
                let landed = event.state == RecoveryState::VerdictLanded;
                self.audit.as_ref().is_some_and(|audit| {
                    audit.landed == landed && audit.sender_quiesced && audit.backend_quiesced
                }) && decision
                    == Some(if landed {
                        Decision::Applied
                    } else {
                        Decision::ConditionConflict
                    })
            }
            RecoveryState::Settled => self.terminal && decision.is_some(),
        };
        if !valid {
            return Err(unresolved(
                "raw correction custody contradicts its selected state",
            ));
        }
        Ok(())
    }

    pub(super) fn owns_quarantined_target(&self, bucket: &str, window: u64) -> bool {
        !self.intent_applied
            && self
                .targets
                .iter()
                .any(|target| target.bucket == bucket && target.window == window)
    }

    pub(super) fn record_verdict(&mut self, resolution: &RecoveryResolution) {
        self.decision = Some(match resolution.verdict {
            RecoveryVerdict::Landed => RawDecision::Applied,
            RecoveryVerdict::NotLanded => RawDecision::ConditionConflict,
        });
        self.audit = Some(OperatorAudit {
            actor: resolution.actor.clone(),
            reason: resolution.reason.clone(),
            expected_revision: resolution.expected_revision,
            landed: resolution.verdict == RecoveryVerdict::Landed,
            sender_quiesced: resolution.sender_quiesced,
            backend_quiesced: resolution.backend_quiesced,
        });
    }

    pub(super) fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub(super) fn selected_cuts(self) -> RecordStoreResult<Vec<(String, u64, BudgetCell)>> {
        let decision = self
            .decision
            .ok_or_else(|| unresolved("selected correction has no decision"))?;
        self.targets
            .into_iter()
            .map(|target| {
                let cut = match decision {
                    RawDecision::Applied => target.accepted,
                    RawDecision::ConditionConflict => target.before,
                };
                Ok((target.bucket, target.window, cut.restore()?))
            })
            .collect()
    }

    pub(super) fn capture(gov: &GovState, pending: &PendingCorrection) -> RecordStoreResult<Self> {
        let previous = pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|event| Self::decode(&event.payload))
            .transpose()?;
        let mut order: Vec<_> = pending
            .targets
            .iter()
            .map(|(bucket, _)| gov.budget.shard_index(bucket))
            .collect();
        order.sort_unstable();
        order.dedup();
        let guards: Vec<_> = order
            .iter()
            .map(|shard| {
                gov.budget
                    .shard_at(*shard)
                    .map
                    .read()
                    .unwrap_or_else(|p| p.into_inner())
            })
            .collect();
        let targets = pending
            .targets
            .iter()
            .map(|(bucket, window)| {
                let index = order
                    .binary_search(&gov.budget.shard_index(bucket))
                    .expect("target shard held");
                let cell = guards[index]
                    .get(bucket)
                    .ok_or_else(|| unresolved("raw custody cell missing"))?;
                let branch = cell
                    .correction
                    .as_ref()
                    .filter(|branch| {
                        branch.op_id == pending.request.op_id && branch.window == *window
                    })
                    .ok_or_else(|| unresolved("raw custody branch missing"))?;
                if branch.accepted.correction.is_some() {
                    return Err(unresolved("nested raw custody branch"));
                }
                Ok(RawTarget {
                    bucket: bucket.clone(),
                    window: *window,
                    before: RawCell::capture(cell)?,
                    accepted: RawCell::capture(&branch.accepted)?,
                    absorbed_plain: None,
                    absorbed_dated: None,
                })
            })
            .collect::<RecordStoreResult<_>>()?;
        Ok(Self {
            version: 1,
            request: pending.request.clone(),
            intent: pending.intent.clone(),
            sent_at: pending.sent_at,
            decision: pending
                .receipt
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .map(Into::into),
            origin: previous.as_ref().and_then(|custody| custody.origin.clone()),
            handoffs: previous
                .as_ref()
                .map(|custody| custody.handoffs.clone())
                .unwrap_or_default(),
            terminal: false,
            age_unknown: false,
            repost_operation_id: previous
                .as_ref()
                .and_then(|custody| custody.repost_operation_id),
            intent_applied: false,
            audit: previous.and_then(|custody| custody.audit),
            targets,
        })
    }

    pub(super) fn encode(&self) -> RecordStoreResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| unresolved("cannot encode raw correction custody"))
    }

    pub(super) fn decode(bytes: &[u8]) -> RecordStoreResult<Self> {
        let custody: Self = serde_json::from_slice(bytes)
            .map_err(|_| unresolved("invalid raw correction custody encoding"))?;
        if custody.version != 1 || custody.targets.is_empty() {
            return Err(unresolved("unsupported or empty raw correction custody"));
        }
        exact(custody.request.validate())?;
        let mut previous = None;
        for target in &custody.targets {
            let identity = (&target.bucket, target.window);
            if previous.is_some_and(|old| old >= identity)
                || target.before.window_start != target.accepted.window_start
            {
                return Err(unresolved("invalid raw correction custody targets"));
            }
            previous = Some(identity);
            for bucket in [target.bucket.clone(), era_bucket(&target.bucket)] {
                if !custody.request.usage.iter().any(|row| {
                    row.address.bucket_id == bucket && row.address.window_start == target.window
                }) {
                    return Err(unresolved("raw correction custody target outside request"));
                }
            }
        }
        Ok(custody)
    }

    pub(super) fn replace_target(
        &mut self,
        bucket: &str,
        cell: &BudgetCell,
        window: u64,
        child: RecoveryChild,
    ) -> RecordStoreResult<()> {
        let branch = cell
            .correction
            .as_ref()
            .filter(|branch| branch.op_id == self.request.op_id && branch.window == window)
            .ok_or_else(|| unresolved("correction handoff target does not match its parent"))?;
        let target = self
            .targets
            .iter_mut()
            .find(|target| target.bucket == bucket && target.window == window)
            .ok_or_else(|| unresolved("correction handoff target is outside raw custody"))?;
        target.before = RawCell::capture(cell)?;
        target.accepted = RawCell::capture(&branch.accepted)?;
        if let Some(existing) = self
            .handoffs
            .iter()
            .find(|existing| existing.operation_id == child.operation_id)
        {
            if existing != &child {
                return Err(unresolved(
                    "correction child identity has another immutable body",
                ));
            }
        } else {
            self.handoffs.push(child);
        }
        Ok(())
    }

    pub(super) fn absorb_negatives(
        &mut self,
        bucket: &str,
        window: u64,
        plain: &ExactUsageDelta,
        dated: &ExactUsageDelta,
    ) -> RecordStoreResult<Option<(ExactUsageDelta, ExactUsageDelta)>> {
        let capacity = |bucket: &str| -> RecordStoreResult<ExactUsageDelta> {
            let row = self
                .request
                .usage
                .iter()
                .find(|row| row.address.bucket_id == bucket && row.address.window_start == window)
                .ok_or_else(|| unresolved("quarantined target has no original raw row"))?;
            let mut capacity = ExactUsageDelta {
                requests: i128::from(row.replacement.requests) - i128::from(row.expected.requests),
                billable_requests: i128::from(row.replacement.billable_requests)
                    - i128::from(row.expected.billable_requests),
                ..Default::default()
            };
            for model in &row.replacement.models {
                let before = row
                    .expected
                    .models
                    .iter()
                    .find(|before| before.model == model.model);
                for (unit, count) in &model.usage_units {
                    let previous = before
                        .and_then(|before| before.usage_units.get(unit))
                        .copied()
                        .unwrap_or(0);
                    change_unit(
                        &mut capacity,
                        &model.model,
                        unit,
                        i128::from(*count) - i128::from(previous),
                    );
                }
            }
            for model in &row.expected.models {
                let after = row
                    .replacement
                    .models
                    .iter()
                    .find(|after| after.model == model.model);
                for (unit, count) in &model.usage_units {
                    if after.is_none_or(|after| !after.usage_units.contains_key(unit)) {
                        change_unit(&mut capacity, &model.model, unit, -i128::from(*count));
                    }
                }
            }
            Ok(capacity)
        };
        let plain_capacity = capacity(bucket)?;
        let dated_capacity = capacity(&era_bucket(bucket))?;
        let target = self
            .targets
            .iter_mut()
            .find(|target| target.bucket == bucket && target.window == window)
            .ok_or_else(|| unresolved("quarantined negative is outside correction targets"))?;
        let mut held_plain = target
            .absorbed_plain
            .clone()
            .map(RawDebt::restore)
            .transpose()?
            .unwrap_or_default();
        let mut held_dated = target
            .absorbed_dated
            .clone()
            .map(RawDebt::restore)
            .transpose()?
            .unwrap_or_default();
        let mut remaining_plain = plain.clone();
        let mut remaining_dated = dated.clone();
        let (absorbed_plain, absorbed_dated) = absorb_with_capacity(
            &mut remaining_plain,
            &mut remaining_dated,
            &plain_capacity,
            &dated_capacity,
            &held_plain,
            &held_dated,
        )?;
        if absorbed_plain.is_zero() && absorbed_dated.is_zero() {
            return Ok(None);
        }
        held_plain.merge(&absorbed_plain);
        held_dated.merge(&absorbed_dated);
        target.absorbed_plain = Some(RawDebt::capture(&held_plain)?);
        target.absorbed_dated = Some(RawDebt::capture(&held_dated)?);
        Ok(Some((remaining_plain, remaining_dated)))
    }

    /// Validate immutable raw evidence and register quarantine, without installing old aggregate
    /// snapshots over the fresh Store-backed admission state.
    pub(super) fn restore(
        self,
        _gov: &GovState,
        event: &RecoveryEvent,
    ) -> RecordStoreResult<PendingCorrection> {
        if self.request.op_id.0 != event.operation_id
            || self.request.fingerprint() != event.body_fingerprint
            || self.sent_at.checked_mul(1_000) != event.first_sent_at_ms
            || event.kind != RecoveryKind::Correction
        {
            return Err(unresolved("raw correction custody event identity mismatch"));
        }
        let mut targets = Vec::new();
        for target in self.targets {
            // Validate the immutable evidence without claiming an old aggregate as current RAM.
            target.before.restore()?;
            target.accepted.restore()?;
            targets.push((target.bucket, target.window));
        }
        Ok(PendingCorrection {
            request: self.request,
            intent: self.intent,
            targets,
            sent_at: self.sent_at,
            started: std::time::Instant::now(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            receipt: Arc::new(std::sync::Mutex::new(self.decision.map(Into::into))),
            settled: Arc::new(std::sync::Mutex::new(None)),
            recovery_event: Arc::new(std::sync::Mutex::new(Some(event.clone()))),
            quarantined: true,
            parent_operation_id: None,
            authorization: Arc::new(std::sync::Mutex::new(None)),
            verdict_pending: Arc::new(std::sync::atomic::AtomicBool::new(matches!(
                event.state,
                RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded
            ))),
        })
    }
}

impl RawCell {
    fn clone_raw(&self) -> RecordStoreResult<BudgetCell> {
        self.clone().restore()
    }
}

/// A cut's exact raw debt has moved into parent-authorized child operations. Advance only that
/// cut, preserving accruals, refunds and rolls that happened while its checkpoint was persisting.
pub(super) fn apply_selected_cut(
    live: &mut BudgetCell,
    cut: &BudgetCell,
    window: u64,
) -> RecordStoreResult<()> {
    for dated in [false, true] {
        let mut transferred = window_debt(cut, window, dated);
        if window == cut.window_start && live.window_start != window {
            transferred.merge(&ExactUsageDelta::of(cut, dated));
        }
        let mut remaining = window_debt(live, window, dated);
        remaining.merge(&negate(transferred));
        let rolled = if dated {
            &mut live.rolled_eras
        } else {
            &mut live.rolled
        };
        rolled.retain(|(at, _)| *at != window);
        if !remaining.is_zero() {
            rolled.push((window, remaining));
        }
    }
    if live.window_start == window && cut.window_start == window {
        live.flushed_requests = cut.requests;
        live.flushed_billable_requests = cut.billable_requests;
        live.flushed_fee_eras = cut.fee_eras.clone();
        for model in &mut live.models {
            if let Some(base) = cut
                .models
                .iter()
                .find(|base| base.model == model.model && base.era == model.era)
            {
                model.flushed = base.cur.clone();
                model.flushed_era = base.cur.clone();
            }
        }
        // A fully refunded segment may have disappeared from the live vector; its cut baseline
        // must still carry the dependent negative until the next ordinary flush.
        for base in &cut.models {
            if !live
                .models
                .iter()
                .any(|model| model.model == base.model && model.era == base.era)
            {
                live.models.push(ModelCell {
                    model: base.model.clone(),
                    era: base.era,
                    cur: BTreeMap::new(),
                    flushed: base.cur.clone(),
                    flushed_era: base.cur.clone(),
                });
            }
        }
    } else if live.window_start < window {
        return Err(unresolved("correction cut moved backwards across windows"));
    }
    live.dirty = has_debt(live);
    Ok(())
}
