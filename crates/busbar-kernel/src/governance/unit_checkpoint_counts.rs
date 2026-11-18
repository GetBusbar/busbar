// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transfer a terminal unit into exact raw recovery custody, without an ordinary second bill.

use super::recovery::{RecoveryEvent, RecoveryState};
use super::unit_checkpoint::UnitCheckpoint;
use super::*;

impl GovState {
    pub(super) fn unit_terminal_events(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<Vec<RecoveryEvent>> {
        // The unit's terminal is one transfer: every child it makes, usage and metering alike,
        // is first sent at this one reading.
        let sent_at_ms = crate::store::now_ms();
        if snapshot.partitions.is_some() {
            return Self::selected_terminal_events(snapshot, sent_at_ms);
        }
        let mut cell = BudgetCell::default();
        // No counts, no row (#42): accrue_raw creates a lane row only from a non-zero count.
        cell.accrue_raw(&snapshot.lane, snapshot.era(), &snapshot.units)
            .map_err(crate::governance::store_error)?;
        let plain = ExactUsageDelta::of(&cell, false);
        let dated = ExactUsageDelta::of(&cell, true);
        let mut events = crate::off_path::governance::runtime::unit_checkpoint_counts_events(
            snapshot
                .targets
                .iter()
                .map(|target| -> RecordStoreResult<Option<RecoveryEvent>> {
                    let Some(child) = Self::usage_recovery_child(
                        &target.bucket,
                        target.window,
                        plain.clone(),
                        dated.clone(),
                        sent_at_ms,
                    )?
                    else {
                        return Ok(None);
                    };
                    self.new_recovery_event(
                        child.operation_id,
                        child.kind,
                        child.body_fingerprint,
                        RecoveryState::Intent,
                        child.first_sent_at_ms,
                        child.payload,
                    )
                    .map(Some)
                    .map_err(crate::governance::store_error)
                }),
        )?;
        let (plane, subject) = busbar_kernel_ledger::cost::split_plane_lane(&snapshot.lane);
        let (model, provider) = if snapshot.measurement.is_some() {
            // Keep the dedicated encoded measurement lane. It is not a model or
            // plane lane and must not merge with either in the metering rows.
            (snapshot.lane.as_str(), "")
        } else if plane.is_empty() {
            (
                snapshot.lane.as_str(),
                snapshot.provider.as_deref().unwrap_or(""),
            )
        } else {
            (subject, plane)
        };
        let mut counts = if snapshot.measurement.is_none()
            && snapshot.metered
            && (!plane.is_empty() || snapshot.provider.is_some())
        {
            if plane.is_empty() {
                MeterCounts::request(&snapshot.units)
            } else {
                MeterCounts {
                    requests: 1,
                    ..Default::default()
                }
            }
        } else {
            MeterCounts::default()
        };
        counts.usage_units =
            crate::off_path::governance::runtime::unit_checkpoint_counts_usage_units(
                &snapshot.units,
                |name, count| {
                    !count.is_zero()
                        && !(snapshot.measurement.is_none()
                            && plane.is_empty()
                            && busbar_contract::records::RESERVED_UNITS.contains(&name))
                },
            );
        let key: MeterIdentity = (
            snapshot.principal.clone(),
            metering_bucket(snapshot.arrived),
            model.into(),
            provider.into(),
            snapshot.era_at,
            snapshot.group.clone(),
            snapshot
                .era()
                .entry_id
                .map(|id| id.metering_version())
                .unwrap_or_default(),
        )
            .into();
        while !counts.is_zero() {
            let (delta, remaining) = metering_flush::metering_chunk(&key, &counts);
            events.push(self.metering_recovery_intent(
                crate::door::op_id().0,
                sent_at_ms,
                &delta,
            )?);
            counts = remaining;
        }
        Ok(events)
    }

    /// Build all selected children without touching the recovery book. One usage child per
    /// admitted target includes every original lane, and each meter retains its exact provider.
    /// Every child is first sent at `sent_at_ms`: the selected terminal is one transfer, and this
    /// builder reads no clock.
    fn selected_terminal_events(
        snapshot: &UnitCheckpoint,
        sent_at_ms: u64,
    ) -> RecordStoreResult<Vec<RecoveryEvent>> {
        use super::unit_checkpoint::partitions::{
            ValidatedSelectedCheckpoint, MAX_TERMINAL_EVENTS,
        };
        let projection = ValidatedSelectedCheckpoint::try_from(snapshot)?.project()?;
        let mut cell = BudgetCell::default();
        for (lane, counts) in projection.billed_by_lane()? {
            cell.accrue_raw(&lane, snapshot.era(), &counts)
                .map_err(crate::governance::store_error)?;
        }
        let plain = ExactUsageDelta::of(&cell, false);
        let dated = ExactUsageDelta::of(&cell, true);
        let initial = |child: super::recovery::RecoveryChild| RecoveryEvent {
            operation_id: child.operation_id,
            revision: 0,
            previous_event: None,
            kind: child.kind,
            body_fingerprint: child.body_fingerprint,
            state: RecoveryState::Intent,
            first_sent_at_ms: child.first_sent_at_ms,
            payload: child.payload,
        };
        let mut events = Vec::new();
        for target in &snapshot.targets {
            if let Some(child) = Self::usage_recovery_child(
                &target.bucket,
                target.window,
                plain.clone(),
                dated.clone(),
                sent_at_ms,
            )? {
                events.push(initial(child));
            }
        }
        for (key, mut counts) in selected_meter_counts(&projection) {
            while !counts.is_zero() {
                if events.len() == MAX_TERMINAL_EVENTS {
                    return Err(RecordStoreError(
                        "selected terminal vector exceeds bound".into(),
                    ));
                }
                let (delta, remaining) = metering_flush::metering_chunk(&key, &counts);
                events.push(initial(Self::metering_recovery_child(
                    crate::door::op_id().0,
                    sent_at_ms,
                    &delta,
                )?));
                counts = remaining;
            }
        }
        Ok(events)
    }

    pub(super) fn validate_selected_terminal(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<()> {
        if snapshot.partitions.is_none() {
            return Ok(());
        }
        let Some(actual) = &snapshot.terminal else {
            return Ok(());
        };
        // The expected vector, dated as the sealed one is: the comparison below reads kind,
        // fingerprint and payload, never a first-sent time, so validating reads no clock.
        let dated = actual
            .first()
            .and_then(|event| event.first_sent_at_ms)
            .unwrap_or_default();
        let expected = Self::selected_terminal_events(snapshot, dated)?;
        if actual.len() != expected.len()
            || actual.iter().zip(expected).any(|(a, e)| {
                a.revision != 0
                    || a.previous_event.is_some()
                    || a.state != RecoveryState::Intent
                    || a.kind != e.kind
                    || a.body_fingerprint != e.body_fingerprint
                    || a.payload != e.payload
            })
        {
            return Err(RecordStoreError(
                "selected terminal vector differs from immutable projection".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_selected_terminal_capacity(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<()> {
        if snapshot.partitions.is_none() {
            return Ok(());
        }
        // Measured as it would be sealed now: the first-sent time is part of the encoded size.
        let events = Self::selected_terminal_events(snapshot, crate::store::now_ms())?;
        let mut sealed = snapshot.clone();
        sealed.terminal = Some(events);
        super::unit_checkpoint::partitions::check_size(&sealed)
    }

    /// Once a recovered unit's durable receipts settle, reload its exact targets before allowing
    /// further admission. Active ordinary flushes retain ownership and postpone this refresh.
    pub(super) async fn refresh_recovered_unit_targets(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<()> {
        // Capture the entire hot value, then release every shard/flush guard
        // before crossing Store. Publish only if that same value still owns it.
        let shards = crate::off_path::governance::runtime::unit_checkpoint_counts_shards(
            snapshot
                .targets
                .iter()
                .map(|t| self.budget.shard_index(&t.bucket)),
        );
        // Each target's captured hot cell, beside the durable cell its reload publishes.
        let capture = || -> RecordStoreResult<Vec<(Option<BudgetCell>, Option<BudgetCell>)>> {
            let guards: smallvec::SmallVec<[_; 4]> = shards
                .iter()
                .map(|&index| self.budget.shard_at(index).read())
                .collect();
            let flights = self
                .budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            crate::off_path::governance::runtime::unit_checkpoint_counts_try_collect(
                snapshot.targets.iter().map(|target| {
                    let index = shards
                        .binary_search(&self.budget.shard_index(&target.bucket))
                        .expect("target shard held");
                    let cell = guards[index].get(&target.bucket);
                    if cell.is_some_and(|cell| {
                        cell.dirty || cell.flushing != 0 || cell.correction.is_some()
                    }) || crate::off_path::governance::runtime::unit_checkpoint_counts_in_flight(
                        &flights,
                        &target.bucket,
                    ) {
                        return Err(RecordStoreError(
                            "recovered unit target still has ordinary raw custody".into(),
                        ));
                    }
                    Ok((cell.cloned(), None))
                }),
            )
        };
        let mut before = capture()?;
        let epoch = self.recovery_selection_epoch();
        let store = self.core_store()?;
        let check_pending = || -> RecordStoreResult<()> {
            for target in &snapshot.targets {
                let namespace = crate::persistence::partition::namespace(
                    super::persistence::ledger::USAGE,
                    &[&target.window.to_be_bytes()],
                );
                if store.has_pending_namespace(namespace).map_err(|e| {
                    rendered_error(
                        RecordStoreError,
                        format_args!("checkpoint ledger custody: {e:?}"),
                    )
                })? {
                    return Err(RecordStoreError(
                        "recovered unit target has an unresolved native candidate".into(),
                    ));
                }
            }
            Ok(())
        };
        check_pending()?;
        let touched = crate::store::now();
        for (target, (previous, refreshed)) in snapshot.targets.iter().zip(before.iter_mut()) {
            if previous
                .as_ref()
                .is_some_and(|cell| cell.window_start > target.window)
            {
                continue;
            }
            let (plain, dated) = store
                .ledger()
                .get_usage_pair(&target.bucket, &era_bucket(&target.bucket), target.window)
                .await?;
            let mut cell = super::state::durable_cell(&target.bucket, plain, dated, target.window)?;
            cell.last_touch = touched;
            if let Some(previous) = previous {
                cell.group_owners.clone_from(&previous.group_owners);
            }
            if let Some(group) = &target.group {
                cell.group_owners.insert(group.clone());
            }
            *refreshed = Some(cell);
        }
        check_pending()?;
        if self.recovery_selection_epoch() != epoch {
            return Err(RecordStoreError(
                "recovery selection changed during unit reload".into(),
            ));
        }
        let mut guards: smallvec::SmallVec<[_; 4]> = shards
            .iter()
            .map(|&index| self.budget.shard_at(index).write())
            .collect();
        let flights = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for (target, (previous, _)) in snapshot.targets.iter().zip(&before) {
            let index = shards
                .binary_search(&self.budget.shard_index(&target.bucket))
                .expect("target shard held");
            if !same_checkpoint_cell(previous.as_ref(), guards[index].get(&target.bucket))
                || crate::off_path::governance::runtime::unit_checkpoint_counts_in_flight(
                    &flights,
                    &target.bucket,
                )
            {
                return Err(RecordStoreError(
                    "running money target changed during durable reload".into(),
                ));
            }
        }
        check_pending()?;
        if self.recovery_selection_epoch() != epoch {
            return Err(RecordStoreError(
                "recovery selection changed before unit reload publication".into(),
            ));
        }
        for (target, (_, cell)) in snapshot.targets.iter().zip(before) {
            if let Some(cell) = cell {
                let index = shards
                    .binary_search(&self.budget.shard_index(&target.bucket))
                    .expect("target shard held");
                match guards[index].get_mut(&target.bucket) {
                    Some(slot) => *slot = cell,
                    None => {
                        guards[index].insert(target.bucket.as_str().into(), cell);
                    }
                }
            }
        }
        Ok(())
    }

    /// The durable checkpoint owns the new counts; move hot counts and both flush watermarks
    /// together so an ordinary flush cannot write the same unit under a second operation id.
    pub(super) fn apply_unit_checkpoint_live(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> Result<(), CountError> {
        if snapshot.partitions.is_some() {
            return self.apply_selected_checkpoint_counts(snapshot, true);
        }
        self.accrue_count_targets(
            &snapshot.targets,
            &snapshot.lane,
            snapshot.era(),
            &snapshot.units,
            snapshot.arrived,
            true,
            || Ok(()),
        )
    }

    pub(super) fn accrue_count_targets<T: CountTarget>(
        &self,
        targets: &[T],
        lane: &str,
        era: RawRateEra,
        units: &std::collections::BTreeMap<String, Count>,
        now: u64,
        durable: bool,
        before_commit: impl FnOnce() -> Result<(), CountError>,
    ) -> Result<(), CountError> {
        self.accrue_lanes_targets(targets, &[(lane, units)], era, now, durable, before_commit)
    }

    fn apply_selected_checkpoint_counts(
        &self,
        snapshot: &UnitCheckpoint,
        durable: bool,
    ) -> Result<(), CountError> {
        let projection =
            super::unit_checkpoint::partitions::ValidatedSelectedCheckpoint::try_from(snapshot)
                .and_then(|view| view.project())
                .map_err(|_| CountError::Malformed)?;
        let grouped = projection
            .billed_by_lane()
            .map_err(|_| CountError::Overflow)?;
        let lanes: smallvec::SmallVec<[_; 4]> = grouped
            .iter()
            .map(|(lane, counts)| (lane.as_str(), counts))
            .collect();
        if durable {
            self.accrue_lanes_targets(
                &snapshot.targets,
                &lanes,
                snapshot.era(),
                snapshot.arrived,
                true,
                || Ok(()),
            )
        } else {
            let meters = selected_meter_counts(&projection);
            self.accrue_lanes_targets(
                &snapshot.targets,
                &lanes,
                snapshot.era(),
                snapshot.arrived,
                false,
                || {
                    self.pending_metering
                        .try_accrue_selected(&snapshot.principal, &meters)
                },
            )
        }
    }

    pub(super) fn apply_selected_checkpoint_memory(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> Result<(), CountError> {
        self.apply_selected_checkpoint_counts(snapshot, false)
    }

    fn accrue_lanes_targets<T: CountTarget, G>(
        &self,
        targets: &[T],
        lanes: &[(&str, &std::collections::BTreeMap<String, Count>)],
        era: RawRateEra,
        now: u64,
        durable: bool,
        before_commit: impl FnOnce() -> Result<G, CountError>,
    ) -> Result<(), CountError> {
        // A count-free unit (e.g. a pool 503 before any member bound its lane) adds no row and no
        // count, matching `record_counts_served_in_era`, so the served and checkpoint bills agree
        // (UPG-H2). It still touches a cell it already charged in this window: its terminal
        // checkpoint is custody of that cell (UPG-A04c).
        let count_free = lanes
            .iter()
            .all(|(_, units)| units.values().all(|n| n.is_zero()));
        // A request charges a handful of buckets: the shard list, its guards and the staged cells
        // stay inline on the stack.
        // Kept ascending and distinct as it is built, so the guards are taken in shard order.
        let mut shards: smallvec::SmallVec<[usize; 4]> = smallvec::SmallVec::new();
        for target in targets {
            let index = self.budget.shard_index(target.bucket());
            if let Err(at) = shards.binary_search(&index) {
                shards.insert(at, index);
            }
        }
        let mut guards: smallvec::SmallVec<[_; 4]> = smallvec::SmallVec::new();
        guards.extend(
            shards
                .iter()
                .map(|index| self.budget.shard_at(*index).write()),
        );
        let mut changes: smallvec::SmallVec<[(usize, &str, BudgetCell); 4]> =
            smallvec::SmallVec::new();
        for target in targets {
            let (bucket, window) = (target.bucket(), target.window());
            let index = shards
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
            if count_free {
                let Some(mut cell) = guards[index].get(bucket).cloned() else {
                    continue;
                };
                if cell.window_start != window {
                    continue;
                }
                cell.mutate(|cell| cell.last_touch = now);
                changes.push((index, bucket, cell));
                continue;
            }
            let mut cell = guards[index]
                .get(bucket)
                .cloned()
                .unwrap_or_else(|| BudgetCell::fresh(window));
            if durable && cell.window_start > window {
                continue;
            }
            if cell.window_start < window {
                cell.roll(window);
            }
            // An exhausted pool unit reports the empty lane with no counts; accrue_raw adds no
            // row for it (#42, LINT-RULES R35).
            fn finish(
                cell: &mut BudgetCell,
                lane: &str,
                era: RawRateEra,
                units: &std::collections::BTreeMap<String, Count>,
                durable: bool,
            ) -> Result<(), CountError> {
                // Totals used for caps must also remain representable; refuse before any bucket changes.
                Count::total(
                    cell.models
                        .iter()
                        .flat_map(|m| m.cur.iter())
                        .filter(|(k, _)| is_token_class(k))
                        .map(|(_, n)| *n),
                )?;
                // Validate changed raw classes and their derived caps before publishing,
                // including ancestors shared by several classes and lanes. A class named twice
                // is only checked twice: the check is pure, so the outcome is the same.
                let classes = units.keys().map(String::as_str).chain(
                    class_owner(lane)
                        .into_iter()
                        .flat_map(|owner| owner.class_parents.iter().map(|edge| edge.parent)),
                );
                for class in classes {
                    cell.models.iter().try_fold(Count::ZERO, |total, model| {
                        total.checked_add(class_total(&model.model, &model.cur, class)?)
                    })?;
                }
                if durable {
                    match cell
                        .models
                        .iter_mut()
                        .find(|m| m.model.as_ref() == lane && m.era == era)
                    {
                        Some(model) => {
                            for (unit, n) in units {
                                for flushed in [&mut model.flushed, &mut model.flushed_era] {
                                    match flushed.get_mut(unit) {
                                        Some(raw) => *raw = raw.checked_add(*n)?,
                                        None => {
                                            // First sight of this unit in the baseline: its one key.
                                            let first = Count::default().checked_add(*n)?;
                                            flushed.insert(unit.as_str().into(), first);
                                        }
                                    }
                                }
                            }
                        }
                        // A zero-only report creates no row, so there is no baseline to move.
                        None => assert!(!has_units(units), "just accrued model"),
                    }
                } else {
                    cell.dirty = true;
                }
                Ok(())
            }
            for (lane, units) in lanes {
                cell.accrue_raw(lane, era, units)?;
                finish(&mut cell, lane, era, units, durable)?;
                if let Some(branch) = cell.correction.as_mut() {
                    finish(&mut branch.accepted, lane, era, units, durable)?;
                }
            }
            cell.mutate(|cell| {
                if let Some(group) = target.group() {
                    // A bucket learns each owning group once; later charges find it held.
                    if !cell.group_owners.contains(group) {
                        cell.group_owners.insert(group.into());
                    }
                }
                cell.last_touch = now;
            });
            changes.push((index, bucket, cell));
        }
        // Selected metering returns its shard guard here, retaining the existing budget-before-
        // meter lock order through the final infallible publication of every budget cell.
        let publication = before_commit()?;
        for (index, bucket, cell) in changes {
            match guards[index].get_mut(bucket) {
                Some(slot) => *slot = cell,
                None => {
                    guards[index].insert(bucket.into(), cell);
                }
            }
        }
        drop(publication);
        Ok(())
    }
}

fn selected_meter_counts(
    projection: &super::unit_checkpoint::partitions::UsageProjection,
) -> Vec<(MeterIdentity, MeterCounts)> {
    let common = &projection.common;
    let key = |lane: &str,
               provider: Option<&str>,
               pricing: &busbar_contract::records::MeteringPricingV1| {
        MeterIdentity {
            common: (
                common.principal.clone(),
                metering_bucket(common.arrived),
                lane.to_owned(),
                provider.unwrap_or_default().to_owned(),
                common.era.effective_from,
                common.group.clone(),
                common
                    .era
                    .entry_id
                    .map(|id| id.metering_version())
                    .unwrap_or_default(),
            ),
            role: Some(pricing.identity()),
        }
    };
    let mut meters = Vec::new();
    for partition in &projection.partitions {
        let pricing = busbar_contract::records::MeteringPricingV1::SelectedUsage;
        let usage_units = partition.billed_counts();
        if !usage_units.is_empty() {
            meters.push((
                key(
                    &partition.identity.lane,
                    partition.identity.provider.as_deref(),
                    &pricing,
                ),
                MeterCounts {
                    pricing: Some(pricing),
                    usage_units,
                    ..MeterCounts::default()
                },
            ));
        }
    }
    if let Some(request) = &projection.logical_request {
        let pricing = busbar_contract::records::MeteringPricingV1::SelectedRequest;
        meters.push((
            key(&request.lane, request.provider.as_deref(), &pricing),
            MeterCounts {
                pricing: Some(pricing),
                requests: 1,
                ..MeterCounts::default()
            },
        ));
    }
    use super::unit_checkpoint::partitions::{CapturedFee, FeeResult};
    let fee_pricing = match &projection.fee {
        CapturedFee::NotOwner { .. } | CapturedFee::PendingOwner { .. } => None,
        CapturedFee::ResolvedOwner { basis, result } => {
            Some(busbar_contract::records::MeteringPricingV1::SelectedFee {
                lane: basis.lane.clone(),
                charged: u64::from(*result == FeeResult::Charged),
                refunded: u64::from(*result == FeeResult::Refunded),
                unknown: 0,
            })
        }
        CapturedFee::RecoveredUnknown { basis } => {
            Some(busbar_contract::records::MeteringPricingV1::SelectedFee {
                lane: basis.lane.clone(),
                charged: 0,
                refunded: 0,
                unknown: 1,
            })
        }
    };
    if let Some(pricing) = fee_pricing {
        let mut identity = key(&projection.session_origin.lane, None, &pricing);
        let era = projection.fee.basis().era;
        identity.common.4 = era.effective_from;
        identity.common.6 = era
            .entry_id
            .map(|id| id.metering_version())
            .unwrap_or_default();
        meters.push((
            identity,
            MeterCounts {
                pricing: Some(pricing),
                ..Default::default()
            },
        ));
    }
    meters
}

/// One bucket an accrual charges: its id, its window and the group that owns it.
pub(super) trait CountTarget {
    fn bucket(&self) -> &str;
    fn window(&self) -> u64;
    fn group(&self) -> Option<&str>;
}

impl CountTarget for (String, u64, Option<String>) {
    fn bucket(&self) -> &str {
        &self.0
    }
    fn window(&self) -> u64 {
        self.1
    }
    fn group(&self) -> Option<&str> {
        self.2.as_deref()
    }
}

impl CountTarget for super::unit_checkpoint::UnitTarget {
    fn bucket(&self) -> &str {
        &self.bucket
    }
    fn window(&self) -> u64 {
        self.window
    }
    fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

// Exact hot-snapshot comparison is the publication revision check. No partial
// comparison of only totals can hide a concurrent fee, era, watermark or owner.
fn same_checkpoint_cell(a: Option<&BudgetCell>, b: Option<&BudgetCell>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.correction.is_none()
                && b.correction.is_none()
                && a.group_owners == b.group_owners
                && a.flushing == b.flushing
                && a.flushing_windows == b.flushing_windows
                && a.window_start == b.window_start
                && a.requests == b.requests
                && a.billable_requests == b.billable_requests
                && a.flushed_requests == b.flushed_requests
                && a.flushed_billable_requests == b.flushed_billable_requests
                && a.fee_eras == b.fee_eras
                && a.flushed_fee_eras == b.flushed_fee_eras
                && a.rolled == b.rolled
                && a.rolled_eras == b.rolled_eras
                && a.dirty == b.dirty
                && a.last_touch == b.last_touch
                && a.models.len() == b.models.len()
                && a.models.iter().zip(&b.models).all(|(a, b)| {
                    a.model == b.model
                        && a.era == b.era
                        && a.cur == b.cur
                        && a.flushed == b.flushed
                        && a.flushed_era == b.flushed_era
                })
        }
        _ => false,
    }
}
