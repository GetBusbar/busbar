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
        // busbar:expect(bp::fresh_buffer, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
        let mut events = Vec::new();
        let mut cell = BudgetCell::default();
        cell.accrue_raw(&snapshot.lane, snapshot.era(), &snapshot.units)
            .map_err(crate::governance::store_error)?;
        let plain = ExactUsageDelta::of(&cell, false);
        let dated = ExactUsageDelta::of(&cell, true);
        for target in &snapshot.targets {
            if let Some(child) = Self::usage_recovery_child(
                &target.bucket,
                target.window,
                plain.clone(),
                dated.clone(),
            )? {
                events.push(
                    self.new_recovery_event(
                        child.operation_id,
                        child.kind,
                        child.body_fingerprint,
                        RecoveryState::Intent,
                        child.first_sent_at_ms,
                        child.payload,
                    )
                    .map_err(crate::governance::store_error)?,
                );
            }
        }
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once"
        )]
        let usage_units = snapshot
            .units
            .iter()
            .filter(|(name, count)| {
                !count.is_zero()
                    && !(snapshot.measurement.is_none()
                        && plane.is_empty()
                        && busbar_contract::records::RESERVED_UNITS.contains(&name.as_str()))
            })
            .map(|(name, count)| (name.clone(), *count))
            .collect();
        counts.usage_units = usage_units;
        // busbar:expect(bp::clone_alloc, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
        let key: MeterKey = (
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
        );
        let sent_at_ms = crate::store::now_ms();
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

    /// Once a recovered unit's durable receipts settle, reload its exact targets before allowing
    /// further admission. Active ordinary flushes retain ownership and postpone this refresh.
    pub(super) async fn refresh_recovered_unit_targets(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<()> {
        // Capture the entire hot value, then release every shard/flush guard
        // before crossing Store. Publish only if that same value still owns it.
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once"
        )]
        let mut shards: Vec<_> = snapshot
            .targets
            .iter()
            .map(|t| self.budget.shard_index(&t.bucket))
            .collect();
        shards.sort();
        shards.dedup();
        let capture = || -> RecordStoreResult<Vec<Option<BudgetCell>>> {
            #[expect(
                clippy::disallowed_methods,
                reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once"
            )]
            let guards: Vec<_> = shards
                .iter()
                .map(|index| self.budget.shard_at(*index).read())
                .collect();
            let flights = self
                .budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            #[expect(
                clippy::disallowed_methods,
                reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once"
            )]
            let built = snapshot
                .targets
                .iter()
                .map(|target| {
                    let index = shards
                        .binary_search(&self.budget.shard_index(&target.bucket))
                        .expect("target shard held");
                    let cell = guards[index].get(&target.bucket);
                    // busbar:expect(bp::state_scan, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
                    if cell.is_some_and(|cell| {
                        cell.dirty || cell.flushing != 0 || cell.correction.is_some()
                    }) || flights.keys().any(|(bucket, _)| bucket == &target.bucket)
                    {
                        return Err(RecordStoreError(
                            "recovered unit target still has ordinary raw custody".into(),
                        ));
                    }
                    Ok(cell.cloned())
                })
                .collect();
            built
        };
        let before = capture()?;
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
        // busbar:expect(bp::fresh_buffer, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
        let mut refreshed = Vec::new();
        for (target, previous) in snapshot.targets.iter().zip(&before) {
            if previous
                .as_ref()
                .is_some_and(|cell| cell.window_start > target.window)
            {
                refreshed.push(None);
                continue;
            }
            let (plain, dated) = store
                .ledger()
                .get_usage_pair(&target.bucket, &era_bucket(&target.bucket), target.window)
                .await?;
            let mut cell = super::state::durable_cell(plain, dated, target.window)?;
            cell.last_touch = touched;
            if let Some(previous) = previous {
                cell.group_owners.clone_from(&previous.group_owners);
            }
            if let Some(group) = &target.group {
                cell.group_owners.insert(group.clone());
            }
            refreshed.push(Some(cell));
        }
        check_pending()?;
        if self.recovery_selection_epoch() != epoch {
            return Err(RecordStoreError(
                "recovery selection changed during unit reload".into(),
            ));
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once"
        )]
        let mut guards: Vec<_> = shards
            .iter()
            .map(|index| self.budget.shard_at(*index).write())
            .collect();
        let flights = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for (target, previous) in snapshot.targets.iter().zip(&before) {
            let index = shards
                .binary_search(&self.budget.shard_index(&target.bucket))
                .expect("target shard held");
            // busbar:expect(bp::state_scan, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
            if !same_checkpoint_cell(previous.as_ref(), guards[index].get(&target.bucket))
                || flights.keys().any(|(bucket, _)| bucket == &target.bucket)
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
        for (target, cell) in snapshot.targets.iter().zip(refreshed) {
            if let Some(cell) = cell {
                let index = shards
                    .binary_search(&self.budget.shard_index(&target.bucket))
                    .expect("target shard held");
                // busbar:expect(bp::clone_alloc, reason = "boot: a terminated or recovered unit's raw custody is staged or reloaded once")
                guards[index].insert(target.bucket.clone(), cell);
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

    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one input of the accrual; bundling them would add a struct per request"
    )]
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
        // A request charges a handful of buckets: the shard list, its guards and the staged cells
        // stay inline on the stack.
        let mut shards: smallvec::SmallVec<[usize; 4]> = smallvec::SmallVec::new();
        shards.extend(
            targets
                .iter()
                .map(|target| self.budget.shard_index(target.bucket())),
        );
        shards.sort_unstable();
        shards.dedup();
        let mut guards: smallvec::SmallVec<[_; 4]> = smallvec::SmallVec::new();
        guards.extend(shards.iter().map(|index| {
            self.budget.shards[*index]
                .map
                .write()
                .unwrap_or_else(|p| p.into_inner())
        }));
        let mut changes: smallvec::SmallVec<[(usize, &str, BudgetCell); 4]> =
            smallvec::SmallVec::new();
        for target in targets {
            let (bucket, window) = (target.bucket(), target.window());
            let index = shards
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
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
            cell.accrue_raw(lane, era, units)?;
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
                        .expect("just accrued model");
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
                } else {
                    cell.dirty = true;
                }
                Ok(())
            }
            finish(&mut cell, lane, era, units, durable)?;
            if let Some(branch) = cell.correction.as_mut() {
                finish(&mut branch.accepted, lane, era, units, durable)?;
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
        before_commit()?;
        for (index, bucket, cell) in changes {
            match guards[index].get_mut(bucket) {
                Some(slot) => *slot = cell,
                None => {
                    guards[index].insert(bucket.into(), cell);
                }
            }
        }
        Ok(())
    }
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
