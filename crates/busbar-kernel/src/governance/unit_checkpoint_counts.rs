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
        let mut events = Vec::new();
        let mut cell = BudgetCell::default();
        cell.accrue_raw(&snapshot.lane, snapshot.era(), &snapshot.units)
            .map_err(|e| RecordStoreError(e.to_string()))?;
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
                    .map_err(|e| RecordStoreError(e.to_string()))?,
                );
            }
        }
        let (plane, subject) = busbar_kernel_ledger::cost::split_plane_lane(&snapshot.lane);
        let (model, provider) = if plane.is_empty() {
            (
                snapshot.lane.as_str(),
                snapshot.provider.as_deref().unwrap_or(""),
            )
        } else {
            (subject, plane)
        };
        let mut counts = if snapshot.metered && (!plane.is_empty() || snapshot.provider.is_some()) {
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
        counts.usage_units = snapshot
            .units
            .iter()
            .filter(|(name, count)| {
                !count.is_zero()
                    && !(plane.is_empty()
                        && busbar_contract::records::RESERVED_UNITS.contains(&name.as_str()))
            })
            .map(|(name, count)| (name.clone(), *count))
            .collect();
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
        while !counts.is_zero() {
            let (delta, remaining) = metering_flush::metering_chunk(&key, &counts);
            events.push(self.metering_recovery_intent(
                crate::door::op_id().0,
                crate::store::now_ms(),
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
        let mut shards: Vec<_> = snapshot
            .targets
            .iter()
            .map(|t| self.budget.shard_index(&t.bucket))
            .collect();
        shards.sort_unstable();
        shards.dedup();
        let capture = || -> RecordStoreResult<Vec<Option<BudgetCell>>> {
            let guards: Vec<_> = shards
                .iter()
                .map(|index| {
                    self.budget.shards[*index]
                        .map
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                })
                .collect();
            let flights = self
                .budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            snapshot
                .targets
                .iter()
                .map(|target| {
                    let index = shards
                        .binary_search(&self.budget.shard_index(&target.bucket))
                        .expect("target shard held");
                    let cell = guards[index].get(&target.bucket);
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
                .collect()
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
                if store
                    .has_pending_namespace(namespace)
                    .map_err(|e| RecordStoreError(format!("checkpoint ledger custody: {e:?}")))?
                {
                    return Err(RecordStoreError(
                        "recovered unit target has an unresolved native candidate".into(),
                    ));
                }
            }
            Ok(())
        };
        check_pending()?;
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
            cell.last_touch = crate::store::now();
            if let Some(previous) = previous {
                cell.group_owners = previous.group_owners.clone();
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
        let mut guards: Vec<_> = shards
            .iter()
            .map(|index| {
                self.budget.shards[*index]
                    .map
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
            })
            .collect();
        let flights = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for (target, previous) in snapshot.targets.iter().zip(&before) {
            let index = shards
                .binary_search(&self.budget.shard_index(&target.bucket))
                .expect("target shard held");
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
        let targets: Vec<_> = snapshot
            .targets
            .iter()
            .map(|t| (t.bucket.clone(), t.window, t.group.clone()))
            .collect();
        self.accrue_count_targets(
            &targets,
            &snapshot.lane,
            snapshot.era(),
            &snapshot.units,
            snapshot.arrived,
            true,
            || Ok(()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accrue_count_targets(
        &self,
        targets: &[(String, u64, Option<String>)],
        lane: &str,
        era: RawRateEra,
        units: &std::collections::BTreeMap<String, Count>,
        now: u64,
        durable: bool,
        before_commit: impl FnOnce() -> Result<(), CountError>,
    ) -> Result<(), CountError> {
        let mut shards: Vec<_> = targets
            .iter()
            .map(|(bucket, _, _)| self.budget.shard_index(bucket))
            .collect();
        shards.sort_unstable();
        shards.dedup();
        let mut guards: Vec<_> = shards
            .iter()
            .map(|index| {
                self.budget.shards[*index]
                    .map
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
            })
            .collect();
        let mut changes = Vec::new();
        for (bucket, window, group) in targets {
            let index = shards
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
            let mut cell = guards[index]
                .get(bucket)
                .cloned()
                .unwrap_or_else(|| BudgetCell::fresh(*window));
            if durable && cell.window_start > *window {
                continue;
            }
            if cell.window_start < *window {
                cell.roll(*window);
            }
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
                for unit in units.keys() {
                    Count::total(
                        cell.models
                            .iter()
                            .map(|m| m.cur.get(unit).copied().unwrap_or_default()),
                    )?;
                }
                if durable {
                    let model = cell
                        .models
                        .iter_mut()
                        .find(|m| m.model.as_ref() == lane && m.era == era)
                        .expect("just accrued model");
                    for (unit, n) in units {
                        let raw = model.flushed.entry(unit.clone()).or_default();
                        *raw = raw.checked_add(*n)?;
                        let raw = model.flushed_era.entry(unit.clone()).or_default();
                        *raw = raw.checked_add(*n)?;
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
                if let Some(group) = group {
                    cell.group_owners.insert(group.clone());
                }
                cell.last_touch = now;
            });
            changes.push((index, bucket.clone(), cell));
        }
        before_commit()?;
        for (index, bucket, cell) in changes {
            guards[index].insert(bucket, cell);
        }
        Ok(())
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
