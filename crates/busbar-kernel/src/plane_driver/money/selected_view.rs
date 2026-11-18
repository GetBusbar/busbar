// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::unit_checkpoint::{
    partitions::{Disposition, PartitionedUsageV1, ValidatedSelectedCheckpoint},
    UnitCheckpoint, UnitTarget,
};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};

/// Attribution readers must explicitly distinguish legacy quantities from an accepted selected
/// revision. The selected arm owns the same complete snapshot used by custody and settlement.
pub enum UsageView {
    Legacy {
        lane: String,
        attribution: String,
        usage: Arc<UsageFold>,
    },
    Partitioned(Arc<UnitCheckpoint>),
}

/// A refused selected view: its message is a fixed word of the program, so nothing is allocated.
fn refused(message: &'static str) -> RecordStoreError {
    RecordStoreError::fixed(message)
}

impl PlaneMoney {
    pub fn usage_view(&self, key: UnitKey) -> Option<Arc<UsageView>> {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::MoneyShardLock);
        let mut all = self.shard(key);
        let open = all.get_mut(&key)?;
        if let Some(native) = &open.native {
            return Some(Arc::new(UsageView::Partitioned(
                native.checkpoint().clone(),
            )));
        }
        let money = &open.money;
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&money.pool);
        let attribution = busbar_kernel_audit::attribution(
            money.key.group.as_deref().unwrap_or_default(),
            pool,
            open.provider.as_deref().unwrap_or_default(),
        );
        Some(Arc::new(UsageView::Legacy {
            lane: money.lane.clone(),
            attribution,
            usage: open.usage_fold(),
        }))
    }

    /// Activation-only capture, called while the actual Open still owns its original admission.
    /// The caller stages this complete snapshot before publishing the effects phase transition.
    pub(super) fn selected_checkpoint_snapshot(
        &self,
        key: UnitKey,
        open: &Open,
        mut parts: PartitionedUsageV1,
    ) -> RecordStoreResult<UnitCheckpoint> {
        let money = &open.money;
        if open.native.is_some()
            || parts.disposition != Disposition::Running
            || !parts.attempts.is_empty()
            || parts.session.is_some()
            || parts.final_target.is_some()
            || parts.far_end_answered
            || parts.caller_bytes_committed
            || parts.request_pool != money.pool
            || parts.session_origin.lane != money.lane
            || parts
                .declared_classes
                .iter()
                .any(|class| !money.classes.iter().any(|name| *class == *name))
        {
            return Err(refused(
                "selected activation does not match its original open",
            ));
        }
        for (index, class) in money.classes.iter().enumerate() {
            if money.fee.is_fee(
                u32::try_from(index)
                    .map_err(|_| refused("selected class index exceeds its domain"))?,
            ) {
                if parts.attempt_classes.contains(class.as_str()) {
                    return Err(refused(
                        "an original fee class cannot be an attempt quantity",
                    ));
                }
                parts.declared_classes.remove(class.as_str());
            }
        }
        let plan = money
            .charge
            .chain()
            .ok_or_else(|| refused("selected admission has no captured chain"))?;
        let chain = money.cost.admitted_chain(&money.key, plan).ok_or_else(|| {
            refused("selected admission chain no longer matches its original generation")
        })?;
        let (_, pool) = busbar_kernel_ledger::cost::split_plane_lane(&money.pool);
        let mut targets: Vec<_> = chain
            .iter()
            .filter(|bucket| bucket.applies_to_pool(pool))
            .map(|bucket| UnitTarget {
                bucket: bucket.bucket_id.to_owned(),
                window: crate::governance::budget_window(bucket.window, money.arrived),
                group: bucket.group_name.map(str::to_owned),
            })
            .collect();
        targets.sort_by(|a, b| (&a.bucket, a.window).cmp(&(&b.bucket, b.window)));
        let audit = self
            .post
            .checkpoint_facts(key)
            .or_else(|| open.checkpoint_audit.clone())
            .ok_or_else(|| refused("selected admission lacks original captured audit facts"))?;
        parts.fee = open.fee.selected_fee().0;
        parts.preflight_terminal_bound(targets.len())?;
        let era = money.charge.raw_era();
        let snapshot = UnitCheckpoint {
            id: open.checkpoint_id,
            revision: 0,
            unit: key.get(),
            principal: money.key.id.clone(),
            group: money.key.group.clone().unwrap_or_default(),
            arrived: money.arrived,
            lane: String::new(),
            provider: None,
            era_at: era.effective_from,
            era_entry: era.entry_id.map(|entry| entry.0),
            units: BTreeMap::new(),
            targets,
            metered: false,
            ended: false,
            terminal: None,
            audit: Some(audit),
            measurement: None,
            unread: None,
            partitions: Some(parts),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Prospective nonfee consumption under the actual original admission. An absent price or
    /// checked total is a refusal; the final target cannot reprice earlier attempts.
    pub(super) fn selected_dry(
        &self,
        request: &crate::plane_driver::request_admission::AdmittedRequest,
        checkpoint: &UnitCheckpoint,
    ) -> RecordStoreResult<bool> {
        let view = ValidatedSelectedCheckpoint::try_from(checkpoint)?;
        if checkpoint.unit != request.unit().get()
            || checkpoint.principal != request.key().id
            || checkpoint.group != request.key().group.as_deref().unwrap_or_default()
            || checkpoint.arrived != request.arrived()
            || view.usage().request_pool != request.pool()
            || checkpoint.era() != request.charge().raw_era()
        {
            return Err(refused(
                "selected budget view differs from its original admission",
            ));
        }
        let projection = view.project()?;
        let admitted = self
            .gov
            .admitted_view(request)
            .map_err(|_| refused("selected budget admission is unavailable"))?;
        let remaining = admitted
            .budgets
            .into_iter()
            .filter_map(|bucket| bucket.remaining_micros)
            .min();
        let Some(remaining) = remaining else {
            return Ok(false);
        };
        let mut tally = busbar_kernel_ledger::cost::Tally::at_card(request.cost().card());
        for (lane, counts) in projection.billed_by_lane()? {
            tally
                .row(
                    &lane,
                    0,
                    busbar_kernel_ledger::cost::STANDARD_TIER_BP,
                    counts.iter().map(|(class, count)| (class.as_str(), *count)),
                    Count::ZERO,
                )
                .map_err(|_| refused("selected usage lane is unpriced"))?;
        }
        let nanos = busbar_kernel_ledger::cost::nanos_of_exact(
            tally
                .exact()
                .map_err(|_| refused("selected usage price overflow"))?,
        )
        .map_err(|_| refused("selected usage price overflow"))?;
        Ok(nanos.div_ceil(NANOS_PER_MICRO) >= u128::try_from(remaining.max(0)).unwrap_or(0))
    }
}

impl UsageFold {
    pub(super) fn selected(checkpoint: &UnitCheckpoint, classes: &[String]) -> Option<Self> {
        let projection = ValidatedSelectedCheckpoint::try_from(checkpoint)
            .ok()?
            .project()
            .ok()?;
        let mut counts = Vec::new();
        let mut by_class = BTreeMap::<u32, Option<Count>>::new();
        for partition in projection.partitions {
            for (class, count) in partition.billed_counts() {
                let class = u32::try_from(classes.iter().position(|name| *name == class)?).ok()?;
                counts.push((class, count));
                let sum = by_class.entry(class).or_insert(Some(Count::ZERO));
                *sum = sum.and_then(|held| held.checked_add(count).ok());
            }
        }
        Some(Self { counts, by_class })
    }
}
