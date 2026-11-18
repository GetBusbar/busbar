// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Session-owned sources share the selected checkpoint and original request budget.

use super::*;
use crate::config::groups::ExhaustionMode;
use crate::plane_driver::cancel::Checkpoint;
use crate::plane_driver::usage::SessionUsage;
use busbar_plugin_abi::plane::{SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED};

impl NativeRequestMoney {
    /// Called only after validating the complete answer, before any output or paid effect.
    /// Fee markers stay with the original fee participant and never become partition quantities.
    pub(crate) fn observe_session(
        &self,
        declaration: &RequestDeclaration,
        usage: &SessionUsage,
    ) -> Result<bool, NativeAttemptError> {
        let mut all = self.money.shard(self.request.unit());
        let open = all
            .get_mut(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open_identity(open)?;
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        if !native
            .declaration
            .as_ref()
            .is_some_and(|held| held.same_declaration(declaration))
        {
            return Err(NativeAttemptError::Binding);
        }
        let mut snapshot = native.checkpoint().as_ref().clone();
        let parts = snapshot
            .partitions
            .as_mut()
            .ok_or(NativeAttemptError::Binding)?;
        if parts.disposition != Disposition::Running {
            return Err(NativeAttemptError::Binding);
        }
        let mut session = parts.session.clone().unwrap_or_else(|| UsagePartition {
            lane: parts.session_origin.lane.clone(),
            provider: parts.session_origin.provider.clone(),
            classes: BTreeMap::new(),
        });
        let mut rounded = false;
        for report in usage.last() {
            declaration
                .declaration()
                .validate_session_class(&report.class)
                .map_err(|_| NativeAttemptError::Usage)?;
            let index = open
                .money
                .classes
                .iter()
                .position(|name| name == &*report.class)
                .and_then(|index| u32::try_from(index).ok())
                .ok_or(NativeAttemptError::Binding)?;
            let (quantity, was_rounded) =
                crate::plane_driver::usage::scaled(report.amount, report.scale)
                    .ok_or(NativeAttemptError::Usage)?;
            rounded |= was_rounded;
            if !matches!(report.source, SRC_REPORTED | SRC_FLOOR | SRC_ESTIMATED) {
                return Err(NativeAttemptError::Usage);
            }
            if open.money.fee.is_fee(index) {
                continue;
            }
            if !parts.declared_classes.contains(&*report.class) {
                return Err(NativeAttemptError::Binding);
            }
            let facts = session.classes.entry(report.class.to_string()).or_default();
            match report.source {
                SRC_REPORTED => facts.reported = Some(quantity),
                SRC_FLOOR => facts.floor = Some(quantity),
                SRC_ESTIMATED => facts.estimated = Some(quantity),
                _ => unreachable!(),
            }
        }
        if !session.classes.is_empty() {
            parts.session = Some(session);
        }
        snapshot.metered =
            crate::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint::try_from(
                &snapshot,
            )
            .and_then(|checked| checked.project())
            .map_err(NativeAttemptError::Custody)?
            .partitions
            .iter()
            .any(|partition| {
                partition
                    .billed_counts()
                    .iter()
                    .any(|(_, count)| !count.is_zero())
            });
        let counted = crate::plane_driver::port_money::unit_counts(usage, &open.money.classes);
        if !counted.dropped.is_empty() {
            return Err(NativeAttemptError::Binding);
        }
        // The entire batch has been validated. Retain fee evidence even if publishing incurred
        // quantity facts refuses; publish_incurred keeps the complete successor for terminal custody.
        open.last = counted.counts;
        native.publish_incurred(&self.money.gov, snapshot)?;
        Ok(rounded)
    }

    pub(crate) fn checkpoint(&self) -> Result<Checkpoint, NativeAttemptError> {
        let snapshot = {
            let all = self.money.shard(self.request.unit());
            let open = all
                .get(&self.request.unit())
                .ok_or(NativeAttemptError::Unavailable)?;
            self.check_open(open)?;
            // Selected child/max-budget activation remains unavailable until its typed budget
            // projection is connected; never fall through to the legacy single-lane calculation.
            if open.spend_ceiling_micros.is_some() {
                return Ok(Checkpoint::Unpriced);
            }
            if open.money.mode != ExhaustionMode::CutStream {
                return Ok(Checkpoint::Continue);
            }
            open.native
                .as_ref()
                .ok_or(NativeAttemptError::Unavailable)?
                .checkpoint()
                .clone()
        };
        self.money
            .selected_dry(&self.request, &snapshot)
            .map(|dry| {
                if dry {
                    Checkpoint::Cut
                } else {
                    Checkpoint::Continue
                }
            })
            .map_err(NativeAttemptError::Custody)
    }
}
