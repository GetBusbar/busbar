// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::selected_resource::{
    CommittedRate, EffectiveToken, EffectiveTokenView, RateFinalSnapshot, TokenCoverage,
};
use crate::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint;

/// Task owns this guard only after the original preparation's actual connector handoff.
/// It cannot be cloned or reconstructed from an attempt number or plugin report.
pub(crate) struct NativeAttempt {
    service: NativeRequestMoney,
    rate: Option<CommittedRate>,
}

impl NativeAttempt {
    pub(super) fn new(service: NativeRequestMoney, rate: CommittedRate) -> Self {
        Self {
            service,
            rate: Some(rate),
        }
    }

    /// Validate the complete answer before any effect, then retain all actual source facts.
    /// A persistence refusal keeps its unpublished successor; incurred rate evidence still applies.
    pub(crate) fn observe(
        &mut self,
        reports: &[AttemptUsage<'_>],
        end: Option<AttemptEnd>,
    ) -> Result<bool, NativeAttemptError> {
        let rate = self.rate.as_mut().ok_or(NativeAttemptError::Unavailable)?;
        let prepared = rate.prepared();
        let mut all = self.service.money.shard(self.service.request.unit());
        let open = all
            .get_mut(&self.service.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.service.check_open_identity(open)?;
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        let mut snapshot = native.checkpoint().as_ref().clone();
        let parts = snapshot
            .partitions
            .as_mut()
            .ok_or(NativeAttemptError::Binding)?;
        let before = parts.attempts.last().ok_or(NativeAttemptError::Binding)?;
        if before.preparation != prepared.selection().preparation() {
            return Err(NativeAttemptError::Binding);
        }
        let staged = stage_attempt_facts(
            before,
            &parts.physical_classes,
            prepared._prepared.declaration(),
            reports,
            end,
        )
        .map_err(NativeAttemptError::Usage)?;
        let physical_classes = prepared.physical_classes().to_vec();
        let rate_view = effective_tokens(&physical_classes, &staged.partition);
        *parts
            .attempts
            .last_mut()
            .ok_or(NativeAttemptError::Binding)? = staged.partition.clone();
        snapshot.metered = ValidatedSelectedCheckpoint::try_from(&snapshot)
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
        let published = native.publish_incurred(&self.service.money.gov, snapshot);
        // The checkpoint book lock is released before entering rate cells. The money shard
        // retains the current attempt's source/authority while both owners observe the batch.
        let observed = rate.observe(&rate_view).map_err(NativeAttemptError::Rate);
        published?;
        observed?;
        Ok(staged.rounded)
    }

    pub(crate) fn seal(mut self) -> Result<RateFinalSnapshot, NativeAttemptError> {
        self.finish()
    }

    fn finish(&mut self) -> Result<RateFinalSnapshot, NativeAttemptError> {
        let rate = self.rate.take().ok_or(NativeAttemptError::Unavailable)?;
        let preparation = rate.prepared().selection().preparation();
        let outcome = (|| {
            let mut all = self.service.money.shard(self.service.request.unit());
            let open = all
                .get_mut(&self.service.request.unit())
                .ok_or(NativeAttemptError::Unavailable)?;
            self.service.check_open_identity(open)?;
            let native = open
                .native
                .as_mut()
                .ok_or(NativeAttemptError::Unavailable)?;
            let mut snapshot = native.checkpoint().as_ref().clone();
            let attempt = snapshot
                .partitions
                .as_mut()
                .and_then(|parts| parts.attempts.last_mut())
                .ok_or(NativeAttemptError::Binding)?;
            if attempt.preparation != preparation || attempt.transport != Transport::Committed {
                return Err(NativeAttemptError::Binding);
            }
            if attempt.finality == Finality::Live {
                attempt.finality = Finality::Unknown;
            }
            let coverage = match attempt.finality {
                Finality::Complete => TokenCoverage::Complete,
                Finality::Partial => TokenCoverage::Partial,
                Finality::Live | Finality::Unknown => TokenCoverage::Unknown,
            };
            let published = native.publish_incurred(&self.service.money.gov, snapshot);
            Ok((coverage, published))
        })();
        match outcome {
            Ok((coverage, published)) => {
                let sealed = rate.seal(coverage).map_err(NativeAttemptError::Rate);
                published?;
                sealed
            }
            Err(error) => {
                let _ = rate.seal(TokenCoverage::Unknown);
                Err(error)
            }
        }
    }
}

impl Drop for NativeAttempt {
    fn drop(&mut self) {
        if self.rate.is_some() {
            let _ = self.finish();
        }
    }
}

pub(super) fn effective_tokens<'a>(
    classes: &'a [Box<str>],
    attempt: &AttemptPartition,
) -> EffectiveTokenView<'a> {
    EffectiveTokenView(
        classes
            .iter()
            .map(|class| {
                let facts = attempt.usage.classes.get(class.as_ref());
                EffectiveToken {
                    class,
                    quantity: facts
                        .filter(|facts| facts.selected().is_some())
                        .map(|facts| facts.rate_high_water),
                    authoritative: facts.is_some_and(|facts| facts.reported.is_some()),
                }
            })
            .collect(),
    )
}
