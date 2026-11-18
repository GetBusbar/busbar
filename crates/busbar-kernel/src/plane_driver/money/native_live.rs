// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::selected_resource::{
    CommittedRate, EffectiveToken, EffectiveTokenView, RateFinalSnapshot, RateRejected,
    RateReservation, TokenCoverage,
};
use crate::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint;

pub(crate) enum NativeCommitError {
    /// Refused before the rate was committed: the still-provisional reservation comes back.
    Before {
        reservation: RateReservation,
    },
    Rate(RateRejected),
}

enum CommitFailure {
    Before,
    Rate(RateRejected),
}
impl From<NativeAttemptError> for CommitFailure {
    fn from(_: NativeAttemptError) -> Self {
        Self::Before
    }
}

impl NativeRequestMoney {
    /// Called only at the real connector handoff, after authorization/local refusal checks.
    /// A custody refusal returns the still-provisional reservation; no irrevocable RPM was taken.
    pub(crate) fn commit(
        &self,
        reservation: RateReservation,
    ) -> Result<NativeAttempt, NativeCommitError> {
        let mut held = Some(reservation);
        self.commit_inner(&mut held).map_err(|error| match error {
            CommitFailure::Before => NativeCommitError::Before {
                reservation: held.take().expect("preflight never consumes reservation"),
            },
            CommitFailure::Rate(error) => NativeCommitError::Rate(error),
        })
    }

    fn commit_inner(
        &self,
        held: &mut Option<RateReservation>,
    ) -> Result<NativeAttempt, CommitFailure> {
        use crate::governance::unit_checkpoint::SelectedCommitError;
        let prepared = held
            .as_ref()
            .expect("original provisional reservation")
            .prepared();
        let mut all = self.money.shard(self.request.unit());
        let open = all
            .get_mut(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open(open)?;
        if !prepared.request.matches_money(
            &self.money.book,
            &open.identity,
            open.grant.as_ref().ok_or(NativeAttemptError::Unavailable)?,
        ) {
            return Err(NativeAttemptError::Binding.into());
        }
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        if native.unpublished.is_some() {
            return Err(NativeAttemptError::Unavailable.into());
        }
        let mut snapshot = native.accepted.as_ref().clone();
        let parts = snapshot
            .partitions
            .as_mut()
            .ok_or(NativeAttemptError::Binding)?;
        let next = parts
            .attempts
            .iter()
            .filter_map(|attempt| attempt.dispatch)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(NativeAttemptError::Binding)?;
        let attempt = parts
            .attempts
            .last_mut()
            .ok_or(NativeAttemptError::Binding)?;
        if attempt.preparation != prepared.selection().preparation()
            || attempt.transport != Transport::Prepared
            || attempt.finality != Finality::Live
        {
            return Err(NativeAttemptError::Binding.into());
        }
        attempt.transport = Transport::Committed;
        attempt.dispatch = Some(next);
        let (accepted, rate) = self
            .money
            .gov
            .commit_selected_checkpoint(snapshot, native.accepted.revision, || {
                held.take()
                    .expect("callback runs at most once")
                    .try_commit()
            })
            .map_err(|error| match error {
                SelectedCommitError::Custody(_) => CommitFailure::Before,
                SelectedCommitError::Commit(error) => CommitFailure::Rate(error),
            })?;
        // Everything after irrevocable rate commitment is an infallible ownership transfer.
        native.accepted = accepted;
        Ok(NativeAttempt::new(
            NativeRequestMoney {
                terminal: self.terminal.clone(),
                money: self.money.clone(),
                request: self.request.clone(),
            },
            rate,
        ))
    }
}

/// Task owns this guard only after the original preparation's actual connector handoff.
/// It cannot be cloned or reconstructed from an attempt number or plugin report.
pub(crate) struct NativeAttempt {
    service: NativeRequestMoney,
    rate: Option<CommittedRate>,
    answered: bool,
}

impl NativeAttempt {
    /// The actual connector returned this committed exchange's upstream response head.
    pub(crate) fn answered(&mut self) -> Result<(), NativeAttemptError> {
        let retained = self.host_response(false);
        self.answered = true;
        retained
    }

    /// The host accepted this exchange as the final response, after retry classification.
    /// Its preparation identity is carried by this guard and cannot be supplied by the plugin.
    pub(crate) fn served(&mut self) -> Result<(), NativeAttemptError> {
        if !self.answered {
            return Err(NativeAttemptError::Binding);
        }
        self.host_response(true)
    }

    fn host_response(&self, served: bool) -> Result<(), NativeAttemptError> {
        let preparation = self
            .rate
            .as_ref()
            .ok_or(NativeAttemptError::Unavailable)?
            .prepared()
            .selection()
            .preparation();
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
        if !parts.attempts.last().is_some_and(|attempt| {
            attempt.preparation == preparation && attempt.transport == Transport::Committed
        }) {
            return Err(NativeAttemptError::Binding);
        }
        if served {
            if !parts.far_end_answered
                || parts
                    .final_target
                    .is_some_and(|previous| previous != preparation)
            {
                return Err(NativeAttemptError::Binding);
            }
            parts.final_target = Some(preparation);
        } else {
            parts.far_end_answered = true;
        }
        native.publish_incurred(&self.service.money.gov, snapshot)
    }

    pub(super) fn new(service: NativeRequestMoney, rate: CommittedRate) -> Self {
        Self {
            service,
            rate: Some(rate),
            answered: false,
        }
    }

    pub(crate) fn accepts(&self, declaration: &RequestDeclaration) -> bool {
        self.rate.as_ref().is_some_and(|rate| {
            self.service
                .request
                .context()
                .same_unit(declaration.context())
                && declaration.accepts(&rate.prepared()._prepared)
        })
    }

    pub(crate) fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        self.rate.as_ref()?.prepared()._prepared.data()
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
        .map_err(|_| NativeAttemptError::Usage)?;
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
        let observed = rate
            .observe(&rate_view)
            .map_err(|_| NativeAttemptError::Rate);
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
                let sealed = rate.seal(coverage).map_err(|_| NativeAttemptError::Rate);
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
