// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned preparation from the same native task. This is not transport or resource authority.

use std::sync::Arc;

use busbar_plugin_abi::fallback_usage::{self as wire, EstimateValue, SelectedResource};
use busbar_plugin_abi::plane::{self as p, ATT_DECLINE};
use busbar_plugin_abi::records::{Records, Reply, Writer};
use busbar_ports::codec::fallback_usage::Declaration;
use busbar_ports::plane::{TargetIn, UsageClass};

use super::{Buffered, Calls, Effects, SessionError, Task, UpExchange, Violation};
use crate::plane_driver::port_upstream::Candidate;

#[derive(Debug)]
pub(super) struct FrozenUsage {
    facts: u64,
    classes: Vec<UsageClass>,
    attempt_classes: Vec<Box<str>>,
}

impl FrozenUsage {
    pub(super) fn of(calls: &(impl Calls + ?Sized)) -> Result<Arc<Self>, SessionError> {
        let (facts, classes, attempt_classes) = calls.usage_metadata();
        Declaration::new(facts, classes, attempt_classes)
            .map_err(|_| SessionError::Violation(Violation::BadRecords))?;
        Ok(Arc::new(Self {
            facts,
            classes: classes.to_vec(),
            attempt_classes: attempt_classes.to_vec(),
        }))
    }

    pub(super) fn declaration(&self) -> Declaration<'_> {
        Declaration::new(self.facts, &self.classes, &self.attempt_classes)
            .expect("the immutable declaration was validated before request")
    }
}

#[derive(Debug)]
struct Selected {
    attempt: u32,
    exchange: u32,
    resource: Box<str>,
}

#[derive(Debug)]
pub(super) struct Estimates {
    attempt: u32,
    exchange: u32,
    entries: Vec<(Box<str>, EstimateValue)>,
}

#[derive(Debug, Default)]
pub(super) struct PreparationFacts {
    selected: Option<Selected>,
    estimates: Option<Estimates>,
}

impl PreparationFacts {
    pub(super) fn selected(&mut self, selected: SelectedResource<'_>) -> Result<(), Violation> {
        selected.validate().map_err(|_| Violation::BadRecords)?;
        if self.selected.is_some() {
            return Err(Violation::BadRecords);
        }
        self.selected = Some(Selected {
            attempt: selected.attempt,
            exchange: selected.exchange,
            resource: selected.resource.into(),
        });
        Ok(())
    }

    pub(super) fn estimates(
        &mut self,
        estimates: wire::PreparedEstimates<'_>,
    ) -> Result<(), Violation> {
        if self.estimates.is_some() {
            return Err(Violation::BadRecords);
        }
        let entries = estimates
            .entries()
            .map(|entry| {
                let entry = entry.map_err(|_| Violation::BadRecords)?;
                Ok((entry.class.into(), entry.value))
            })
            .collect::<Result<Vec<_>, Violation>>()?;
        self.estimates = Some(Estimates {
            attempt: estimates.attempt,
            exchange: estimates.exchange,
            entries,
        });
        Ok(())
    }

    pub(super) fn validate(
        &self,
        declaration: Declaration<'_>,
        target: &TargetIn<'_>,
        declined: bool,
    ) -> Result<(), Violation> {
        let expected =
            wire::selected_from_admission(target.admission).map_err(|_| Violation::BadRecords)?;
        if expected.is_some_and(|selected| selected.attempt != target.attempt) {
            return Err(Violation::BadRecords);
        }
        let mut records = Reply::new();
        if let Some(selected) = &self.selected {
            wire::write_selected(
                &mut records,
                SelectedResource {
                    attempt: selected.attempt,
                    exchange: selected.exchange,
                    resource: &selected.resource,
                },
            )
            .map_err(|_| Violation::BadRecords)?;
        }
        if let Some(estimates) = &self.estimates {
            let entries: Vec<_> = estimates
                .entries
                .iter()
                .map(|(class, value)| wire::Estimate {
                    class,
                    value: *value,
                })
                .collect();
            wire::write_prepared_estimates(
                &mut records,
                SelectedResource {
                    attempt: estimates.attempt,
                    exchange: estimates.exchange,
                    resource: "",
                },
                &entries,
            )
            .map_err(|_| Violation::BadRecords)?;
        }
        if declined {
            records
                .put_pod_tail(
                    p::tag::ATTEMPT,
                    &p::AttemptRec {
                        verdict: ATT_DECLINE,
                        class: 0,
                        retry_after_s: 0,
                    },
                    &[],
                )
                .map_err(|_| Violation::BadRecords)?;
        }
        declaration
            .validate_preparation(expected, Records::new(records.as_bytes()))
            .map_err(|_| Violation::BadRecords)?;
        Ok(())
    }
}

/// The exact validated preparation and its full target. No constructor accepts a free exchange.
/// Resource authorization and live monetary/transport admission are separate required proofs.
pub(crate) struct PreparedExchange {
    target: Candidate,
    attempt: u32,
    exchange: UpExchange,
    estimates: Option<Estimates>,
    declaration: Arc<FrozenUsage>,
}

impl PreparedExchange {
    pub(crate) fn target(&self) -> &Candidate {
        &self.target
    }
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }
    pub(crate) fn exchange(&self) -> &UpExchange {
        &self.exchange
    }
    pub(crate) fn estimates(&self) -> Option<&[(Box<str>, EstimateValue)]> {
        self.estimates
            .as_ref()
            .map(|estimates| estimates.entries.as_slice())
    }
    pub(crate) fn declaration(&self) -> Declaration<'_> {
        self.declaration.declaration()
    }
}

impl<K: Calls + ?Sized> Task<'_, K> {
    /// Calls the actual encoder once, then moves its unique exchange into immutable custody.
    pub(crate) fn prepare(
        &mut self,
        target: &Candidate,
        attempt: u32,
        dialect: &str,
        model: &str,
        admission: &[u8],
        effects: &dyn Effects,
    ) -> Result<Option<PreparedExchange>, SessionError> {
        let selected = wire::selected_from_admission(admission)
            .map_err(|_| SessionError::Violation(Violation::BadRecords))?;
        if selected.is_some_and(|selected| {
            selected.attempt != attempt
                || selected.resource != target.resource.as_deref().unwrap_or("")
        }) {
            self.session = None;
            return Err(SessionError::Violation(Violation::BadRecords));
        }
        let buffered = Buffered::new(effects);
        let usage_before = self.usage.clone();
        let mut answer =
            target.with_admission_target(attempt, dialect, model, admission, |input| {
                self.upstream(input, &buffered)
            })?;
        if answer
            .attempt
            .as_ref()
            .is_some_and(|attempt| attempt.verdict == ATT_DECLINE)
        {
            buffered.release();
            return Ok(None);
        }
        if answer.exchanges.len() != 1
            || answer.exchanges[0].id != 0
            || answer.exchanges[0].cut
            || !answer.exchanges[0].end
            || (!admission.is_empty()
                && (!buffered.emits.borrow().is_empty()
                    || !answer.client.is_empty()
                    || !answer.intents.is_empty()
                    || !answer.ex_msgs.is_empty()
                    || !answer.audits.is_empty()
                    || answer.detach.is_some()
                    || answer.wake_at.is_some()
                    || answer.forward.is_some()))
        {
            self.session = None;
            self.usage = usage_before;
            return Err(SessionError::Violation(Violation::BadRecords));
        }
        let exchange = answer.exchanges.pop().unwrap();
        let prepared = PreparedExchange {
            target: target.clone(),
            attempt,
            exchange,
            estimates: answer.preparation.estimates,
            declaration: Arc::clone(&self.declaration),
        };
        buffered.release();
        Ok(Some(prepared))
    }
}
