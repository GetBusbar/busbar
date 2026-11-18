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
    route: Option<u32>,
    origin: Option<crate::plane_driver::route_identity::OriginalPlaneRoute>,
    facts: u64,
    /// The plane's declared classes: its own lists, shared, never copied per session.
    pub(super) classes: Arc<[UsageClass]>,
    attempt_classes: Arc<[Box<str>]>,
}

impl FrozenUsage {
    pub(super) fn of(
        calls: &(impl Calls + ?Sized),
        route: Option<u32>,
        origin: Option<crate::plane_driver::route_identity::OriginalPlaneRoute>,
    ) -> Result<Arc<Self>, SessionError> {
        let (facts, classes, attempt_classes) = calls.usage_metadata();
        Declaration::new(facts, &classes, &attempt_classes)
            .map_err(|_| SessionError::Violation(Violation::BadRecords))?;
        Ok(Arc::new(Self {
            route,
            origin,
            facts,
            classes,
            attempt_classes,
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
    dialect: Box<str>,
    model: Box<str>,
    exchange: PreparedOperands,
    estimates: Option<Estimates>,
    declaration: Arc<FrozenUsage>,
}

enum PreparedOperands {
    Plain(UpExchange),
    Resource {
        forward: crate::resource_admission::ValidatedForward,
        data: Arc<crate::auth::native_data::NativeDataPending>,
    },
}

/// The actual retained task's immutable declaration, supplied before its money admission.
/// Clones share the same frozen descriptor; neither names nor caller-provided facts construct it.
#[derive(Clone)]
pub struct RequestDeclaration {
    context: crate::host_services::InvocationContext,
    declaration: Arc<FrozenUsage>,
}

impl RequestDeclaration {
    pub(crate) fn same_declaration(&self, other: &Self) -> bool {
        self.context.same_unit(&other.context) && Arc::ptr_eq(&self.declaration, &other.declaration)
    }
    pub fn original_route(
        &self,
    ) -> Option<&crate::plane_driver::route_identity::OriginalPlaneRoute> {
        self.declaration.origin.as_ref()
    }
    pub fn route(&self) -> u32 {
        self.declaration
            .route
            .expect("a request declaration comes from request(), never probe()")
    }
    pub fn context(&self) -> &crate::host_services::InvocationContext {
        &self.context
    }
    pub fn declaration(&self) -> Declaration<'_> {
        self.declaration.declaration()
    }
    pub fn classes(&self) -> &[UsageClass] {
        &self.declaration.classes
    }
    pub(crate) fn accepts(&self, prepared: &PreparedExchange) -> bool {
        Arc::ptr_eq(&self.declaration, &prepared.declaration)
    }
    pub(crate) fn selected(&self) -> bool {
        self.declaration().facts() & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0
    }
}

impl PreparedExchange {
    pub(crate) fn original_route(
        &self,
    ) -> Option<&crate::plane_driver::route_identity::OriginalPlaneRoute> {
        self.declaration.origin.as_ref()
    }
    pub(crate) fn route(&self) -> u32 {
        self.declaration
            .route
            .expect("a preparation comes from a request task")
    }
    pub(crate) fn target(&self) -> &Candidate {
        &self.target
    }
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }
    pub(crate) fn exchange(&self) -> &UpExchange {
        match &self.exchange {
            PreparedOperands::Plain(exchange) => exchange,
            PreparedOperands::Resource { forward, .. } => forward.exchange(),
        }
    }
    pub(crate) fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        match &self.exchange {
            PreparedOperands::Plain(_) => None,
            PreparedOperands::Resource { data, .. } => Some(data),
        }
    }

    /// Bind the actual encoder output to the exact eligible walk definition and DATA selection.
    /// The immutable checked exchange and its physical execution owner remain inseparable.
    pub(crate) fn bind_resource(
        mut self,
        selected: &crate::plane_driver::port_egress::SelectedWalkAttempt,
        data: Arc<crate::auth::native_data::NativeDataPending>,
    ) -> Result<Self, SessionError> {
        let execution = data.execution().ok_or(SessionError::NotDriven)?;
        if !data.is_live()
            || execution.binding().check_executing().is_err()
            || !execution.money().accepts_walk(selected.walk())
            || selected.target() != &self.target
            || selected.preparation() != self.attempt
            || self.route() != data.selected().request().route()
        {
            return Err(SessionError::NotDriven);
        }
        let bound = data
            .selected()
            .forward_for_target(&self.target, &self.dialect, &self.model)
            .map_err(|_| SessionError::NotDriven)?;
        let PreparedOperands::Plain(exchange) = self.exchange else {
            return Err(SessionError::NotDriven);
        };
        let echo = bound
            .resolve_echo(
                exchange
                    .resource_echo
                    .as_ref()
                    .ok_or(SessionError::Violation(Violation::BadRecords))?
                    .borrowed(),
            )
            .map_err(|_| SessionError::Violation(Violation::BadRecords))?;
        let forward = bound
            .validate(
                echo,
                &self.target,
                &self.dialect,
                &self.model,
                selected.definition().ok_or(SessionError::NotDriven)?,
                exchange,
            )
            .map_err(|_| SessionError::Violation(Violation::BadRecords))?;
        self.exchange = PreparedOperands::Resource { forward, data };
        Ok(self)
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
    /// Prepare from the host's actual retained resource selection, never a plugin descriptor id.
    pub(crate) fn prepare_selected(
        &mut self,
        target: &Candidate,
        attempt: u32,
        dialect: &str,
        model: &str,
        effects: &dyn Effects,
    ) -> Result<Option<PreparedExchange>, SessionError> {
        let mut admission = Reply::new();
        if let Some(data) = self.data() {
            let execution = data.execution().ok_or(SessionError::NotDriven)?;
            if !data.is_live() || execution.binding().check_executing().is_err() {
                return Err(SessionError::NotDriven);
            }
            target.with_target(attempt, dialect, model, |input| {
                data.selected()
                    .forward_for_target(target, input.dialect, input.model)
                    .map_err(|_| SessionError::NotDriven)?
                    .write_admission(&mut admission)
                    .map_err(|_| SessionError::Encode)
            })?;
        }
        if self.selected_attempts() {
            wire::write_selected(
                &mut admission,
                SelectedResource {
                    attempt,
                    exchange: 0,
                    resource: target.resource.as_deref().unwrap_or(""),
                },
            )
            .map_err(|_| SessionError::Encode)?;
        }
        self.prepare(
            target,
            attempt,
            dialect,
            model,
            admission.as_bytes(),
            effects,
        )
    }

    pub(crate) fn request_declaration(&self) -> Result<RequestDeclaration, SessionError> {
        self.declaration.route.ok_or(SessionError::NotDriven)?;
        Ok(RequestDeclaration {
            context: self.invocation.clone().ok_or(SessionError::NotDriven)?,
            declaration: Arc::clone(&self.declaration),
        })
    }

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
        self.declaration.route.ok_or(SessionError::NotDriven)?;
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
        let (dialect, model) = target.with_target(attempt, dialect, model, |input| {
            (
                Box::<str>::from(input.dialect),
                Box::<str>::from(input.model),
            )
        });
        let prepared = PreparedExchange {
            target: target.clone(),
            attempt,
            dialect,
            model,
            exchange: PreparedOperands::Plain(exchange),
            estimates: answer.preparation.estimates,
            declaration: Arc::clone(&self.declaration),
        };
        buffered.release();
        Ok(Some(prepared))
    }
}
