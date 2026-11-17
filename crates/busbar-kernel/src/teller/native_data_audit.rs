// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One native allocation's call-bound audit custody. This does not admit money, sign a
//! record, acknowledge a journal write or release a response. Node owns those real joins.

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{Audit, AuditFacts, Exit, Grant, OriginKind, Outcome, Pass, UnitKey};
use busbar_contract::records::VirtualKey;
use busbar_contract::FinishClass;

use super::{Kernel, UnitCtx};
use crate::host_services::InvocationContext;
use crate::inbound::native::RequestBinding;
use crate::inflight::UnitSlot;
use crate::plane_driver::port_admission::AdmittedUnit;
use crate::plane_driver::request_admission::AdmittedRequest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAuditError {
    Taken,
    Phase,
    Identity,
    Generation,
    Cancelled,
    Capacity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Allocated,
    Registered,
    Bound,
    NodeReady,
    MoneyBound,
    Executing,
    Terminal,
    Complete,
}

struct State {
    phase: Phase,
    ctx: Option<UnitCtx>,
    admitted: Option<AdmittedRequest>,
}

/// Shared with the original DATA allocation, never constructible by a plugin or root caller.
pub struct NativeAuditState {
    invocation: InvocationContext,
    principal: Arc<VirtualKey>,
    binding: Arc<RequestBinding>,
    state: Mutex<State>,
}

impl NativeAuditState {
    pub(crate) fn new(
        invocation: InvocationContext,
        principal: Arc<VirtualKey>,
        binding: Arc<RequestBinding>,
    ) -> Arc<Self> {
        Arc::new(Self {
            invocation,
            principal,
            binding,
            state: Mutex::new(State {
                phase: Phase::Allocated,
                ctx: None,
                admitted: None,
            }),
        })
    }

    pub(crate) fn take_registration(
        self: &Arc<Self>,
    ) -> Result<NativeAuditRegistration, NativeAuditError> {
        let mut state = self.state.lock().map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::Allocated {
            return Err(NativeAuditError::Taken);
        }
        if !self.invocation.is_live() || self.binding.check_live().is_err() {
            return Err(NativeAuditError::Cancelled);
        }
        state.phase = Phase::Registered;
        Ok(NativeAuditRegistration {
            state: self.clone(),
        })
    }

    /// Checked before the preparatory Task, independently of monetary admission.
    pub(crate) fn node_ready(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.phase == Phase::NodeReady)
    }

    /// A money phase is already ADMITTED here, but the DATA effect gate is still closed.
    /// Calling AdmittedRequest::is_live would incorrectly require that gate to be open.
    pub(crate) fn bind_money(&self, admitted: &AdmittedUnit) -> Result<(), NativeAuditError> {
        let mut state = self.state.lock().map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::NodeReady {
            return Err(NativeAuditError::Phase);
        }
        if !self.invocation.is_live() || self.binding.check_live().is_err() {
            return Err(NativeAuditError::Cancelled);
        }
        let original = state.ctx.as_ref().ok_or(NativeAuditError::Phase)?;
        if !self.invocation.same_unit(admitted.request.context())
            || !Arc::ptr_eq(&self.principal, admitted.request.key())
            || admitted.request.unit() != original.key
            || !same_context(original, &admitted.unit.ctx)
        {
            return Err(NativeAuditError::Identity);
        }
        state.admitted = Some(admitted.request.clone());
        state.phase = Phase::MoneyBound;
        Ok(())
    }

    /// Only the DATA physical execution owner calls this, after winning its actual transition.
    pub(crate) fn executing(&self) -> Result<(), NativeAuditError> {
        let mut state = self.state.lock().map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::MoneyBound {
            return Err(NativeAuditError::Phase);
        }
        self.binding
            .check_executing()
            .map_err(|_| NativeAuditError::Cancelled)?;
        state.phase = Phase::Executing;
        Ok(())
    }
}

/// Obtained once from the actual newly registered allocation. No constructor from IDs.
pub struct NativeAuditRegistration {
    state: Arc<NativeAuditState>,
}

impl NativeAuditRegistration {
    /// Bind the original allocation to Node's actual kernel, before its inflight insertion.
    pub fn bind(self, kernel: Arc<Kernel>) -> Result<NativeAuditOwner, NativeAuditError> {
        let generation = self
            .state
            .invocation
            .generation()
            .routing_generation()
            .ok_or(NativeAuditError::Generation)?;
        let mut state = self
            .state
            .state
            .lock()
            .map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::Registered {
            return Err(NativeAuditError::Phase);
        }
        if !self.state.invocation.is_live() || self.state.binding.check_live().is_err() {
            return Err(NativeAuditError::Cancelled);
        }
        let ctx = UnitCtx {
            call: kernel.next_call(),
            key: UnitKey::new(self.state.invocation.unit()),
            origin: OriginKind::Client,
            session: None,
            generation,
            admin_listener: false,
            kernel_verb_only: false,
        };
        let pass = super::audit_pass(kernel.seal(), ctx.call);
        state.ctx = Some(ctx.clone());
        state.phase = Phase::Bound;
        drop(state);
        Ok(NativeAuditOwner {
            shared: self.state,
            kernel,
            ctx,
            pass,
            slot: None,
        })
    }
}

/// Move-only right retained in Node's charged native entry before effects are enabled.
/// Drop neither acknowledges completion nor schedules a detached replacement.
pub struct NativeAuditOwner {
    shared: Arc<NativeAuditState>,
    kernel: Arc<Kernel>,
    ctx: UnitCtx,
    pass: Pass<Audit>,
    slot: Option<Arc<UnitSlot>>,
}

impl NativeAuditOwner {
    pub fn context(&self) -> &UnitCtx {
        &self.ctx
    }

    pub fn invocation(&self) -> &InvocationContext {
        &self.shared.invocation
    }

    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.shared.binding
    }

    /// Node invokes this only after installing the owner in its charged custody entry.
    /// Create the arrival here; an arbitrary slot with an equal key is not call authority.
    pub fn enter(
        &mut self,
        inflight: &crate::inflight::InFlight,
        door: &dyn crate::inflight::ArrivalDoor,
        now: crate::Millis,
    ) -> Result<(), NativeAuditError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::Bound || self.slot.is_some() {
            return Err(NativeAuditError::Phase);
        }
        if !self.shared.invocation.is_live() || self.shared.binding.check_live().is_err() {
            return Err(NativeAuditError::Cancelled);
        }
        let arrival = crate::inflight::arrival_hold(
            &self.kernel,
            door,
            busbar_contract::caps::PrincipalId::new(&self.shared.principal.id),
            self.ctx.call,
        );
        let slot = inflight
            .insert(crate::inflight::Enter {
                key: self.ctx.key,
                origin: self.ctx.origin,
                session: None,
                admin_listener: false,
                zero_hold_tick: false,
                arrival,
                now,
            })
            .map_err(|_| NativeAuditError::Capacity)?;
        self.slot = Some(slot);
        state.phase = Phase::NodeReady;
        Ok(())
    }

    pub fn slot(&self) -> Option<&Arc<UnitSlot>> {
        self.slot.as_ref()
    }

    /// Freeze facts after root checks its original work and ACK-bound delivery (or proves
    /// registration never happened). An error returns the whole owner for continued custody.
    pub fn into_terminal(
        self,
        outcome: Outcome,
        first_payload_written: bool,
    ) -> Result<NativeAuditTerminal, (Self, NativeAuditError)> {
        let result = self.freeze(outcome);
        match result {
            Ok(admitted) => Ok(NativeAuditTerminal {
                owner: self,
                admitted,
                facts: terminal_facts(outcome, first_payload_written),
                outcome,
            }),
            Err(error) => Err((self, error)),
        }
    }

    fn freeze(&self, outcome: Outcome) -> Result<Option<AdmittedRequest>, NativeAuditError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| NativeAuditError::Phase)?;
        if !matches!(
            state.phase,
            Phase::NodeReady | Phase::MoneyBound | Phase::Executing
        ) || (outcome.is_completed() && state.phase != Phase::Executing)
            || self.slot.is_none()
        {
            return Err(NativeAuditError::Phase);
        }
        let admitted = state.admitted.clone();
        state.phase = Phase::Terminal;
        Ok(admitted)
    }
}

/// Frozen original facts and pass. Retain this across input preparation, stage refusal,
/// original journal retry and notary confirmation; borrow the pass rather than reminting it.
pub struct NativeAuditTerminal {
    owner: NativeAuditOwner,
    admitted: Option<AdmittedRequest>,
    facts: AuditFacts,
    outcome: Outcome,
}

impl NativeAuditTerminal {
    pub fn context(&self) -> &UnitCtx {
        &self.owner.ctx
    }

    pub fn facts(&self) -> AuditFacts {
        self.facts
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn pass(&self) -> &Pass<Audit> {
        &self.owner.pass
    }

    pub fn admission(&self) -> Option<&AdmittedRequest> {
        self.admitted.as_ref()
    }

    /// Root calls only after money, original signed audit and physical retirement joined.
    /// This releases arrival custody; it never posts usage or settles the monetary owner.
    pub fn complete(
        self,
        gauge: &crate::slice::ConcurrencyGauge,
    ) -> Result<(), (Self, NativeAuditError)> {
        let result = self.release(gauge);
        result.map_err(|error| (self, error))
    }

    fn release(&self, gauge: &crate::slice::ConcurrencyGauge) -> Result<(), NativeAuditError> {
        let mut state = self
            .owner
            .shared
            .state
            .lock()
            .map_err(|_| NativeAuditError::Phase)?;
        if state.phase != Phase::Terminal {
            return Err(NativeAuditError::Phase);
        }
        let slot = self.owner.slot.as_ref().ok_or(NativeAuditError::Phase)?;
        let exit = Grant::<Exit>::mint_bound(self.owner.kernel.seal(), self.owner.ctx.call);
        let hold = slot.cell().take(&exit).ok_or(NativeAuditError::Phase)?;
        drop(hold);
        let _ = slot.leases().release_all(gauge);
        state.phase = Phase::Complete;
        Ok(())
    }
}

fn same_context(original: &UnitCtx, returned: &UnitCtx) -> bool {
    original.call == returned.call
        && original.key == returned.key
        && original.origin == returned.origin
        && original.session == returned.session
        && original.generation == returned.generation
        && original.admin_listener == returned.admin_listener
        && original.kernel_verb_only == returned.kernel_verb_only
}

fn terminal_facts(outcome: Outcome, first_payload_written: bool) -> AuditFacts {
    AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("data"),
        finish: if outcome.is_completed() {
            FinishClass::Complete
        } else if first_payload_written {
            FinishClass::Partial
        } else {
            FinishClass::Error
        },
    }
}

#[cfg(test)]
#[path = "native_data_audit_tests.rs"]
mod tests;
