// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete serving ownership, lent to operations rather than plugin instances.
use super::{Caller, KernelServices, Nest, NestAsk, NestDone, NestRoute, NEST_NO_UNIT};
use std::sync::Arc;

/// The lifetime of one actually opened native plane's execution admission. This confers no
/// legacy service declarations; the native port's Needs and intent owners retain those policies.
/// Root keeps the lease with the opened port in its complete serving generation.
pub struct NativeInvocationAdmission {
    core: Arc<KernelServices>,
    caller: Caller,
}

impl Drop for NativeInvocationAdmission {
    fn drop(&mut self) {
        self.core
            .native_invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(self.caller.incarnation());
    }
}

impl KernelServices {
    /// Called by root after the native plane opened and its driver accepted its route declaration.
    /// The sealed Caller is the very same handle retained by that driver, never another issuance
    /// of the same namespace. A failed/retired candidate drops the returned lease.
    pub fn admit_native_invocation(
        self: &Arc<Self>,
        caller: &Caller,
    ) -> Result<NativeInvocationAdmission, &'static str> {
        if caller.kind() != busbar_contract::kinds::codes::KindCode::Plane {
            return Err("native invocation owner is not a plane");
        }
        if !self
            .native_invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(caller.incarnation().clone())
        {
            return Err("native invocation owner already admitted");
        }
        Ok(NativeInvocationAdmission {
            core: Arc::clone(self),
            caller: caller.clone(),
        })
    }

    fn invocation_admitted(&self, caller: &Caller) -> bool {
        self.native_invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(caller.incarnation())
            || self.facts(caller).is_some()
    }
}

/// Root constructs this only after its immutable dispatch snapshot is complete.
/// The route owns that snapshot; instances in it retain only core services.
/// Core persistence cannot be installed after a service has been shared.
///
/// ```compile_fail,E0599
/// use busbar_kernel::{host_services::KernelServices, persistence::facade::CoreStore};
/// use std::sync::Arc;
/// fn attach(host: &KernelServices, store: Arc<CoreStore>) {
///     host.attach_persistence(store);
/// }
/// ```
///
/// The same constructor-only rule applies to executors.
///
/// ```compile_fail,E0599
/// use busbar_kernel::host_services::{KernelServices, Offload};
/// use std::sync::Arc;
/// fn attach(host: &KernelServices, pool: Arc<dyn Offload>) {
///     host.attach_pool(pool);
/// }
/// ```
pub struct ServingGeneration {
    core: Arc<KernelServices>,
    route: Arc<dyn NestRoute>,
    routing_generation: Option<crate::registry::Generation>,
}

impl ServingGeneration {
    pub fn new(core: Arc<KernelServices>, route: Arc<dyn NestRoute>) -> Self {
        Self {
            core,
            route,
            routing_generation: None,
        }
    }

    /// Native snapshot construction refuses counter exhaustion rather than assigning FIRST or
    /// borrowing mutable metadata from a later publication.
    pub fn try_new(
        core: Arc<KernelServices>,
        route: Arc<dyn NestRoute>,
    ) -> Result<Self, crate::registry::GenerationExhausted> {
        Ok(Self {
            core,
            route,
            routing_generation: Some(crate::registry::Generation::allocate()?),
        })
    }

    pub fn routing_generation(&self) -> Option<crate::registry::Generation> {
        self.routing_generation
    }

    pub fn core(&self) -> &Arc<KernelServices> {
        &self.core
    }
}

/// Execution authority for one admitted unit and instance in one generation.
/// Retaining a numeric request ID alone never constructs this authority.
#[derive(Clone)]
pub struct InvocationContext {
    data_gate: Option<Arc<crate::auth::native_data::NativeDataEffectGate>>,
    generation: Arc<ServingGeneration>,
    caller: Caller,
    unit: u64,
    record: Arc<crate::host_units::UnitRecord>,
    phase: Arc<crate::plane_driver::request_admission::AdmissionPhase>,
    signed_authority: Option<Arc<crate::governance::current_credential::VerifiedKeyAuthority>>,
}

impl InvocationContext {
    pub fn new(
        generation: Arc<ServingGeneration>,
        caller: Caller,
        unit: u64,
    ) -> Result<Self, &'static str> {
        if !generation.core.invocation_admitted(&caller) {
            return Err(super::NOT_ADMITTED);
        }
        let record = generation
            .core
            .units()
            .invocation_record(unit, &caller)
            .ok_or(NEST_NO_UNIT)?;
        let phase = generation
            .core
            .units()
            .invocation_phase(unit, &caller, &record)
            .ok_or(NEST_NO_UNIT)?;
        let data_gate = generation
            .core
            .units()
            .invocation_data_gate(unit, &caller, &record)
            .ok_or(NEST_NO_UNIT)?;
        let signed_authority = generation
            .core
            .units()
            .invocation_signed_authority(unit, &caller, &record);
        Ok(Self {
            data_gate,

            generation,
            caller,
            unit,
            record,
            phase,
            signed_authority,
        })
    }

    pub fn generation(&self) -> &Arc<ServingGeneration> {
        &self.generation
    }

    pub fn unit(&self) -> u64 {
        self.unit
    }

    /// The verified key of the exact record this context checked at admission. A later numeric
    /// unit lookup cannot replace the principal used by hooks, budgets or nested authorization.
    pub fn principal(&self) -> Option<&Arc<busbar_contract::records::VirtualKey>> {
        self.record.principal.as_ref()
    }

    pub(crate) fn signed_authority(
        &self,
    ) -> Option<&Arc<crate::governance::current_credential::VerifiedKeyAuthority>> {
        self.signed_authority.as_ref()
    }

    pub fn instance(&self) -> &str {
        self.caller.namespace()
    }

    /// The instance's name as shared text: the caller's own name, shared, never copied.
    pub fn instance_name(&self) -> busbar_contract::kept::Text {
        busbar_contract::kept::Text::from(Arc::clone(self.caller.namespace()))
    }

    pub fn is_live(&self) -> bool {
        self.accepts(&self.caller)
    }

    /// Release this exact registered allocation; a later unit reusing its number is untouched.
    pub fn retire(&self) {
        self.generation
            .core
            .units()
            .ended_if_record(self.unit, &self.record);
    }

    /// Required before effectful host services; pre-admission keeps only read prerequisites.
    pub fn effects_allowed(&self) -> bool {
        self.is_live()
            && self.phase.effects_allowed()
            && self
                .data_gate
                .as_ref()
                .is_none_or(|gate| gate.effects_allowed())
    }

    pub(crate) fn admission_phase(
        &self,
    ) -> &crate::plane_driver::request_admission::AdmissionPhase {
        &self.phase
    }

    pub(crate) fn same_unit(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.record, &other.record)
            && Arc::ptr_eq(&self.generation, &other.generation)
            && self.caller.same_incarnation(&other.caller)
            && Arc::ptr_eq(&self.phase, &other.phase)
    }

    /// Keep hook work on the exact retained generation's bounded executor, including after
    /// the request stops waiting for a tap or an expired call.
    pub(crate) fn offload_hook(&self, job: Box<dyn FnOnce() + Send>) -> Result<(), &'static str> {
        if self.data_gate.is_some() || !self.effects_allowed() {
            return Err(NEST_NO_UNIT);
        }
        self.generation.core.pool().ok_or(super::NO_POOL)?.run(job);
        Ok(())
    }

    pub fn accepts(&self, caller: &Caller) -> bool {
        self.caller.incarnation() == caller.incarnation()
            && self.generation.core.invocation_admitted(caller)
            && self
                .generation
                .core
                .units()
                .invocation_record(self.unit, caller)
                .is_some_and(|record| Arc::ptr_eq(&record, &self.record))
    }

    pub fn nest(&self, caller: &Caller, ask: NestAsk, done: NestDone) -> Result<(), &'static str> {
        if self.data_gate.is_some() || !self.accepts(caller) || !self.effects_allowed() {
            return Err(NEST_NO_UNIT);
        }
        let retained = self.clone();
        self.generation.core.dispatch_child(
            self.clone(),
            &self.generation.route,
            Nest {
                parent: self.unit,
                depth: self.record.depth.saturating_add(1),
                principal: self.record.principal.clone(),
                ask,
                ancestry: self.generation.core.units().child_ancestry(self.unit),
                constraints: None,
            },
            Box::new(move |reply| {
                let _context = retained;
                done(reply);
            }),
        );
        Ok(())
    }
}
