// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native DATA authorization retains the original physical request, selected resources and
//! real verification. Registration and monetary admission cannot reconstruct this proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use busbar_contract::records::VirtualKey;
use busbar_contract::services::Caller;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
use busbar_ports::CallCx;

use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use crate::host_services::{InvocationContext, ServingGeneration};
use crate::inbound::native::{
    AuthorizedPhysicalData, CompletingPhysicalRequest, PhysicalExecutionOwner, RequestBinding,
    RouteBinding, RouteTarget,
};
use crate::plane_driver::port::PortSeat;
use crate::plane_driver::port_admission::{AdmittedUnit, Pending};
use crate::plane_driver::port_session::RequestDeclaration;
use crate::plane_driver::request_admission::{
    AdmittedRequest, RequestAllocation, RequestPoolReceipt, RequestRoutes,
};
use crate::refusal::ClientRefusal;
use crate::resource_admission::{ResourceInventory, SelectedResources};
use crate::state::{AdmissionLease, App};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRefused {
    Unsupported,
    Binding,
    Cancelled,
    Capacity,
    Credential,
    Policy,
    Replay,
    Unit,
}

/// Actual immutable candidate owners. Root assembles these; none is a plugin proof.
pub struct DataRouteOwners {
    pub generation: Arc<ServingGeneration>,
    pub inventory: Arc<ResourceInventory>,
    pub chain: Arc<NativeChain>,
    pub keys: Arc<crate::door::UnitKeyMint>,
    pub routes: Arc<RequestRoutes>,
}

/// One canonical physical route and its candidate's actual native owners. No App Arc cycle.
pub struct NativeDataRoute {
    binding: Arc<RouteBinding>,
    caller: Caller,
    owners: DataRouteOwners,
    cost: Arc<crate::cost::CostModel>,
}

impl NativeDataRoute {
    /// Lend the actual inventory retained by this canonical route for pre-auth resource selection.
    /// A reconstructed inventory with equal entries is not the same authorization owner.
    pub fn inventory(&self) -> &Arc<ResourceInventory> {
        &self.owners.inventory
    }

    pub fn bind(
        app: &App,
        seat: &PortSeat,
        binding: Arc<RouteBinding>,
        owners: DataRouteOwners,
    ) -> Result<Arc<Self>, DataRefused> {
        let RouteTarget::Plane(target) = binding.target() else {
            return Err(DataRefused::Unsupported);
        };
        let mounted = target.mounted();
        if app.oauth_as.is_some()
            || seat.audience.is_some()
            || mounted.flags != 0
            || mounted.catalog
            || mounted.auth != AUTH_PRINCIPAL
            || mounted.effective != AUTH_PRINCIPAL
            || mounted.resource_kinds.is_empty()
            || seat.driver.port().facts() & busbar_plugin_abi::plane::FB_RESOURCE_ADMISSION == 0
            || seat.driver.has_hooks(mounted.route)
            || !owners.chain.is_data()
        {
            return Err(DataRefused::Unsupported);
        }
        if !seat.driver.caller().same_incarnation(target.caller())
            || !Arc::ptr_eq(seat.driver.core(), owners.generation.core())
            || !seat
                .driver
                .routes()
                .data
                .iter()
                .any(|route| route == mounted)
            || owners.inventory.instance() != target.caller().incarnation()
            || owners.inventory.epoch() != owners.chain.epoch()
            || !owners.chain.matches_names(target.auth_instances())
        {
            return Err(DataRefused::Binding);
        }
        Ok(Arc::new(Self {
            caller: target.caller().clone(),
            binding,
            owners,
            cost: Arc::clone(&app.cost),
        }))
    }

    /// Takes the sole pending physical owner. Calling code cannot duplicate verification
    /// by retaining a read-only RequestBinding or reuse an admin PreparedIdentity.
    pub async fn prepare(
        self: &Arc<Self>,
        physical: CompletingPhysicalRequest,
        selected: SelectedResources,
        cx: CallCx,
    ) -> Result<PendingData, DataRefused> {
        let binding = physical.binding();
        binding.check_live().map_err(|_| DataRefused::Cancelled)?;
        if !Arc::ptr_eq(binding.route(), &self.binding)
            || cx.request_id != binding.invocation().request_id().get()
            || binding.deadline().is_some_and(|at| cx.deadline > at)
            || Instant::now() >= cx.deadline
            || selected.invocation() != binding.invocation()
            || !Arc::ptr_eq(selected.inventory(), &self.owners.inventory)
        {
            return Err(DataRefused::Binding);
        }
        let snapshot = binding.snapshot().map_err(|_| DataRefused::Capacity)?;
        if !selected.request().matches_snapshot(&snapshot)
            || selected.request().route() != self.binding.line().route.rung
            || !snapshot.request().same_request(binding.request())
        {
            return Err(DataRefused::Binding);
        }
        // Restrictive scans cover every relevant occurrence, not a decoy first bearer.
        snapshot.with_auth_input(|request| {
            for field in request.headers {
                let name = field.name.get();
                let Ok(value) = std::str::from_utf8(field.value.get()) else { continue };
                let token = if name.eq_ignore_ascii_case("authorization") {
                    let Some((scheme, token)) = value.split_once(' ') else { continue };
                    if scheme.eq_ignore_ascii_case("DPoP") {
                        return Err(DataRefused::Credential);
                    }
                    if !scheme.eq_ignore_ascii_case("Bearer") { continue }
                    token.trim()
                } else if self.owners.chain.reads_header(name)
                    || matches!(self.binding.target(), RouteTarget::Plane(route)
                        if route.mounted().cred_header.as_deref().is_some_and(|header| header.eq_ignore_ascii_case(name)))
                {
                    value
                } else { continue };
                if super::dpop::is_dpop_bound(token)
                    || token.starts_with(crate::governance::signing::TOKEN_PREFIX)
                {
                    return Err(DataRefused::Credential);
                }
            }
            Ok(())
        }).map_err(|_| DataRefused::Capacity)??;
        let prepared = tokio::select! {
            biased;
            () = binding.cancelled() => return Err(DataRefused::Cancelled),
            () = tokio::time::sleep_until(cx.deadline.into()) => return Err(DataRefused::Cancelled),
            answer = self.owners.chain.prepare_snapshot(cx, snapshot) => answer.map_err(|_| DataRefused::Credential)?,
        };
        let NativePreparedAnswer::Identity(prepared) = prepared else {
            return Err(DataRefused::Credential);
        };
        Ok(PendingData {
            physical,
            route: self.clone(),
            selected: Arc::new(selected),
            prepared,
            deadline: cx.deadline,
        })
    }
}

pub struct PendingData {
    physical: CompletingPhysicalRequest,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    deadline: Instant,
}
impl PendingData {
    /// Consumes the completion right before awaiting replay. Publication after this lease
    /// is not cancellation; reset/deadline and an uncertain replay still grant no effects.
    pub async fn complete(self) -> Result<AuthorizedPhysicalData, DataRefused> {
        let binding = self.physical.binding().clone();
        binding.check_live().map_err(|_| DataRefused::Cancelled)?;
        if Instant::now() >= self.deadline {
            return Err(DataRefused::Cancelled);
        }
        let mut key = None;
        let lease = binding
            .handle()
            .admit_current(binding.app(), binding.invocation(), |app| {
                let now = crate::store::now();
                self.prepared.fresh(now).map_err(|_| DataRefused::Policy)?;
                if !self.prepared.belongs_to(&self.route.owners.chain)
                    || !self
                        .selected
                        .request()
                        .matches_snapshot(self.prepared.snapshot())
                    || app.config_generation.load(Ordering::Acquire) != self.selected.epoch()
                {
                    return Err(DataRefused::Binding);
                }
                let identity = self.prepared.identity();
                let (_, gov) = super::resolve_identity_from_bindings(
                    &app.role_bindings,
                    super::ChainVerdict::Identified {
                        module: self.prepared.provider().to_owned(),
                        principal: super::Principal {
                            id: identity.subject().to_owned(),
                            name: None,
                            roles: identity.groups().map(str::to_owned).collect(),
                            ttl_secs: identity.cache_s().map(u64::from),
                        },
                        resolved: None,
                    },
                )
                .map_err(|_| DataRefused::Policy)?;
                let resolved = gov.key.ok_or(DataRefused::Policy)?;
                if !resolved.enabled
                    || resolved.deleted_at.is_some()
                    || resolved.expires_at.is_some_and(|until| now >= until)
                    || !self.selected.scope_allowed(&resolved)
                {
                    return Err(DataRefused::Policy);
                }
                key = Some(resolved);
                Ok(())
            })
            .map_err(|_| DataRefused::Policy)?;
        let claimed = tokio::select! {
            biased;
            () = binding.cancelled() => return Err(DataRefused::Cancelled),
            () = tokio::time::sleep_until(self.deadline.into()) => return Err(DataRefused::Cancelled),
            result = self.prepared.claim() => result,
        };
        if !claimed {
            return Err(DataRefused::Replay);
        }
        binding.check_live().map_err(|_| DataRefused::Cancelled)?;
        if Instant::now() >= self.deadline {
            return Err(DataRefused::Cancelled);
        }
        let authorization = DataAuthorization {
            binding,
            route: self.route,
            selected: self.selected,
            prepared: self.prepared,
            lease,
            key: key.ok_or(DataRefused::Policy)?,
            deadline: self.deadline,
        };
        self.physical
            .complete(authorization)
            .map_err(|_| DataRefused::Cancelled)
    }
}

/// Privately minted after actual policy and replay, not from a public identity callback.
///
/// ```compile_fail,E0599
/// use std::sync::Arc;
/// use busbar_kernel::auth::{native_admin::PreparedIdentity, native_data::DataAuthorization};
/// fn fabricate(identity: Arc<dyn PreparedIdentity>) -> DataAuthorization {
///     DataAuthorization::from_identity(identity)
/// }
/// ```
pub struct DataAuthorization {
    binding: Arc<RequestBinding>,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    lease: AdmissionLease,
    key: Arc<VirtualKey>,
    deadline: Instant,
}
impl DataAuthorization {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}

/// Separate from the money phase: a successful grant cannot open effects while the
/// actual callback identity and physical execution transition are still unchecked.
pub(crate) struct NativeDataEffectGate {
    binding: Arc<RequestBinding>,
    ready: AtomicBool,
    deadline: Instant,
}
impl NativeDataEffectGate {
    fn new(binding: Arc<RequestBinding>, deadline: Instant) -> Self {
        Self {
            binding,
            deadline,
            ready: AtomicBool::new(false),
        }
    }
    pub(crate) fn effects_allowed(&self) -> bool {
        self.ready.load(Ordering::Acquire)
            && Instant::now() < self.deadline
            && self.binding.check_executing().is_ok()
    }
}

struct Registration {
    context: InvocationContext,
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.context.retire();
    }
}

/// Owns the newly inserted record and exact original request, never an arbitrary existing context.
pub struct NativeDataAllocation {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
    gate: Arc<NativeDataEffectGate>,
    allocation: RequestAllocation,
}
impl NativeDataAllocation {
    pub fn register(physical: AuthorizedPhysicalData) -> Result<Self, DataRefused> {
        let (authorization, physical) = physical.into_parts();
        authorization
            .binding
            .check_live()
            .map_err(|_| DataRefused::Cancelled)?;
        if Instant::now() >= authorization.deadline {
            return Err(DataRefused::Cancelled);
        }
        let plan = &authorization.route;
        let unit = plan.owners.keys.mint();
        let gate = Arc::new(NativeDataEffectGate::new(
            authorization.binding.clone(),
            authorization.deadline,
        ));
        let units = plan.owners.generation.core().units();
        let record = units
            .pre_admitted_data(
                unit.get(),
                &plan.caller,
                crate::host_units::UnitRecord {
                    principal: Some(authorization.key.clone()),
                    depth: 0,
                },
                gate.clone(),
            )
            .ok_or(DataRefused::Unit)?;
        let context = match InvocationContext::new(
            plan.owners.generation.clone(),
            plan.caller.clone(),
            unit.get(),
        ) {
            Ok(context) => context,
            Err(_) => {
                units.ended_if_record(unit.get(), &record);
                return Err(DataRefused::Unit);
            }
        };
        let registration = Arc::new(Registration { context });
        let allocation = RequestAllocation::new(
            registration.context.clone(),
            plan.cost.clone(),
            authorization.prepared.snapshot().now_s(),
        )
        .map_err(|_| DataRefused::Unit)?;
        Ok(Self {
            authorization,
            physical,
            registration,
            gate,
            allocation,
        })
    }

    pub fn context(&self) -> &InvocationContext {
        &self.registration.context
    }

    /// Wrap the existing same-Task monetary callback. The opaque DATA carrier, not a
    /// free Pending or InvocationContext, unlocks the resource-scoped preparatory phase.
    pub fn into_pending(
        self,
        commit: impl FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send + 'static,
    ) -> NativeDataPending {
        self.into_pending_using(
            move |receipt, ()| commit(receipt),
            |allocation, routes, commit| {
                Pending::new(allocation, routes, None, move |receipt| commit(receipt, ()))
            },
        )
    }

    /// Preserve the declaration minted by the same preparatory Task for the selected
    /// monetary binder. This does not mint or reconstruct a declaration from route facts.
    pub fn into_pending_selected(
        self,
        commit: impl FnOnce(RequestPoolReceipt, RequestDeclaration) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
    ) -> NativeDataPending {
        self.into_pending_using(commit, |allocation, routes, commit| {
            Pending::new_selected(allocation, routes, None, commit)
        })
    }

    fn into_pending_using<D: Send + 'static>(
        self,
        commit: impl FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
        build: impl FnOnce(RequestAllocation, Arc<RequestRoutes>, DataCommit<D>) -> Pending,
    ) -> NativeDataPending {
        let Self {
            authorization,
            physical,
            registration,
            gate,
            allocation,
        } = self;
        let execution = Arc::new(OnceLock::new());
        let retained = execution.clone();
        let context = registration.context.clone();
        let routes = authorization.route.owners.routes.clone();
        let route = authorization.route.clone();
        let selected = authorization.selected.clone();
        let prepared = authorization.prepared.clone();
        let binding = authorization.binding.clone();
        let deadline = authorization.deadline;
        let pending = build(
            allocation,
            routes,
            Box::new(move |receipt, declaration| {
                let refuse = || ClientRefusal {
                    status: 503,
                    code: busbar_plugin_abi::fail::refused::R_POLICY,
                    text: "native data admission refused".into(),
                };
                if authorization.binding.check_live().is_err()
                    || !registration.context.is_live()
                    || Instant::now() >= authorization.deadline
                {
                    return Err(refuse());
                }
                let admitted = commit(receipt, declaration)?;
                // effects-dependent is_live is intentionally NOT called until DATA starts.
                if !admitted.request.context().same_unit(&registration.context)
                    || !registration.context.is_live()
                    || Instant::now() >= authorization.deadline
                    || admitted.unit.ctx.key != admitted.request.unit()
                    || !Arc::ptr_eq(admitted.request.key(), &authorization.key)
                {
                    return Err(refuse());
                }
                let proof = DataExecutionAdmission {
                    authorization,
                    physical,
                    registration,
                    money: admitted.request.clone(),
                };
                gate.ready.store(true, Ordering::Release);
                if proof.physical.start_execution(&proof).is_err() {
                    return Err(refuse());
                }
                retained.set(proof).map_err(|_| refuse())?;
                Ok(admitted)
            }),
        );
        NativeDataPending {
            pending: Arc::new(pending),
            execution,
            context,
            route,
            selected,
            prepared,
            binding,
            deadline,
        }
    }
}

type DataCommit<D> =
    Box<dyn FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal> + Send>;

pub struct NativeDataPending {
    binding: Arc<RequestBinding>,
    deadline: Instant,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    pending: Arc<Pending>,
    execution: Arc<OnceLock<DataExecutionAdmission>>,
    context: InvocationContext,
}
impl NativeDataPending {
    pub fn is_live(&self) -> bool {
        self.context.is_live()
            && Instant::now() < self.deadline
            && self.binding.check_live().is_ok()
    }

    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn selected(&self) -> &SelectedResources {
        &self.selected
    }
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.prepared.identity()
    }
    pub fn snapshot(&self) -> &Arc<crate::inbound::request_snapshot::ChargedRequestSnapshot> {
        self.prepared.snapshot()
    }
    pub(crate) fn accepts(
        &self,
        driver: &crate::plane_driver::port::PortDriver,
        route: u32,
    ) -> bool {
        self.is_live()
            && self.route.caller.same_incarnation(driver.caller())
            && Arc::ptr_eq(self.route.owners.generation.core(), driver.core())
            && self.route.binding.line().route.rung == route
            && self.selected.request().route() == route
    }

    pub(crate) fn pending(&self) -> &Arc<Pending> {
        &self.pending
    }
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }
    pub fn execution(&self) -> Option<&DataExecutionAdmission> {
        self.execution.get()
    }
}

/// Actual DATA + physical + exact-context + monetary completion. No public constructor.
pub struct DataExecutionAdmission {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
    money: AdmittedRequest,
}
impl DataExecutionAdmission {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.authorization.binding
    }
    pub fn selected(&self) -> &SelectedResources {
        &self.authorization.selected
    }
    pub fn context(&self) -> &InvocationContext {
        &self.registration.context
    }
    pub fn identity(&self) -> &busbar_ports::auth::Identity {
        self.authorization.prepared.identity()
    }
    pub fn principal(&self) -> &Arc<VirtualKey> {
        &self.authorization.key
    }
    pub fn lease(&self) -> &AdmissionLease {
        &self.authorization.lease
    }
    pub fn money(&self) -> &AdmittedRequest {
        &self.money
    }
}

#[cfg(test)]
#[path = "tests/native_data_tests.rs"]
mod tests;
