// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native DATA authorization retains the original physical request, selected resources and
//! real verification. Registration and monetary admission cannot reconstruct this proof.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use busbar_contract::records::VirtualKey;
use busbar_contract::services::Caller;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
use busbar_ports::CallCx;

use super::native_chain::{NativeChain, NativePreparedAnswer, PreparedNativeIdentity};
use crate::host_services::{InvocationContext, ServingGeneration};
use crate::inbound::native::{
    AuthorizedPhysicalData, DataPreparation, DataPreparationDenied, DataPreparationSuccess,
    PhysicalExecutionOwner, RequestBinding, RouteBinding, RouteTarget,
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
    Unavailable,
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

    /// Consumes the original physical preparation latch before verification.
    /// Root retains the completion owner for the exact authorization or denied result.
    pub async fn prepare(
        self: &Arc<Self>,
        preparation: DataPreparation,
        selected: SelectedResources,
        cx: CallCx,
    ) -> Result<PendingData, DataPreparationFailed> {
        let binding = preparation.binding().clone();
        let selected = Arc::new(selected);
        let result = async {
        // One reading for this step's two deadlines: the binding's own and the call's. No lock
        // and no await sits between the reading and the second check.
        let live_at = binding.check_live_now().map_err(|_| DataRefused::Cancelled)?;
        if !Arc::ptr_eq(binding.route(), &self.binding)
            || cx.request_id != binding.invocation().request_id().get()
            || binding.deadline().is_some_and(|at| cx.deadline > at)
            || live_at >= cx.deadline
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
        let prepared = self.owners.chain.prepare_snapshot(cx, snapshot).await.map_err(|_| DataRefused::Unavailable)?;
        binding.check_live().map_err(|_| DataRefused::Cancelled)?;
        let NativePreparedAnswer::Identity(prepared) = prepared else {
            return Err(DataRefused::Credential);
        };
            Ok(prepared)
        }.await;
        match result {
            Ok(prepared) => Ok(PendingData {
                preparation,
                route: self.clone(),
                selected,
                prepared,
                deadline: cx.deadline,
            }),
            Err(reason) => Err(preparation_failed(
                preparation,
                self.clone(),
                selected,
                None,
                reason,
            )),
        }
    }
}

pub struct PendingData {
    preparation: DataPreparation,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    deadline: Instant,
}
impl PendingData {
    /// Consumes the completion right before awaiting replay. Publication after this lease
    /// is not cancellation; reset/deadline and an uncertain replay still grant no effects.
    pub async fn complete(self) -> Result<DataAuthorization, DataPreparationFailed> {
        let binding = self.preparation.binding().clone();
        let result = async {
            // One reading for this step's two deadlines: the binding's own and the pending one.
            let live_at = binding
                .check_live_now()
                .map_err(|_| DataRefused::Cancelled)?;
            if live_at >= self.deadline {
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
                            module: super::admin_module(self.prepared.provider()),
                            principal: super::Principal {
                                id: identity.subject().to_owned(),
                                name: None,
                                roles: identity.groups().map(str::to_owned).collect(),
                                ttl_secs: identity.cache_s().map(u64::from),
                            },
                            resolved: None,
                            signed_authority: None,
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
            match self.prepared.claim_classified().await {
                super::native_admin::NativeReplayClaim::Claimed => {}
                super::native_admin::NativeReplayClaim::Duplicate => {
                    return Err(DataRefused::Replay)
                }
                super::native_admin::NativeReplayClaim::Unknown(_) => {
                    return Err(DataRefused::Unavailable);
                }
                super::native_admin::NativeReplayClaim::Inconsistent => {
                    return Err(DataRefused::Binding)
                }
            }
            // The replay claim above may have waited: a second reading is needed, and it is this
            // step's one reading for both deadlines.
            let live_at = binding
                .check_live_now()
                .map_err(|_| DataRefused::Cancelled)?;
            if live_at >= self.deadline {
                return Err(DataRefused::Cancelled);
            }
            Ok((lease, key.ok_or(DataRefused::Policy)?))
        }
        .await;
        let (lease, key) = match result {
            Ok(parts) => parts,
            Err(reason) => {
                return Err(preparation_failed(
                    self.preparation,
                    self.route,
                    self.selected,
                    Some(self.prepared),
                    reason,
                ))
            }
        };
        let preparation = self.preparation.authorize().map_err(|_| {
            DataPreparationFailed::Unknown(UnknownDataPreparation {
                _preparation: None,
                _prepared: Some(self.prepared.clone()),
                reason: DataRefused::Cancelled,
            })
        })?;
        Ok(DataAuthorization {
            preparation,
            binding,
            route: self.route,
            selected: self.selected,
            prepared: self.prepared,
            lease,
            key,
            deadline: self.deadline,
        })
    }
}

pub enum DataPreparationFailed {
    Denied(PreparedDataDenial),
    Unknown(UnknownDataPreparation),
}
impl std::fmt::Debug for DataPreparationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataPreparationFailed")
            .field("reason", &self.reason())
            .finish()
    }
}
impl DataPreparationFailed {
    pub fn reason(&self) -> DataRefused {
        match self {
            Self::Denied(denied) => denied.decision,
            Self::Unknown(unknown) => unknown.reason,
        }
    }
}

pub struct PreparedDataDenial {
    preparation: DataPreparationDenied,
    _route: Arc<NativeDataRoute>,
    _selected: Arc<SelectedResources>,
    _prepared: Option<Arc<PreparedNativeIdentity>>,
    decision: DataRefused,
}
impl PreparedDataDenial {
    pub(crate) fn preparation(&self) -> &DataPreparationDenied {
        &self.preparation
    }
    pub fn binding(&self) -> &Arc<RequestBinding> {
        self.preparation.binding()
    }
    pub fn decision(&self) -> DataRefused {
        self.decision
    }
}

pub struct UnknownDataPreparation {
    _preparation: Option<DataPreparation>,
    _prepared: Option<Arc<PreparedNativeIdentity>>,
    reason: DataRefused,
}

fn preparation_failed(
    preparation: DataPreparation,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Option<Arc<PreparedNativeIdentity>>,
    reason: DataRefused,
) -> DataPreparationFailed {
    if matches!(
        reason,
        DataRefused::Credential | DataRefused::Policy | DataRefused::Replay
    ) {
        match preparation.deny() {
            Ok(preparation) => DataPreparationFailed::Denied(PreparedDataDenial {
                preparation,
                _route: route,
                _selected: selected,
                _prepared: prepared,
                decision: reason,
            }),
            Err(_) => DataPreparationFailed::Unknown(UnknownDataPreparation {
                _preparation: None,
                _prepared: prepared,
                reason: DataRefused::Cancelled,
            }),
        }
    } else {
        DataPreparationFailed::Unknown(UnknownDataPreparation {
            _preparation: Some(preparation),
            _prepared: prepared,
            reason,
        })
    }
}

/// Privately minted after actual policy and replay, not from a public identity callback.
///
/// ```compile_fail,E0599
/// use std::sync::Arc;
/// use busbar_kernel::auth::{native_admin::PreparedIdentity, native_data::DataAuthorization};
/// fn fabricate(identity: Arc<PreparedIdentity>) -> DataAuthorization {
///     DataAuthorization::from_identity(identity)
/// }
/// ```
pub struct DataAuthorization {
    preparation: DataPreparationSuccess,
    binding: Arc<RequestBinding>,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    lease: AdmissionLease,
    key: Arc<VirtualKey>,
    deadline: Instant,
}
impl DataAuthorization {
    pub(crate) fn preparation(&self) -> &DataPreparationSuccess {
        &self.preparation
    }
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
    audit: Arc<crate::teller::native_data_audit::NativeAuditState>,
}
impl NativeDataAllocation {
    pub fn register(physical: AuthorizedPhysicalData) -> Result<Self, DataRefused> {
        let (authorization, physical) = physical.into_parts();
        // One reading for both deadlines: the binding's own and the authorization's.
        let live_at = authorization
            .binding
            .check_live_now()
            .map_err(|_| DataRefused::Cancelled)?;
        if live_at >= authorization.deadline {
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
        .map_err(|_| DataRefused::Unit)?
        .with_selection(Arc::clone(&authorization.selected));
        let audit = crate::teller::native_data_audit::NativeAuditState::new(
            registration.context.clone(),
            authorization.key.clone(),
            authorization.binding.clone(),
        )
        .map_err(|_| DataRefused::Capacity)?;
        Ok(Self {
            audit,
            authorization,
            physical,
            registration,
            gate,
            allocation,
        })
    }

    pub fn request(&self) -> &crate::limits::process_admission::RequestLease {
        self.authorization.binding.request()
    }

    /// Transfer the original allocation's one-shot audit registration to Node custody.
    pub fn take_audit_registration(
        &mut self,
    ) -> Result<crate::teller::native_data_audit::NativeAuditRegistration, DataRefused> {
        self.audit
            .take_registration()
            .map_err(|_| DataRefused::Unit)
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
            |pending| pending,
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
        self.into_pending_using(
            commit,
            |allocation, routes, commit| Pending::new_selected(allocation, routes, None, commit),
            |pending| pending,
        )
    }

    /// Wire the original candidate's route and budgets before exposing the preparatory Task.
    pub fn into_pending_runtime(
        self,
        seat: &PortSeat,
        journal: Option<Arc<dyn crate::plane_driver::HookJournal>>,
        commit: impl FnOnce(RequestPoolReceipt) -> Result<AdmittedUnit, ClientRefusal> + Send + 'static,
    ) -> Result<NativeDataPending, DataRefused> {
        if !seat
            .driver
            .caller()
            .same_incarnation(&self.authorization.route.caller)
            || !Arc::ptr_eq(
                &seat.request_routes,
                &self.authorization.route.owners.routes,
            )
        {
            return Err(DataRefused::Binding);
        }
        let route = seat
            .retain_route(
                self.context(),
                self.authorization.route.binding.line().route.rung,
            )
            .ok_or(DataRefused::Binding)?;
        let budget = seat.channel_budget.unit();
        let rates = self
            .authorization
            .binding
            .handle()
            .selected_rate_admission();
        Ok(self.into_pending_using(
            move |receipt, ()| commit(receipt),
            move |allocation, routes, commit| {
                Pending::new(allocation, routes, journal, move |receipt| {
                    commit(receipt, ())
                })
            },
            move |pending| {
                pending
                    .with_route(route)
                    .with_channel_budget(budget)
                    .with_current_rates(rates)
            },
        ))
    }

    /// Selected Tasks additionally retain their own declaration through the monetary callback.
    pub fn into_pending_selected_runtime(
        self,
        seat: &PortSeat,
        journal: Option<Arc<dyn crate::plane_driver::HookJournal>>,
        commit: impl FnOnce(RequestPoolReceipt, RequestDeclaration) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
    ) -> Result<NativeDataPending, DataRefused> {
        if !seat
            .driver
            .caller()
            .same_incarnation(&self.authorization.route.caller)
            || !Arc::ptr_eq(
                &seat.request_routes,
                &self.authorization.route.owners.routes,
            )
        {
            return Err(DataRefused::Binding);
        }
        let route = seat
            .retain_route(
                self.context(),
                self.authorization.route.binding.line().route.rung,
            )
            .ok_or(DataRefused::Binding)?;
        let budget = seat.channel_budget.unit();
        let rates = self
            .authorization
            .binding
            .handle()
            .selected_rate_admission();
        Ok(self.into_pending_using(
            commit,
            move |allocation, routes, commit| {
                Pending::new_selected(allocation, routes, journal, commit)
            },
            move |pending| {
                pending
                    .with_route(route)
                    .with_channel_budget(budget)
                    .with_current_rates(rates)
            },
        ))
    }

    fn into_pending_using<D: Send + 'static>(
        self,
        commit: impl FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal>
            + Send
            + 'static,
        build: impl FnOnce(RequestAllocation, Arc<RequestRoutes>, DataCommit<D>) -> Pending,
        configure: impl FnOnce(Pending) -> Pending,
    ) -> NativeDataPending {
        let Self {
            authorization,
            physical,
            registration,
            gate,
            allocation,
            audit,
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
        let custody = Arc::new(Mutex::new(DataCommitCustody {
            phase: DataCommitPhase::Awaiting,
            bundle: Some(DataCommitBundle {
                authorization,
                physical,
                registration,
            }),
            refusal: None,
        }));
        let commit_custody = custody.clone();
        let commit_audit = audit.clone();
        let pending = build(
            allocation,
            routes,
            Box::new(move |receipt, declaration| {
                let refuse = || ClientRefusal {
                    status: 503,
                    code: busbar_plugin_abi::fail::refused::R_POLICY,
                    text: "native data admission refused".into(),
                };
                {
                    let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                    let bundle = custody.bundle.as_ref().ok_or_else(refuse)?;
                    // The binding's liveness is asked last and answers the reading it judged at;
                    // the authorization's deadline is judged at that same reading. It is taken
                    // after every lock these checks take: no deadline is judged before a lock.
                    if custody.phase != DataCommitPhase::Awaiting
                        || !commit_audit.node_ready()
                        || !bundle.registration.context.is_live()
                        || !bundle
                            .authorization
                            .binding
                            .check_live_now()
                            .is_ok_and(|live_at| live_at < bundle.authorization.deadline)
                    {
                        return Err(refuse());
                    }
                    custody.phase = DataCommitPhase::Committing;
                }
                // The original physical owner remains installed while the callback runs.
                // No custody lock crosses monetary work or a plugin/Store call.
                let admitted = match commit(receipt, declaration) {
                    Ok(admitted) => admitted,
                    Err(decision) => {
                        let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                        custody.phase = DataCommitPhase::ExpectedPreMoneyRefusal;
                        custody.refusal = Some(decision.clone());
                        return Err(decision);
                    }
                };
                let bundle = {
                    let mut custody = commit_custody.lock().map_err(|_| refuse())?;
                    custody.phase = DataCommitPhase::MoneyAccepted;
                    let bundle = custody.bundle.as_ref().ok_or_else(refuse)?;
                    if !admitted
                        .request
                        .context()
                        .same_unit(&bundle.registration.context)
                        || !bundle.registration.context.is_live()
                        || Instant::now() >= bundle.authorization.deadline
                        || admitted.unit.ctx.key != admitted.request.unit()
                        || !Arc::ptr_eq(admitted.request.key(), &bundle.authorization.key)
                    {
                        return Err(refuse());
                    }
                    commit_audit.bind_money(&admitted).map_err(|_| refuse())?;
                    let bundle = custody.bundle.take().ok_or_else(refuse)?;
                    custody.phase = DataCommitPhase::ExecutingTransferred;
                    bundle
                };
                let proof = DataExecutionAdmission {
                    authorization: bundle.authorization,
                    physical: bundle.physical,
                    registration: bundle.registration,
                    money: admitted.request.clone(),
                };
                if proof.physical.start_execution(&proof).is_err() {
                    return Err(refuse());
                }
                commit_audit.executing().map_err(|_| refuse())?;
                retained.set(proof).map_err(|_| refuse())?;
                gate.ready.store(true, Ordering::Release);
                Ok(admitted)
            }),
        );
        NativeDataPending {
            audit,
            custody,
            pending: Arc::new(configure(pending)),
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

struct DataCommitBundle {
    authorization: DataAuthorization,
    physical: PhysicalExecutionOwner,
    registration: Arc<Registration>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataCommitPhase {
    Awaiting,
    Committing,
    MoneyAccepted,
    ExecutingTransferred,
    ExpectedPreMoneyRefusal,
    RefusalTransferred,
}

struct DataCommitCustody {
    phase: DataCommitPhase,
    bundle: Option<DataCommitBundle>,
    refusal: Option<ClientRefusal>,
}

pub(crate) struct DataRefusalCustody {
    authorization: DataAuthorization,
    _registration: Arc<Registration>,
}
impl DataRefusalCustody {
    pub(crate) fn matches(&self, binding: &Arc<RequestBinding>) -> bool {
        Arc::ptr_eq(&self.authorization.binding, binding)
    }
}

type DataCommit<D> =
    Box<dyn FnOnce(RequestPoolReceipt, D) -> Result<AdmittedUnit, ClientRefusal> + Send>;

pub struct NativeDataPending {
    audit: Arc<crate::teller::native_data_audit::NativeAuditState>,
    binding: Arc<RequestBinding>,
    deadline: Instant,
    route: Arc<NativeDataRoute>,
    selected: Arc<SelectedResources>,
    prepared: Arc<PreparedNativeIdentity>,
    pending: Arc<Pending>,
    execution: Arc<OnceLock<DataExecutionAdmission>>,
    context: InvocationContext,
    custody: Arc<Mutex<DataCommitCustody>>,
}
impl NativeDataPending {
    pub(crate) fn take_refusal(
        &self,
        decision: &ClientRefusal,
    ) -> Result<(PhysicalExecutionOwner, DataRefusalCustody), DataRefused> {
        let mut custody = self.custody.lock().map_err(|_| DataRefused::Unit)?;
        if custody.phase != DataCommitPhase::ExpectedPreMoneyRefusal
            || custody.refusal.as_ref() != Some(decision)
            || self.execution.get().is_some()
            || self.pending.admitted().is_some()
        {
            return Err(DataRefused::Unit);
        }
        let bundle = custody.bundle.take().ok_or(DataRefused::Unit)?;
        custody.phase = DataCommitPhase::RefusalTransferred;
        Ok((
            bundle.physical,
            DataRefusalCustody {
                authorization: bundle.authorization,
                _registration: bundle.registration,
            },
        ))
    }

    pub fn is_live(&self) -> bool {
        // The binding's liveness answers the reading it judged at (after its lock); the pending
        // deadline is judged at that same reading.
        self.context.is_live()
            && self
                .binding
                .check_live_now()
                .is_ok_and(|live_at| live_at < self.deadline)
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
        self.audit.node_ready()
            && self.is_live()
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
    /// Whether this runtime belongs to the exact original invocation of `owner`.
    pub fn owned_by(&self, owner: &crate::teller::native_data_audit::NativeAuditOwner) -> bool {
        self.context.same_unit(owner.invocation())
    }
    pub fn execution(&self) -> Option<&DataExecutionAdmission> {
        self.execution.get()
    }

    /// Lend the same accepted monetary owner for the registered response's terminal join.
    pub fn admitted(&self) -> Option<&AdmittedUnit> {
        self.execution.get()?;
        self.pending.admitted()
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
