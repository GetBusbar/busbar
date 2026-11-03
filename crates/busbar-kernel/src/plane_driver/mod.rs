// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod answer;
mod cancel;
mod close;
pub mod dispatch;
pub mod door;
mod far_end;
mod govern;
pub(crate) mod hooks;
pub mod host;
mod money;
mod needs;
mod probe;
pub mod registry;
mod route;
pub mod route_input;
pub mod route_tables;
pub mod serve;
pub mod slots;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, Outcome as AbiOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    class_of, reason_code, ArriveIn, ArriveOut, OutField, RefusalClass, RefusalIn, RefusalOut,
    RefusalStatus, UnitCount, REFUSAL_ANY_DIALECT, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL,
    ROUTE_LOCAL, ROUTE_SCOPE_LOCAL, ROUTE_SESSION,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{
    Admission, Admittance, Audit, Authenticated, Consumption, Dial, Encode, Grant, HoldAccrual,
    Meter, OpClassId, Outcome, Pass, PrincipalId, ReasonCode, Refusal, Route, RoutePlan,
    SeatVerdict as StepAnswer, Usage, VerifiedDestination,
};
use busbar_contract::plane_calls::{InstanceDecl, PlaneCalls};
use busbar_contract::services::Caller;
use tokio::sync::{watch, Notify};

pub use answer::PlaneAnswer;
pub use cancel::{CancelBill, Checkpoint, MoneySeam};
pub use far_end::{
    fixed_breaker, AuthBinding, BreakerSource, Egress, EgressFarEnd, MemberFacts, MemberRoute,
    MemberSignals, MemberStanding, ResponseKeep, Ride, UnitRoute, DEFAULT_ERROR_BODY_MAX,
};
pub use hooks::{
    Bind, BoundHooks, CallerFacts, CallerKey, CandidateFacts, Candidates, Constraint, GroupScope,
    HookBinder, HookJournal, HookRead, HooksRan, HostHooks, Projection, Restrict, RewriteChain,
    SessionStage, StageTaps, UnitHooks, CONTENT_ROLE, STAGE_GONE,
};
pub use hooks::{GatedHooks, GatedScan, GenerationHost, HookOrder, HostGatedHooks, PrincipalKeys};
pub use host::{
    engine_host, engine_host_from_handle, engine_host_value, live_host_factory, live_standing,
    standing_over, CostHandle, EngineHost, EngineHostImpl, GovHandle, LiveHostFactory, MeterPin,
};
pub use money::{
    EndPost, FeeRefund, ParentMoney, PlaneMoney, ReservedRequestLineage, ReturnedTicketReservation,
    SpentTicketReservation, TicketReservation, UnitEnd, UnitMoney,
};
pub use needs::{resolve_member_needs, MemberAuth, NeedRefusal};
pub use probe::PlaneProbes;
pub use route::{configure_route_policy_headers, HDR_ROUTE_POLICY, HDR_ROUTE_TARGET};
pub use route::{
    CallerEnd, FarEnd, FarPiece, OutboundRequest, Pick, RoutedScope, SessionCaller, SessionInput,
};

use crate::auth::CallerRefKey;
use crate::host_services::{InstanceFacts, KernelServices, Signing};
use crate::slice::GroupLeaseSlip;
use crate::teller::{Ended, Evidence, RouteAwait, RouteLeg, Screen, UnitCtx, UnitEnds};
use crate::trust::book::{Distrust, TrustFacts};
use crate::trust::section::parse_section;
use busbar_contract::ids::RecordSchemaId;

/// The capacities of the host buffers the driver hands a plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferCaps {
    /// Reply bytes per `on_piece` (the backpressure window); a caller's piece's window adds its
    /// arrival's body length.
    pub reply: usize,
    /// Unit counts.
    pub units: usize,
    /// Record writes.
    pub records: usize,
    /// Head fields.
    pub fields: usize,
    /// Arena bytes.
    pub arena: usize,
}

impl BufferCaps {
    pub const DEFAULT: BufferCaps = BufferCaps {
        reply: 16 * 1024,
        units: 8,
        records: 16,
        fields: 32,
        arena: 4096,
    };

    pub const EMPTY: BufferCaps = BufferCaps {
        reply: 0,
        units: 0,
        records: 0,
        fields: 0,
        arena: 0,
    };
}

impl Default for BufferCaps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A plane instance's driver settings.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The host buffers' capacities.
    pub caps: BufferCaps,
    /// The plane's operation classes, in its tail's order: `arrive`'s `op_class` indexes them.
    pub op_classes: Vec<OpClassId>,
    /// The status number the kernel chooses for a refusal the plane renders, where the plane
    /// states none of its own.
    pub status_of: fn(ReasonCode) -> u32,
    /// The statuses the plane's tail states per dialect and reason (validated at load).
    pub refusal_statuses: Vec<RefusalStatus>,
    /// The key the caller's opaque reference is derived under, LIVE ([`CallerRefs`]: the book's
    /// slot, which always holds a key: the node's signing material, else its deployment keyset,
    /// else its per-boot key); `None` = no book, and only then is no reference lent.
    pub caller_refs: Option<CallerRefs>,
}

pub type CallerRefs = Arc<std::sync::RwLock<Option<Arc<CallerRefKey>>>>;

impl DriverConfig {
    pub fn status(&self, dialect: u32, reason: ReasonCode) -> u32 {
        let code = reason_code(reason);
        let row = |d: u32| {
            self.refusal_statuses
                .iter()
                .find(|r| r.dialect == d && r.reason == code)
                .map(|r| r.status)
        };
        row(dialect)
            .or_else(|| row(REFUSAL_ANY_DIALECT))
            .unwrap_or_else(|| (self.status_of)(reason))
    }
}

fn is_authentication(reason: ReasonCode) -> bool {
    class_of(reason) == RefusalClass::Unauthenticated
}

pub fn refusal_status(reason: ReasonCode) -> u32 {
    class_status(class_of(reason))
}

pub const fn class_status(class: RefusalClass) -> u32 {
    match class {
        RefusalClass::Unreadable | RefusalClass::Rejected => 400,
        RefusalClass::Unauthenticated => 401,
        RefusalClass::Forbidden => 403,
        RefusalClass::NotFound => 404,
        RefusalClass::TooLarge => 413,
        RefusalClass::Throttled | RefusalClass::Busy | RefusalClass::QuotaExhausted => 429,
        RefusalClass::PlaneFault => 502,
        RefusalClass::Timeout => 504,
        RefusalClass::Unreachable | RefusalClass::Unavailable | RefusalClass::NodeFault => 503,
    }
}

pub struct PlaneDriver {
    calls: Arc<dyn PlaneCalls>,
    config: DriverConfig,
    money: Arc<dyn MoneySeam>,
    buried: Mutex<Vec<cancel::Buried>>,
    cleanup_sweep: Mutex<()>,

    owed: Mutex<Vec<close::Owed>>,
    reload: watch::Sender<bool>,

    records: Option<(Arc<KernelServices>, Caller)>,
    driver: Option<Ticket>,
    services: Arc<KernelServices>,

    sessions: Mutex<HashMap<u64, Arc<Notify>>>,

    hooks: Option<Arc<dyn HookBinder>>,

    hook_journal: Option<Arc<dyn HookJournal>>,

    label: Arc<str>,

    audit: Arc<dyn AuditSink>,

    refused_piece: bool,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);
}

/// THE KERNEL'S OWN AUDIT CHAIN (`audit::journal`, read by `GET /audit`): the sink every driver
/// writes a unit's audit row to unless built with another ([`PlaneDriver::with_audit`]). The same
/// chokepoint a plane's admin-audit emit reached before it was served through its door.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreAudit;

pub(crate) fn audit_row_to(
    sink: &dyn AuditSink,
    outcome: u32,
    key: &[u8],
    value: &[u8],
    principal: Option<&PrincipalId>,
) -> Result<(), ()> {
    use busbar_contract::abi::plane::{AUDIT_APPLIED, AUDIT_DEGRADED, AUDIT_REJECTED};
    let outcome = match outcome {
        AUDIT_APPLIED => busbar_contract::vocab::OUTCOME_APPLIED,
        AUDIT_REJECTED => busbar_contract::vocab::OUTCOME_REJECTED,
        AUDIT_DEGRADED => busbar_contract::vocab::OUTCOME_DEGRADED,
        _ => return Err(()),
    };
    let action = std::str::from_utf8(key).map_err(|_| ())?;
    let resource = std::str::from_utf8(value).map_err(|_| ())?;
    if action.is_empty() {
        return Err(());
    }
    let anonymous = PrincipalId::anonymous();
    let principal = principal.unwrap_or(&anonymous);
    sink.record(action, resource, outcome, principal.as_str());
    Ok(())
}

impl AuditSink for CoreAudit {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }
}

impl Drop for PlaneDriver {
    fn drop(&mut self) {
        if let Some(t) = self.driver.take() {
            self.calls.recycle(t);
        }
    }
}

impl std::fmt::Debug for PlaneDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneDriver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

enum Cause {
    Timer,

    Woke,
}

const fn earlier(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => {
            if a < b {
                a
            } else {
                b
            }
        }
    }
}

/// A section's complete host admission, prepared without changing the live instance.
#[must_use = "prepared host facts take effect only when committed"]
pub struct PreparedSection<'a> {
    services: &'a KernelServices,
    label: Arc<str>,
    facts: InstanceFacts,
    work: crate::host_work::WorkBounds,
}

impl PreparedSection<'_> {
    /// Commit after every other fallible step of a generation refresh has succeeded.
    pub fn commit(self) -> Result<(), String> {
        self.services
            .admit(&self.label, self.facts)
            .map_err(|e| e.to_string())?;
        self.services.bound_work(&self.label, self.work);
        Ok(())
    }
}

fn prepare_admission<'a>(
    d: &InstanceDecl,
    services: &'a KernelServices,
    section: (&str, &serde_yaml::Value),
) -> Result<PreparedSection<'a>, String> {
    if d.conditional_records && !services.supports_record_transactions() {
        return Err("the configured store does not support conditional record transactions".into());
    }
    let trust = parse_section(section.0, section.1, &d.trust_keys)?;
    let facts = InstanceFacts {
        conditional_record_kinds: d.conditional_record_kinds.clone(),
        record_kinds: d
            .record_kinds
            .iter()
            .copied()
            .map(RecordSchemaId::new)
            .collect(),
        signing: d.signing.map(|(domain, kid_prefix)| Signing {
            domain: domain.into(),
            kid_prefix: kid_prefix.into(),
        }),
        trust: trust.into_iter().collect(),
        scope_kinds: d.scope_kinds.iter().map(|k| (*k).to_string()).collect(),
        record_chains: d.record_chains.clone(),
        record_retentions: d.record_retentions.clone(),
        ticket_prefix: d.ticket_prefix.map(str::to_string),
    };

    let work = crate::host_work::WorkBounds::of_section(
        section.0,
        section.1,
        services.default_work_bounds(),
    )?;
    Ok(PreparedSection {
        services,
        label: Arc::clone(&d.label),
        facts,
        work,
    })
}

impl PlaneDriver {
    pub fn new(
        calls: Arc<dyn PlaneCalls>,
        config: DriverConfig,
        money: Arc<dyn MoneySeam>,
        services: Arc<KernelServices>,
        section: (&str, &serde_yaml::Value),
    ) -> Result<Self, String> {
        let d = calls.declared();
        prepare_admission(&d, &services, section)?.commit()?;
        let driver = calls.driver();
        Ok(PlaneDriver {
            calls,
            config,
            money,
            buried: Mutex::new(Vec::new()),
            cleanup_sweep: Mutex::new(()),
            owed: Mutex::new(Vec::new()),
            reload: watch::channel(false).0,
            records: None,
            driver,
            services,
            sessions: Mutex::default(),
            hooks: None,
            hook_journal: None,
            label: Arc::from(&*d.label),
            audit: Arc::new(CoreAudit),
            refused_piece: false,
        })
    }

    /// Prepare the same host facts and work bounds as initial admission for a new section.
    pub fn prepare_section(
        &self,
        section: (&str, &serde_yaml::Value),
    ) -> Result<PreparedSection<'_>, String> {
        prepare_admission(&self.calls.declared(), &self.services, section)
    }

    pub async fn ticks(&self) {
        let Some(driver) = self.driver else {
            return;
        };
        let mut at = 0;
        let mut cause = Cause::Timer;
        loop {
            let Some(next) = self.calls.tick(driver, self.calls.now_ns()).await else {
                return;
            };
            at = match cause {
                Cause::Timer => next,
                Cause::Woke => earlier(at, next),
            };
            let Some(woken) = self.await_tick(at).await else {
                return;
            };
            cause = woken;
        }
    }

    async fn await_tick(&self, at: u64) -> Option<Cause> {
        let timer = async {
            if at == 0 {
                std::future::pending::<()>().await;
            }
            let now = self.calls.now_ns();
            if at > now {
                tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
            }
        };
        let woke = self.calls.woke();
        tokio::pin!(timer, woke);
        let mut channel = true;
        loop {
            tokio::select! {
                () = &mut timer => return Some(Cause::Timer),
                alive = &mut woke, if channel => {
                    if alive {
                        return Some(Cause::Woke);
                    }
                    channel = false;
                    if at == 0 {
                        return None;
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, binder: Arc<dyn HookBinder>) -> Self {
        self.hooks = Some(binder);
        self
    }

    #[must_use]
    pub fn with_refused_piece(mut self) -> Self {
        self.refused_piece = true;
        self
    }

    #[must_use]
    pub fn with_hook_journal(mut self, journal: Arc<dyn HookJournal>) -> Self {
        self.hook_journal = Some(journal);
        self
    }

    pub(crate) fn audit_row(
        &self,
        outcome: u32,
        key: &[u8],
        value: &[u8],
        principal: Option<&PrincipalId>,
    ) -> Result<(), ()> {
        audit_row_to(&*self.audit, outcome, key, value, principal)
    }

    pub(crate) fn fold_writes(
        &self,
        writes: &[busbar_contract::plane_calls::CancelWrite],
        principal: Option<&PrincipalId>,
    ) {
        use busbar_contract::abi::plane::{RECORD_AUDIT, RECORD_PUT};
        for w in writes {
            let written = match w.op {
                RECORD_AUDIT => self.audit_row(w.kind, &w.key, &w.value, principal),
                RECORD_PUT => self.records.as_ref().map_or(Err(()), |(services, caller)| {
                    let kind = services.record_kind(caller, w.kind).ok_or(())?;
                    let value = busbar_contract::kinds::RecordBytes::new(w.value.clone())
                        .map_err(|_| ())?;
                    services
                        .record_write(caller, kind.as_str(), &w.key, value, Box::new(|_| {}))
                        .map_err(|_| ())
                }),
                _ => Err(()),
            };
            if written.is_err() {
                tracing::warn!(
                    op = w.op,
                    "a plane's record write at a unit's end could not be applied; the end stands"
                );
            }
        }
    }

    #[must_use]
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    #[must_use]
    pub fn with_records(mut self, services: Arc<KernelServices>, caller: Caller) -> Self {
        self.records = Some((services, caller));
        self
    }

    pub fn reload(&self) {
        self.reload.send_replace(true);
    }

    pub fn unit<'d, S, F, C>(
        &'d self,
        steps: &'d S,
        far: &'d F,
        caller: &'d C,
        arrival: Arrival,
        deadline_ns: u64,
    ) -> PlaneUnits<'d, S, F, C> {
        PlaneUnits {
            driver: self,
            steps,
            far,
            caller,
            arrival,
            deadline_ns,
            state: Mutex::new(UnitState::default()),
        }
    }

    fn cancel_unit(&self, ticket: Ticket, unit: u64) -> cancel::CancelFuture {
        self.calls.cancel_unit(ticket, unit)
    }
}

pub type HeadFields = Vec<(Vec<u8>, Vec<u8>)>;

/// What arrived: the claim it matched and the caller's request, as the kernel keeps it.
#[derive(Debug, Clone)]
pub struct Arrival {
    /// Index into the plane's snapshot claims.
    pub claim: u32,
    /// The request method.
    pub method: Vec<u8>,
    /// The request target.
    pub target: Vec<u8>,
    /// The head fields.
    pub fields: HeadFields,
    /// The caller's body, kept for every attempt.
    pub body: bytes::Bytes,
}

/// What `arrive` said.
#[derive(Debug, Clone)]
pub struct Decoded {
    /// Index into the plane's operation classes.
    pub op_class: u32,
    /// `PRINCIPAL_*`.
    pub principal_need: u32,
    /// Index into the plane's dialects.
    pub dialect: u32,
    /// The expected units (the admission estimate).
    pub expected: Vec<UnitCount>,
    /// The entry it routes over: the name inside the plane's own section, opaque
    /// bytes the kernel never parses; `None` = it named none.
    pub pool: Option<Vec<u8>>,
    /// What [`Decoded::pool`] names: `ROUTE_POOL` or `ROUTE_DIRECT`, or how the
    /// unit routes with no entry named (`ROUTE_LOCAL`, `ROUTE_SCOPE`, `ROUTE_SCOPE_LOCAL`).
    pub route: u8,
    /// The `ROUTE_*` flag bits its `arrive` stated (`ROUTE_ONCE`, `ROUTE_SESSION`,
    /// `ROUTE_STREAM`).
    pub route_flags: u8,
    /// The trust facts its `arrive` stated (a counterparty, and an item at a digest), which
    /// the kernel's Approve judges; `None` = the unit rests on no counterparty.
    pub trust: Option<busbar_contract::plane_calls::ArrivedTrust>,
    /// The sticky-routing key its `arrive` stated, opaque; `None` = none.
    pub affinity: Option<Vec<u8>>,
}

#[must_use]
pub fn sticky_hash(key: &[u8]) -> u64 {
    key.iter().fold(crate::store::FNV1A_OFFSET_BASIS, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(crate::store::FNV1A_PRIME)
    })
}

pub trait DriverSteps {
    /// Remove the sole receipt for an already adopted ticket reservation.
    fn take_reserved_request_lineage(&self, _ctx: &UnitCtx) -> Option<ReservedRequestLineage> {
        None
    }

    fn arrival(&self, ctx: &UnitCtx) -> Result<busbar_contract::ArrivalRecord, Refusal>;

    fn authenticate(&self, ctx: &UnitCtx) -> Result<Authenticated, Refusal>;

    fn verify(
        &self,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Result<Vec<VerifiedDestination>, Refusal>;

    fn approve(
        &self,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::ScopeFacts, Refusal>;

    fn admit(
        &self,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Result<Admission, Refusal>;

    fn meter(
        &self,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> Result<Usage, Refusal>;

    fn audit(&self, ctx: &UnitCtx, outcome: &Outcome) -> busbar_contract::AuditFacts;

    fn audit_refused(&self, ctx: &UnitCtx, refusal: &Refusal) -> busbar_contract::AuditFacts;

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }

    fn at_parent_exit(&self, _ctx: &UnitCtx, _accrual: &HoldAccrual) -> Result<(), Refusal> {
        Ok(())
    }

    fn decoded(&self, _ctx: &UnitCtx, _op: OpClassId, _route: u8, _pool: Option<&[u8]>) {}

    fn route_flags(&self, _ctx: &UnitCtx, _flags: u8) {}

    fn counterparty(&self, _ctx: &UnitCtx, _counterparty: &[u8]) {}

    fn affinity(&self, _ctx: &UnitCtx, _hash: u64) {}

    fn expected(&self, _ctx: &UnitCtx, _units: &[UnitCount]) {}

    fn resolved(&self, _ctx: &UnitCtx) -> Option<Vec<u8>> {
        None
    }

    fn pool_holds(&self, _pool: &[u8], _member: &str) -> bool {
        false
    }

    fn scope_entry(&self) -> Option<Vec<u8>> {
        None
    }

    fn request_span(
        &self,
        _ctx: &UnitCtx,
        _decoded: &Decoded,
        _op: OpClassId,
    ) -> Option<(tracing::Span, u64)> {
        None
    }

    fn refused_words(&self) -> (Option<u32>, Option<String>) {
        (None, None)
    }

    fn attempting(&self, _ctx: &UnitCtx, _dialect: u32, _provider: &str) {}

    fn usage_tap_fault(&self, _ctx: &UnitCtx, _dialect: u32, _reason: &'static str) {}

    fn answered(&self, _ctx: &UnitCtx, _streamed: bool, _cut: bool) {}

    fn refusal_words(&self, _reason: ReasonCode) -> Option<Vec<u8>> {
        None
    }
}

/// A refusal or failure the plane rendered, for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The status number.
    pub status: u32,
    /// The head fields.
    pub fields: HeadFields,
    /// The body.
    pub body: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct UnitState {
    /// The unit's kernel-minted key, once decode has run.
    unit: u64,
    /// Where the unit stands with its plane's closing call, from `arrive` on ([`close`]).
    close: close::Close,
    /// The logical unit posts one cancellation bill across both session tickets and sweeps.
    cancel_billed: Arc<std::sync::atomic::AtomicBool>,
    /// A worker cancellation has a result owner; idle siblings must wait for that owner to bill.
    cancel_started: Arc<std::sync::atomic::AtomicBool>,
    /// The unit's correlation id, where its host minted one with its request span
    /// ([`DriverSteps::request_span`]): the id its hooks carry. `None`: the hooks' binder mints.
    request_id: Option<u64>,
    decoded: Option<Decoded>,
    /// A REFUSED `arrive`'s own code and 4xx status.
    declined: Option<(u32, u32)>,
    /// A REFUSED `arrive`'s own words (its `head.error`), for the plane's `refusal`.
    declined_words: Option<Vec<u8>>,
    /// A REFUSED `arrive`'s stated outcome (`ArriveOut::refusal_flags`, `REFUSED_*`).
    declined_flags: u32,
    /// THE WAIT THE KERNEL'S REFUSAL CARRIES: the reason the loop refused the unit
    /// under, and the Retry-After its `Refusal` names in whole seconds: an admission's window
    /// reset, as 1.5.5 rendered it. Handed to the plane's `refusal` beside that reason alone.
    refused_wait: Option<(ReasonCode, u32)>,
    rendered: Option<Rendered>,
    facts: cancel::Facts,
    bill: Option<CancelBill>,
    /// The caller's opaque reference, derived at verify (never the principal itself).
    caller_ref: Vec<u8>,
    /// The principal the kernel verified, for the hooks the unit binds and its audit row (never a
    /// plane input).
    principal: Option<PrincipalId>,
    /// A gate-first plane's hooks screened the unit before the door ([`RouteAwait::screen`]).
    screened: bool,
    /// The session open's request hooks passed, either at its opener or its route leg.
    open_hooks_ran: bool,
    /// The body a request-stage rewrite left, kept for every attempt; `None` = the caller's own.
    body: Option<bytes::Bytes>,
    /// The unit's hooks and the plane's view of its effective request, once the request stage ran.
    hooked: Option<(UnitHooks, hooks::Projection)>,
    /// The `response` stage tap has fired.
    responded: bool,
    /// The pool the unit's hooks were bound over (the walk's, else the plane's).
    hooked_pool: String,
    /// The hook that ordered or restricted the walk, for the opt-in transparency fields.
    route_policy: Option<std::sync::Arc<str>>,
    /// Why the kernel's Approve did not trust the unit's stated facts, for the plane's rendering.
    distrust: Option<Distrust>,
}

pub struct PlaneUnits<'d, S, F, C> {
    driver: &'d PlaneDriver,
    steps: &'d S,
    far: &'d F,
    caller: &'d C,
    arrival: Arrival,
    deadline_ns: u64,
    state: Mutex<UnitState>,
}

impl<S, F, C> std::fmt::Debug for PlaneUnits<'_, S, F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneUnits").finish_non_exhaustive()
    }
}

fn blob(b: &[u8]) -> Blob {
    if b.is_empty() {
        return Blob::ABSENT;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

const ZERO_UNIT: UnitCount = UnitCount {
    class: 0,
    source: 0,
    amount: 0,
};
const NO_SPAN: Span = Span { offset: 0, len: 0 };
pub(crate) const NO_RECORD: busbar_contract::abi::plane::RecordWrite =
    busbar_contract::abi::plane::RecordWrite {
        kind: 0,
        op: 0,
        key: NO_SPAN,
        value: NO_SPAN,
    };
const NO_FIELD: OutField = OutField {
    name: NO_SPAN,
    value: NO_SPAN,
};

impl<S, F, C> PlaneUnits<'_, S, F, C> {
    fn lock(&self) -> std::sync::MutexGuard<'_, UnitState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn decoded(&self) -> Option<Decoded> {
        self.lock().decoded.clone()
    }

    pub fn declined_status(&self) -> Option<u32> {
        self.lock().declined.map(|(_, status)| status)
    }

    pub fn declined_unsupported_action(&self) -> bool {
        let st = self.lock();
        st.declined.is_some()
            && st.declined_flags & busbar_contract::abi::plane::REFUSED_UNSUPPORTED_ACTION != 0
    }

    fn declined_after_admission(&self) -> bool {
        let st = self.lock();
        st.declined.is_some()
            && st.decoded.is_some()
            && st.declined_flags & busbar_contract::abi::plane::REFUSED_AFTER_ADMISSION != 0
    }

    fn status_for(&self, reason: ReasonCode) -> u32 {
        let st = self.lock();
        let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
        match st.declined {
            Some((_, status)) if reason == ReasonCode::DecodeFailed => status,
            _ => self.driver.config.status(dialect, reason),
        }
    }

    pub fn take_rendered(&self) -> Option<Rendered> {
        self.lock().rendered.take()
    }

    pub fn cancel_bill(&self) -> Option<CancelBill> {
        self.lock().bill.clone()
    }

    fn arrive(&self, unit: u64) -> Option<Decoded> {
        let a = &self.arrival;
        let fields: Vec<Field> = a
            .fields
            .iter()
            .map(|(n, v)| Field {
                name: AbiStr::over(n),
                value: AbiStr::over(v),
            })
            .collect();
        let mut units = vec![ZERO_UNIT; self.driver.config.caps.units];
        let mut input = ArriveIn {
            unit,
            claim: a.claim,
            target: AbiStr::over(&a.target),
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            body: blob(&a.body),
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            method: AbiStr::over(&a.method),
            ..blank_in()
        };
        let mut o: ArriveOut = blank_out();

        {
            let mut st = self.lock();
            st.unit = unit;
            st.close = close::Close::Open;
        }
        let outcome = self
            .driver
            .calls
            .arrive(&mut input, &mut o, &mut |short, i| {
                units = vec![ZERO_UNIT; short.units_needed as usize];
                i.units_buf = units.as_mut_ptr();
                i.units_cap = units.len();
            });
        let pool = self.driver.calls.arrived_pool(&o);
        if outcome == AbiOutcome::Refused {
            let words = self
                .driver
                .calls
                .arrived_refusal(&o)
                .filter(|w| !w.is_empty());
            let mut st = self.lock();
            st.declined = Some((o.refusal, o.refusal_status));
            st.declined_words = words;
            st.declined_flags = o.refusal_flags;
        }

        let held = outcome == AbiOutcome::Refused && pool.is_some();
        (outcome == AbiOutcome::Ready || held).then(|| Decoded {
            op_class: o.op_class,
            principal_need: o.principal_need,
            dialect: o.dialect,
            expected: units
                .iter()
                .take(o.units_written as usize)
                .copied()
                .collect(),
            pool,
            route: o.route,
            route_flags: o.route_flags,
            trust: (outcome == AbiOutcome::Ready)
                .then(|| self.driver.calls.arrived_trust(&o))
                .flatten(),
            affinity: (outcome == AbiOutcome::Ready)
                .then(|| self.driver.calls.arrived_affinity(&o))
                .flatten()
                .filter(|k| !k.is_empty()),
        })
    }
}

impl<S: DriverSteps, F, C> PlaneUnits<'_, S, F, C> {
    fn render(&self, reason: ReasonCode) -> Rendered {
        self.render_as(reason, None, None, None, None)
    }

    fn render_as(
        &self,
        reason: ReasonCode,
        walk: Option<(u32, Option<u32>)>,
        said: Option<&str>,
        retry_after: Option<u32>,
        hook: Option<&str>,
    ) -> Rendered {
        let (unit, dialect, declined, words, refused_wait) = {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
            let declined = st.declined.filter(|_| reason == ReasonCode::DecodeFailed);

            let words = declined.and(st.declined_words.clone());
            let refused_wait = st
                .refused_wait
                .filter(|(refused, _)| *refused == reason)
                .map(|(_, secs)| secs);

            let unit = if st.close == close::Close::Closed {
                0
            } else {
                st.unit
            };
            (unit, dialect, declined, words, refused_wait)
        };

        let status = match (walk, declined) {
            (Some((status, _)), _) => status,
            (None, Some((_, status))) => status,
            (None, None) => self.driver.config.status(dialect, reason),
        };

        let retry_after_s = walk
            .and_then(|(_, r)| r)
            .or(retry_after)
            .or(refused_wait)
            .unwrap_or(0);
        let steps_words = if words.is_none() {
            self.steps.refusal_words(reason)
        } else {
            None
        };
        let text: &[u8] = words
            .as_deref()
            .or(steps_words.as_deref())
            .unwrap_or(said.unwrap_or(reason.as_str()).as_bytes());
        let mut input = RefusalIn {
            cause: if words.is_some() {
                REFUSAL_ARRIVE
            } else if reason == ReasonCode::HookVeto {
                REFUSAL_GATE
            } else {
                REFUSAL_KERNEL
            },
            status,
            dialect,
            reason: reason_code(reason),
            text: AbiStr::over(text),
            unit,
            plane_code: declined.map_or(0, |(code, _)| code),
            retry_after_s,
            target: AbiStr::over(&self.arrival.target),
            trust: if reason == ReasonCode::Untrusted {
                self.lock().distrust.map_or(0, |why| {
                    u32::try_from(crate::host_services::distrust_code(why)).unwrap_or(0)
                })
            } else {
                0
            },
            ..blank_in()
        };

        if let Some(hook) = hook {
            input.hook = AbiStr::over(hook.as_bytes());
        }
        let principal = self.lock().principal.clone();
        let rendered = self.driver.render_refusal(input, principal.as_ref());

        self.lock().close.closed();
        rendered
    }
}

impl PlaneDriver {
    fn render_refusal(&self, mut input: RefusalIn, principal: Option<&PrincipalId>) -> Rendered {
        let status = input.status;
        let caps = self.config.caps;
        let (mut reply, mut fields, mut arena) = (
            vec![0u8; caps.reply],
            vec![NO_FIELD; caps.fields],
            vec![0u8; caps.arena],
        );
        let mut records = vec![NO_RECORD; caps.records];
        (input.reply_buf, input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (input.fields_buf, input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (input.arena_buf, input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (input.records_buf, input.records_cap) = (records.as_mut_ptr(), records.len());
        let mut o: RefusalOut = blank_out();
        let outcome = self.calls.refusal(&mut input, &mut o, &mut |short, i| {
            reply.resize((short.reply_needed as usize).max(reply.len()), 0);
            fields.resize((short.fields_needed as usize).max(fields.len()), NO_FIELD);
            arena.resize((short.arena_needed as usize).max(arena.len()), 0);
            records.resize(
                (short.records_needed as usize).max(records.len()),
                NO_RECORD,
            );
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        });
        if outcome != AbiOutcome::Ready {
            return Rendered {
                status,
                fields: Vec::new(),
                body: Vec::new(),
            };
        }

        let written = (o.records_written as usize).min(records.len());
        if written != 0 {
            let arena_written = (o.arena_written as usize).min(arena.len());
            let writes = busbar_contract::plane_calls::CancelWrite::owned(
                &records,
                written,
                &arena[..arena_written],
            );
            self.fold_writes(&writes, principal);
        }
        let span = |s: Span| {
            let start = s.offset as usize;
            arena
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
                .to_vec()
        };
        Rendered {
            status: if o.status == 0 { status } else { o.status },
            fields: fields
                .iter()
                .take(o.fields_written as usize)
                .map(|f| (span(f.name), span(f.value)))
                .collect(),
            body: reply
                .get(..o.reply_written as usize)
                .unwrap_or_default()
                .to_vec(),
        }
    }

    #[must_use]
    pub fn refuse_kernel(
        &self,
        reason: ReasonCode,
        status: u32,
        text: &str,
        dialect: u32,
        target: &[u8],
    ) -> Option<Rendered> {
        let input = RefusalIn {
            cause: REFUSAL_KERNEL,
            status,
            dialect,
            reason: reason_code(reason),
            text: AbiStr::over(text.as_bytes()),
            unit: 0,
            target: AbiStr::over(target),
            ..blank_in()
        };
        let rendered = self.render_refusal(input, None);

        (!rendered.body.is_empty() || !rendered.fields.is_empty()).then_some(rendered)
    }

    #[must_use]
    pub fn refuse_unitless(&self, reason: ReasonCode, dialect: u32, target: &[u8]) -> Rendered {
        let input = RefusalIn {
            cause: REFUSAL_KERNEL,
            status: self.config.status(dialect, reason),
            dialect,
            reason: reason_code(reason),
            text: AbiStr::over(reason.as_str().as_bytes()),
            unit: 0,
            target: AbiStr::over(target),
            ..blank_in()
        };
        self.render_refusal(input, None)
    }

    #[must_use]
    pub fn catalog_unitless(
        &self,
        method: &[u8],
        target: &[u8],
        head: &[(Vec<u8>, Vec<u8>)],
        names: &[String],
    ) -> Option<Rendered> {
        use busbar_contract::abi::plane::{CatalogIn, CatalogOut};
        let fields: Vec<Field> = head
            .iter()
            .map(|(n, v)| Field {
                name: AbiStr::over(n),
                value: AbiStr::over(v),
            })
            .collect();
        let listed: Vec<AbiStr> = names.iter().map(|n| AbiStr::over(n.as_bytes())).collect();
        let caps = self.config.caps;
        let (mut reply, mut out_fields, mut arena) = (
            vec![0u8; caps.reply],
            vec![NO_FIELD; caps.fields],
            vec![0u8; caps.arena],
        );
        let mut input = CatalogIn {
            method: AbiStr::over(method),
            target: AbiStr::over(target),
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            names: listed.as_ptr(),
            names_len: listed.len(),
            reply_buf: reply.as_mut_ptr(),
            reply_cap: reply.len(),
            fields_buf: out_fields.as_mut_ptr(),
            fields_cap: out_fields.len(),
            arena_buf: arena.as_mut_ptr(),
            arena_cap: arena.len(),
            ..blank_in()
        };
        let mut o: CatalogOut = blank_out();
        let outcome = self.calls.catalog(&mut input, &mut o, &mut |short, i| {
            reply.resize((short.reply_needed as usize).max(reply.len()), 0);
            out_fields.resize(
                (short.fields_needed as usize).max(out_fields.len()),
                NO_FIELD,
            );
            arena.resize((short.arena_needed as usize).max(arena.len()), 0);
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (out_fields.as_mut_ptr(), out_fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        });
        if outcome != AbiOutcome::Ready {
            return None;
        }
        let span = |s: Span| {
            let start = s.offset as usize;
            arena
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
                .to_vec()
        };
        Some(Rendered {
            status: o.status,
            fields: out_fields
                .iter()
                .take(o.fields_written as usize)
                .map(|f| (span(f.name), span(f.value)))
                .collect(),
            body: reply
                .get(..o.reply_written as usize)
                .unwrap_or_default()
                .to_vec(),
        })
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    fn stopped(&self, stopped: hooks::Stopped) -> ReasonCode {
        match stopped {
            hooks::Stopped::Veto(veto) => {
                let rendered = self.render_as(
                    ReasonCode::HookVeto,
                    Some((veto.status, None)),
                    Some(veto.text.as_str()),
                    None,
                    veto.hook.as_deref(),
                );
                self.lock().rendered = Some(rendered);
                self.response_tap(true, veto.status);
                ReasonCode::HookVeto
            }
            hooks::Stopped::Unreadable | hooks::Stopped::Unparseable { .. } => {
                let status = self.status_for(ReasonCode::DecodeFailed);
                self.response_tap(true, status);
                ReasonCode::DecodeFailed
            }
        }
    }

    pub async fn open_hooks(&self, token: &Pass<Route>, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        if self.lock().open_hooks_ran {
            return Ok(());
        }
        match self.request_stage(token).await {
            Ok(()) => {
                self.lock().open_hooks_ran = true;
                Ok(())
            }
            Err(stopped) => {
                let reason = self.stopped(stopped);
                self.driver.money.finished(ctx);
                Err(reason)
            }
        }
    }

    async fn route_async(&self, token: &Pass<Route>, ctx: &UnitCtx) -> StepAnswer<Route> {
        let d = self.driver;
        d.sweep();
        self.state_stage(token);
        if let Err(stopped) = self.request_stage(token).await {
            let reason = self.stopped(stopped);
            d.money.finished(ctx);
            return StepAnswer::refuse(token, Refusal::new(reason));
        }
        let Some(ticket) = d.calls.mint() else {
            return StepAnswer::refuse(token, Refusal::new(ReasonCode::InFlightCap));
        };

        let deadline_ns = match (self.deadline_ns, self.far.deadline_ns(d.calls.now_ns())) {
            (own, 0) => own,
            (0, stated) => stated,
            (own, stated) => own.min(stated),
        };
        let mut run = route::Pumping::new(
            d,
            token,
            &self.state,
            ctx,
            ticket,
            deadline_ns,
            self.lock()
                .body
                .clone()
                .unwrap_or_else(|| self.arrival.body.clone()),
        );
        {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
            let caller_ref = st.caller_ref.clone();
            drop(st);
            run.lend_unit(self.arrival.claim, dialect, &caller_ref, 0);
        }

        let scope_local = self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.route == ROUTE_SCOPE_LOCAL);
        let end = if scope_local {
            if let Some(entry) = self.steps.resolved(ctx) {
                run.lend_resolved(&entry);
            }
            self.answered_here(&mut run).await
        } else {
            self.attempts(&mut run, None).await
        };

        match &end {
            route::End::Done | route::End::Cancel(ReasonCode::ClientGone, _) => {}
            route::End::Failed(reason) | route::End::Cancel(reason, _) => {
                self.response_tap(false, self.status_for(*reason));
            }
            route::End::Exhausted(status, ..) => self.response_tap(false, *status),
            route::End::Vetoed(status, _) => self.response_tap(true, *status),
        }
        let answer = match end {
            route::End::Done => StepAnswer::proceed(token, RoutePlan::default()),
            route::End::Failed(reason) => failed(token, reason),
            route::End::Exhausted(status, retry_after, detail) => {
                let rendered = self.render_as(
                    ReasonCode::BreakerOpen,
                    Some((status, retry_after)),
                    Some(detail),
                    None,
                    None,
                );
                self.lock().rendered = Some(rendered);
                StepAnswer::refuse(token, Refusal::new(ReasonCode::BreakerOpen))
            }
            route::End::Vetoed(status, text) => {
                let rendered = self.render_as(
                    ReasonCode::HookVeto,
                    Some((status, None)),
                    Some(&text),
                    None,
                    None,
                );
                self.lock().rendered = Some(rendered);
                StepAnswer::refuse(token, Refusal::new(ReasonCode::HookVeto))
            }
            route::End::Cancel(cause, done) => {
                let bill = run.cancel(cause, done).await;
                self.lock().bill = Some(bill);
                if cause == ReasonCode::OverBudget {
                    self.cut_frame().await;
                }
                StepAnswer::refuse(token, Refusal::new(cause))
            }
        };
        if self.lock().bill.is_none() {
            d.money.finished(ctx);
        }
        run.finish();
        answer
    }

    async fn cut_frame(&self) {
        let rendered = self.render(ReasonCode::OverBudget);
        let streamed = std::mem::replace(&mut self.lock().facts.streamed, true);
        if !streamed {
            self.lock().facts.status = rendered.status;
            self.caller.head(rendered.status, rendered.fields);
        }
        let _written = self.caller.write(&rendered.body).await;
    }
}

fn failed(token: &Pass<Route>, reason: ReasonCode) -> StepAnswer<Route> {
    StepAnswer::refuse(token, Refusal::new(reason))
}

fn seated<S: busbar_contract::caps::Step>(
    token: &Pass<S>,
    answer: Result<S::Facts, Refusal>,
) -> StepAnswer<S> {
    match answer {
        Ok(facts) => StepAnswer::proceed(token, facts),
        Err(refusal) => StepAnswer::refuse(token, refusal),
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    fn decoded_op(&self, ctx: &UnitCtx) -> Result<OpClassId, Refusal> {
        self.driver.sweep();
        self.lock().unit = ctx.key.get();
        let decoded = self.arrive(ctx.key.get());
        let classes = &self.driver.config.op_classes;
        let op = decoded
            .as_ref()
            .and_then(|d| classes.get(d.op_class as usize).copied());
        if let (Some(op), Some(d)) = (op, decoded.as_ref()) {
            self.steps.decoded(ctx, op, d.route, d.pool.as_deref());
            self.steps.route_flags(ctx, d.route_flags);
            if let Some(t) = d.trust.as_ref() {
                self.steps.counterparty(ctx, &t.counterparty);
            }
            if let Some(key) = &d.affinity {
                self.steps.affinity(ctx, sticky_hash(key));
            }
            self.steps.expected(ctx, &d.expected);
        }
        self.lock().decoded = decoded;
        op.ok_or_else(|| Refusal::new(ReasonCode::DecodeFailed))
    }

    fn verified(
        &self,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Result<Vec<VerifiedDestination>, Refusal> {
        if let Some(slot) = &self.driver.config.caller_refs {
            let key = slot.read().unwrap_or_else(|e| e.into_inner()).clone();
            if *principal != PrincipalId::anonymous() {
                let Some(key) = key.filter(|_| !principal.as_str().is_empty()) else {
                    return Err(Refusal::new(ReasonCode::Unauthenticated));
                };
                self.lock().caller_ref = key.caller_ref(principal.as_str()).into_bytes();
            } else if let Some(key) = key {
                self.lock().caller_ref = key.caller_ref(principal.as_str()).into_bytes();
            }
        }

        self.lock().principal = Some(principal.clone());
        self.steps.verify(trust, ctx, principal)
    }

    fn approved(
        &self,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Result<busbar_contract::ScopeFacts, Refusal> {
        let facts = self.steps.approve(ctx, principal, destinations)?;
        let stated = self.lock().decoded.as_ref().and_then(|d| d.trust.clone());
        let Some(t) = stated else {
            return Ok(facts);
        };
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let (counterparty, item, digest) = (
            text(&t.counterparty),
            t.item.as_deref().map(text),
            t.digest.as_deref().map(text),
        );
        let stated = TrustFacts {
            counterparty: &counterparty,
            item: item.as_deref(),
            digest: digest.as_deref(),
        };
        if let Err(why) = self
            .driver
            .services
            .trust_judge(&self.driver.label, &stated)
        {
            self.lock().distrust = Some(why);
            return Err(Refusal::new(ReasonCode::Untrusted));
        }
        Ok(facts)
    }

    fn admitted(
        &self,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Result<Admission, Refusal> {
        let declined = self.lock().declined.is_some();
        if declined && !self.declined_after_admission() {
            return Err(Refusal::new(ReasonCode::DecodeFailed));
        }
        self.steps
            .admit(admit, ctx, principal, destinations, leases)
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> UnitEnds for PlaneUnits<'_, S, F, C> {
    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> StepAnswer<Meter> {
        seated(
            token,
            self.steps.meter(usage, ctx, provisional, destinations),
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        self.steps.evidence(ctx)
    }

    fn at_parent_exit(&self, ctx: &UnitCtx, accrual: &HoldAccrual) -> Result<(), Refusal> {
        self.steps.at_parent_exit(ctx, accrual)
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> StepAnswer<Audit> {
        let (streamed, cut) = {
            let st = self.lock();
            let success = st.facts.status == 0 || (200..300).contains(&st.facts.status);
            (st.facts.content && success, st.facts.cut)
        };
        self.steps.answered(ctx, streamed, cut);
        StepAnswer::proceed(token, self.steps.audit(ctx, outcome))
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> StepAnswer<Audit> {
        self.lock().refused_wait = refusal
            .retry_after_secs()
            .filter(|secs| *secs != 0)
            .map(|secs| (refusal.reason(), secs));
        StepAnswer::proceed(token, self.steps.audit_refused(ctx, refusal))
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> StepAnswer<Route> {
        StepAnswer::refuse(token, Refusal::new(ReasonCode::HandoffMismatch))
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> StepAnswer<Encode> {
        let reason = match outcome {
            Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => Some(*reason),
            _ => None,
        };
        let pending = {
            let st = self.lock();
            st.facts.streamed || st.rendered.is_some()
        };
        let body = match reason {
            Some(reason) if !pending => {
                let (retry_after, said) = self.steps.refused_words();
                let rendered = self.render_as(reason, None, said.as_deref(), retry_after, None);
                if let (Some(binder), true) = (&self.driver.hooks, is_authentication(reason)) {
                    let dialect = self.lock().decoded.as_ref().map_or(0, |d| d.dialect);
                    binder.denied(dialect, u16::try_from(rendered.status).unwrap_or(u16::MAX));
                }
                let body = rendered.body.clone();
                self.lock().rendered = Some(rendered);
                body
            }
            _ => Vec::new(),
        };
        StepAnswer::proceed(
            token,
            busbar_contract::caps::Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(Arc::from(body)),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: SessionCaller> PlaneUnits<'_, S, F, C> {
    async fn session_async(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        sealed: &[VerifiedDestination],
    ) -> StepAnswer<Route> {
        let local = self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.route == ROUTE_LOCAL || d.route == ROUTE_SCOPE_LOCAL);
        match self.session_priced(token, ctx, sealed, !local).await {
            Ok(()) => StepAnswer::proceed(token, RoutePlan::default()),
            Err(reason) => failed(token, reason),
        }
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: SessionCaller> RouteAwait for PlaneUnits<'_, S, F, C> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        if self.declined_after_admission() {
            self.driver.money.finished(ctx);
            return Box::pin(std::future::ready(failed(token, ReasonCode::DecodeFailed)));
        }
        let session = self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.route_flags & ROUTE_SESSION != 0);
        if session {
            Box::pin(self.session_async(token, ctx, destinations))
        } else {
            use tracing::Instrument as _;

            let decoded = self.lock().decoded.clone();
            let opened = decoded.as_ref().and_then(|d| {
                let op = *self.driver.config.op_classes.get(d.op_class as usize)?;
                self.steps.request_span(ctx, d, op)
            });
            let span = match opened {
                Some((span, request_id)) => {
                    self.lock().request_id = Some(request_id);
                    span
                }
                None => tracing::Span::none(),
            };
            Box::pin(self.route_async(token, ctx).instrument(span))
        }
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.driver.money.abandoned(ctx, ended);
    }

    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        Box::pin(async move {
            let Some(binder) = self.driver.hooks.as_ref() else {
                return Ok(());
            };

            if binder.order() != hooks::HookOrder::Gated
                || self.arrival.claim == busbar_contract::abi::plane::CLAIM_PROBE
                || self.declined_after_admission()
            {
                return Ok(());
            }
            match self.gated_stage(&**binder).await {
                Ok(()) => {
                    self.lock().screened = true;
                    Ok(())
                }
                Err(stopped) => {
                    let reason = self.stopped(stopped);
                    self.driver.money.finished(ctx);

                    Err(if reason == ReasonCode::HookVeto {
                        Refusal::new(ReasonCode::HookVeto)
                    } else {
                        Refusal::new(ReasonCode::DecodeFailed)
                    })
                }
            }
        })
    }
}

#[cfg(test)]
mod section_admission_tests {
    use super::*;
    use crate::trust::book::Ruling;
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
    use busbar_contract::services::{HostServices, Ran};

    const INSTANCE: &str = "section-admission";
    const MECHANISMS: &[PinMechanismDecl] = &[PinMechanismDecl {
        token: "rooted",
        root: true,
        peer_key: false,
    }];

    fn declaration() -> InstanceDecl {
        InstanceDecl {
            label: Arc::from(INSTANCE),
            record_kinds: vec!["sample"],
            signing: Some(("section-admission-domain", "sample-")),
            scope_kinds: vec!["peer"],
            trust_keys: vec![TrustKeyDecl {
                key: "pin",
                role: TrustRole::Pin,
                fingerprint: true,
                default: None,
                mechanisms: MECHANISMS,
            }],
            ..InstanceDecl::default()
        }
    }

    fn section(key: &str, max_live: usize) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "peer:\n  pin: {{mechanism: rooted, key: '{key}'}}\nwork: {{max_live: {max_live}, retain_s: 7}}"
        ))
        .expect("the section parses")
    }

    fn judge(services: &KernelServices) -> Result<(), Distrust> {
        services.trust_judge(
            INSTANCE,
            &TrustFacts {
                counterparty: "peer",
                item: None,
                digest: None,
            },
        )
    }

    fn approve(services: &KernelServices) {
        let caller = Caller {
            instance: Arc::from(INSTANCE),
            plugin: Arc::from("test-plane"),
            kind: KindCode::Plane,
        };
        let Ran::Now(answer) = services.trust_sight(
            &caller,
            "peer",
            "catalogue",
            Box::new(|_| panic!("an in-memory sighting does not pend")),
        ) else {
            panic!("an in-memory sighting completes inline");
        };
        assert_eq!(answer.outcome, AbiOutcome::Ready);
        services
            .trust_rule(&format!("{INSTANCE}/peer"), Ruling::Approve)
            .expect("the operator approves the sighted card");
        assert_eq!(judge(services), Ok(()));
    }

    fn approved() -> KernelServices {
        let services = KernelServices::new();
        prepare_admission(&declaration(), &services, ("peers", &section("root-a", 32)))
            .unwrap()
            .commit()
            .unwrap();
        approve(&services);
        services
    }

    #[test]
    fn dropping_a_prepared_section_preserves_live_approval_and_work_bounds() {
        let services = approved();
        let before = services.trust_rows();
        let work = services.work_bounds_of(INSTANCE);
        let candidate =
            prepare_admission(&declaration(), &services, ("peers", &section("root-b", 64)))
                .unwrap();
        assert_eq!(services.trust_rows(), before);
        assert_eq!(services.work_bounds_of(INSTANCE), work);
        drop(candidate);
        assert_eq!(services.trust_rows(), before);
        assert_eq!(services.work_bounds_of(INSTANCE), work);
        assert_eq!(judge(&services), Ok(()));
    }

    #[test]
    fn a_rejected_section_preserves_live_approval_and_work_bounds() {
        let services = approved();
        let before = services.trust_rows();
        let work = services.work_bounds_of(INSTANCE);
        let error = prepare_admission(&declaration(), &services, ("peers", &section("root-b", 0)))
            .err()
            .expect("a zero work bound is refused");
        assert!(error.contains("whole number above zero"), "{error}");
        assert_eq!(services.trust_rows(), before);
        assert_eq!(services.work_bounds_of(INSTANCE), work);
        assert_eq!(judge(&services), Ok(()));
    }

    #[test]
    fn a_refused_admission_commit_preserves_live_approval_and_work_bounds() {
        let services = approved();
        services
            .admit(
                "other",
                InstanceFacts {
                    signing: Some(Signing {
                        domain: "held-domain".into(),
                        kid_prefix: "held-".into(),
                    }),
                    ..InstanceFacts::default()
                },
            )
            .unwrap();
        let before = services.trust_rows();
        let work = services.work_bounds_of(INSTANCE);
        let mut changed = declaration();
        changed.signing = Some(("held-domain", "sample-"));
        let candidate =
            prepare_admission(&changed, &services, ("peers", &section("root-b", 64))).unwrap();
        assert!(
            candidate.commit().is_err(),
            "the other instance owns its signing domain"
        );
        assert_eq!(services.trust_rows(), before);
        assert_eq!(services.work_bounds_of(INSTANCE), work);
        assert_eq!(judge(&services), Ok(()));
    }

    #[test]
    fn a_committed_section_keeps_same_pin_approval_and_requires_approval_for_a_new_pin() {
        let services = approved();
        let before = services.trust_rows();
        prepare_admission(&declaration(), &services, ("peers", &section("root-a", 48)))
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(services.trust_rows(), before);
        assert_eq!(services.work_bounds_of(INSTANCE).max_live, 48);
        assert_eq!(judge(&services), Ok(()));
        prepare_admission(&declaration(), &services, ("peers", &section("root-b", 64)))
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(services.work_bounds_of(INSTANCE).max_live, 64);
        assert_eq!(judge(&services), Err(Distrust::Unsighted));
        let rows = services.trust_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].approved, None);
        assert_eq!(rows[0].seen, None);
        approve(&services);
    }
}
