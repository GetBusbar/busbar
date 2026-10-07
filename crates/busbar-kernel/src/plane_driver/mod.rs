// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER (`BUSBAR-1.6.0.md` Part 3, §12): the kernel serves every plane through this
//! one driver. [`PlaneUnits`] implements the loop's [`Units`] and [`RouteAwait`] over one plane
//! instance's [`PlaneCalls`] (the one dispatcher's plane handle, as the composition root hands it),
//! so [`crate::teller::run_unit_async`] and [`crate::teller::open_unit`] drive it and no second
//! loop exists. A compiled-in and a dropped-in plane reach it through the same table, and the
//! kernel names neither: only the contract's call surface.
//!
//! One unit, step by step (`BUSBAR-1.6.0.md` THE DESIGN, §1's order):
//!
//! | State | Plane op | Kernel |
//! |---|---|---|
//! | arrival | — | the kernel's own gates ([`Units::arrival`] of the kernel steps) |
//! | decode | `arrive` (pure) | the op class, the principal need, the dialect, the expected units; a short answer is re-called once, and a second short answer is FAULT |
//! | authenticate → verify → approve → admit | `project` (pure, once per unit, when a hook is bound) | the kernel steps, unchanged; then, at the head of the route leg, the request-stage hooks see the projection |
//! | refused | `refusal` | the kernel steps audit the refusal; the plane renders it; nothing was charged |
//! | route | the `on_piece` pump ([`route`]) | attempts, backpressure, the far end, cancel |
//! | meter, audit, exit | — | the kernel steps and the loop's one exit |
//!
//! The pure ops (`arrive`, `refusal`, `project`) and the driver's own `cancel` between ops cross
//! ticketless on the caller's task: they never pend, and the loop's decode and encode seats answer
//! in place.
//! `on_piece`, which may pend, crosses on the dispatcher's worker for the unit's ticket and is
//! awaited, so the pump never parks a runtime thread.
//!
//! The driver moves no money: units, cancel bills and abandoned ends go to the [`MoneySeam`].
//!
//! A plane's admin routes are served by its `serve` op, on the admin router: [`serve`].
//!
//! THE INSTANCE'S ONE DRIVER TICKET (`BUSBAR-1.6.0.md` :2558, :3315, B.3.7): minted when the driver
//! is built, persistent, outside `max_inflight`, recycled when the driver goes. [`PlaneDriver::ticks`]
//! runs the instance's lifecycle `tick` on it at each `next_tick_ns` the last answered (the first at
//! once; `0` = no more), so a conn read or a host service that pends inside `tick` is woken through
//! `drive`. A session's unsolicited output (R-B) wakes the same ticket: [`PlaneDriver::drives`]
//! wakes each session its `drive` names, and the session collects its output.
//!
//! DUPLEX SESSIONS (K6): [`PlaneUnits::session`], after `open_unit` admitted the unit, or as the
//! route leg of a unit whose `arrive` stated `ROUTE_SESSION` (ARCHITECT round 5 Q-L3B-K6-HTTP (a)):
//! the unit's own caller side is then the session's caller leg ([`SessionCaller`]).
//!
//! THE INSTANCE'S ADMISSION: built, the driver admits the instance to the kernel's host services
//! ([`KernelServices::admit`]) from what it declares ([`PlaneCalls::declared`], its Statement tail)
//! and its configured section, so its caller-scoped services (`records.*`, `sign`, `trust.*`)
//! answer; right before each `tick` it marks what is due ([`KernelServices::mark_due`]), so the
//! plane's `trust.due` sees the marks.
//!
//! THE INSTANCE'S RECORD WRITES (ruling H2 U10): a piece's `RecordWrite`s join the kernel's one
//! write-behind batcher ([`crate::host_records::WriteBehind`]) and the instance reads them at once
//! through the pending-records overlay; the piece completes only once the store took every one.
//! The batcher's cadence is not the plane's tick schedule: [`KernelServices::flushes`] restarts a
//! stalled flush every second, and a reload never waits on a store write (the unit waiting on it is
//! cancelled; the write itself runs on).

mod cancel;
mod epoch;
mod far_end;
pub(crate) mod hooks;
mod money;
mod needs;
mod probe;
mod route;
pub mod serve;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, Outcome as AbiOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    reason_code, ArriveIn, ArriveOut, OutField, RefusalIn, RefusalOut, RefusalStatus, UnitCount,
    REFUSAL_ANY_DIALECT, REFUSAL_ARRIVE, REFUSAL_GATE, REFUSAL_KERNEL, ROUTE_COUNTED, ROUTE_LOCAL,
    ROUTE_SESSION,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival as ArrivalStep, Audit, Authenticate, Consumption, Decode,
    Dial, Encode, Grant, HoldAccrual, Meter, OpClassId, Outcome, Pass, PrincipalId, ReasonCode,
    Refusal, Route, RoutePlan, SeatVerdict as StepAnswer, VerifiedDestination, Verify,
};
use busbar_contract::plane_calls::PlaneCalls;
use busbar_contract::services::Caller;
use tokio::sync::{watch, Notify};

pub use cancel::{CancelBill, Checkpoint, MoneySeam};
pub use epoch::FlushEpoch;
pub use far_end::{
    AuthBinding, Egress, EgressFarEnd, MemberFacts, MemberRoute, MemberSignals, MemberStanding,
    ResponseKeep, Ride, UnitRoute, DEFAULT_ERROR_BODY_MAX,
};
pub use hooks::{
    Bind, BoundHooks, CallerFacts, CallerKey, CandidateFacts, Candidates, Constraint, EngineCaller,
    GroupScope, HookBinder, HookRead, HostHooks, HostSource, Projection, Restrict, RewriteChain,
    SessionStage, StageTaps, UnitHooks, CONTENT_ROLE, GATE_UNAVAILABLE, GATE_UNAVAILABLE_STATUS,
    STAGE_GONE,
};
pub use hooks::{GatedHooks, GatedScan, GenerationHost, HookOrder, HostGatedHooks, PrincipalKeys};
pub use money::{EndPost, FeeRefund, PlaneMoney, UnitMoney};
pub use needs::{resolve_member_needs, MemberAuth, NeedRefusal};
pub use probe::PlaneProbes;
pub use route::{CallerEnd, FarEnd, FarPiece, OutboundRequest, Pick, SessionCaller};

use crate::auth::CallerRefKey;
use crate::host_services::{InstanceFacts, KernelServices, Signing};
use crate::slice::GroupLeaseSlip;
use crate::teller::{Ended, Evidence, RouteAwait, RouteLeg, Screen, UnitCtx, Units};
use crate::trust::section::parse_section;
use busbar_contract::ids::RecordSchemaId;

/// The capacities of the host buffers the driver hands a plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferCaps {
    /// Reply bytes per `on_piece` (the backpressure window).
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
    /// No buffers at all.
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
        BufferCaps {
            reply: 16 * 1024,
            units: 8,
            records: 16,
            fields: 32,
            arena: 4096,
        }
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
    /// The key the caller's opaque reference is derived under (the node's signing material);
    /// `None` = the node keeps none, and no reference is lent.
    pub caller_refs: Option<Arc<CallerRefKey>>,
}

impl DriverConfig {
    /// The status a refusal for `reason` wears in `dialect`: the plane's row for that dialect,
    /// else its row for every dialect, else [`DriverConfig::status_of`].
    pub fn status(&self, dialect: u32, reason: ReasonCode) -> u32 {
        self.stated(dialect, reason)
            .unwrap_or_else(|| (self.status_of)(reason))
    }

    /// The status the plane's tail STATES for `reason` in `dialect` (its row for that dialect, else
    /// its row for every dialect); `None` when it states none.
    pub fn stated(&self, dialect: u32, reason: ReasonCode) -> Option<u32> {
        let code = reason_code(reason);
        let row = |d: u32| {
            self.refusal_statuses
                .iter()
                .find(|r| r.dialect == d && r.reason == code)
                .map(|r| r.status)
        };
        row(dialect).or_else(|| row(REFUSAL_ANY_DIALECT))
    }
}

/// Whether `reason` refuses a unit at authentication.
fn is_authentication(reason: ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::Unauthenticated
            | ReasonCode::Revoked
            | ReasonCode::SchemeNotDeclared
            | ReasonCode::SessionUnbound
    )
}

/// The status the kernel hands `refusal` for a reason, when the deployment states no other.
pub fn refusal_status(reason: ReasonCode) -> u32 {
    match reason {
        ReasonCode::DecodeFailed | ReasonCode::SchemeNotDeclared => 400,
        ReasonCode::Unauthenticated | ReasonCode::Revoked | ReasonCode::SessionUnbound => 401,
        ReasonCode::ScopeDenied | ReasonCode::PoolNotPermitted | ReasonCode::HookVeto => 403,
        ReasonCode::BodyTooLarge => 413,
        ReasonCode::RateLimited | ReasonCode::OverBudget | ReasonCode::GroupFrozen => 429,
        ReasonCode::DestinationUnreachable | ReasonCode::PlanePanic => 502,
        ReasonCode::DeadlineExceeded | ReasonCode::Stalled => 504,
        _ => 503,
    }
}

/// THE DRIVER OF ONE PLANE INSTANCE: the instance's calls (the one dispatcher's plane handle, as
/// the composition root hands it), the money seam, and the units whose caller went away while
/// their cancel finishes.
pub struct PlaneDriver {
    calls: Arc<dyn PlaneCalls>,
    config: DriverConfig,
    money: Arc<dyn MoneySeam>,
    buried: Mutex<Vec<cancel::Buried>>,
    reload: watch::Sender<bool>,
    /// The kernel's record write path and the instance the plane's writes are keyed by.
    records: Option<(Arc<KernelServices>, Caller)>,
    driver: Option<Ticket>,
    services: Arc<KernelServices>,
    /// The open duplex sessions, by stream: what wakes each when `drive` names it (R-B).
    sessions: Mutex<HashMap<u64, Arc<Notify>>>,
    /// Which hooks bind to a unit of this plane; `None` = none ever does.
    hooks: Option<Arc<dyn HookBinder>>,
    /// The instance's label, as admitted to the services.
    label: Arc<str>,
    /// Where a unit's audit row (a `RECORD_AUDIT` write) is written: the kernel's own audit chain.
    audit: Arc<dyn AuditSink>,
    /// The plane's billable class names, in its tail's order: a [`UnitCount::class`] indexes
    /// them. Empty until the root states them ([`PlaneDriver::with_billable_classes`]).
    billable_classes: Arc<[String]>,
}

/// WHERE A DOOR UNIT'S AUDIT ROW GOES (ARCHITECT SEAM-L(k)): a plane writes its unit's audit row
/// as a `RECORD_AUDIT` record write on its `on_piece` answer (no host op of its own), and the
/// driver folds it into the kernel's one audit chain, under the principal the kernel verified. The
/// row's action, resource and outcome are the plane's words; the kernel names none.
pub trait AuditSink: Send + Sync {
    /// Write one row: `action` on `resource`, with `outcome` (`applied` or `rejected`), by
    /// `principal`. Fire-and-forget: a store that refuses it never fails the unit.
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);
}

/// THE KERNEL'S OWN AUDIT CHAIN (`audit::journal`, read by `GET /audit`): the sink every driver
/// writes a unit's audit row to unless built with another ([`PlaneDriver::with_audit`]). The same
/// chokepoint a plane's admin-audit emit reached before it was served through its door.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreAudit;

/// ONE AUDIT ROW a plane wrote (`RECORD_AUDIT`) onto `sink`: its outcome code, its action (`key`)
/// and resource (`value`), under `principal` (anonymous when none). `Err` = a plane fault (an
/// unknown outcome, an empty action, words that are not UTF-8); nothing is written.
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

impl PlaneDriver {
    /// The driver of one open plane instance, reached through `calls`: the instance admitted to
    /// `services` from what it declares and its configured `section` (its key and value), then its
    /// one driver ticket minted.
    ///
    /// # Errors
    ///
    /// The section's trust keys or its reserved `work:` bounds break their rule, or `services`
    /// refused the admission.
    pub fn new(
        calls: Arc<dyn PlaneCalls>,
        config: DriverConfig,
        money: Arc<dyn MoneySeam>,
        services: Arc<KernelServices>,
        section: (&str, &serde_yaml::Value),
    ) -> Result<Self, String> {
        let d = calls.declared();
        let trust = parse_section(section.0, section.1, &d.trust_keys)?;
        let facts = InstanceFacts {
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
        };
        // The instance's own work bounds (its section's reserved `work:`), the host's where it
        // states none; a section that misstates them refuses the instance.
        let work = crate::host_work::WorkBounds::of_section(
            section.0,
            section.1,
            services.default_work_bounds(),
        )?;
        services.admit(&d.label, facts).map_err(|e| e.to_string())?;
        services.bound_work(&d.label, work);
        let driver = calls.driver();
        Ok(PlaneDriver {
            calls,
            config,
            money,
            buried: Mutex::new(Vec::new()),
            reload: watch::channel(false).0,
            records: None,
            driver,
            services,
            sessions: Mutex::default(),
            hooks: None,
            label: Arc::from(&*d.label),
            audit: Arc::new(CoreAudit),
            billable_classes: Arc::from(Vec::new()),
        })
    }

    /// THE INSTANCE'S TICK SCHEDULE, on its driver ticket: `tick` at once, then at each
    /// `next_tick_ns` it answers, on the dispatcher's clock; it ends when an answer names `0`, or
    /// is not READY or PENDING, or no driver ticket was minted. It waits on the runtime's timer
    /// (as the route's deadline does) and holds no `max_inflight` slot.
    pub async fn ticks(&self) {
        let Some(driver) = self.driver else {
            return;
        };
        let mut at = 0;
        loop {
            let now = self.calls.now_ns();
            if at > now {
                tokio::time::sleep(std::time::Duration::from_nanos(at - now)).await;
            }
            self.services.mark_due();
            match self.calls.tick(driver, self.calls.now_ns()).await {
                Some(next) if next != 0 => at = next,
                _ => return,
            }
        }
    }

    /// Bind the hooks `binder` names to each unit of this plane: its request-stage hooks run over
    /// the plane's projection at the head of the route leg, and its stage taps observe the walk.
    #[must_use]
    pub fn with_hooks(mut self, binder: Arc<dyn HookBinder>) -> Self {
        self.hooks = Some(binder);
        self
    }

    /// The plane's billable class names, in its tail's order (the Statement's billable classes):
    /// what a reported [`UnitCount::class`] names, so a response-stage signal reads the count of
    /// the class it is about.
    #[must_use]
    pub fn with_billable_classes(mut self, classes: impl IntoIterator<Item = String>) -> Self {
        self.billable_classes = classes.into_iter().collect();
        self
    }

    /// ONE AUDIT ROW a plane wrote (`RECORD_AUDIT`): its outcome code (`kind`), its action (`key`)
    /// and resource (`value`), written on the audit sink under `principal` (anonymous when none
    /// was verified). `Err` = a plane fault: an unknown outcome, an empty action, or words that are
    /// not UTF-8; nothing is written.
    pub(crate) fn audit_row(
        &self,
        outcome: u32,
        key: &[u8],
        value: &[u8],
        principal: Option<&PrincipalId>,
    ) -> Result<(), ()> {
        audit_row_to(&*self.audit, outcome, key, value, principal)
    }

    /// THE RECORD WRITES OF AN ANSWER THAT ENDS NOTHING FURTHER (a refusal's, SEAM-L(o); a
    /// `cancel`'s, SEAM-L(r)): each audit row folded as [`Self::audit_row`], each put handed to the
    /// record write path, its acknowledgement not awaited (the unit has nothing left to fail). A
    /// write the plane got wrong, or a put with no record path, is logged and dropped: the unit's
    /// end stands.
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

    /// Write a unit's audit row (a `RECORD_AUDIT` record write) to `sink` instead of the kernel's
    /// own audit chain ([`CoreAudit`]).
    #[must_use]
    pub fn with_audit(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit = sink;
        self
    }

    /// Apply the plane's record writes through `services`, as the instance `caller`. Without it a
    /// piece that writes a record fails its unit: a write is never dropped.
    #[must_use]
    pub fn with_records(mut self, services: Arc<KernelServices>, caller: Caller) -> Self {
        self.records = Some((services, caller));
        self
    }

    /// A REFUSAL WITH NO UNIT, rendered by the plane through its `refusal` (ticketless, one re-call
    /// when short): the kernel's own refusal before any arrival (its 401, its no-route 404, its
    /// wrong-method 405, the body cap's 413, the request-panic 500) on a line of this plane. The
    /// kernel chooses the status from the plane's stated row for the line's `dialect` and `reason`,
    /// else the listener's own `status` for that answer (the 1.5.5 one: these are the listener's
    /// answers, not a unit's), and passes the TARGET, which the plane renders by its own path rule
    /// (spec Part 3 §12 l.2645); the plane may state the status its rendering carries. `None` when
    /// the plane renders nothing. [`Self::refuse_unitless`] is the same refusal for a door route's
    /// `401`, at the kernel's own status table and with the reason's own words.
    #[must_use]
    pub fn refuse_unitless_at(
        &self,
        dialect: u32,
        reason: ReasonCode,
        status: u32,
        text: &str,
        target: &[u8],
    ) -> Option<Rendered> {
        let status = self.config.stated(dialect, reason).unwrap_or(status);
        let caps = self.config.caps;
        let (mut reply, mut fields, mut arena) = (
            vec![0u8; caps.reply],
            vec![NO_FIELD; caps.fields],
            vec![0u8; caps.arena],
        );
        let mut records = vec![NO_RECORD; caps.records];
        let mut input = RefusalIn {
            cause: REFUSAL_KERNEL,
            status,
            dialect,
            reason: reason_code(reason),
            text: AbiStr::over(text.as_bytes()),
            reply_buf: reply.as_mut_ptr(),
            reply_cap: reply.len(),
            fields_buf: fields.as_mut_ptr(),
            fields_cap: fields.len(),
            arena_buf: arena.as_mut_ptr(),
            arena_cap: arena.len(),
            unit: 0,
            plane_code: 0,
            retry_after_s: 0,
            target: AbiStr::over(target),
            records_buf: records.as_mut_ptr(),
            records_cap: records.len(),
            ..blank_in()
        };
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
            // The status the plane's rendering carries, where it states one (`0` = the kernel's).
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
        })
    }

    /// THE LISTING RENDER on this plane (ARCHITECT RULING D, 2026-10-07): `names`, the kernel's
    /// visible names for the caller in its order, rendered by the plane's `serve` op
    /// ([`serve::render_listing`]) for the request `target` and the caller's `head` (the plane picks
    /// the dialect by its own rule). Not a unit. `None` when the plane renders nothing.
    pub async fn render_listing(
        &self,
        target: &[u8],
        head: HeadFields,
        names: &[&str],
    ) -> Option<Rendered> {
        let served = serve::render_listing(&*self.calls, self.config.caps, target, head, names)
            .await
            .ok()?;
        Some(Rendered {
            status: served.status,
            fields: served.fields,
            body: served.body,
        })
    }

    /// The plane's generation is being replaced: every running unit is cancelled by the driver
    /// itself, and a unit that starts after this is cancelled at its first crossing.
    pub fn reload(&self) {
        self.reload.send_replace(true);
    }

    /// One unit of this plane: the kernel `steps` answer arrival, identity, scope, budget, meter
    /// and audit; the plane answers decode, refusal and route through `far` and `caller`.
    /// `deadline_ns` is on the dispatcher's clock; `0` = none.
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

    /// The driver's own ticketless `cancel` of `ticket`, on the calling task: its disposition and
    /// its record writes, or `None` when it did not answer READY.
    fn cancel_now(&self, ticket: Ticket) -> Option<busbar_contract::plane_calls::Cancelled> {
        self.calls.cancel(ticket)
    }
}

/// A head's fields, name and value, in order.
pub type HeadFields = Vec<(Vec<u8>, Vec<u8>)>;

/// THE CALLER'S HEAD AS IT CROSSES TO THE PLANE: its fields in order, but the contract's
/// `NEVER_KEPT` ones (the credentials, and the caller's connection's own fields, `connection` among
/// them) and every field the caller's `connection` field nominates, which is per-connection like it
/// (RFC 9110 section 7.6.1). They go where `connection` goes: once it is struck, nothing downstream
/// can tell a field it nominated from any other, and that field would be forwarded to a far end.
#[must_use]
pub fn caller_head(headers: &axum::http::HeaderMap) -> HeadFields {
    use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
    let nominated: Vec<&[u8]> = headers
        .get_all(axum::http::header::CONNECTION)
        .iter()
        .map(axum::http::HeaderValue::as_bytes)
        .collect();
    headers
        .iter()
        .filter(|(n, _)| {
            let n = n.as_str();
            !NEVER_KEPT.contains(&n)
                && !busbar_contract::abi::transport::fields::hop_by_hop(
                    n,
                    nominated.iter().copied(),
                )
        })
        .map(|(n, v)| (n.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

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
    pub body: Arc<[u8]>,
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
    /// The entry it routes over: the name inside the plane's own section (ARCHITECT Q-SW6), opaque
    /// bytes the kernel never parses; `None` = it named none.
    pub pool: Option<Vec<u8>>,
    /// What [`Decoded::pool`] names: `ROUTE_POOL` or `ROUTE_DIRECT` (ARCHITECT Q-FL3).
    pub route: u8,
    /// The `ROUTE_*` flag bits its `arrive` stated (`ROUTE_ONCE`, `ROUTE_SESSION`,
    /// `ROUTE_STREAM`).
    pub route_flags: u8,
    /// The sticky-routing key its `arrive` stated, opaque; `None` = none.
    pub affinity: Option<Vec<u8>>,
}

/// THE WALK'S AFFINITY POSITION for a plane's opaque sticky key: FNV-1a over its bytes, the hash
/// 1.5.5 put on a session key (v1.5.5 `stable_hash`, `store::fnv1a_u64`), so one session lands on
/// the member it landed on before.
#[must_use]
pub fn sticky_hash(key: &[u8]) -> u64 {
    key.iter().fold(crate::store::FNV1A_OFFSET_BASIS, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(crate::store::FNV1A_PRIME)
    })
}

/// THE KERNEL STEPS A PLANE'S UNIT IS SERVED UNDER ([`PlaneDriver::unit`]'s `steps`): the loop's
/// [`Units`], told once what the plane's `arrive` decided, before identity and scope run.
pub trait DriverSteps: Units {
    /// The unit `ctx` decoded to operation class `op`, routing over the entry its `arrive` named
    /// (`None` = none named) as a pool or directly (`route`, `ROUTE_*`). Called once, when decode
    /// proceeds.
    fn decoded(&self, _ctx: &UnitCtx, _op: OpClassId, _route: u8, _pool: Option<&[u8]>) {}

    /// The `ROUTE_*` flag bits the unit's `arrive` stated (`ROUTE_ONCE`: an answered failure is
    /// not retried on another member), told with [`Self::decoded`].
    fn route_flags(&self, _ctx: &UnitCtx, _flags: u8) {}

    /// The sticky-routing key the unit's `arrive` stated (ARCHITECT Q1 ArriveOut), as the walk's
    /// affinity position: [`sticky_hash`] of the plane's opaque key. Told with [`Self::decoded`],
    /// and only when the plane stated a key.
    fn affinity(&self, _ctx: &UnitCtx, _hash: u64) {}

    /// The units the plane's `arrive` expects the unit to do (its admission estimate, THE DESIGN
    /// §7 `admission: estimate`), told with [`Self::decoded`]. An estimate never bills.
    fn expected(&self, _ctx: &UnitCtx, _units: &[UnitCount]) {}

    /// The words of the refusal one of these steps raised, where it has its own: its Retry-After
    /// seconds (a rolling limit's wait, `RefusalIn::retry_after_s`, the previous release's
    /// `Retry-After` on a limit's 429) and its message (`RefusalIn::text`, the kernel's own message
    /// for the refusal: the previous release's sentence for a pool the key may not use or a model
    /// no rate prices). `(None, None)` = the reason's own spelling, no wait.
    fn refused_words(&self) -> (Option<u32>, Option<String>) {
        (None, None)
    }

    /// An attempt of the unit starts on a member of `provider`, the unit's request read in its
    /// `dialect` (the one `arrive` answered): the previous release's translation counter counts an
    /// attempt whose far end speaks another dialect.
    fn attempting(&self, _ctx: &UnitCtx, _dialect: u32, _provider: &str) {}
    /// THE STEPS' OWN WORDS for a refusal they decided with `reason`, handed to the plane's
    /// `refusal` as [`busbar_contract::abi::plane::RefusalIn::text`] (as a limit names the bucket
    /// that blocked); `None` = the reason's word. A `ROUTE_SCOPE` unit refused because several
    /// entries reach names them here.
    fn refusal_words(&self, _reason: ReasonCode) -> Option<Vec<u8>> {
        None
    }

    /// THE END THE PLANE REPORTED for a reply the far end cut (abi/plane `PIECE_CUT`, ARCHITECT
    /// RULING U11 Q1 2026-10-06): [`busbar_contract::FinishClass::Partial`] when a byte of it
    /// reached the caller before the cut, [`busbar_contract::FinishClass::Error`] when none did.
    /// Told when the route step ends with the reply done, before the audit seat; untold, the
    /// reply's status decides the end the audit seals.
    fn reported_finish(&self, _ctx: &UnitCtx, _finish: busbar_contract::FinishClass) {}
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
    decoded: Option<Decoded>,
    /// A REFUSED `arrive`'s own code and 4xx status.
    declined: Option<(u32, u32)>,
    /// A REFUSED `arrive`'s own words (its `head.error`), for the plane's `refusal`.
    declined_words: Option<Vec<u8>>,
    /// A REFUSED `arrive` stated `ROUTE_COUNTED`: a dialect read the request.
    declined_counted: bool,
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
    /// The body a request-stage rewrite left, kept for every attempt; `None` = the caller's own.
    body: Option<Arc<[u8]>>,
    /// The unit's hooks and the plane's view of its effective request, once the request stage ran.
    hooked: Option<(UnitHooks, hooks::Projection)>,
    /// The `response` stage tap has fired.
    responded: bool,
    /// The pool the unit's hooks were bound over (the walk's, else the plane's).
    hooked_pool: String,
    /// The hook that ordered or restricted the walk, for the opt-in transparency fields.
    route_policy: Option<&'static str>,
}

/// ONE UNIT OF A PLANE, as the loop drives it.
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

    /// What `arrive` said, once decode has run.
    pub fn decoded(&self) -> Option<Decoded> {
        self.lock().decoded.clone()
    }

    /// The status the plane's `arrive` refused the arrival under, when it refused it.
    pub fn declined_status(&self) -> Option<u32> {
        self.lock().declined.map(|(_, status)| status)
    }

    /// The plane's `arrive` refused the arrival stating `ROUTE_COUNTED` (abi/plane "A refused
    /// arrival", rule 7): a dialect read the request, so it is counted whatever its status.
    pub fn declined_counted(&self) -> bool {
        let st = self.lock();
        st.declined.is_some() && st.declined_counted
    }

    /// The status a refusal for `reason` goes out under, as [`Self::render`] chooses it.
    fn status_for(&self, reason: ReasonCode) -> u32 {
        let st = self.lock();
        let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
        match st.declined {
            Some((_, status)) if reason == ReasonCode::DecodeFailed => status,
            _ => self.driver.config.status(dialect, reason),
        }
    }

    /// The refusal or failure the plane rendered for the caller, if the unit ended in one before
    /// any byte reached the caller. The kernel's front door writes it.
    pub fn take_rendered(&self) -> Option<Rendered> {
        self.lock().rendered.take()
    }

    /// The bill of a unit the driver cancelled, if it did.
    pub fn cancel_bill(&self) -> Option<CancelBill> {
        self.lock().bill.clone()
    }

    /// S1: `arrive`, ticketless, with the one re-call a short answer earns. The caller's head
    /// crosses here, once, under the unit's kernel-minted key.
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
            // The dispatcher judged the answer: a nonzero code and a 4xx status (5xx for a
            // refusal about an entry).
            let words = self
                .driver
                .calls
                .arrived_refusal(&o)
                .filter(|w| !w.is_empty());
            let mut st = self.lock();
            st.declined = Some((o.refusal, o.refusal_status));
            st.declined_words = words;
            st.declined_counted = o.route_flags & ROUTE_COUNTED != 0;
        }
        // A REFUSAL ABOUT AN ENTRY (abi/plane "A refused arrival", rule 6; ARCHITECT
        // Q-DEL-A2A-GATE) decodes as the entry it names: the caller's grant over it is judged
        // first, and the refusal is rendered at admission, before anything is charged.
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
            affinity: (outcome == AbiOutcome::Ready)
                .then(|| self.driver.calls.arrived_affinity(&o))
                .flatten()
                .filter(|k| !k.is_empty()),
        })
    }
}

impl<S: DriverSteps, F, C> PlaneUnits<'_, S, F, C> {
    /// The plane renders a refusal (`refusal`, ticketless, one re-call when short); the kernel's
    /// generic failure, with no body, when it cannot.
    fn render(&self, reason: ReasonCode) -> Rendered {
        self.render_as(reason, None, None, None, None)
    }

    /// [`Self::render`], or under the status and Retry-After the walk chose (an exhaustion
    /// terminal's `walk`, a hook veto's own status), which the plane renders in its dialect; `said`
    /// is the refusal's own words where it has them (a hook veto's message).
    fn render_as(
        &self,
        reason: ReasonCode,
        walk: Option<(u32, Option<u32>)>,
        said: Option<&str>,
        retry_after: Option<u32>,
        hook: Option<&str>,
    ) -> Rendered {
        let (unit, dialect, declined, words) = {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
            let declined = st.declined.filter(|_| reason == ReasonCode::DecodeFailed);
            // THE PLANE'S OWN WORDS for the arrival it refused (abi/plane "A refused arrival"): they
            // reach the caller only through its `refusal`, as REFUSAL_ARRIVE, unparsed.
            let words = declined.and(st.declined_words.clone());
            (st.unit, dialect, declined, words)
        };
        // A refusal the plane's own `arrive` decided wears the status it stated; the walk's
        // terminal wears its own; every other one the plane's stated row or the kernel's default.
        let status = match (walk, declined) {
            (Some((status, _)), _) => status,
            (None, Some((_, status))) => status,
            (None, None) => self.driver.config.status(dialect, reason),
        };
        let retry_after_s = walk.and_then(|(_, r)| r).or(retry_after).unwrap_or(0);
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
            ..blank_in()
        };
        // The vetoing hook's name, on a gate refusal alone (absent = NULL otherwise).
        if let Some(hook) = hook {
            input.hook = AbiStr::over(hook.as_bytes());
        }
        let principal = self.lock().principal.clone();
        self.driver.render_refusal(input, principal.as_ref())
    }
}

impl PlaneDriver {
    /// THE ONE REFUSAL CROSSING: `input` (every field but the host buffers) through the plane's
    /// `refusal`, its short buffers re-called at the sizes it asks, its record writes folded under
    /// `principal`, and its rendering read back. A plane that answers other than READY renders an
    /// empty body at the kernel's status.
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
        // THE REFUSAL'S RECORD WRITES (SEAM-L(o)): the plane's audit row for the unit the kernel
        // refused, and any put it writes beside it.
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
            // The status the plane's rendering carries, where it states one (`0` = the kernel's).
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

    /// A UNIT-LESS REFUSAL (spec Part 3 section 12, "Refusals": "for a refusal with no unit — the
    /// TARGET, which the plane renders by its own path rule"): `reason`, decided by the kernel before
    /// any unit exists (an unauthenticated caller at the door), rendered by the plane's `refusal` in
    /// `dialect` (the matched route's `refusal_dialect`) for `target`, at the status the plane's tail
    /// states for that dialect and reason, else the kernel's. No unit, no principal, nothing charged.
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
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    /// A request stage that stopped the unit: what the caller is answered (rendered by the plane),
    /// and the reason the unit is refused under.
    fn stopped(&self, stopped: hooks::Stopped) -> ReasonCode {
        match stopped {
            hooks::Stopped::Veto(veto) => {
                // A HOOK VETO wears the hook's own clamped status and words, rendered by the
                // plane in its dialect; nothing was charged.
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
            hooks::Stopped::Unreadable => {
                // 1.5.5 answered an unreadable request a rewrite hook had to see as a gate's
                // refusal: the response tap reports it so.
                let status = self.status_for(ReasonCode::DecodeFailed);
                self.response_tap(true, status);
                ReasonCode::DecodeFailed
            }
        }
    }

    /// THE SESSION OPEN'S HOOK STAGE (ARCHITECT Q-L5B-PROJECT 2026-10-03; K5): the request stage the
    /// route leg runs, run once for a duplex session, after its admission and before its caller is
    /// answered: the plane's `project` of the session's open, the operator's gates and rewrites over
    /// it. `Err` when a hook stopped it; what the caller is answered is then the plane's rendering
    /// ([`Self::take_rendered`]), and nothing was charged.
    ///
    /// # Errors
    ///
    /// The reason a hook stopped the session's open.
    pub async fn open_hooks(&self, token: &Pass<Route>, ctx: &UnitCtx) -> Result<(), ReasonCode> {
        match self.request_stage(token).await {
            Ok(()) => Ok(()),
            Err(stopped) => {
                let reason = self.stopped(stopped);
                self.driver.money.finished(ctx);
                Err(reason)
            }
        }
    }

    /// S3, the route step: the pump over the unit's own ticket, then the cancel the driver makes
    /// itself on a deadline, a cut or a reload.
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
        let mut run = route::Pumping::new(
            d,
            token,
            &self.state,
            ctx,
            ticket,
            self.deadline_ns,
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
        let end = self.attempts(&mut run, None).await;
        // THE END A CUT REACHED, as the plane reported it, for the audit seat to seal.
        if matches!(end, route::End::Done) {
            let finish = self.lock().facts.finish;
            if let Some(finish) = finish {
                self.steps.reported_finish(ctx, finish);
            }
        }
        // THE `response` STAGE TAP of a unit whose answer never reached the caller's head (the
        // head itself fires it, in the pump): the status the caller is answered under.
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
                // THE WALK'S EXHAUSTION TERMINAL: its status and its Retry-After floor, handed to
                // the plane's `refusal` (RefusalIn.retry_after_s), which renders them in its dialect.
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
                // THE WALK'S REFUSAL FOR A HOOK'S RESTRICTION: answered as the hook would be.
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
                let bill = run.cancel(cause, done);
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

    /// A cut under `cut-stream`: the plane renders the error frame through `refusal` and it goes
    /// to the caller in the stream (or as the whole reply, when nothing had streamed yet).
    async fn cut_frame(&self) {
        let rendered = self.render(ReasonCode::OverBudget);
        let streamed = std::mem::replace(&mut self.lock().facts.streamed, true);
        if !streamed {
            self.caller.head(rendered.status, rendered.fields);
        }
        let _written = self.caller.write(&rendered.body).await;
    }
}

/// The route step refused for the `reason` its leg ended with.
fn failed(token: &Pass<Route>, reason: ReasonCode) -> StepAnswer<Route> {
    StepAnswer::refuse(token, Refusal::new(reason))
}

/// The seats the kernel's own steps answer, forwarded to `self.steps` unchanged: one line per
/// seat, so the plane's own seats (decode, verify, route, encode) are the only bodies in the impl.
macro_rules! forward_to_steps {
    ($($seat:ident($($arg:ident: $ty:ty),* $(,)?) -> $answer:ty;)*) => {$(
        fn $seat(&self, $($arg: $ty),*) -> $answer {
            self.steps.$seat($($arg),*)
        }
    )*};
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> Units for PlaneUnits<'_, S, F, C> {
    forward_to_steps! {
        arrival(token: &Pass<ArrivalStep>, ctx: &UnitCtx) -> StepAnswer<ArrivalStep>;
        authenticate(token: &Pass<Authenticate>, ctx: &UnitCtx) -> StepAnswer<Authenticate>;
        approve(token: &Pass<Approve>, ctx: &UnitCtx, principal: &PrincipalId,
            destinations: &[VerifiedDestination]) -> StepAnswer<Approve>;
        meter(token: &Pass<Meter>, usage: &Grant<Consumption>, ctx: &UnitCtx, provisional: &Outcome,
            destinations: &[VerifiedDestination]) -> StepAnswer<Meter>;
        audit(token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> StepAnswer<Audit>;
        audit_refused(token: &Pass<Audit>, ctx: &UnitCtx, refusal: &Refusal) -> StepAnswer<Audit>;
        evidence(ctx: &UnitCtx) -> Evidence;
        at_parent_exit(ctx: &UnitCtx, accrual: &HoldAccrual) -> Result<u64, Refusal>;
    }

    /// The kernel's admission, unless the plane's `arrive` refused the unit about the entry it
    /// named (abi/plane "A refused arrival", rule 6): that refusal is rendered here, after the
    /// caller's identity and grant were judged and before anything is charged (ARCHITECT
    /// Q-DEL-A2A-GATE: "refused → audits the refusal; nothing was charged").
    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> StepAnswer<Admit> {
        if self.lock().declined.is_some() {
            return StepAnswer::refuse(token, Refusal::new(ReasonCode::DecodeFailed));
        }
        self.steps
            .admit(token, admit, ctx, principal, destinations, leases)
    }

    /// The kernel's verify, after which the unit's caller reference is derived under the node's
    /// key (none when the node keeps no key); the principal itself never enters a plane input.
    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> StepAnswer<Verify> {
        if let Some(key) = &self.driver.config.caller_refs {
            self.lock().caller_ref = key.caller_ref(principal.as_str()).into_bytes();
        }
        // The verified principal: the hooks the unit binds read it, and the unit's audit row is
        // written under it (never a plane input).
        self.lock().principal = Some(principal.clone());
        self.steps.verify(token, trust, ctx, principal)
    }

    /// S1, DECODE: the plane's `arrive`; a plane that did not answer, or named an operation class
    /// it does not have, is refused.
    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> StepAnswer<Decode> {
        self.lock().unit = ctx.key.get();
        let decoded = self.arrive(ctx.key.get());
        let classes = &self.driver.config.op_classes;
        let op = decoded
            .as_ref()
            .and_then(|d| classes.get(d.op_class as usize).copied());
        if let (Some(op), Some(d)) = (op, decoded.as_ref()) {
            self.steps.decoded(ctx, op, d.route, d.pool.as_deref());
            self.steps.route_flags(ctx, d.route_flags);
            if let Some(key) = &d.affinity {
                self.steps.affinity(ctx, sticky_hash(key));
            }
            self.steps.expected(ctx, &d.expected);
        }
        self.lock().decoded = decoded;
        op.map_or_else(
            || StepAnswer::refuse(token, Refusal::new(ReasonCode::DecodeFailed)),
            |op| StepAnswer::proceed(token, op),
        )
    }

    /// The in-place Route seat: a plane's route awaits its far end, so the driver is reached
    /// only through [`RouteAwait::route_leg`]; the synchronous entry refuses it.
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[VerifiedDestination],
    ) -> StepAnswer<Route> {
        StepAnswer::refuse(token, Refusal::new(ReasonCode::HandoffMismatch))
    }

    /// The bytes that leave. A refused or failed unit whose caller has no byte yet gets the
    /// plane's rendering of the refusal. An abandoned unit crosses nothing: this seat also runs
    /// inside the loop's `Drop` guard.
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
                    // A unit refused at authentication: the response taps see the previous
                    // release's synthetic completion, under the status the caller is answered.
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
    /// S3 for a unit its `arrive` stated `ROUTE_SESSION` (ARCHITECT round 5 Q-L3B-K6-HTTP (a)):
    /// the route leg is the duplex session ([`PlaneUnits::session`]) under the unit's one
    /// admission, inside the destinations its approval sealed, its caller leg the unit's own caller
    /// side; a session its plane answers itself (`ROUTE_LOCAL`) bills nothing, as a local request
    /// unit does. A session that ended on its own proceeds; one that ended for a cause is refused
    /// with it (a caller that already has its head is told nothing more by the loop's encode).
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
            .is_some_and(|d| d.route == ROUTE_LOCAL);
        match self.session_priced(token, ctx, sealed, !local).await {
            Ok(()) => StepAnswer::proceed(token, RoutePlan::default()),
            Err(reason) => failed(token, reason),
        }
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: SessionCaller> RouteAwait for PlaneUnits<'_, S, F, C> {
    /// The unit's route leg: one request's pump, or, for an arrival its `arrive` stated
    /// `ROUTE_SESSION`, the duplex session (K6).
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        let session = self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.route_flags & ROUTE_SESSION != 0);
        if session {
            Box::pin(self.session_async(token, ctx, destinations))
        } else {
            Box::pin(self.route_async(token, ctx))
        }
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.driver.money.abandoned(ctx, ended);
    }

    /// THE GATE-FIRST ORDER'S SCREEN (ARCHITECT ruling on Mode B, spec Part 3 section 12 "Hooks":
    /// the hook order 1.5.5 used for that plane): a plane whose hooks run gate-first has its entry's
    /// gates and rewrites screen the unit BEFORE the door, so a veto admits nothing (no request is
    /// counted, nothing is charged) and an over-budget caller is answered the gate's refusal before
    /// the door's. Every other plane's hooks run at the head of the route leg, as before.
    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        Box::pin(async move {
            let Some(binder) = self.driver.hooks.as_ref() else {
                return Ok(());
            };
            if binder.order() != hooks::HookOrder::Gated
                || self.arrival.claim == busbar_contract::abi::plane::CLAIM_PROBE
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
                    // Named at the site: a screen stops a unit for a hook's veto or an unreadable
                    // request, nothing else.
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
