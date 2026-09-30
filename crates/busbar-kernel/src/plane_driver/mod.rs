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
//! | authenticate → verify → approve → admit | — | the kernel steps, unchanged |
//! | refused | `refusal` | the kernel steps audit the refusal; the plane renders it; nothing was charged |
//! | route | the `on_piece` pump ([`route`]) | attempts, backpressure, the far end, cancel |
//! | meter, audit, exit | — | the kernel steps and the loop's one exit |
//!
//! The pure ops (`arrive`, `refusal`) and the driver's own `cancel` between ops cross ticketless
//! on the caller's task: they never pend, and the loop's decode and encode seats answer in place.
//! `on_piece`, which may pend, crosses on the dispatcher's worker for the unit's ticket and is
//! awaited, so the pump never parks a runtime thread.
//!
//! The driver moves no money: units, cancel bills and abandoned ends go to the [`MoneySeam`].

mod cancel;
mod epoch;
mod far_end;
mod money;
mod route;

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, Outcome as AbiOutcome, Span, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    reason_code, ArriveIn, ArriveOut, OutField, RefusalIn, RefusalOut, RefusalStatus, UnitCount,
    REFUSAL_ANY_DIALECT, REFUSAL_GATE, REFUSAL_KERNEL,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{
    Admit, Admittance, Approve, Arrival as ArrivalStep, Audit, Authenticate, Consumption, Decode,
    Dial, Encode, Grant, HoldAccrual, Meter, OpClassId, Outcome, Pass, PrincipalId, ReasonCode,
    Refusal, Route, RoutePlan, SeatVerdict as StepAnswer, VerifiedDestination, Verify,
};
use busbar_contract::plane_calls::PlaneCalls;
use tokio::sync::watch;

pub use cancel::{CancelBill, Checkpoint, MoneySeam};
pub use epoch::FlushEpoch;
pub use far_end::{AuthBinding, Egress, EgressFarEnd, MemberRoute, UnitRoute};
pub use money::{EndPost, PlaneMoney, UnitMoney};
pub use route::{CallerEnd, FarEnd, FarPiece, OutboundRequest, Pick};

use crate::slice::GroupLeaseSlip;
use crate::teller::{Ended, Evidence, RouteAwait, RouteLeg, UnitCtx, Units};

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
    pub caller_refs: Option<Arc<busbar_kernel_identity::caller_ref::CallerRefKey>>,
}

impl DriverConfig {
    /// The status a refusal for `reason` wears in `dialect`: the plane's row for that dialect,
    /// else its row for every dialect, else [`DriverConfig::status_of`].
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
}

impl std::fmt::Debug for PlaneDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneDriver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PlaneDriver {
    /// The driver of one open plane instance, reached through `calls`.
    pub fn new(
        calls: Arc<dyn PlaneCalls>,
        config: DriverConfig,
        money: Arc<dyn MoneySeam>,
    ) -> Self {
        PlaneDriver {
            calls,
            config,
            money,
            buried: Mutex::new(Vec::new()),
            reload: watch::channel(false).0,
        }
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

    /// The driver's own ticketless `cancel` of `ticket`, on the calling task: its disposition, or
    /// `None` when it did not answer READY.
    fn cancel_now(&self, ticket: Ticket) -> Option<u32> {
        self.calls.cancel(ticket)
    }
}

/// A head's fields, name and value, in order.
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
    rendered: Option<Rendered>,
    facts: cancel::Facts,
    bill: Option<CancelBill>,
    /// The caller's opaque reference, derived at verify (never the principal itself).
    caller_ref: Vec<u8>,
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
        if outcome == AbiOutcome::Refused {
            // The dispatcher judged the answer: a nonzero code and a 4xx status.
            self.lock().declined = Some((o.refusal, o.refusal_status));
        }
        (outcome == AbiOutcome::Ready).then(|| Decoded {
            op_class: o.op_class,
            principal_need: o.principal_need,
            dialect: o.dialect,
            expected: units
                .iter()
                .take(o.units_written as usize)
                .copied()
                .collect(),
        })
    }

    /// The plane renders a refusal (`refusal`, ticketless, one re-call when short); the kernel's
    /// generic failure, with no body, when it cannot.
    fn render(&self, reason: ReasonCode) -> Rendered {
        self.render_as(reason, None)
    }

    /// [`Self::render`], or under the status and Retry-After the walk chose (an exhaustion
    /// terminal's `walk`), which the plane renders in its dialect.
    fn render_as(&self, reason: ReasonCode, walk: Option<(u32, Option<u32>)>) -> Rendered {
        let (unit, dialect, declined) = {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
            let declined = st.declined.filter(|_| reason == ReasonCode::DecodeFailed);
            (st.unit, dialect, declined)
        };
        // A refusal the plane's own `arrive` decided wears the status it stated; the walk's
        // terminal wears its own; every other one the plane's stated row or the kernel's default.
        let status = match (walk, declined) {
            (Some((status, _)), _) => status,
            (None, Some((_, status))) => status,
            (None, None) => self.driver.config.status(dialect, reason),
        };
        let retry_after_s = walk.and_then(|(_, r)| r).unwrap_or(0);
        let text = reason.as_str();
        let caps = self.driver.config.caps;
        let (mut reply, mut fields, mut arena) = (
            vec![0u8; caps.reply],
            vec![NO_FIELD; caps.fields],
            vec![0u8; caps.arena],
        );
        let mut input = RefusalIn {
            cause: if reason == ReasonCode::HookVeto {
                REFUSAL_GATE
            } else {
                REFUSAL_KERNEL
            },
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
            unit,
            plane_code: declined.map_or(0, |(code, _)| code),
            retry_after_s,
            target: AbiStr::over(&self.arrival.target),
            ..blank_in()
        };
        let mut o: RefusalOut = blank_out();
        let outcome = self
            .driver
            .calls
            .refusal(&mut input, &mut o, &mut |short, i| {
                reply.resize((short.reply_needed as usize).max(reply.len()), 0);
                fields.resize((short.fields_needed as usize).max(fields.len()), NO_FIELD);
                arena.resize((short.arena_needed as usize).max(arena.len()), 0);
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
        let span = |s: Span| {
            let start = s.offset as usize;
            arena
                .get(start..start.saturating_add(s.len as usize))
                .unwrap_or_default()
                .to_vec()
        };
        Rendered {
            status,
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
}

impl<S: Units + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    /// S3, the route step: the pump over the unit's own ticket, then the cancel the driver makes
    /// itself on a deadline, a cut or a reload.
    async fn route_async(&self, token: &Pass<Route>, ctx: &UnitCtx) -> StepAnswer<Route> {
        let d = self.driver;
        d.sweep();
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
            self.arrival.body.clone(),
        );
        {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |d| d.dialect);
            let caller_ref = st.caller_ref.clone();
            drop(st);
            run.lend_unit(self.arrival.claim, dialect, &caller_ref);
        }
        let end = self.attempts(&mut run).await;
        let answer = match end {
            route::End::Done => StepAnswer::proceed(token, RoutePlan::default()),
            route::End::Failed(reason) => StepAnswer::refuse(token, Refusal::new(reason)),
            route::End::Exhausted(status, retry_after) => {
                // THE WALK'S EXHAUSTION TERMINAL: its status and its Retry-After floor, handed to
                // the plane's `refusal` (RefusalIn.retry_after_s), which renders them in its dialect.
                let rendered = self.render_as(ReasonCode::BreakerOpen, Some((status, retry_after)));
                self.lock().rendered = Some(rendered);
                StepAnswer::refuse(token, Refusal::new(ReasonCode::BreakerOpen))
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

/// The seats the kernel's own steps answer, forwarded to `self.steps` unchanged: one line per
/// seat, so the plane's own seats (decode, verify, route, encode) are the only bodies in the impl.
macro_rules! forward_to_steps {
    ($($seat:ident($($arg:ident: $ty:ty),* $(,)?) -> $answer:ty;)*) => {$(
        fn $seat(&self, $($arg: $ty),*) -> $answer {
            self.steps.$seat($($arg),*)
        }
    )*};
}

impl<S: Units + Sync, F: FarEnd, C: CallerEnd> Units for PlaneUnits<'_, S, F, C> {
    forward_to_steps! {
        arrival(token: &Pass<ArrivalStep>, ctx: &UnitCtx) -> StepAnswer<ArrivalStep>;
        authenticate(token: &Pass<Authenticate>, ctx: &UnitCtx) -> StepAnswer<Authenticate>;
        approve(token: &Pass<Approve>, ctx: &UnitCtx, principal: &PrincipalId,
            destinations: &[VerifiedDestination]) -> StepAnswer<Approve>;
        admit(token: &Pass<Admit>, admit: &Grant<Admittance>, ctx: &UnitCtx, principal: &PrincipalId,
            destinations: &[VerifiedDestination], leases: &GroupLeaseSlip) -> StepAnswer<Admit>;
        meter(token: &Pass<Meter>, usage: &Grant<Consumption>, ctx: &UnitCtx, provisional: &Outcome,
            destinations: &[VerifiedDestination]) -> StepAnswer<Meter>;
        audit(token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> StepAnswer<Audit>;
        audit_refused(token: &Pass<Audit>, ctx: &UnitCtx, refusal: &Refusal) -> StepAnswer<Audit>;
        evidence(ctx: &UnitCtx) -> Evidence;
        at_parent_exit(ctx: &UnitCtx, accrual: &HoldAccrual) -> Result<u64, Refusal>;
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
                let rendered = self.render(reason);
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

impl<S: Units + Sync, F: FarEnd, C: CallerEnd> RouteAwait for PlaneUnits<'_, S, F, C> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        _destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        Box::pin(self.route_async(token, ctx))
    }

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended) {
        self.driver.money.abandoned(ctx, ended);
    }
}
