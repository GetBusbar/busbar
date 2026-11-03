// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::canary::Canary;
use busbar_contract::caps::{
    Abort, AdminVerb, Admission, Admit, Admittance, Approve, Arrival, Audit, AuditFacts,
    Authenticate, Authenticated, CallId, CellError, Consumption, Decode, Dial, DurabilityLost,
    DurableWrite, Encode, Exit, Grant, Hold, HoldAccrual, HoldCell, HoldCellState, KernelSeal,
    Meter, Origin, OriginKind, Outcome, Pass, Posted, PostingFlags, PrincipalId, QuantitySource,
    ReasonCode, Refusal, Route, SeatVerdict, SessionId, Step, StepName, UnitEnd, UnitKey, Usage,
    UsageLine, VerifiedDestination, Verify, WriteMoney,
};

use crate::registry::Generation;
use crate::slice::{takes_lease, ConcurrencyGauge, GroupLeaseSlip, LeaseCell, IN_FLIGHT};

/// The kernel's own authority: the one place the tokens the units are lent are minted.
///
/// One of these exists per node, made at boot. It is not a capability the units can see; it is the
/// thing that hands them the capabilities, for the length of one call.
#[derive(Debug)]
pub struct Kernel {
    seal: KernelSeal,
    /// The per-request generation counter (#74). Bumped once per unit, so every request's proofs
    /// carry a generation distinct from the last, and a proof stamped for one request does not match
    /// another. A plain `u64` compared by the stages — no crypto on the hot path (#71).
    call_gen: AtomicU64,
}

impl Default for Kernel {
    fn default() -> Self {
        Kernel::new()
    }
}

impl Kernel {
    pub fn new() -> Self {
        Kernel {
            seal: crate::seal::acquire(),
            call_gen: AtomicU64::new(0),
        }
    }

    pub fn next_call(&self) -> CallId {
        let gen = self.call_gen.fetch_add(1, Ordering::Relaxed) % (u64::MAX - 1);
        CallId::seal(&self.seal, gen)
    }

    pub fn admit_token_for(&self, call: CallId) -> Grant<Admittance> {
        Grant::<Admittance>::mint_bound(&self.seal, call)
    }

    pub fn origin(&self, kind: OriginKind) -> Origin {
        Origin::seal(&self.seal, kind)
    }

    pub fn session_id(&self, id: u64) -> SessionId {
        SessionId::mint(&self.seal, id)
    }

    pub fn admit_token(&self) -> Grant<Admittance> {
        Grant::<Admittance>::mint(&self.seal)
    }

    pub fn admin_token(&self) -> Grant<AdminVerb> {
        Grant::<AdminVerb>::mint(&self.seal)
    }

    pub fn durability_token(&self) -> Grant<DurableWrite> {
        Grant::<DurableWrite>::mint(&self.seal)
    }

    pub fn ledger_token(&self) -> Grant<WriteMoney> {
        Grant::<WriteMoney>::mint(&self.seal)
    }

    pub fn usage_token(&self) -> Grant<Consumption> {
        Grant::<Consumption>::mint(&self.seal)
    }

    pub(crate) fn seal(&self) -> &KernelSeal {
        &self.seal
    }
}

/// What the loop knows about a unit that is not the money.
#[derive(Debug, Clone)]
pub struct UnitCtx {
    /// The per-request generation the unit's proofs are bound to (#74). A caller builds the
    /// context [`CallId::UNBOUND`]; the loop binds it at the unit's start ([`Kernel::next_call`])
    /// and mints every pass and grant it hands a stage for that call.
    pub call: CallId,
    /// The unit's key.
    pub key: UnitKey,
    /// Where it came from.
    pub origin: OriginKind,
    /// Its session, if it has one.
    pub session: Option<SessionId>,
    /// The registry generation it pinned when it started. The registry is built once at boot and
    /// never replaced, so every unit pins `Generation::FIRST` (see `registry`'s "Generations").
    pub generation: Generation,
    /// Whether it arrived on the administrative listener.
    pub admin_listener: bool,
    /// Whether every destination it may reach is a kernel verb, which is what makes it exempt from
    /// the concurrency gauge.
    pub kernel_verb_only: bool,
}

/// A running count a test rig keeps of what its unit spent, in nano-units.
///
/// NOT a money figure the exit reads. The exit spends and settles the hold by the settlement
/// writer's one `amount`; a second figure here could only disagree with it. No
/// production leg accrues onto this.
#[derive(Debug, Default)]
pub struct AccrualMeter {
    spent: AtomicU64,
}

impl AccrualMeter {
    pub fn new() -> Self {
        AccrualMeter::default()
    }

    pub fn accrue(&self, amount: u64) {
        self.spent.fetch_add(amount, Ordering::AcqRel);
    }

    pub fn total(&self) -> u64 {
        self.spent.load(Ordering::Acquire)
    }
}

pub use crate::settlement::{
    requests_drawn, requests_settled, settle_written, Evidence, FinishClass, StatusAt,
    WireStatusClass, Written, KERNEL_ACCRUAL_CLASS,
};

pub trait Units: UnitEnds {
    /// Consume host custody once, only at the actual hold's terminal posting.
    fn take_reserved_request_lineage(
        &self,
        _ctx: &UnitCtx,
    ) -> Option<crate::plane_driver::ReservedRequestLineage> {
        None
    }

    fn govern<'a>(
        &'a self,
        ctx: &'a UnitCtx,
        door: Door<'a>,
    ) -> impl Future<Output = Result<Governed, Refusal>> + Send + 'a;
}

impl<T: DoorSeats + UnitEnds + ?Sized> Units for T {
    fn govern<'a>(
        &'a self,
        ctx: &'a UnitCtx,
        door: Door<'a>,
    ) -> impl Future<Output = Result<Governed, Refusal>> + Send + 'a {
        by_seats(self, ctx, door)
    }
}

pub trait SeatedUnits: DoorSeats + UnitEnds {}

impl<T: DoorSeats + UnitEnds + ?Sized> SeatedUnits for T {}

pub trait DoorSeats: Sync {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival>;

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode>;

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate>;

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify>;

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve>;

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit>;
}

pub trait UnitEnds: Sync {
    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route>;

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter>;

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit>;

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit>;

    fn audited(&self, _ctx: &UnitCtx, _facts: AuditFacts, _pass: Pass<Audit>) {}

    fn encode(&self, token: &Pass<Encode>, ctx: &UnitCtx, outcome: &Outcome)
        -> SeatVerdict<Encode>;

    fn evidence(&self, ctx: &UnitCtx) -> Evidence;

    fn at_parent_exit(&self, _ctx: &UnitCtx, _accrual: &HoldAccrual) -> Result<(), Refusal> {
        Ok(())
    }
}

pub trait RouteAwait {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a>;

    fn abandoned(&self, ctx: &UnitCtx, ended: Ended);

    fn screen<'a>(&'a self, ctx: &'a UnitCtx) -> Screen<'a> {
        let _ = ctx;
        Box::pin(std::future::ready(Ok(())))
    }
}

pub type Screen<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), Refusal>> + Send + 'a>>;

pub type RouteLeg<'a> = std::pin::Pin<Box<dyn Future<Output = SeatVerdict<Route>> + Send + 'a>>;

struct Blocking<'u, U: ?Sized>(&'u U);

impl<U: Units + ?Sized> RouteAwait for Blocking<'_, U> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        let answer = self.0.route(token, ctx, destinations);
        Box::pin(std::future::ready(answer))
    }

    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
}

pub struct Run<'r> {
    pub cell: &'r HoldCell,

    pub parent: Option<&'r HoldCell>,

    pub leases: &'r LeaseCell,

    pub gauge: &'r ConcurrencyGauge,

    pub canary: &'r Canary,

    pub meter: &'r AccrualMeter,

    pub taps: Option<&'r dyn UnitTaps>,
}

impl std::fmt::Debug for Run<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Run")
            .field("cell", &self.cell)
            .field("parent", &self.parent)
            .field("leases", &self.leases)
            .field("gauge", &self.gauge)
            .field("canary", &self.canary)
            .field("meter", &self.meter)
            .field("taps", &self.taps.is_some())
            .finish()
    }
}

pub trait UnitTaps: Sync {
    fn audited(&self, ctx: &UnitCtx, facts: AuditFacts, pass: Pass<Audit>);

    fn ended_as(&self, ctx: &UnitCtx, outcome: Outcome);

    fn routed(&self, ctx: &UnitCtx, destinations: &[VerifiedDestination]);
}

/// How a unit finished, from the loop's point of view.
#[derive(Debug)]
pub enum Ended {
    /// The hold was taken and settled here.
    Settled {
        /// The sealed end, with its posting.
        end: UnitEnd,
        /// How many request slots the unit consumed — drawn at the door, never released.
        requests: u32,
        /// Whether the flat per-request fee posted.
        fee: u32,
    },
    /// Somebody else — the node's sweep — took the hold first and has already settled it. Doing
    /// anything here would be the second settlement of one unit.
    AlreadySettled,
}

fn bound(kernel: &Kernel, ctx: &UnitCtx) -> UnitCtx {
    let mut ctx = ctx.clone();
    if ctx.call == CallId::UNBOUND {
        ctx.call = kernel.next_call();
    }
    ctx
}

fn presented<S: Step>(pass: &Pass<S>, ctx: &UnitCtx) -> bool {
    pass.bound_to(ctx.call)
}

pub fn run_unit<U: Units + ?Sized>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
) -> Ended {
    let blocking = Blocking(units);
    block_on(run_unit_async(kernel, units, ctx, run, &blocking))
}

fn block_on<T>(f: impl Future<Output = T>) -> T {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(value) => break value,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

pub async fn run_unit_async<U: Units + ?Sized, R: RouteAwait + Sync>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    route: &R,
) -> Ended {
    let seal = &kernel.seal;
    let bound_ctx = bound(kernel, ctx);
    let ctx = &bound_ctx;

    run.canary.draft_accepted();

    let pending = HoldCount(Some(run.canary));
    let opened = open_to_door(seal, units, ctx, &run, Some(route)).await;
    pending.disarm();
    if !matches!(opened, Ok((Admission::Accrual(_), _))) {
        run.canary.hold_opened();
    }

    match opened {
        Err(refusal) => {
            let outcome =
                Outcome::Refused(refusal.step().unwrap_or(StepName::Admit), refusal.reason());
            sealed_end(seal, units, run.taps, ctx, &outcome, Some(&refusal));
            exit(kernel, units, ctx, run, outcome, false)
        }

        Ok((admission, destinations)) => {
            let (settling, refused_cell) = match admission {
                Admission::Accrual(accrual) => {
                    run.canary.accrual_taken();
                    (Settling::Parent(accrual), None)
                }

                Admission::ZeroHold => (Settling::Exit(false), None),

                Admission::Own(hold) => {
                    match run
                        .cell
                        .admit(hold, &Grant::<Admittance>::mint_bound(seal, ctx.call))
                    {
                        Ok(arrival) => {
                            drop_arrival(arrival);
                            (Settling::Exit(true), None)
                        }
                        Err(rejected) => {
                            let reason = if rejected.error == CellError::CallMismatch {
                                ReasonCode::Replayed
                            } else {
                                ReasonCode::InFlight
                            };
                            drop_arrival(rejected.hold);
                            (
                                Settling::Exit(true),
                                Some(Outcome::Failed(StepName::Admit, reason)),
                            )
                        }
                    }
                }
            };
            match refused_cell {
                Some(outcome) => terminal(kernel, units, ctx, run, outcome, settling),
                None => {
                    let taps = run.taps;
                    let mut abandoned = Abandoned {
                        kernel,
                        units,
                        route,
                        ctx,
                        ending: Some((run, settling)),
                    };
                    let outcome = under_hold(kernel, units, route, taps, ctx, &destinations).await;
                    abandoned.reached(outcome)
                }
            }
        }
    }
}

pub struct Door<'d> {
    pub(crate) seal: &'d KernelSeal,
    pub(crate) screens: Option<&'d (dyn RouteAwait + Sync)>,
}

impl<'d> Door<'d> {
    pub(crate) fn screen(&self, ctx: &'d UnitCtx) -> Option<Screen<'d>> {
        self.screens.map(|route| route.screen(ctx))
    }
}

impl std::fmt::Debug for Door<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Door")
            .field("screens", &self.screens.is_some())
            .finish_non_exhaustive()
    }
}

/// What the door answered a unit it let through ([`Units::govern`]): its admission, the destinations
/// Verify sealed (EMPTY for a challenge round, which never reaches Verify), and the slip the door
/// named its capped groups on — `None` for a challenge round, which draws no lease. Only the kernel
/// builds one, so only a kernel implementor answers the door other than seat by seat.
#[derive(Debug)]
pub struct Governed {
    pub(crate) admission: Admission,
    pub(crate) destinations: Vec<VerifiedDestination>,
    pub(crate) lease: Option<GroupLeaseSlip>,
}

pub async fn by_seats<'a, U: DoorSeats + ?Sized>(
    units: &'a U,
    ctx: &'a UnitCtx,
    door: Door<'a>,
) -> Result<Governed, Refusal> {
    let seal = door.seal;
    let authenticated = units
        .arrival(&Pass::<Arrival>::mint_bound(seal, ctx.call), ctx)
        .into_result(seal)
        .and_then(|_| {
            units
                .decode(&Pass::<Decode>::mint_bound(seal, ctx.call), ctx)
                .into_result(seal)
        })
        .and_then(|_| {
            units
                .authenticate(&Pass::<Authenticate>::mint_bound(seal, ctx.call), ctx)
                .into_result(seal)
        });

    let to_door = authenticated.map(|authenticated| async move {
        match authenticated {
            Authenticated::Challenge(_) => {
                let anonymous = PrincipalId::anonymous();

                let nowhere: [VerifiedDestination; 0] = [];
                let groups = GroupLeaseSlip::new();
                units
                    .approve(
                        &Pass::<Approve>::mint_bound(seal, ctx.call),
                        ctx,
                        &anonymous,
                        &nowhere,
                    )
                    .into_result(seal)
                    .and_then(|_| {
                        units
                            .admit(
                                &Pass::<Admit>::mint_bound(seal, ctx.call),
                                &Grant::<Admittance>::mint_bound(seal, ctx.call),
                                ctx,
                                &anonymous,
                                &nowhere,
                                &groups,
                            )
                            .into_result(seal)
                    })
                    .map(|_admitted| Governed {
                        admission: Admission::ZeroHold,
                        destinations: Vec::new(),
                        lease: None,
                    })
            }
            Authenticated::Principal(principal) => {
                let approved = units
                    .verify(
                        &Pass::<Verify>::mint_bound(seal, ctx.call),
                        &Grant::<Dial>::mint_bound(seal, ctx.call),
                        ctx,
                        &principal,
                    )
                    .into_result(seal)
                    .and_then(|destinations| {
                        units
                            .approve(
                                &Pass::<Approve>::mint_bound(seal, ctx.call),
                                ctx,
                                &principal,
                                &destinations,
                            )
                            .into_result(seal)
                            .map(|_| destinations)
                    });

                screened_by(approved, &door, ctx, seal)
                    .await
                    .and_then(|destinations| {
                        let groups = GroupLeaseSlip::new();
                        let admitted = units
                            .admit(
                                &Pass::<Admit>::mint_bound(seal, ctx.call),
                                &Grant::<Admittance>::mint_bound(seal, ctx.call),
                                ctx,
                                &principal,
                                &destinations,
                                &groups,
                            )
                            .into_result(seal);

                        admitted.map(|admission| Governed {
                            admission,
                            destinations,
                            lease: Some(groups),
                        })
                    })
            }
        }
    });
    door_answer(to_door).await
}

async fn open_to_door<U: Units + ?Sized>(
    seal: &KernelSeal,
    units: &U,
    ctx: &UnitCtx,
    run: &Run<'_>,
    screens: Option<&(dyn RouteAwait + Sync)>,
) -> Result<(Admission, Vec<VerifiedDestination>), Refusal> {
    let governed = units.govern(ctx, Door { seal, screens }).await;
    governed.map(|governed| {
        if let Some(groups) = &governed.lease {
            draw_lease(ctx, run, groups);
        }
        (governed.admission, governed.destinations)
    })
}

async fn screened_by<'d>(
    approved: Result<Vec<VerifiedDestination>, Refusal>,
    door: &Door<'d>,
    ctx: &'d UnitCtx,
    seal: &KernelSeal,
) -> Result<Vec<VerifiedDestination>, Refusal> {
    match approved {
        Ok(destinations) => match door.screen(ctx) {
            Some(screen) => screen
                .await
                .map(|()| destinations)
                .map_err(|refusal| screened(seal, ctx.call, refusal)),
            None => Ok(destinations),
        },
        Err(refusal) => Err(refusal),
    }
}

async fn door_answer<T>(
    to_door: Result<impl Future<Output = Result<T, Refusal>>, Refusal>,
) -> Result<T, Refusal> {
    match to_door {
        Ok(chain) => chain.await,
        Err(refusal) => Err(refusal),
    }
}

struct HoldCount<'c>(Option<&'c Canary>);

impl HoldCount<'_> {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for HoldCount<'_> {
    fn drop(&mut self) {
        if let Some(canary) = self.0 {
            canary.hold_opened();
        }
    }
}

fn screened(seal: &KernelSeal, call: CallId, refusal: Refusal) -> Refusal {
    match SeatVerdict::<Approve>::refuse(&Pass::<Approve>::mint_bound(seal, call), refusal.clone())
        .into_result(seal)
    {
        Err(stamped) => stamped,
        Ok(_) => refusal,
    }
}

/// How a session opener left the door.
#[derive(Debug)]
pub enum SessionOpen {
    /// The door passed. A session admits at [`Admission::ZeroHold`], so nothing was swapped into
    /// the cell and there is nothing to settle. The caller opens its live carrier next: every turn
    /// leg of the session is a route walk under this ONE admission, with this Route pass, inside
    /// the destination set Verify sealed at the open (K6).
    Admitted {
        /// The session's Route pass, for its turn legs.
        route: Pass<Route>,
        /// The destination set sealed at the open.
        destinations: Vec<VerifiedDestination>,
    },
    /// The door refused before any charge. The plane's own refusal was audited and encoded; nothing
    /// was charged and nothing settled.
    Refused,
}

pub async fn open_unit<U: Units + ?Sized>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
) -> SessionOpen {
    let seal = &kernel.seal;
    let bound_ctx = bound(kernel, ctx);
    let ctx = &bound_ctx;
    match open_to_door(seal, units, ctx, &run, None).await {
        Err(refusal) => {
            let outcome =
                Outcome::Refused(refusal.step().unwrap_or(StepName::Admit), refusal.reason());
            sealed_end(seal, units, run.taps, ctx, &outcome, Some(&refusal));
            SessionOpen::Refused
        }

        Ok((_admission, destinations)) => {
            let outcome = Outcome::Completed;
            sealed_end(seal, units, run.taps, ctx, &outcome, None);
            SessionOpen::Admitted {
                route: Pass::<Route>::mint_bound(seal, ctx.call),
                destinations,
            }
        }
    }
}

fn draw_lease(ctx: &UnitCtx, run: &Run<'_>, groups: &GroupLeaseSlip) {
    if takes_lease(ctx.origin, ctx.kernel_verb_only) {
        for bucket in std::iter::once(IN_FLIGHT).chain(groups.taken()) {
            run.gauge.record(&bucket);
            if !run.leases.take(bucket) {
                run.gauge.release(&bucket);
            }
        }

        if let Some(grant) = groups.grant_taken() {
            run.leases.hold_grant(grant);
        }
    }
}

enum Settling {
    Parent(HoldAccrual),

    Exit(bool),

    Converted,
}

struct Abandoned<'k, 'r, U: Units + ?Sized, R: RouteAwait> {
    kernel: &'k Kernel,
    units: &'k U,

    route: &'k R,
    ctx: &'k UnitCtx,

    ending: Option<(Run<'r>, Settling)>,
}

impl<U: Units + ?Sized, R: RouteAwait> Abandoned<'_, '_, U, R> {
    fn reached(&mut self, outcome: Outcome) -> Ended {
        match self.ending.take() {
            Some((run, settling)) => {
                terminal(self.kernel, self.units, self.ctx, run, outcome, settling)
            }

            None => Ended::AlreadySettled,
        }
    }
}

impl<U: Units + ?Sized, R: RouteAwait> Drop for Abandoned<'_, '_, U, R> {
    fn drop(&mut self) {
        if let Some((run, settling)) = self.ending.take() {
            let ended = terminal(
                self.kernel,
                self.units,
                self.ctx,
                run,
                Outcome::Aborted(Abort::Kernel {
                    reason: ReasonCode::ClientGone,
                }),
                settling,
            );
            self.route.abandoned(self.ctx, ended);
        }
    }
}

fn terminal<U: Units + ?Sized>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    outcome: Outcome,
    settling: Settling,
) -> Ended {
    let seal = &kernel.seal;

    let parent_gone = run
        .parent
        .is_some_and(|p| p.state() == HoldCellState::Taken);
    let (outcome, settling) = match settling {
        Settling::Parent(accrual) if parent_gone => match units.at_parent_exit(ctx, &accrual) {
            Err(no) => {
                let step = no.step().unwrap_or(StepName::Admit);
                (
                    Outcome::Failed(step, no.reason()),
                    Settling::Parent(accrual),
                )
            }
            Ok(()) => {
                let admit = Grant::<Admittance>::mint_bound(seal, ctx.call);
                match accrual.convert_at_parent_exit(&admit) {
                    Ok(own) => {
                        drop_arrival(run.cell.admit(own, &admit).unwrap_or_else(|lost| lost.hold));
                        (outcome, Settling::Converted)
                    }

                    Err(accrual) => (
                        Outcome::Failed(StepName::Admit, ReasonCode::Replayed),
                        Settling::Parent(accrual),
                    ),
                }
            }
        },
        other => (outcome, other),
    };
    sealed_end(seal, units, run.taps, ctx, &outcome, None);
    match settling {
        Settling::Exit(reached_admitted) => {
            exit(kernel, units, ctx, run, outcome, reached_admitted)
        }

        Settling::Converted => match exit(kernel, units, ctx, run, outcome, false) {
            Ended::Settled { end, .. } => Ended::Settled {
                end,
                requests: 0,
                fee: 0,
            },
            ended => ended,
        },
        Settling::Parent(accrual) => {
            let taken = run.cell.take(&Grant::<Exit>::mint_bound(seal, ctx.call));
            run.leases.release_all(run.gauge);
            match taken {
                None => Ended::AlreadySettled,
                Some(arrival) => {
                    drop_arrival(arrival);

                    let ledger = Grant::<WriteMoney>::mint_bound(seal, ctx.call);
                    let parent = run.parent.unwrap_or(run.cell);
                    let posted = match Posted::into_parent(accrual, parent, &ledger) {
                        Ok(posted) => posted,
                        Err(missed) => Posted::settle_late(missed, &ledger),
                    };
                    run.canary.settled();
                    Ended::Settled {
                        end: UnitEnd::seal(
                            &Grant::<Exit>::mint_bound(seal, ctx.call),
                            outcome,
                            Ok(posted),
                        ),

                        requests: 0,
                        fee: 0,
                    }
                }
            }
        }
    }
}

async fn under_hold<U: Units + ?Sized, R: RouteAwait>(
    kernel: &Kernel,
    units: &U,
    route: &R,
    taps: Option<&dyn UnitTaps>,
    ctx: &UnitCtx,
    destinations: &[VerifiedDestination],
) -> Outcome {
    let seal = &kernel.seal;
    let token = Pass::<Route>::mint_bound(seal, ctx.call);

    if !presented(&token, ctx) {
        Outcome::Failed(StepName::Route, ReasonCode::Replayed)
    } else {
        if let Some(taps) = taps {
            taps.routed(ctx, destinations);
        }
        let leg = route.route_leg(&token, ctx, destinations).await;
        match leg.into_result(seal) {
            Err(refusal) => {
                Outcome::Failed(refusal.step().unwrap_or(StepName::Route), refusal.reason())
            }
            Ok(_) => {
                let provisional = Outcome::Completed;
                match units
                    .meter(
                        &Pass::<Meter>::mint_bound(seal, ctx.call),
                        &Grant::<Consumption>::mint_bound(seal, ctx.call),
                        ctx,
                        &provisional,
                        destinations,
                    )
                    .into_result(seal)
                {
                    Ok(_) => Outcome::Completed,
                    Err(refusal) => {
                        Outcome::Failed(refusal.step().unwrap_or(StepName::Meter), refusal.reason())
                    }
                }
            }
        }
    }
}

fn sealed_end<U: Units + ?Sized>(
    seal: &KernelSeal,
    units: &U,
    taps: Option<&dyn UnitTaps>,
    ctx: &UnitCtx,
    outcome: &Outcome,
    refused: Option<&Refusal>,
) {
    let pass = audit_pass(seal, ctx.call);
    let sealed = match refused {
        Some(refusal) => units.audit_refused(&pass, ctx, refusal),
        None => units.audit(&pass, ctx, outcome),
    };
    if let Ok(facts) = sealed.into_result(seal) {
        match taps {
            Some(taps) => taps.audited(ctx, facts, pass),
            None => units.audited(ctx, facts, pass),
        }
    }
    if let Some(taps) = taps {
        taps.ended_as(ctx, *outcome);
    }
    let _bytes = units
        .encode(&Pass::<Encode>::mint_bound(seal, ctx.call), ctx, outcome)
        .into_result(seal);
}

pub(crate) fn audit_pass(seal: &KernelSeal, call: CallId) -> Pass<Audit> {
    Pass::<Audit>::mint_bound(seal, call)
}

pub fn verb_audit_pass(kernel: &Kernel) -> Pass<Audit> {
    audit_pass(&kernel.seal, kernel.next_call())
}

fn drop_arrival(_hold: Hold) {}

pub fn exit<U: Units + ?Sized>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    outcome: Outcome,
    reached_admitted: bool,
) -> Ended {
    let seal = &kernel.seal;

    let bound_ctx = bound(kernel, ctx);
    let ctx = &bound_ctx;
    let taken = run.cell.take(&Grant::<Exit>::mint_bound(seal, ctx.call));
    run.leases.release_all(run.gauge);
    match taken {
        None => Ended::AlreadySettled,
        Some(hold) => {
            let evidence = units.evidence(ctx);
            let Written { amount, flags, fee } = settle_written(&outcome, &evidence);
            let drawn = match crate::settlement::requests_drawn_with_lineage(
                ctx,
                hold.principal(),
                evidence.upstream_candidate,
                units.take_reserved_request_lineage(ctx),
            ) {
                Ok(drawn) => drawn,
                Err(reason) => {
                    drop_arrival(hold);
                    run.canary.settled();
                    return Ended::Settled {
                        end: UnitEnd::seal(
                            &Grant::<Exit>::mint_bound(seal, ctx.call),
                            Outcome::Failed(StepName::Admit, reason),
                            Err(DurabilityLost::observed(
                                &Grant::<DurableWrite>::mint_bound(seal, ctx.call),
                                StepName::Admit,
                            )),
                        ),
                        requests: 0,
                        fee: 0,
                    };
                }
            };
            let requests = requests_settled(reached_admitted, drawn);
            let class = evidence.class.unwrap_or(KERNEL_ACCRUAL_CLASS);
            let lines = vec![UsageLine {
                class,
                quantity: amount,
                // The figure the plane reported, written as it was told.
                source: QuantitySource::Count,
                estimated: flags.contains(PostingFlags::ESTIMATED),
            }];
            let usage_token = Grant::<Consumption>::mint_bound(seal, ctx.call);
            let usage = if flags.contains(PostingFlags::ESTIMATED) {
                Usage::estimate(&usage_token, lines)
            } else {
                Usage::report(&usage_token, lines)
            };
            let posted = match usage {
                Ok(usage) => Ok(Posted::settle(
                    hold,
                    amount,
                    &usage,
                    &Grant::<WriteMoney>::mint_bound(seal, ctx.call),
                )
                .flagged(flags)),

                Err(_) => {
                    drop_arrival(hold);
                    Err(DurabilityLost::observed(
                        &Grant::<DurableWrite>::mint_bound(seal, ctx.call),
                        StepName::Meter,
                    ))
                }
            };
            run.canary.settled();
            Ended::Settled {
                end: UnitEnd::seal(&Grant::<Exit>::mint_bound(seal, ctx.call), outcome, posted),
                requests,
                fee,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/call_binding_tests.rs"]
mod call_binding_tests;

#[cfg(test)]
#[path = "tests/teller_verified_destination_tests.rs"]
mod teller_verified_destination_tests;
