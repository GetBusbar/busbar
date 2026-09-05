// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loop. Ten steps, two audit doors, one exit.
//!
//! Think of a bank teller. Can this person do these things, in this order? If so, do them — and
//! post it. Every unit of work this node performs, whatever transport it arrived on and whatever
//! protocol it turns out to be, runs through [`run_unit`] and through nothing else.
//!
//! ## The order is fixed twice
//!
//! Once by the source below, which reads top to bottom, and once by the types: each step's answer
//! can only be built with that step's own token, the hold can only be opened with the door's token,
//! and the end can only be sealed with the exit's. A step cannot answer a question it was not
//! asked, and no step but the last can end a unit.
//!
//! ## The two audit doors
//!
//! A unit that never passed the door is audited WITHOUT a hold: nothing was charged, and there is
//! nothing to settle beyond the arrival hold the table minted. A unit that passed is audited WITH
//! its hold, because the caller was charged and the record has to say what for. Both doors lead to
//! the same exit.
//!
//! ## The one exit
//!
//! Every end — completed, refused, failed, aborted, timed out — leaves through [`exit`]. It takes
//! the hold out of the cell by compare-and-set, releases the unit's concurrency leases in the same
//! breath, settles per the table below and seals the end. Two callers hold a key to that cell: this
//! path, and the node's sweep. Whichever arrives second is told the unit is already settled, and
//! does nothing. There is no third.
//!
//! ## The one await
//!
//! Route is the only step that touches the wire, so it is the only step that waits on anything: the
//! other nine read what is already in hand and answer in place. The loop is therefore written once,
//! as [`run_unit_async`], with exactly one await in it — the Route leg — and reached two ways.
//!
//! A caller whose Route answers in place calls [`run_unit`], which drives that same body with a leg
//! that is ready on its first poll: one loop, one order of steps, no thread parked anywhere. A
//! caller whose Route awaits an upstream calls [`run_unit_async`] on its own runtime and holds
//! nothing while the upstream thinks — no blocking-pool thread, so the node's in-flight ceiling is
//! the in-flight table's and not the size of a thread pool.
//!
//! Awaiting is also what makes a unit CANCELLABLE. A client that goes away drops the loop's future,
//! and because the loop awaits in exactly one place it is dropped in exactly one place: inside
//! Route, with the hold in the cell and the leases drawn. [`Abandoned`] stands there. It owns
//! everything the terminal needs, so a dropped unit leaves through the SAME audit door, the same
//! settle and the same exit a finished one leaves through — named for what happened, the client
//! went away — and the cell is emptied and the leases released before the loop's frame is gone.
//! ## No early exits
//!
//! Nothing in this file uses `?` and nothing returns early. Not style: a `?` in the middle of a
//! loop that is holding a reservation is a path where the hold is dropped instead of settled, and
//! "every unit posts exactly once" has to be readable in the shape of the code, not just true.

use std::future::Future;

use busbar_caps::{
    Abort, AdminToken, Admission, Admit, AdmitToken, Approve, Arrival, Audit, Authenticate,
    Authenticated, Canary, Decision, Decode, DurabilityLost, Encode, ExitToken, Hold, HoldAccrual,
    HoldCell, KernelSeal, LedgerToken, Meter, MeterClassId, Origin, OriginKind, Outcome, Posted,
    PostingFlags, PrincipalId, QuantitySource, ReasonCode, Refusal, Route, SessionId, StepName,
    TransportKeyToken, TrustToken, UnitEnd, UnitKey, UnitToken, Usage, UsageLine, UsageToken,
    VerifiedDestination, Verify,
};

use crate::registry::Generation;
use crate::slice::{ConcurrencyGauge, LeaseSet};

/// The kernel's own authority: the one place the tokens the units are lent are minted.
///
/// One of these exists per node, made at boot. It is not a capability the units can see; it is the
/// thing that hands them the capabilities, for the length of one call.
#[derive(Debug)]
pub struct Kernel {
    seal: KernelSeal,
}

impl Default for Kernel {
    fn default() -> Self {
        Kernel::new()
    }
}

impl Kernel {
    /// Take the seal. Boot only.
    pub fn new() -> Self {
        Kernel {
            seal: KernelSeal::acquire_for_kernel(),
        }
    }

    /// Seal an origin, which nothing outside the kernel can construct.
    pub fn origin(&self, kind: OriginKind) -> Origin {
        Origin::seal(&self.seal, kind)
    }

    /// Mint a session id.
    pub fn session_id(&self, id: u64) -> SessionId {
        SessionId::mint(&self.seal, id)
    }

    /// The door's token, as the loop lends it.
    ///
    /// The admission unit is handed one of these for the length of its call, and that is how every
    /// hold in the system is opened — including the arrival hold, which the in-flight table now
    /// asks the door for rather than opening itself. This is the seam that hands the unit its
    /// token, and it is a named symbol precisely so the source scan can see every use of it. The
    /// batteries name it too, to drive the door directly and prove what the cell does under a race.
    pub fn admit_token(&self) -> AdmitToken<Admit> {
        AdmitToken::<Admit>::mint(&self.seal)
    }

    /// The transport-key unit's token, as the composition root lends it.
    ///
    /// The one token minted OUTSIDE the loop. Keys are resolved at listen, dial and upgrade, none
    /// of which is a step of a unit, so there is no step whose token could stand in — and without
    /// this the unit's `provision_server` and `provision_client` have a parameter no caller in the
    /// tree can supply, which is why the only thing that ever registered a listener's TLS config
    /// was the transport's own tests.
    ///
    /// Kept beside `admit_token` and named the same way, so the source scan that accounts for every
    /// mint sees this one too.
    pub fn transport_key_token(&self) -> TransportKeyToken {
        TransportKeyToken::mint(&self.seal)
    }

    /// The verbs unit's token, as the composition root lends it.
    ///
    /// The second token minted outside the loop, and for the same reason as the first: a kernel
    /// verb is a Route DESTINATION rather than a step of its own, so there is no step whose token
    /// could stand in, and without this the verbs unit's `execute` has a parameter no caller in the
    /// tree can supply. That was true of `provision_server` until `transport_key_token` existed and
    /// it is true of `execute` until this does.
    ///
    /// Kept beside the other two and named the same way, so the source scan that accounts for every
    /// mint sees this one too.
    pub fn admin_token(&self) -> AdminToken {
        AdminToken::mint(&self.seal)
    }

    /// The seal itself, for the other two places in the kernel that mint tokens: the recovery
    /// module, which materialises a hold from a journal record, and the node's sweep, which is the
    /// second and last holder of an exit token.
    pub(crate) fn seal(&self) -> &KernelSeal {
        &self.seal
    }
}

/// What the loop knows about a unit that is not the money.
#[derive(Debug, Clone)]
pub struct UnitCtx {
    /// The unit's key.
    pub key: UnitKey,
    /// Where it came from.
    pub origin: OriginKind,
    /// Its session, if it has one.
    pub session: Option<SessionId>,
    /// The registry generation it pinned when it started, so it finishes against what it started
    /// with even while a reload installs a replacement.
    pub generation: Generation,
    /// Whether it arrived on the administrative listener.
    pub admin_listener: bool,
    /// Whether every destination it may reach is a kernel verb, which is what makes it exempt from
    /// the concurrency gauge.
    pub kernel_verb_only: bool,
}

/// The kernel's running total of what a unit has spent, in nano-units.
///
/// The hold itself lives inside the cell where nothing can borrow it mutably, so the loop counts
/// here as the unit accrues and applies the total to the hold at the exit, where the hold is out of
/// the cell and owned. An accrual is never lost by this: the total is atomic and the exit reads it
/// after the compare-and-set that took the hold.
#[derive(Debug, Default)]
pub struct AccrualMeter {
    spent: std::sync::atomic::AtomicU64,
    headroom: std::sync::atomic::AtomicU64,
}

impl AccrualMeter {
    /// A meter reading zero, with no headroom offered.
    pub fn new() -> Self {
        AccrualMeter::default()
    }

    /// Add a spend.
    pub fn accrue(&self, amount: u64) {
        self.spent
            .fetch_add(amount, std::sync::atomic::Ordering::AcqRel);
    }

    /// What the unit has spent so far.
    pub fn total(&self) -> u64 {
        self.spent.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Say how far the unit's reservation may still be grown, in nano-units.
    ///
    /// The loop cannot work this out: it is what the principal's slice has left in the window, and
    /// only the plane's own leg holds the chain that answers. So the leg offers it here, while it is
    /// running, and the exit reads it when it applies the accrual to the hold. A leg that offers
    /// nothing gets the safe answer — the reservation does not grow and the excess is carried —
    /// which is a unit that still runs and still posts, never one that is refused.
    ///
    /// Offered rather than added: the last word wins, because the figure is a reading of the window
    /// and not a quantity that accumulates.
    pub fn offer_headroom(&self, nanos: u64) {
        self.headroom
            .store(nanos, std::sync::atomic::Ordering::Release);
    }

    /// What the leg said the reservation may still grow by.
    pub fn headroom(&self) -> u64 {
        self.headroom.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Where a transport reports a status, what it reported, and what the plane made of the ending.
///
/// All three are the contract's own. They are plugin-visible: a transport declares where its status
/// arrives, a plane declares how a unit finished, and the settlement table below reads both. A
/// kernel-local restatement of any of them would be a second spelling of a value that crosses the
/// plugin boundary in both directions.
pub use busbar_contract::{FinishClass, StatusAt, StatusClass};

/// Everything the settlement table reads.
///
/// Deliberately plain data: the table is a pure function of this, so it can be read as a table and
/// tested as one, row by row, with no loop and no clock anywhere near it.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// What the destination reported, where a locator found it.
    pub located: Option<u64>,
    /// What the kernel counted while the unit ran — the floor.
    pub accrued_floor: u64,
    /// Whether a present rate card requires a locator for a class it prices.
    pub locator_required: bool,
    /// Whether the stream's end carried an error signal in the protocol's own terms.
    pub terminal_error: bool,
    /// Whether this hold came back from a journal record after a crash.
    pub recovered: bool,
    /// Whether the record showed the unit had dispatched before the crash.
    pub dispatched: bool,
    /// What the last checkpoint recorded as accrued.
    pub checkpointed: u64,
    /// Two REPORTED sources for one class family that disagree beyond tolerance.
    pub variance: Option<(u64, u64)>,
    /// The two priced readings of a three-way lane cross-check that did not agree.
    pub lane_mismatch: Option<(u64, u64)>,
    /// Whether the settle record itself was lost after value was delivered.
    pub settle_record_lost: bool,
    /// Which class the settled amount is reported against.
    pub class: Option<MeterClassId>,
    /// Whether the verified set contained an upstream candidate, which is what makes a client unit
    /// draw a request slot.
    pub upstream_candidate: bool,
    /// Everything the flat fee is decided from.
    pub fee: FeeEvidence,
}

/// The settlement table, as one pure function.
///
/// Every row of it says the same thing in a different situation: **post the lower evidence, mark
/// it, and put it where someone will look at it.** Nothing here ever resolves an ambiguity in the
/// house's favour, and nothing here is silent about having resolved one.
///
/// The rows, in the order they are decided:
///
/// 1. **Recovered from a journal record.** If the record shows the unit had dispatched, post the
///    last checkpointed accrual — zero if there never was one — marked recovered. If it had not
///    dispatched, nothing happened: post zero, marked void.
/// 2. **A three-way lane mismatch.** The request said one lane, the destination another, the
///    response a third. Post the cheaper reading, marked disputed.
/// 3. **Two reported sources disagreeing beyond tolerance.** Post the lower, marked disputed.
/// 4. **Completed with a located figure.** Post what the destination reported.
/// 5. **Completed with a required locator missing.** Post ZERO — an upstream that reported no usage
///    is billed nothing — and keep the kernel's floor as internal evidence on the disputes report.
/// 6. **A live end that is not completed, with a located figure.** Post it, unless the stream ended
///    with an error signal, in which case post zero.
/// 7. **A live end that is not completed, with nothing located.** Post the kernel's own floor,
///    marked estimated.
///
/// A lost settle record adds its own mark on top of whichever row applied: the posting is retained
/// and re-appended, and it is not forgotten in the meantime.
pub fn settle_amount(end: &Outcome, evidence: &Evidence) -> (u64, PostingFlags) {
    let (amount, flags) = if evidence.recovered {
        if evidence.dispatched {
            (evidence.checkpointed, PostingFlags::RECOVERED)
        } else {
            (0, PostingFlags::VOIDED)
        }
    } else if let Some((left, right)) = evidence.lane_mismatch {
        (left.min(right), PostingFlags::METER_DISPUTED)
    } else if let Some((left, right)) = evidence.variance {
        (left.min(right), PostingFlags::METER_DISPUTED)
    } else if end.is_completed() {
        match evidence.located {
            Some(located) => (located, PostingFlags::NONE),
            None if evidence.locator_required => (
                0,
                PostingFlags::ESTIMATED.with(PostingFlags::METER_DISPUTED),
            ),
            None => (0, PostingFlags::NONE),
        }
    } else {
        match evidence.located {
            Some(_) if evidence.terminal_error => (0, PostingFlags::NONE),
            Some(located) => (located, PostingFlags::NONE),
            None => (evidence.accrued_floor, PostingFlags::ESTIMATED),
        }
    };
    let flags = if evidence.settle_record_lost {
        flags.with(PostingFlags::UNPOSTED)
    } else {
        flags
    };
    (amount, flags)
}

/// Everything the flat per-request fee is decided from.
#[derive(Debug, Clone, Copy, Default)]
pub struct FeeEvidence {
    /// Whether this is a client unit that opened or ran as a one-shot. A provider push through a
    /// session's own upstream is not, and posts no fee.
    pub client_open_or_one_shot: bool,
    /// Whether the route selected an upstream leg at all. It is the KIND that decides, not the
    /// price: with no rate card the fee still posts.
    pub selected_upstream: bool,
    /// Whether the kernel relayed the first response frame to the client. A status frame with an
    /// empty body counts.
    pub relayed_first_response_frame: bool,
    /// Where this transport reports its status, if it reports one. `None` means the transport
    /// contributes no status leg at all and the plane's finish decides alone; `Some` with no
    /// `status` below means the frame that would have carried it never arrived.
    pub status_at: Option<StatusAt>,
    /// The status class at the frame the transport reports it on.
    pub status: Option<StatusClass>,
    /// The plane's own verdict.
    pub finish: Option<FinishClass>,
}

/// Decide the flat fee, and say whether the two sources of truth disagreed.
///
/// The fee is decided at the first frame the client actually saw, and it is never reversed by a
/// later abort: a stream that dies halfway through a good response was still a good response at the
/// moment it started. Where the transport reports a status AND the plane reports a finish, the two
/// have to agree; where they do not, the LOWER count is posted and the posting is disputed, which
/// is what makes a plane that lies about its finish visible rather than profitable.
///
/// A transport that says WHERE its status is reported and then reports none has lost the evidence:
/// the stream ended before the frame carrying it. Nothing is billed, and a plane claiming a clean
/// finish over a status that never arrived is disputed.
pub fn fee_count(evidence: &FeeEvidence) -> (u32, PostingFlags) {
    let eligible = evidence.client_open_or_one_shot
        && evidence.selected_upstream
        && evidence.relayed_first_response_frame;
    let by_status = evidence.status.map(|status| status == StatusClass::Success);
    let by_finish = evidence.finish.map(|finish| finish != FinishClass::Error);
    // A transport that declares WHERE its status is reported and then does not report one is a
    // stream that died before the frame carrying it — most often a trailer. The status is the
    // evidence the fee is decided from, so a missing one posts nothing; a plane that says the unit
    // finished cleanly anyway is the second source disagreeing, and that is a dispute.
    let missing_status = evidence.status_at.is_some() && evidence.status.is_none();
    // A plane that reports a PARTIAL answer against a missing status is telling the same story the
    // transport is: the stream stopped early. A plane that reports a WHOLE one is not, and that
    // disagreement is what the dispute flag is for.
    let claims_whole = matches!(
        evidence.finish,
        Some(FinishClass::Complete | FinishClass::TurnComplete)
    );
    match (eligible, missing_status, by_status, by_finish) {
        (false, _, _, _) => (0, PostingFlags::NONE),
        (true, true, _, _) if claims_whole => (0, PostingFlags::METER_DISPUTED),
        (true, true, _, _) => (0, PostingFlags::NONE),
        (true, _, Some(status_ok), Some(finish_ok)) if status_ok != finish_ok => {
            (0, PostingFlags::METER_DISPUTED)
        }
        (true, _, Some(true), _) => (1, PostingFlags::NONE),
        (true, _, Some(false), _) => (0, PostingFlags::NONE),
        (true, _, None, Some(finish_ok)) => (u32::from(finish_ok), PostingFlags::NONE),
        (true, _, None, None) => (1, PostingFlags::NONE),
    }
}

/// How many request slots a unit draws at the door.
///
/// A client unit whose verified set contains an upstream draws one; everything else draws none, so
/// a provider push consumes no client's slot.
pub fn requests_drawn(origin: OriginKind, upstream_candidate: bool) -> u32 {
    u32::from(origin == OriginKind::Client && upstream_candidate)
}

/// How many request slots a unit settles at.
///
/// The drawn quantity, for every unit whose hold cell reached admitted — and it is NEVER released,
/// whatever the unit's end. That is the rule that makes it impossible to escape a cap by failing:
/// a thousand failed requests consume a thousand slots and post no fee at all.
pub fn requests_settled(reached_admitted: bool, drawn: u32) -> u32 {
    if reached_admitted {
        drawn
    } else {
        0
    }
}

/// The seam every unit behind a sealed trait is reached through.
///
/// The kernel calls these in this order and never in another. Each one is handed the token for its
/// own step, minted for the length of the call: the auth unit cannot open a hold, the trust unit
/// cannot report usage, and the ledger cannot decide who the caller is — not because they are well
/// behaved, but because the value they would need does not exist in their scope.
// contract: the sealed unit traits (auth, trust, scope, admission, egress, usage, ledger, audit)
pub trait Units {
    /// The kernel's own gate: size, rate, source and the budgets, before any plane is known.
    fn arrival(&self, token: &UnitToken<Arrival>, ctx: &UnitCtx) -> Decision<Arrival>;

    /// The plane says what shape arrived.
    fn decode(&self, token: &UnitToken<Decode>, ctx: &UnitCtx) -> Decision<Decode>;

    /// Who is calling.
    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        ctx: &UnitCtx,
    ) -> Decision<Authenticate>;

    /// Where the unit may go.
    ///
    /// Lent TWO tokens, for the same reason admit and meter are: the step's answer is a set of
    /// SEALED destinations, and sealing one takes the trust token. A step lent only its unit token
    /// could decide where a unit may go but could not say so, so every implementor would have to
    /// answer with the empty set — which is a legitimate answer for a pool with every lane excluded
    /// and a silent one for everything else. The trust token is lent for the length of this call and
    /// nowhere else, so no other step can seal a destination.
    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &TrustToken,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify>;

    /// Whether the caller may do this at all.
    fn approve(
        &self,
        token: &UnitToken<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve>;

    /// The door.
    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Admit>;

    /// Dial, send, relay — all under the hold, with the meter running.
    fn route(
        &self,
        token: &UnitToken<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route>;

    /// What the unit actually cost, folded from what the legs reported.
    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        ctx: &UnitCtx,
        provisional: &Outcome,
    ) -> Decision<Meter>;

    /// Seal the end for the record. The door a unit that PASSED the door leaves through.
    fn audit(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit>;

    /// Seal the end of a unit that never passed the door. Nothing was charged.
    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit>;

    /// The bytes that leave.
    fn encode(
        &self,
        token: &UnitToken<Encode>,
        ctx: &UnitCtx,
        outcome: &Outcome,
    ) -> Decision<Encode>;

    /// What the unit's evidence looks like once it has run. Read by the settlement table.
    fn evidence(&self, ctx: &UnitCtx) -> Evidence;
}

/// The Route step, as the loop AWAITS it.
///
/// Route is the one step of the ten that dials, sends and relays, so it is the one step whose answer
/// is not already in hand when the loop asks for it. Meter folds what Route observed and the exit
/// settles what the meter counted; neither waits on anything, so neither is here and neither needs
/// to be. This trait is that single seam, stated: one method, one future, one place the loop yields.
///
/// A plane whose Route answers in place does not implement this at all — [`run_unit`] supplies a leg
/// that is ready on its first poll, over that plane's own [`Units::route`], and the loop body it
/// drives is the same one. A plane whose Route awaits an upstream implements it and is reached
/// through [`run_unit_async`], which parks no thread and drops the leg when the caller goes away.
pub trait RouteAwait {
    /// The leg, borrowed for the length of one unit's Route step.
    ///
    /// Deliberately an associated type rather than a boxed future: the synchronous entry point's leg
    /// is a `Ready`, which is a value and not an allocation, so keeping the old callers costs them
    /// nothing at all. A plane whose leg is an `async` block boxes its own.
    type Leg<'a>: std::future::Future<Output = Decision<Route>>
    where
        Self: 'a;

    /// Dial, send, relay — all under the hold, with the meter running, as a future the loop awaits
    /// on the caller's own runtime.
    fn route_leg<'a>(
        &'a self,
        token: &'a UnitToken<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
    ) -> Self::Leg<'a>;
}

/// A plane whose Route answers in place, as the one loop reaches it.
///
/// The loop has exactly one await, and this is what the synchronous entry point puts in it: a future
/// that is ready the first time it is polled. It is what makes [`run_unit`] a DRIVER of the loop
/// body rather than a second copy of it.
struct Blocking<'u, U>(&'u U);

impl<U: Units> RouteAwait for Blocking<'_, U> {
    type Leg<'a>
        = std::future::Ready<Decision<Route>>
    where
        Self: 'a;

    fn route_leg<'a>(
        &'a self,
        token: &'a UnitToken<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
    ) -> Self::Leg<'a> {
        std::future::ready(self.0.route(token, ctx, meter))
    }
}

/// Everything one run of the loop borrows.
#[derive(Debug)]
pub struct Run<'r> {
    /// The unit's hold cell, in the in-flight table.
    pub cell: &'r HoldCell,
    /// The parent unit's cell, where this unit is a child spending against a parent's admission.
    ///
    /// The child never sees the parent's HOLD — that is the whole point of the accrual — but it
    /// does need the cell, to ask at its own exit whether the parent is still open. A parent that
    /// has exited is what turns the child's posting into a late one.
    pub parent: Option<&'r HoldCell>,
    /// The concurrency leases the unit took at the door.
    pub leases: &'r mut LeaseSet,
    /// The node's gauge, which the leases go back to.
    pub gauge: &'r ConcurrencyGauge,
    /// The counts the node balances.
    pub canary: &'r Canary,
    /// What the unit has spent so far.
    pub meter: &'r AccrualMeter,
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

/// Run one unit through every step, and end it exactly once — for a plane whose Route answers in
/// place.
///
/// The same loop body as [`run_unit_async`], driven here rather than on a runtime: the leg it awaits
/// is this plane's own [`Units::route`] wrapped in a `Ready`, so the one await answers on its first
/// poll and the whole unit runs to its end on the calling thread, exactly as it always has. Nothing
/// is spawned, nothing is allocated for the leg, and no caller that was synchronous yesterday has to
/// change.
pub fn run_unit<U: Units>(kernel: &Kernel, units: &U, ctx: &UnitCtx, run: Run<'_>) -> Ended {
    let blocking = Blocking(units);
    let mut loop_ = std::pin::pin!(run_unit_async(kernel, units, ctx, run, &blocking));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match loop_.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(ended) => ended,
        // Unreachable, and provably so: the loop awaits in exactly one place, the leg it awaits
        // there is the one `Blocking` hands it, and `Ready` answers on its first poll. `Blocking` is
        // private to this file and is the only leg this entry point can be given, so there is no
        // caller — inside the kernel or outside it — that can make this arm happen.
        std::task::Poll::Pending => {
            unreachable!("the synchronous loop's one await is a leg that is ready on its first poll")
        }
    }
}

/// Run one unit through every step, and end it exactly once — for a plane whose Route awaits.
///
/// The order below is the whole point of this function, so it is written as one chain: each step
/// hands the next what it produced, a refusal simply stops the chain, and there is no `?` and no
/// early return anywhere in it.
///
/// The unit runs on the CALLER'S runtime: nothing here is spawned, nothing is parked on a blocking
/// worker, and the only thing this task occupies while the upstream thinks is its own in-flight
/// slot. Drop the future and the unit is cancelled — see [`Abandoned`] for what the caller going
/// away costs and what it does not.
pub async fn run_unit_async<U: Units, R: RouteAwait>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    route: &R,
) -> Ended {
    let seal = &kernel.seal;
    let opened = units
        .arrival(&UnitToken::<Arrival>::mint(seal), ctx)
        .into_result(seal)
        .and_then(|_| {
            units
                .decode(&UnitToken::<Decode>::mint(seal), ctx)
                .into_result(seal)
        })
        .and_then(|_| {
            run.canary.draft_accepted();
            units
                .authenticate(&UnitToken::<Authenticate>::mint(seal), ctx)
                .into_result(seal)
        })
        // A challenge is not a decision about this unit: it is a request for one more round before
        // one can be made. The kernel delivers it and asks again, and the round itself is a
        // handshake unit — it reaches no destination, is scoped against nothing and opens no
        // reservation, which is exactly the zero-hold admission. Only an established identity walks
        // on to verify.
        .and_then(|authenticated| match authenticated {
            Authenticated::Challenge(_) => Ok(Admission::ZeroHold),
            Authenticated::Principal(principal) => units
                .verify(
                    &UnitToken::<Verify>::mint(seal),
                    &TrustToken::mint(seal),
                    ctx,
                    &principal,
                )
                .into_result(seal)
                .map(|destinations| (principal, destinations))
                .and_then(
                    |(principal, destinations): (PrincipalId, Vec<VerifiedDestination>)| {
                        units
                            .approve(
                                &UnitToken::<Approve>::mint(seal),
                                ctx,
                                &principal,
                                &destinations,
                            )
                            .into_result(seal)
                            .map(|_| (principal, destinations))
                    },
                )
                .and_then(
                    |(principal, destinations): (PrincipalId, Vec<VerifiedDestination>)| {
                        units
                            .admit(
                                &UnitToken::<Admit>::mint(seal),
                                &AdmitToken::<Admit>::mint(seal),
                                ctx,
                                &principal,
                                &destinations,
                            )
                            .into_result(seal)
                    },
                ),
        });

    match opened {
        // The refused door: nothing was charged beyond the arrival hold the table minted, and the
        // audit that seals it never sees a hold.
        Err(refusal) => {
            let outcome = Outcome::Refused(refusal.step(), refusal.reason());
            let _sealed = units
                .audit_refused(&UnitToken::<Audit>::mint(seal), ctx, &refusal)
                .into_result(seal);
            let _bytes = units
                .encode(&UnitToken::<Encode>::mint(seal), ctx, &outcome)
                .into_result(seal);
            exit(kernel, units, ctx, run, outcome, false)
        }
        // The door answered, and its answer decides exactly two things: whether a hold goes into the
        // cell, and what the end is settled against. Everything after it — the walk, the meter, the
        // audit door, the bytes and the settle — is the same for all three shapes, so it is written
        // once, below and in `terminal`, rather than three times.
        Ok(admission) => {
            let (settling, refused_cell) = match admission {
                // A child spending against its parent's admission. It still runs the rest of the
                // loop; what it does not do is open a reservation of its own.
                Admission::Accrual(accrual) => {
                    run.canary.accrual_taken();
                    (Settling::Parent(accrual), None)
                }
                // A zero-priced unit: the heartbeat, the sweep, a handshake. It holds nothing, so
                // there is nothing to swap into the cell, and the arrival hold is what the exit
                // settles.
                Admission::ZeroHold => (Settling::Exit(false), None),
                // The ordinary case: the door's hold replaces the arrival hold in the cell, once.
                Admission::Own(hold) => {
                    match run.cell.admit(hold, &AdmitToken::<Admit>::mint(seal)) {
                        Ok(arrival) => {
                            run.canary.hold_opened();
                            // The arrival hold has done its job; the admitted hold has taken its
                            // place and is the one the exit settles.
                            drop_arrival(arrival);
                            (Settling::Exit(true), None)
                        }
                        Err(rejected) => {
                            // The cell refused a second hold. The unit that lost the race ends here
                            // and the hold it was carrying comes back rather than vanishing.
                            drop_arrival(rejected.hold);
                            (
                                Settling::Exit(true),
                                Some(Outcome::Failed(StepName::Admit, ReasonCode::InFlight)),
                            )
                        }
                    }
                }
            };
            match refused_cell {
                // A unit that never reached the wire, so there is nothing to await and nothing a
                // caller going away could interrupt. It still ends where every admitted unit ends.
                Some(outcome) => terminal(kernel, units, ctx, run, outcome, settling),
                None => {
                    let meter = run.meter;
                    // THE ONE AWAIT is inside this scope, and so is the only place a caller that
                    // goes away can drop the loop. The guard owns the terminal for the length of it.
                    let mut abandoned = Abandoned::arm(kernel, units, ctx, run, settling);
                    let outcome = under_hold(kernel, units, route, ctx, meter).await;
                    abandoned.reached(outcome)
                }
            }
        }
    }
}

/// What a unit's end is settled against, as the door decided it.
///
/// Not a second copy of `Admission`: what the loop needs after the door is only which of the two
/// settles applies, and — for the one that opens a reservation of its own — whether the unit reached
/// the door at all.
enum Settling {
    /// A child's spend, which goes into the parent's still-open hold rather than a hold of its own.
    Parent(HoldAccrual),
    /// A hold the [`exit`] path settles, and whether the unit reached the door.
    Exit(bool),
}

/// THE UNIT THE CALLER WENT AWAY FROM.
///
/// The loop awaits in exactly one place, so a client that disconnects mid-request drops the loop's
/// future in exactly one place too: inside Route, with the hold in the cell, the leases drawn and
/// the in-flight slot held. This is what stands there.
///
/// It owns everything the terminal needs from the moment the door answered, so an abandoned unit
/// leaves through the SAME audit door, the same settle and the same exit a finished unit leaves
/// through — with the end named for what happened, the client went away. The upstream's own future
/// is dropped by the same unwind, because it is what the loop was awaiting; the hold comes out of
/// the cell and is forgotten rather than posted for delivery that did not happen, the leases go back
/// to the gauge, and the slot the unit occupied is free before the loop's frame is gone.
///
/// [`reached`](Abandoned::reached) is how a unit that finished on its own takes its end back out. A
/// guard whose terminal has been taken does nothing when it is dropped, which is the whole of the
/// arming.
struct Abandoned<'k, 'r, U: Units> {
    kernel: &'k Kernel,
    units: &'k U,
    ctx: &'k UnitCtx,
    /// The terminal, until somebody runs it. `None` once one of the two callers has.
    ending: Option<(Run<'r>, Settling)>,
}

impl<'k, 'r, U: Units> Abandoned<'k, 'r, U> {
    /// Take the terminal, for the length of the await.
    fn arm(
        kernel: &'k Kernel,
        units: &'k U,
        ctx: &'k UnitCtx,
        run: Run<'r>,
        settling: Settling,
    ) -> Self {
        Abandoned {
            kernel,
            units,
            ctx,
            ending: Some((run, settling)),
        }
    }

    /// The unit reached its own end: take the terminal back out and run it there.
    fn reached(&mut self, outcome: Outcome) -> Ended {
        match self.ending.take() {
            Some((run, settling)) => {
                terminal(self.kernel, self.units, self.ctx, run, outcome, settling)
            }
            // Unreachable: this is called exactly once, on the one path out of the await, and the
            // only other taker is the drop below — which cannot have run while this borrow exists.
            // Answered rather than unwrapped, because an arm that cannot be taken still has to say
            // something if it is.
            None => Ended::AlreadySettled,
        }
    }
}

impl<U: Units> Drop for Abandoned<'_, '_, U> {
    fn drop(&mut self) {
        if let Some((run, settling)) = self.ending.take() {
            // The end is discarded because there is nobody left to hand it to: the caller that
            // would have read it is the one that went away. What matters is that it was REACHED —
            // the audit door sealed it, the cell is empty and the leases are back.
            let _ended = terminal(
                self.kernel,
                self.units,
                self.ctx,
                run,
                Outcome::Aborted(Abort::Client),
                settling,
            );
        }
    }
}

/// THE ONE TERMINAL for a unit that passed the door: the audit that seals the end, the bytes that
/// leave, and the settle.
///
/// Every admitted unit's end is here — completed, failed, or abandoned by the caller — and there is
/// no second copy of it for the shapes the door answered with, because the shape decides only which
/// of the two settles the last line runs.
fn terminal<U: Units>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    outcome: Outcome,
    settling: Settling,
) -> Ended {
    let seal = &kernel.seal;
    let _sealed = units
        .audit(&UnitToken::<Audit>::mint(seal), ctx, &outcome)
        .into_result(seal);
    let _bytes = units
        .encode(&UnitToken::<Encode>::mint(seal), ctx, &outcome)
        .into_result(seal);
    match settling {
        Settling::Exit(reached_admitted) => exit(kernel, units, ctx, run, outcome, reached_admitted),
        Settling::Parent(accrual) => {
            // The child opened no reservation of its own, but the table minted it an arrival hold
            // like every other unit, and that hold is in a cell the sweep also has a key to.
            // Emptying the cell HERE is what makes the child's end final: leaving it full would
            // leave the sweep free to settle a unit that already finished, and the parent's hold
            // already carries this spend.
            let taken = run.cell.take(&ExitToken::mint(seal));
            run.leases.release_all(run.gauge);
            match taken {
                None => Ended::AlreadySettled,
                Some(arrival) => {
                    drop_arrival(arrival);
                    // The child ends like every other unit: one posting, one sealed end. Its
                    // posting reserved nothing, because the reservation behind it is the parent's,
                    // which already carries this spend. A parent that exited while the child ran
                    // hands the accrual back and it posts late instead — always posted, flagged as
                    // late, against a synchronous draw.
                    let ledger = LedgerToken::mint(seal);
                    let parent = run.parent.unwrap_or(run.cell);
                    let posted = match Posted::into_parent(accrual, parent, &ledger) {
                        Ok(posted) => posted,
                        Err(missed) => Posted::settle_late(missed, &ledger),
                    };
                    run.canary.settled();
                    Ended::Settled {
                        end: UnitEnd::seal(&ExitToken::mint(seal), outcome, Ok(posted)),
                        // A child draws no request slot and posts no flat fee: the unit that drew
                        // both is the parent it is spending against.
                        requests: 0,
                        fee: 0,
                    }
                }
            }
        }
    }
}

/// Route and meter, both under the hold. Produces the provisional end the audit seals.
///
/// The Route leg is awaited here and nowhere else, which is what makes the drop that cancels a unit
/// land in one known place with one known guard over it.
async fn under_hold<U: Units, R: RouteAwait>(
    kernel: &Kernel,
    units: &U,
    route: &R,
    ctx: &UnitCtx,
    meter: &AccrualMeter,
) -> Outcome {
    let seal = &kernel.seal;
    let token = UnitToken::<Route>::mint(seal);
    match route.route_leg(&token, ctx, meter).await.into_result(seal) {
        Err(refusal) => Outcome::Failed(refusal.step(), refusal.reason()),
        Ok(_) => {
            let provisional = Outcome::Completed;
            match units
                .meter(
                    &UnitToken::<Meter>::mint(seal),
                    &UsageToken::mint(seal),
                    ctx,
                    &provisional,
                )
                .into_result(seal)
            {
                Ok(_) => Outcome::Completed,
                Err(refusal) => Outcome::Failed(refusal.step(), refusal.reason()),
            }
        }
    }
}

/// A hold the cell handed back. It has been superseded by the admitted one and carries no spend of
/// its own; taking it by value here is what makes "the arrival hold is consumed by the swap" a fact
/// about ownership rather than a comment.
fn drop_arrival(_hold: Hold) {}

/// The one exit path.
///
/// Takes the hold out of the cell by compare-and-set, releases the unit's concurrency leases in the
/// same breath — every end, whatever it was — settles per the table, and seals the end. If the cell
/// is already empty the node's sweep got here first and this call does nothing at all, which is the
/// only correct answer: a unit is settled once.
pub fn exit<U: Units>(
    kernel: &Kernel,
    units: &U,
    ctx: &UnitCtx,
    run: Run<'_>,
    outcome: Outcome,
    reached_admitted: bool,
) -> Ended {
    let seal = &kernel.seal;
    let taken = run.cell.take(&ExitToken::mint(seal));
    run.leases.release_all(run.gauge);
    match taken {
        None => Ended::AlreadySettled,
        Some(mut hold) => {
            let evidence = units.evidence(ctx);
            let (amount, table_flags) = settle_amount(&outcome, &evidence);
            let (fee, fee_flags) = fee_count(&evidence.fee);
            let flags = table_flags.with(fee_flags);
            let requests = requests_settled(
                reached_admitted,
                requests_drawn(ctx.origin, evidence.upstream_candidate),
            );
            // What the unit spent while it ran is applied to the hold here, where the hold is
            // owned. The spend lands in full: past the end of the reservation it grows out of
            // whatever headroom the leg offered while it ran, and whatever nothing can back is
            // carried out as an overdraft. There is no arm on this path that refuses — value was
            // delivered, so the only question left is which column it lands in.
            let _spend = hold.spend(run.meter.total(), run.meter.headroom());
            let class = evidence
                .class
                .unwrap_or_else(|| MeterClassId::new("nano_units"));
            let lines = vec![UsageLine {
                class,
                quantity: amount,
                // The exit path settles what the accrual meter counted while the unit ran, which
                // is the kernel's own figure, not one a destination reported.
                source: QuantitySource::Count,
                estimated: flags.contains(PostingFlags::ESTIMATED),
            }];
            let usage_token = UsageToken::mint(seal);
            let usage = if flags.contains(PostingFlags::ESTIMATED) {
                Usage::estimate(&usage_token, lines)
            } else {
                Usage::report(&usage_token, lines)
            };
            let posted = match usage {
                Ok(usage) => {
                    Ok(Posted::settle(hold, &usage, &LedgerToken::mint(seal)).flagged(flags))
                }
                // A usage report the record cannot hold is a durability failure, not a discount:
                // the unit delivered value it cannot prove it recorded.
                Err(_) => {
                    drop_arrival(hold);
                    Err(DurabilityLost::observed(
                        &busbar_caps::DurabilityToken::mint(seal),
                        StepName::Meter,
                    ))
                }
            };
            run.canary.settled();
            Ended::Settled {
                end: UnitEnd::seal(&ExitToken::mint(seal), outcome, posted),
                requests,
                fee,
            }
        }
    }
}
