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
//! And the end it reaches is POSTED rather than discarded: the settle is a pure constructor and
//! the books move only where somebody reads the [`Ended`], so the guard hands it to the leg's own
//! [`RouteAwait::abandoned`] — the one party still standing that knows which book it belongs on.
//!
//! ## No early exits
//!
//! Nothing in this file uses `?` and nothing returns early. Not style: a `?` in the middle of a
//! loop that is holding a reservation is a path where the hold is dropped instead of settled, and
//! "every unit posts exactly once" has to be readable in the shape of the code, not just true.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::caps::{
    Abort, AdminVerb, Admission, Admit, Admittance, Approve, Arrival, Audit, Authenticate,
    Authenticated, CallId, Canary, Consumption, Decision, Decode, Dial, DurabilityLost,
    DurableWrite, Encode, Exit, Grant, Hold, HoldAccrual, HoldCell, KernelSeal, KeyHandle, Meter,
    MeterClassId, Origin, OriginKind, Outcome, Pass, Posted, PostingFlags, PrincipalId,
    QuantitySource, ReasonCode, Refusal, Route, SessionId, StepName, UnitEnd, UnitKey, Usage,
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
    /// Take the seal. Boot only.
    pub fn new() -> Self {
        Kernel {
            seal: KernelSeal::acquire_for_kernel(),
            call_gen: AtomicU64::new(0),
        }
    }

    /// Open a new per-request generation (#74). Called once at the top of a unit; the value is
    /// carried in the unit context and stamped onto every `Pass`/`Grant` the loop mints for it, so a
    /// stray or stored proof from an earlier request is rejected. Wraps below `u64::MAX`, which is
    /// reserved for the unbound sentinel.
    pub fn next_call(&self) -> CallId {
        let gen = self.call_gen.fetch_add(1, Ordering::Relaxed) % (u64::MAX - 1);
        CallId::seal(&self.seal, gen)
    }

    /// The door's grant, bound to one request (#74). The bound counterpart of [`admit_token`]: the
    /// loop mints the admittance grant for the current call so a hold cannot be opened with a grant
    /// minted for a different one.
    pub fn admit_token_for(&self, call: CallId) -> Grant<Admittance> {
        Grant::<Admittance>::mint_bound(&self.seal, call)
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
    pub fn admit_token(&self) -> Grant<Admittance> {
        Grant::<Admittance>::mint(&self.seal)
    }

    /// The transport-key unit's token, as the composition root lends it.
    ///
    /// The first token minted OUTSIDE the loop. Keys are resolved at listen, dial and upgrade, none
    /// of which is a step of a unit, so there is no step whose token could stand in — and without
    /// this the unit's `provision_server` and `provision_client` have a parameter no caller in the
    /// tree can supply, which is why the only thing that ever registered a listener's TLS config
    /// was the transport's own tests.
    ///
    /// Kept beside `admit_token` and named the same way, so the source scan that accounts for every
    /// mint sees this one too.
    pub fn transport_key_token(&self) -> Grant<KeyHandle> {
        Grant::<KeyHandle>::mint(&self.seal)
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
    pub fn admin_token(&self) -> Grant<AdminVerb> {
        Grant::<AdminVerb>::mint(&self.seal)
    }

    /// The journal's token, as the composition root lends it to an exit arm.
    ///
    /// The third token minted outside the loop, and for the same reason as the other two: making a
    /// posting durable happens AFTER the exit has sealed the end, so there is no step of the unit
    /// whose token could stand in, and the root's exit arm has a parameter no caller in the tree can
    /// supply without this. Without it a root that wanted to journal what the loop posted had to
    /// reach for the seal itself, which is the one symbol that must not be spelled outside this
    /// crate.
    ///
    /// Kept beside the other three and named the same way, so the source scan that accounts for
    /// every mint sees this one too.
    pub fn durability_token(&self) -> Grant<DurableWrite> {
        Grant::<DurableWrite>::mint(&self.seal)
    }

    /// The ledger unit's token, as the composition root lends it to a posting made after the exit.
    ///
    /// The fourth token minted outside the loop, and the reason is the sharpest of the four. Inside
    /// the loop the ledger's token is minted at the terminal, which is where every posting the loop
    /// itself makes is built — and a figure that only exists AFTER that terminal cannot be built
    /// there. There is no step of the unit still running when it arrives, so there is no step token
    /// that could stand in, and a root that wanted to post it had to reach for the seal itself.
    ///
    /// This is what a late accrual is: the money a streamed or deferred body reports once the body
    /// has drained, posted onto the same balance and the same window the terminal settled in. The
    /// token is minted for one such posting and dropped with it, exactly as the terminal's is.
    ///
    /// Kept beside the other three and named the same way, so the source scan that accounts for
    /// every mint sees this one too.
    pub fn ledger_token(&self) -> Grant<WriteMoney> {
        Grant::<WriteMoney>::mint(&self.seal)
    }

    /// The usage record's token, as the composition root lends it to a report assembled after the exit.
    ///
    /// The fifth token minted outside the loop, and it travels with the fourth. A late accrual is a
    /// spend the node learned about after its terminal, and pricing one means holding what the unit
    /// CONSUMED — a usage record — beside the card that says what those quantities are worth. Inside
    /// the loop that record is built at the Meter step against the step's own token; a report that
    /// arrives after the terminal has no step left to be built at.
    ///
    /// It mints nothing a step could not: a usage record is evidence and moves no balance on its own.
    /// What the token is for is the same thing every token here is for — a record cannot be conjured
    /// by anything the kernel did not hand one to, and without this a root assembling one had to reach
    /// for the seal, which is the one symbol that must not be spelled outside this crate.
    ///
    /// Kept beside the other four and named the same way, so the source scan that accounts for every
    /// mint sees this one too.
    pub fn usage_token(&self) -> Grant<Consumption> {
        Grant::<Consumption>::mint(&self.seal)
    }

    /// The seal itself, for the other two places in the kernel that mint tokens. Between them they
    /// mint seven, two of them `WriteMoney` — the source scan that accounts for every mint counts
    /// these as well as the factories above:
    ///
    /// - the recovery module, which materialises a hold from a journal record and settles it:
    ///   `Recover`, `Consumption` and `WriteMoney`;
    /// - the node's sweep, which settles an abandoned unit: `Exit` for the take, `Consumption`,
    ///   `WriteMoney`, and `Exit` again to seal the end.
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
    /// The registry generation it pinned when it started, so it would finish against what it
    /// started with if a reload installed a replacement. None does today: the registry is built once
    /// at boot and every unit pins `Generation::FIRST` (see `registry`'s "Generations").
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
    spent: AtomicU64,
    headroom: AtomicU64,
}

impl AccrualMeter {
    /// A meter reading zero, with no headroom offered.
    pub fn new() -> Self {
        AccrualMeter::default()
    }

    /// Add a spend.
    pub fn accrue(&self, amount: u64) {
        self.spent.fetch_add(amount, Ordering::AcqRel);
    }

    /// What the unit has spent so far.
    pub fn total(&self) -> u64 {
        self.spent.load(Ordering::Acquire)
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
        self.headroom.store(nanos, Ordering::Release);
    }

    /// What the leg said the reservation may still grow by.
    pub fn headroom(&self) -> u64 {
        self.headroom.load(Ordering::Acquire)
    }
}

/// Where a transport reports a status, what it reported, and what the plane made of the ending.
///
/// All three are the contract's own. They are plugin-visible: a transport declares where its status
/// arrives, a plane declares how a unit finished, and the settlement table below reads both. A
/// kernel-local restatement of any of them would be a second spelling of a value that crosses the
/// plugin boundary in both directions.
pub use busbar_contract::{FinishClass, StatusAt, WireStatusClass};

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

/// The class the kernel's own accrual is reported against when nothing else named one.
///
/// Spelled ONCE. The exit path, the sweep and the recovery path all post the same figure against
/// the same class, and three string literals for one class is three places a typo can put a
/// settled unit on a meter nobody prices.
pub const KERNEL_ACCRUAL_CLASS: MeterClassId = MeterClassId::new("nano_units");

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
    pub status: Option<WireStatusClass>,
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
    let by_status = evidence.status.map(|s| s == WireStatusClass::Success);
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
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> Decision<Arrival>;

    /// The plane says what shape arrived.
    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> Decision<Decode>;

    /// Who is calling.
    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> Decision<Authenticate>;

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
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify>;

    /// Whether the caller may do this at all.
    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Decision<Approve>;

    /// The door.
    ///
    /// Lent a `leases` slip as well as its two tokens. The design gives a unit one concurrency lease
    /// per capped-`concurrent` group it charges through, and only the door knows which groups those
    /// are: the names are config-derived and the decision is the door's alone. So the door names
    /// them here and the loop records them on the unit's slot, where both of the unit's ends can
    /// give them back. A door that names nothing is a unit counted only on the node-wide gauge,
    /// which is what every unit was counted on before, and the slip is written AFTER the decision —
    /// nothing in it can turn a yes into a no.
    ///
    /// The slip is also where a door hands over the count its own yes is holding, so the slot can
    /// keep it for the life of the unit. A door whose cap is enforced elsewhere hands over nothing
    /// and is unaffected; a door that keeps its count in the value it returns has to, or its cap is
    /// released before the unit it admitted has run.
    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Decision<Admit>;

    /// Dial, send, relay — all under the hold, with the meter running.
    ///
    /// Lent the SAME destinations Verify sealed and Approve and Admit already saw, rather than a
    /// second copy this step derives for itself. Verify-then-act only holds if the thing a later
    /// step acts on is provably the thing an earlier step proved — a Route that re-derived its own
    /// set could dial a lane nothing verified, and the sealed set on the door would have priced a
    /// decision Route never actually made.
    fn route(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
        destinations: &[VerifiedDestination],
    ) -> Decision<Route>;

    /// What the unit actually cost, folded from what the legs reported.
    ///
    /// Lent the same sealed set Route consumed, for the same reason: a meter reading is only
    /// evidence about what actually ran if it is read against what actually ran, not against a set
    /// the step reconstructed on its own after the fact.
    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> Decision<Meter>;

    /// Seal the end for the record. The door a unit that PASSED the door leaves through.
    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit>;

    /// Seal the end of a unit that never passed the door. Nothing was charged.
    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit>;

    /// The bytes that leave.
    fn encode(&self, token: &Pass<Encode>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Encode>;

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
    /// Dial, send, relay — all under the hold, with the meter running, as a future the loop awaits
    /// on the caller's own runtime.
    ///
    /// Boxed, and deliberately: a plane's unit borrows its node, so the `async` block its Route step
    /// is written as has a type that mentions that borrow, and carrying that type through an
    /// associated type turns every caller of the loop into a higher-ranked lifetime puzzle. One
    /// allocation, on the one step that is about to dial an upstream, buys a seam a plane implements
    /// by writing `async move` and the loop reads as a single await.
    ///
    /// Lent the same sealed destinations [`Units::route`] is, for the same reason: an awaited leg
    /// is still Route, and Route consumes what Verify sealed rather than re-deriving it.
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a>;

    /// THE END OF A UNIT THE CALLER WENT AWAY FROM — handed here so it is POSTED, not discarded.
    ///
    /// A caller that drops the loop drops it at the one await, and the loop's guard runs the unit's
    /// terminal there: the audit door seals the end, the hold leaves the cell and the leases go
    /// back. What the terminal RETURNS is the posting, and a posting is a value — `Posted::settle`
    /// is a pure constructor that moves no book, and the books move only where somebody reads the
    /// [`Ended`]. The caller that would have read it is the one that went away, so the guard hands it
    /// here instead, to the plane whose leg the unit was waiting on: the one party still standing
    /// that knows which book the unit settles onto. It used to be bound to `let _ended` and dropped,
    /// which consumed the hold, emptied the cell, wrote no ledger row and no journal entry, and left
    /// the reservation drawn against the principal's window (item 99).
    ///
    /// REQUIRED, with no default body, because the only default there is — dropping the end — is the
    /// defect. An implementation settles it exactly as its own caller settles a returned end.
    ///
    /// Runs inside a `Drop`, possibly during an unwind: it must not panic and must not await.
    fn abandoned(&self, ctx: &UnitCtx, ended: Ended);
}

/// The Route step's future, as the loop holds it while it waits.
pub type RouteLeg<'a> = std::pin::Pin<Box<dyn Future<Output = Decision<Route>> + Send + 'a>>;

/// A plane whose Route answers in place, as the one loop reaches it.
///
/// The loop has exactly one await, and this is what the synchronous entry point puts in it: a future
/// that is ready the first time it is polled. It is what makes [`run_unit`] a DRIVER of the loop
/// body rather than a second copy of it.
struct Blocking<'u, U>(&'u U);

impl<U: Units> RouteAwait for Blocking<'_, U> {
    fn route_leg<'a>(
        &'a self,
        token: &'a Pass<Route>,
        ctx: &'a UnitCtx,
        meter: &'a AccrualMeter,
        destinations: &'a [VerifiedDestination],
    ) -> RouteLeg<'a> {
        let answer = self.0.route(token, ctx, meter, destinations);
        Box::pin(std::future::ready(answer))
    }

    /// Unreachable by a caller going away: the synchronous driver polls its one await once and it
    /// is ready, so the guard's terminal is always taken back out by [`Abandoned::reached`]. The one
    /// way here is an unwind out of a step, and on that path [`run_unit`]'s caller receives no end
    /// either — the panic is the answer it gets — so there is no reader of this end to hand it to.
    fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
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
    /// The concurrency leases the unit took at the door, as the unit's SLOT owns them.
    ///
    /// The cell and not the set, because the exit path is only one of the unit's two ends: the
    /// sweep is the other, and a set that lived in this task's frame went away with the task.
    /// Whichever end runs first gives the leases back, and the second finds nothing to give.
    pub leases: &'r LeaseCell,
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
/// is spawned, nothing is scheduled, and no caller that was synchronous yesterday has to change.
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
            unreachable!("the synchronous loop's one await is ready on its first poll")
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
    // THE CANARY'S THREE COUNTS, each at the seat that makes it true for EVERY unit (item 272). A
    // draft is a unit the table admitted and this loop runs; every unit ends with exactly one hold
    // or one accrual (the arrival hold the table minted is the hold a refused or zero-priced unit
    // settles, and the door's hold replaces it for an admitted one); and exactly one settlement, by
    // the exit or the sweep, whichever takes the cell. Counting the draft four steps before the door
    // and the hold only on the admitted arm left every refusal and every zero-hold unit unbalanced.
    run.canary.draft_accepted();
    let opened = open_to_door(seal, units, ctx, &run);
    if !matches!(opened, Ok((Admission::Accrual(_), _))) {
        run.canary.hold_opened();
    }

    match opened {
        // The refused door: nothing was charged beyond the arrival hold the table minted, and the
        // audit that seals it never sees a hold.
        Err(refusal) => {
            // The step comes from the decision that stamped it. `unwrap_or` names the door
            // rather than a sentinel: a refusal that reached here without a stamp did not come
            // from a decision at all, and the door is the last step it could have been raised at.
            let outcome =
                Outcome::Refused(refusal.step().unwrap_or(StepName::Admit), refusal.reason());
            let _sealed = units
                .audit_refused(&Pass::<Audit>::mint(seal), ctx, &refusal)
                .into_result(seal);
            let _bytes = units
                .encode(&Pass::<Encode>::mint(seal), ctx, &outcome)
                .into_result(seal);
            exit(kernel, units, ctx, run, outcome, false)
        }
        // The door answered, and its answer decides exactly two things: whether a hold goes into the
        // cell, and what the end is settled against. Everything after it — the walk, the meter, the
        // audit door, the bytes and the settle — is the same for all three shapes, so it is written
        // once, below and in `terminal`, rather than three times. The destinations travel alongside
        // the admission all the way to `under_hold`, so Route and Meter see the SAME sealed set
        // Approve and Admit already answered against.
        Ok((admission, destinations)) => {
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
                    match run.cell.admit(hold, &Grant::<Admittance>::mint(seal)) {
                        Ok(arrival) => {
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
                    let mut abandoned = Abandoned {
                        kernel,
                        units,
                        route,
                        ctx,
                        ending: Some((run, settling)),
                    };
                    let outcome = under_hold(kernel, units, route, ctx, meter, &destinations).await;
                    abandoned.reached(outcome)
                }
            }
        }
    }
}

/// THE GOVERNANCE-TO-DOOR CHAIN, factored so both the one-shot loop and a session opener run the
/// SAME arrival→decode→authenticate→verify→approve→admit, in the same order, minting the same tokens.
///
/// Returns the door's [`Admission`] on a pass, alongside the destinations [`Units::verify`] sealed —
/// EMPTY for a challenge round, which never reaches verify at all — or the [`Refusal`] of the step
/// that stopped the unit. No response is shaped here and nothing is settled — that is the caller's,
/// whichever caller it is: [`run_unit_async`] carries the sealed set on to Route and Meter, under the
/// hold, and [`open_unit`] stops at the door and hands it back. Written as the one chain it always
/// was, moved verbatim out of [`run_unit_async`], so the order reads top to bottom and a refusal
/// simply stops the chain.
///
/// The destinations travel in the SAME `Result` the admission does, rather than a second one beside
/// it, because they are exactly as much this call's answer as the admission is: Approve and Admit
/// already read them here, and a caller that carries the `Admission` forward without the set Verify
/// sealed it against is the verify-then-act gap this return type exists to close.
fn open_to_door<U: Units>(
    seal: &KernelSeal,
    units: &U,
    ctx: &UnitCtx,
    run: &Run<'_>,
) -> Result<(Admission, Vec<VerifiedDestination>), Refusal> {
    units
        .arrival(&Pass::<Arrival>::mint(seal), ctx)
        .into_result(seal)
        .and_then(|_| {
            units
                .decode(&Pass::<Decode>::mint(seal), ctx)
                .into_result(seal)
        })
        .and_then(|_| {
            units
                .authenticate(&Pass::<Authenticate>::mint(seal), ctx)
                .into_result(seal)
        })
        // A challenge is not a decision about this unit: it is a request for one more round before
        // one can be made. The kernel delivers it and asks again, and the round itself is a
        // handshake unit — it reaches no destination and opens no reservation, which is exactly the
        // zero-hold admission. Only an established identity walks on to VERIFY.
        //
        // BUT "REACHES NO DESTINATION" IS NOT "FACES NO POLICY", and reading the two as one thing
        // was an unauthenticated path straight around the node's own admission control. The three
        // seats split cleanly, and the split is the reason this arm is written out rather than
        // short-circuited:
        //
        // - VERIFY genuinely cannot apply. It answers WHERE a unit may go, for a named principal,
        //   and it SEALS that answer with the trust grant so Route and Meter consume the set
        //   Approve and Admit read. A round that dials nothing has nothing to seal, and the planes
        //   that implement it record the principal there — recording the anonymous one would put an
        //   identity nobody established onto the unit's own record. So verify is skipped, and the
        //   sealed set stays EMPTY, which every later seat already accepts as a legitimate answer.
        // - APPROVE must still be asked. It is the hook-veto seat: an operator's own runtime
        //   opinion about whether the node will engage AT ALL, which is a question about the
        //   exchange and not about where it goes. Skipping it meant a hook wired to veto the
        //   handshake never got consulted — and the planes already write the answer for it (a
        //   session plane's approve has an explicit handshake arm), so the seat was being answered
        //   into a call that never came.
        // - ADMIT must still be asked. The door is where a frozen group, a disabled bucket and the
        //   node's own gauges are read; a round that walked past it was an unauthenticated caller
        //   getting work out of a node that had said it would do none.
        //
        // The round has no principal to present, so it presents the ANONYMOUS one — the same
        // identity the open front door admits a caller nothing identified under — over the empty
        // destination set.
        //
        // AND ITS ADMISSION IS THE ZERO HOLD, whatever the door sized. A challenge opens no
        // reservation, so there is nothing for the exit to settle and nothing to swap into the
        // cell. Nothing the door drew is stranded by that: what a door COUNTS travels on the
        // `groups` slip below, and the slip — with the door's own grant on it — is dropped at the
        // end of this arm, which gives the count straight back; what a door RESERVES is a figure
        // carried in the hold itself and recorded nowhere else, so a hold that is not settled
        // leaves no draw behind it. For the same reason the round draws NO LEASE: it holds no slot,
        // and a node at a saturated gauge still has to be able to finish a handshake.
        .and_then(|authenticated| match authenticated {
            Authenticated::Challenge(_) => {
                let anonymous = PrincipalId::anonymous();
                // THE EMPTY SEALED SET, named rather than implied: it is what the seats are handed
                // and it is what travels back, because a round that reaches no destination has
                // nothing for Route and Meter to consume either.
                let nowhere: [VerifiedDestination; 0] = [];
                let groups = GroupLeaseSlip::new();
                units
                    .approve(&Pass::<Approve>::mint(seal), ctx, &anonymous, &nowhere)
                    .into_result(seal)
                    .and_then(|_| {
                        units
                            .admit(
                                &Pass::<Admit>::mint(seal),
                                &Grant::<Admittance>::mint(seal),
                                ctx,
                                &anonymous,
                                &nowhere,
                                &groups,
                            )
                            .into_result(seal)
                    })
                    .map(|_admitted| (Admission::ZeroHold, Vec::new()))
            }
            Authenticated::Principal(principal) => units
                .verify(
                    &Pass::<Verify>::mint(seal),
                    &Grant::<Dial>::mint(seal),
                    ctx,
                    &principal,
                )
                .into_result(seal)
                .and_then(|destinations| {
                    units
                        .approve(&Pass::<Approve>::mint(seal), ctx, &principal, &destinations)
                        .into_result(seal)
                        .map(|_| destinations)
                })
                .and_then(|destinations| {
                    // The slip the door names its capped groups on, for the length of the one
                    // call. It lives here rather than on the unit's context because it is not
                    // something the unit IS: it is what the door said, read once, on the next
                    // line, by the draw.
                    let groups = GroupLeaseSlip::new();
                    let admitted = units
                        .admit(
                            &Pass::<Admit>::mint(seal),
                            &Grant::<Admittance>::mint(seal),
                            ctx,
                            &principal,
                            &destinations,
                            &groups,
                        )
                        .into_result(seal);
                    // THE LEASE, drawn on the one answer that entitles a unit to it. The door
                    // said yes, so from here until this unit's end the node is running it, and
                    // the lease is what says so. A refusal draws nothing — there is no slot to
                    // count — and neither does a challenge round, which now faces this same
                    // door but opens no reservation behind it (see the arm above).
                    if admitted.is_ok() {
                        draw_lease(ctx, run, &groups);
                    }
                    // The sealed set travels WITH the admission from here on, so Route and
                    // Meter consume the exact set Approve and Admit just read rather than a
                    // recomputation of it.
                    admitted.map(|admission| (admission, destinations))
                }),
        })
}

/// How a session opener left the door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOpen {
    /// The door passed. A session admits at [`Admission::ZeroHold`] — it opens its own reservation
    /// AFTER, plane-side — so nothing was swapped into the cell and there is nothing to settle. The
    /// caller opens its live carrier next.
    Admitted,
    /// The door refused before any charge. The plane's own refusal was audited and encoded; nothing
    /// was charged and nothing settled.
    Refused,
}

/// OPEN A SESSION — run the governance-to-door chain and STOP at the door, for a plane whose unit
/// binds its live carrier AFTER admission and has no one-shot Route leg (voice, duplex).
///
/// The kernel twin of the substrate `open_unit`: it runs the SAME arrival→…→admit as
/// [`run_unit_async`] (through [`open_to_door`]), then the success/refused audit — and RETURNS. It
/// NEVER runs `under_hold` (there is no Route leg) and NEVER runs the settling [`exit`]. A session's
/// door is [`Admission::ZeroHold`] — an empty hold — so there is nothing for the exit to settle, and
/// the plane's own reserve-on-admit and per-turn settle stay entirely plane-side, AFTER this gate.
/// The result says only whether the door passed; a refusing plane's own response is the plane's to
/// carry (it shaped it at its refusing step), exactly as the substrate session opener carries it.
///
/// Sync: every step up to and including the door is synchronous (only Route awaits, and a session has
/// no Route here), so a synchronous `begin_session` calls this directly.
pub fn open_unit<U: Units>(kernel: &Kernel, units: &U, ctx: &UnitCtx, run: Run<'_>) -> SessionOpen {
    let seal = &kernel.seal;
    match open_to_door(seal, units, ctx, &run) {
        // The door refused, at or before Admit: nothing was charged. Audit the refusal and encode
        // its bytes — the same two doors a refused one-shot leaves through, minus the settling exit
        // (a session that never opened has no reservation to settle).
        Err(refusal) => {
            let outcome =
                Outcome::Refused(refusal.step().unwrap_or(StepName::Admit), refusal.reason());
            let _sealed = units
                .audit_refused(&Pass::<Audit>::mint(seal), ctx, &refusal)
                .into_result(seal);
            let _bytes = units
                .encode(&Pass::<Encode>::mint(seal), ctx, &outcome)
                .into_result(seal);
            SessionOpen::Refused
        }
        // The door passed at ZeroHold. Record the admission (success-audit + encode) and hand the
        // door back OPEN — no `under_hold`, no `exit`. The plane opens its own reservation next.
        // A session's door is always ZeroHold (see the doc above), so there is no Route or Meter
        // step here to hand the sealed destinations to; they are discarded with the admission.
        Ok((_admission, _destinations)) => {
            let outcome = Outcome::Completed;
            let _sealed = units
                .audit(&Pass::<Audit>::mint(seal), ctx, &outcome)
                .into_result(seal);
            let _bytes = units
                .encode(&Pass::<Encode>::mint(seal), ctx, &outcome)
                .into_result(seal);
            SessionOpen::Admitted
        }
    }
}

/// Draw the concurrency lease the door's yes entitles a unit to, on the unit's own SLOT.
///
/// The lease is the other half of a rule the exit path has kept on its own until now: leases go back
/// on every end. Nothing drew one, so what went back was always nothing, and the gauge read zero
/// while the node was full. This is the draw.
///
/// It is recorded on the slot's cell rather than in this frame, because the unit has two ends and
/// only one of them is here. A task that disappears takes its frame with it; the sweep finds the
/// slot, and the slot is where the lease it has to give back lives.
///
/// The exempt origins are the design's own: a handshake and a tick move no money and take no lease,
/// so a node at a saturated gauge still finishes its handshakes and still runs the sweep that
/// empties it, and a kernel-verb unit takes none either — which is what makes the administrative
/// surface answer while everything else is capped out.
///
/// The gauge is counted BEFORE the cell is asked, and given straight back when the cell says no.
/// A cell that refuses a lease is a unit whose other end has already run, and the count it would
/// otherwise be left holding is one no exit and no sweep would ever release — a cap that only goes
/// up, invisible until the node stops admitting anything.
///
/// ONE LEASE PER CAPPED GROUP, and the node-wide one beside them. The design's `concurrent` lease is
/// per capped group, and the groups are the door's to name — so the slip carries what the door
/// counted and every name in it becomes a lease of its own on the same slot, released by the same
/// two ends in the same breath. The count here is a READING and never a gate: `record` is the entry
/// point that cannot refuse, so a unit the door admitted is never turned away by the counting of it.
/// A door that named nothing leaves the node-wide lease exactly as it was.
///
/// AND THE DOOR'S OWN COUNT COMES HERE TOO. The names above are the node's reading; the count the
/// door took when it said yes is the `concurrent` cap itself, and it is a cap only for as long as
/// something holds it. Held for the length of the door's call, it is released before the unit it
/// admitted has done anything, and the N+1th unit is measured against a gauge that has already
/// forgotten the N in flight. So the slot holds it, beside the leases, and the same two ends give
/// it back.
fn draw_lease(ctx: &UnitCtx, run: &Run<'_>, groups: &GroupLeaseSlip) {
    if !takes_lease(ctx.origin, ctx.kernel_verb_only) {
        return;
    }
    for bucket in std::iter::once(IN_FLIGHT).chain(groups.taken()) {
        run.gauge.record(&bucket);
        if !run.leases.take(bucket) {
            run.gauge.release(&bucket);
        }
    }
    // AND THE DOOR'S OWN COUNT, onto the same slot. The kernel's leases are a reading; the door's
    // count is the cap, and a cap released the moment it is taken is a comparison against zero. It
    // is parked here because this is the one place that has both the door's answer and the slot,
    // and it goes back where the leases go back: at whichever of the unit's two ends arrives first.
    if let Some(grant) = groups.grant_taken() {
        run.leases.hold_grant(grant);
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
/// is dropped by the same unwind, because it is what the loop was awaiting. The hold comes out of
/// the cell and is settled by the table's own row for an end that is not `Completed` — the kernel's
/// floor, marked estimated, never a full charge for an answer nobody received — and the leases go
/// back to the gauge in the same breath. Both are done before the loop's frame is gone, so the cell
/// the sweep also holds a key to is already empty and the caller's slot is free to give back.
///
/// And the end is POSTED: it goes to the leg's [`RouteAwait::abandoned`], which settles it onto the
/// book exactly as a returned end is settled. The sealed end IS the money write — the posting inside
/// it has moved nothing until somebody reads it — so an end dropped here was a charge dropped here.
///
/// [`reached`](Abandoned::reached) is how a unit that finished on its own takes its end back out. A
/// guard whose terminal has been taken does nothing when it is dropped, which is the whole of the
/// arming.
struct Abandoned<'k, 'r, U: Units, R: RouteAwait> {
    kernel: &'k Kernel,
    units: &'k U,
    /// Where an abandoned unit's end is handed, so it is posted rather than dropped.
    route: &'k R,
    ctx: &'k UnitCtx,
    /// The terminal, until somebody runs it. `None` once one of the two callers has.
    ending: Option<(Run<'r>, Settling)>,
}

impl<U: Units, R: RouteAwait> Abandoned<'_, '_, U, R> {
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

impl<U: Units, R: RouteAwait> Drop for Abandoned<'_, '_, U, R> {
    fn drop(&mut self) {
        if let Some((run, settling)) = self.ending.take() {
            // The end is REACHED here — the audit door seals it, the cell is emptied and the leases
            // go back — and then it is HANDED ON, because reaching it is not posting it. The value
            // below carries the posting, and a posting moves no book until somebody reads it; the
            // caller that would have is the one that went away, so the leg's own plane reads it.
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
        .audit(&Pass::<Audit>::mint(seal), ctx, &outcome)
        .into_result(seal);
    let _bytes = units
        .encode(&Pass::<Encode>::mint(seal), ctx, &outcome)
        .into_result(seal);
    match settling {
        Settling::Exit(reached_admitted) => {
            exit(kernel, units, ctx, run, outcome, reached_admitted)
        }
        Settling::Parent(accrual) => {
            // The child opened no reservation of its own, but the table minted it an arrival hold
            // like every other unit, and that hold is in a cell the sweep also has a key to.
            // Emptying the cell HERE is what makes the child's end final: leaving it full would
            // leave the sweep free to settle a unit that already finished, and the parent's hold
            // already carries this spend.
            let taken = run.cell.take(&Grant::<Exit>::mint(seal));
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
                    let ledger = Grant::<WriteMoney>::mint(seal);
                    let parent = run.parent.unwrap_or(run.cell);
                    let posted = match Posted::into_parent(accrual, parent, &ledger) {
                        Ok(posted) => posted,
                        Err(missed) => Posted::settle_late(missed, &ledger),
                    };
                    run.canary.settled();
                    Ended::Settled {
                        end: UnitEnd::seal(&Grant::<Exit>::mint(seal), outcome, Ok(posted)),
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
///
/// `destinations` is the SAME set [`Units::verify`] sealed and [`open_to_door`] carried through
/// Approve and Admit — passed to both Route and Meter here rather than let either re-derive its own,
/// which is what makes "verify-then-act" true of this loop rather than merely stated by it.
async fn under_hold<U: Units, R: RouteAwait>(
    kernel: &Kernel,
    units: &U,
    route: &R,
    ctx: &UnitCtx,
    meter: &AccrualMeter,
    destinations: &[VerifiedDestination],
) -> Outcome {
    let seal = &kernel.seal;
    let token = Pass::<Route>::mint(seal);
    let leg = route.route_leg(&token, ctx, meter, destinations).await;
    match leg.into_result(seal) {
        Err(refusal) => {
            Outcome::Failed(refusal.step().unwrap_or(StepName::Route), refusal.reason())
        }
        Ok(_) => {
            let provisional = Outcome::Completed;
            match units
                .meter(
                    &Pass::<Meter>::mint(seal),
                    &Grant::<Consumption>::mint(seal),
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
    let taken = run.cell.take(&Grant::<Exit>::mint(seal));
    run.leases.release_all(run.gauge);
    match taken {
        None => Ended::AlreadySettled,
        Some(mut hold) => {
            let evidence = units.evidence(ctx);
            let (amount, table_flags) = settle_amount(&outcome, &evidence);
            let (fee, fee_flags) = fee_count(&evidence.fee);
            let flags = table_flags.with(fee_flags);
            let drawn = requests_drawn(ctx.origin, evidence.upstream_candidate);
            let requests = requests_settled(reached_admitted, drawn);
            // What the unit spent while it ran is applied to the hold here, where the hold is
            // owned. The spend lands in full: past the end of the reservation it grows out of
            // whatever headroom the leg offered while it ran, and whatever nothing can back is
            // carried out as an overdraft. There is no arm on this path that refuses — value was
            // delivered, so the only question left is which column it lands in.
            let _spend = hold.spend(run.meter.total(), run.meter.headroom());
            let class = evidence.class.unwrap_or(KERNEL_ACCRUAL_CLASS);
            let lines = vec![UsageLine {
                class,
                quantity: amount,
                // The exit path settles what the accrual meter counted while the unit ran, which
                // is the kernel's own figure, not one a destination reported.
                source: QuantitySource::Count,
                estimated: flags.contains(PostingFlags::ESTIMATED),
            }];
            let usage_token = Grant::<Consumption>::mint(seal);
            let usage = if flags.contains(PostingFlags::ESTIMATED) {
                Usage::estimate(&usage_token, lines)
            } else {
                Usage::report(&usage_token, lines)
            };
            let posted = match usage {
                Ok(usage) => {
                    // `amount` is the settlement table's money figure, in nano-units; the line
                    // above carries it as a quantity against whichever class the unit metered on.
                    // The posting settles the money, and reads the report for its evidence.
                    Ok(Posted::settle(
                        hold,
                        u128::from(amount),
                        &usage,
                        &Grant::<WriteMoney>::mint(seal),
                    )
                    .flagged(flags))
                }
                // A usage report the record cannot hold is a durability failure, not a discount:
                // the unit delivered value it cannot prove it recorded.
                Err(_) => {
                    drop_arrival(hold);
                    Err(DurabilityLost::observed(
                        &Grant::<DurableWrite>::mint(seal),
                        StepName::Meter,
                    ))
                }
            };
            run.canary.settled();
            Ended::Settled {
                end: UnitEnd::seal(&Grant::<Exit>::mint(seal), outcome, posted),
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

#[cfg(test)]
#[path = "tests/teller_seal_doc_tests.rs"]
mod teller_seal_doc_tests;
