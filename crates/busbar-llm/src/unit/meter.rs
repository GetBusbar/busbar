// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 6 — **Meter**: what the unit actually used, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::meter` row: the step's own unit token, the usage
//! token the report is sealed with, the request's context and the provisional end, answering with
//! `Decision<Meter>` carrying the `Usage` the exit path settles against.
//!
//! # One posting per unit, and the walk is the one that makes it
//!
//! The accrual is `engine::usage::ledger_and_meter` — the tier split against the key's budget chain
//! in the window the pinned arrival epoch names, then the raw per-model consumption row — and it is
//! made by the taps INSIDE the walk: the stream-end tap in `FirstByteBody`, its drop-time partial,
//! and the buffered tap on the cross-protocol path. It has to be there: a streamed answer's usage is
//! known at stream end and nowhere earlier, which is after the Route step returned, after this step
//! ran and after the Audit step gave the client its bytes.
//!
//! **So this step never accrues.** It SEALS what the walk posted. It used to carry an arm that made
//! the accrual itself, for a unit whose walk held no meter half — but no unit can be in that state:
//! Route hands the meter half to the walk on every unit that resolves candidates and hands it back
//! on exactly one exit, the candidate miss, which resolves no lane. A meter half and a serving lane
//! therefore never arrive together, and the arm that needed both is gone. What stands in its place
//! is an assertion, so a Route step that ever handed both back stops here instead of opening the
//! door to a second accrual. [`Metered::posted`] is `false` for every unit, and the rehearsal
//! asserts it — which is what keeps the deletion honest rather than merely believed.
//!
//! # A STREAMED UNIT'S REPORT IS EMPTY BY CONSTRUCTION, and that is the decision
//!
//! The figures a stream is billed on arrive in a terminal usage frame at the END of the body. The
//! loop hands the client its bytes at step 7. So at step 6 the frame has not arrived, and there is
//! no shape of [`MeterFacts`], no cell and no seam a tap could post through that would put figures
//! into a report which is sealed before those figures exist. Deferring the seal until they do would
//! mean holding the unit open past its own terminal, which is a different loop.
//!
//! So this step does not pretend. For a streamed unit it reports what it honestly has — nothing —
//! and the accrual is the tap's: `ledger_and_meter` puts the tier split onto the key's budget chain
//! and the raw row into the metering series from inside the walk, at the one moment a streamed
//! answer's usage is knowable. What must NOT be empty is the statement of who made that posting,
//! because "one accrual per unit" is a property of the pair, and that is what [`Metered::posted`]
//! carries.
//!
//! What this step CAN do, and does, is read as late as it is allowed to. Route folds the tap's
//! report on the way out, which catches every end that had already finished by then; the walk folds
//! it again out of the response's own cell just before binding this step, which catches every end
//! that finished in between — a buffered answer, and a stream cut short before its terminal frame.
//! Only a stream still flowing at step 6 reports empty, and for that one the tap is the posting.
//!
//! # Where the money is
//!
//! **The fee basis is the client-facing status, decided once.** The flat per-request fee posts on a
//! 2xx and on nothing else, and it is decided at the first frame relayed to the CLIENT — which is
//! why a buffered cross-protocol response whose upstream 2xx became a client 502 posts no fee and
//! no tokens. Once decided it is never reversed by a later abort: a 2xx stream that dies mid-way
//! posts its fee, because the caller got the value that was on the wire when the status was
//! settled. The fee is a lookahead at the door and a posting here, and this step reports which.
//!
//! **The refund rule is one counter, not two.** A non-2xx end refunds the fee base
//! (`billable_requests`) and never the admission count (`requests`). That asymmetry is the whole
//! design: the caller is not billed a flat fee for a failure outside its control, and a thousand
//! failed requests still consume a thousand slots, so a cap cannot be escaped by hammering
//! failures. A refund is only ever issued for a request whose charge LANDED — the admit step's
//! `charged` — because the refund is a blind decrement of a shared window counter, and issuing one
//! for a request that never charged erodes some other request's spend in the same window. It lands
//! in the window the pinned arrival epoch names, which is the window the charge landed in, so a
//! request that straddles a boundary refunds where it charged.
//!
//! **A stream that ends in an error bills ZERO tokens.** Not the tokens observed before the error,
//! and not a floor: the accrual is skipped entirely, exactly as the live taps skip it when the
//! translator reports a terminal error or an abort. The figures observed either side of it are
//! evidence, and evidence is not a charge.
//!
//! **A response that reports no usage bills ZERO and still counts its request.** The token ledger
//! is untouched — nothing is charged to the key's budget — and the metering series records one
//! request for the serving model with every tier at zero. Dropping the row because the tiers were
//! empty would make the request count and the consumption disagree about the same response.
//!
//! # The hold, and the settle that is not here
//!
//! Meter computes; the exit path settles. There are exactly two places a hold is taken out of its
//! cell — the exit and the node's sweep — and a third would be a unit that could post twice. So
//! this step takes the hold, accrues against it, and hands it straight back for the exit to close;
//! it never builds a `Posted`. What it does own is the report the posting is made against.
//!
//! **What it accrues is MONEY, and this step is not what turns the counts into it.** A reservation
//! is in nano-units, so the spend has to be too. The report's lines are quantities in four different
//! meter classes and their sum is a figure in no unit at all. What those quantities are WORTH is a
//! question about the deployment's rates, and the rates belong to whoever keeps the books — so this
//! step assembles the report and asks, through [`Worth`], and takes the answer back. That is the
//! same seam the late accrual goes through and the same report shape it hands back
//! ([`crate::unit::walk::LateReport`]): one statement of what a unit consumed, whether it is read at
//! the step or after the body drained, and one place that prices it.
//!
//! So there is no rate, no fee, no card and no price anywhere in this file. A plane says what it
//! did; the composition root says what it cost.

use busbar_caps::{
    step::Meter, Decision, Hold, MeterClassId, Outcome, QuantitySource, UnitToken, Usage,
    UsageLine, UsageToken,
};
use busbar_contract::ClassDirection;

/// WHAT THE ROUTE STEP OBSERVED — the facts this step is bound to, as the step before it hands
/// them over.
///
/// This is the value that was missing: `Routed` used to carry a response and nothing else, so no
/// expression a driver could write produced a [`MeterCtx`] from what Route returned. Every field
/// here is read off the walk that actually ran.
///
/// [`MeterFacts::accrued`] is the load-bearing one, and it says where this unit's ONE posting is
/// made. The walk is handed the admission's meter half and its taps — the buffered tap and the
/// stream-end tap — are the only places a streamed answer's usage becomes known at all; a stream is
/// still flowing when Route returns and when this step runs, so no shape of this type could carry
/// its figures forward. So the walk's tap IS this step's body for a unit that reached it, and this
/// step's job on that unit is to SEAL what was posted rather than to post it again. Where the walk
/// held no sink there is nothing to seal and this step is the posting.
///
/// These facts are folded from the tap's report TWICE — once by Route on the way out, once by the
/// walk just before the Meter step binds — because the cell rides on the response and may fill in
/// between. Folding takes the whole report or none of it, so the second fold rewrites the same three
/// figures with themselves where the first already ran.
// Built by the Route step and read by the chain that drives the two together; both are dark until
// the composition root installs these steps, which is what this allow covers and what retires it.
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct MeterFacts {
    /// The serving lane, as an index into the engine's lane table — the lane that actually answered
    /// after any failover. Filled from [`MeterFacts::tap`] where the tap had already finished when
    /// Route returned (every buffered end); `None` while a stream is still flowing, and read off the
    /// cell instead when this step runs after it.
    pub(crate) lane: Option<usize>,
    /// The usage the dialect's reader found. Same source and the same timing: a stream's terminal
    /// usage frame has not arrived when Route returns, so the snapshot is empty and the cell is what
    /// answers later.
    pub(crate) usage: Option<busbar_substrate::billing::TokenUsage>,
    /// The status the CLIENT saw — the fee basis, decided at the frame that carried it.
    pub(crate) status: u16,
    /// The terminal-error/abort/cut fact the taps read at the end of the response.
    pub(crate) billing_failed: bool,
    /// Whether the unit reached an upstream at all, which is what makes it a fee-bearing client
    /// request rather than a turn-away that never dialled.
    pub(crate) upstream_leg: bool,
    /// Whether the walk's own taps hold this unit's accrual. When true this step seals; when false
    /// this step posts.
    pub(crate) accrued: bool,
}

impl MeterFacts {
    /// FOLD A TAP'S REPORT INTO THESE FACTS.
    ///
    /// The three figures the Route step could not fill are the tap's, and this is where they land:
    /// the serving lane, the usage the dialect's reader found, and whether those figures are
    /// evidence rather than a charge. Route calls it on the way out, which fills them for every end
    /// the tap had already reached — every buffered answer, and every transfer that failed before a
    /// body could flow. A stream's report does not exist yet at that moment, so nothing is folded and
    /// the facts stay as they were, `accrued` says the tap owns the posting, and the tap's own
    /// accrual is the unit's one accrual.
    ///
    /// A report is folded ONCE and never partially: reading three figures out of two different
    /// observations of the same response is the divergence this takes the whole report to avoid.
    pub(crate) fn fold(&mut self, report: &crate::engine::TapReport) {
        self.lane = Some(report.lane);
        self.usage = report.usage.clone();
        self.billing_failed = report.billing_failed;
    }
}

/// What the accrual needs that the step shape has nowhere to put.
///
/// Built by the Route step out of what the response actually was, so every figure here is observed
/// rather than assumed: the status the CLIENT saw, the lane that actually answered post-failover,
/// and the usage the dialect's reader found — or did not.
/// NO HOST SEAM AND NO `accrued`. Both were the accrual arm's, and the arm is gone: this step
/// reaches nothing and posts nothing, so a host to post through is not something it needs, and
/// "who made the accrual" is not a question it branches on any more. `MeterFacts` still carries
/// `accrued` for the Route step's own assertions, which is where the fact belongs.
pub struct MeterCtx<'a> {
    /// The admission's meter half, where the walk handed it back. Kept only so the step can CHECK
    /// that it never arrives beside a lane — see the assertion in [`meter`].
    sink: Option<&'a crate::engine::UsageSink>,
    lane: Option<&'a crate::engine::Lane>,
    usage: Option<&'a busbar_substrate::billing::TokenUsage>,
    status: u16,
    charged: bool,
    upstream_leg: bool,
    billing_failed: bool,
}

impl<'a> MeterCtx<'a> {
    /// Bind the step to one response.
    ///
    /// `status` is the status the CLIENT saw, never the upstream's — the fee is decided from the
    /// client-facing frame. `charged` is the admit step's: whether the admission charge landed, and
    /// therefore whether there is anything a non-2xx could refund. `upstream_leg` says the unit
    /// routed to an upstream, which is what makes it a fee-bearing client request rather than a
    /// kernel verb or a delivery. `billing_failed` is the terminal-error/abort fact the stream taps
    /// read off the translator.
    ///
    /// `allow(dead_code)` while the module is dark: the Route step is what builds one of these on
    /// the request path, and it does not exist yet.
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn new(
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        usage: Option<&'a busbar_substrate::billing::TokenUsage>,
        status: u16,
        charged: bool,
        upstream_leg: bool,
        billing_failed: bool,
    ) -> Self {
        MeterCtx {
            sink,
            lane,
            usage,
            status,
            charged,
            upstream_leg,
            billing_failed,
        }
    }

    /// Bind the step to what the ROUTE step observed.
    ///
    /// The expression that did not exist: a [`MeterFacts`] plus the two things the facts cannot
    /// own — the host seam and the borrowed lane the index names — is a context. `charged` is still
    /// the admit step's, because whether the admission charge landed is not a fact about the walk.
    #[allow(dead_code)]
    pub(crate) fn bind(
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        facts: &'a MeterFacts,
        charged: bool,
    ) -> Self {
        MeterCtx {
            sink,
            lane,
            usage: facts.usage.as_ref(),
            status: facts.status,
            charged,
            upstream_leg: facts.upstream_leg,
            billing_failed: facts.billing_failed,
        }
    }

    /// Whether the client saw a success. The one reading the fee and the refund both key off.
    #[must_use]
    pub fn delivered(&self) -> bool {
        matches!(self.status, 200..=299)
    }
}

/// The step's answer, plus what the Audit step and the exit path read.
///
/// [`Metered::decision`] is exactly what the kernel's `Units::meter` returns. The hold rides back
/// out untouched by anything but its accrual, because settling it is the exit's and only the
/// exit's.
pub struct Metered {
    /// The sealed step-6 answer: the usage report the posting is made against.
    pub decision: Decision<Meter>,
    /// The unit's reservation, handed back for the exit path to settle. Never settled here: there
    /// are two places a hold leaves its cell and this is not one of them.
    pub hold: Option<Hold>,
    /// Whether the flat per-request fee posts: 1 on a delivered 2xx from an upstream leg, 0
    /// otherwise. Decided here, from the client-facing status, and never reversed later.
    pub fee_count: u32,
    /// Whether the Audit step must refund the fee base. True exactly when the admission charge
    /// landed and the client did not see a 2xx.
    pub refund: bool,
    /// WHETHER THIS STEP MADE THE ACCRUAL, as opposed to sealing one the walk's tap already made.
    ///
    /// Set inside the accrual arm and nowhere else, so it is the arm's own report of itself rather
    /// than a fact derived after the fact. [`Metered::row`] cannot answer this: a row is what the
    /// response consumed and it is reported on both sides of the branch, because sealing is not a
    /// reason to report nothing.
    pub posted: bool,
    /// WHAT THE UNIT CONSUMED, for whoever keeps the books.
    ///
    /// The classes and quantities the tap read, the count of billable requests this unit is, and the
    /// two names the row it belongs to is keyed by. No amount, no rate and no card — the holder
    /// prices it and the step is told a total.
    ///
    /// It is the SAME type the late reading hands back, deliberately: a unit that reports one shape
    /// at the step and a different shape after its body drained is a unit whose two readings can
    /// disagree about what it consumed. `None` where there was no lane, no meter half, or nothing
    /// billable to report — which is the honest statement that there is nothing to price.
    pub report: Option<crate::unit::walk::LateReport>,
}

impl Metered {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Meter> {
        self.decision
    }
}

/// WHAT A REPORT IS WORTH, as this plane is handed it.
///
/// A report goes in and an amount in nano-units comes back. That is the whole of the seam, and it is
/// the reason no rate, no fee and no card appears on this side of it: the plane holds none of them,
/// so it asks whoever does and takes the answer. The composition root supplies this against the card
/// the admission pinned — the same card the late reading is priced against — and a build with no
/// card bound answers zero, which is the honest figure for a node that can price nothing.
pub type Worth<'a> = &'a dyn Fn(&crate::unit::walk::LateReport) -> u64;

/// The shape of this step, as a value — the `Units::meter` row with the plane's own context.
///
/// The kernel's row also takes the hold implicitly, through the cell; here it is passed and
/// returned explicitly, because a plane holds no cell and the point is that the hold leaves this
/// step exactly as it arrived plus its accrual.
pub type MeterStep = for<'a> fn(
    &UnitToken<Meter>,
    &UsageToken,
    &MeterCtx<'a>,
    Option<Hold>,
    &Outcome,
    Worth<'a>,
) -> Metered;

/// The four reserved meter classes, in the canonical order the pricer prices them.
///
/// Named from the neutral reserved-unit spellings rather than any dialect's wire field, because the
/// readers already normalize every dialect onto them: input is UNCACHED input, and the two cache
/// tiers are ADDITIVE, so the four partition what the response consumed on every provider.
const CLASS_INPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_INPUT);
const CLASS_OUTPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_OUTPUT);
const CLASS_CACHE_READ: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_READ);
const CLASS_CACHE_WRITE: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_WRITE);

/// Step 6. Fold what the legs reported, accrue it, and say what the posting is made against.
///
/// The provisional end is carried for the record and does not lower the fee: the fee was decided
/// at the frame that carried the status, and a unit that ended badly after that still delivered
/// what the caller was billed for.
pub fn meter(
    unit_token: &UnitToken<Meter>,
    usage_token: &UsageToken,
    ctx: &MeterCtx<'_>,
    hold: Option<Hold>,
    _provisional: &Outcome,
    worth: Worth<'_>,
) -> Metered {
    let delivered = ctx.delivered();
    // The fee is the KIND of leg and the client-facing status, and nothing else: one per delivered
    // client request that routed to an upstream. Decided once, here, and carried on both the step's
    // own answer and the report handed over to be priced, so the two cannot come to different
    // answers about the same unit.
    let fee_count = u32::from(delivered && ctx.upstream_leg);
    // A stream whose end carried a terminal error, or whose translation aborted, bills ZERO: the
    // accrual is skipped, not floored. The figures seen before the error are evidence only.
    let bills = !ctx.billing_failed;
    let reported = if bills { ctx.usage } else { None };

    // THE ACCRUAL IS THE TAP'S, ON EVERY UNIT THAT REACHED A LANE — and this step does not make a
    // second one. The Route step hands the admission's meter half to the walk on every unit that
    // resolved candidates, and the walk's own tap makes the accrual with these arguments; it is
    // where a streamed answer's usage becomes known, and making the call again here would post the
    // same tokens twice. So this step SEALS that unit rather than accruing it.
    //
    // The arm that used to accrue here, for "the walk held no sink", is gone because no unit can
    // reach it: Route hands the meter half BACK on exactly one exit — the candidate miss — and that
    // exit resolves no lane, so a sink and a lane never arrive together. The assertion is what keeps
    // that true rather than merely true today: a Route step that handed both back would be opening
    // the door to a second accrual, and it stops here instead of posting one.
    debug_assert!(
        !(ctx.sink.is_some() && ctx.lane.is_some()),
        "the walk holds the meter half on every routed unit; a sink beside a lane is a second accrual"
    );
    // WHAT THE UNIT CONSUMED, assembled for whoever keeps the books. `None` until there is a lane to
    // attribute it to, which is the honest statement that there is nothing to price.
    //
    // Built through the SAME constructor the late reading uses, and gated on the lane alone. It is
    // deliberately not gated on `bills`: a unit whose stream carried a terminal error reached a lane
    // and consumed nothing the node will charge for, which is an EMPTY tier rather than no report at
    // all — and it still carries the fee count the previous release charges on it. Gating the report
    // here as well would have been this step answering that question differently from the late
    // reading, about the same unit.
    let report = ctx
        .lane
        .map(|lane| crate::unit::walk::LateReport::of(reported, fee_count, lane));

    // The report the posting is made against: one line per non-zero tier, in canonical order. A
    // response that reported nothing reports no lines — zero, not a floor, because that is what the
    // older release bills when an upstream tells it nothing.
    let mut lines = Vec::new();
    if let Some(u) = reported {
        push_line(&mut lines, CLASS_INPUT, ClassDirection::Input, u.input);
        push_line(&mut lines, CLASS_OUTPUT, ClassDirection::Response, u.output);
        push_line(
            &mut lines,
            CLASS_CACHE_READ,
            ClassDirection::CacheRead,
            u.cache_read.unwrap_or(0),
        );
        push_line(
            &mut lines,
            CLASS_CACHE_WRITE,
            ClassDirection::CacheWrite,
            u.cache_creation.unwrap_or(0),
        );
    }
    let usage = Usage::report(usage_token, lines).expect("four tiers fit any record");

    // The hold, spent against and handed straight back. Nothing settles here.
    let hold = hold.map(|mut h| {
        // Nano-units against a reservation in nano-units. The report's own quantity sum is still
        // there to be read and is still not a money figure.
        //
        // `spend` rather than `accrue`, and with ZERO headroom. The difference between them is what
        // happens when the spend runs past the reservation: `accrue` reports it and `spend` records
        // it. The reservation was sized by a guess made at the door before a single upstream token
        // existed, and the value has been delivered by the time this step prices it — so a guess
        // that came in low is a normal outcome, not an error, and the excess is carried out on the
        // hold into the next window's admissible budget. Dropping it would settle the unit as one
        // that fitted.
        //
        // The headroom is zero because this step has none to offer. Drawing a top-up from the
        // principal's slice of the bucket window is the admission unit's act against a slice this
        // plane does not hold; claiming headroom here would mean growing a reservation against
        // budget nobody checked. So the whole shortfall is carried, which is the conservative half
        // of the same accounting.
        //
        // WHAT IS SPENT IS WHAT THE HOLDER OF THE CARD SAID, and nothing this file worked out. A
        // unit with nothing to report spends zero, which is the honest figure for one that reached
        // no lane and for one that billed none.
        h.spend(report.as_ref().map(worth).unwrap_or(0), 0);
        h
    });

    Metered {
        decision: Decision::proceed(unit_token, usage),
        hold,
        fee_count,
        // The refund is owed only where a charge landed and the client did not see a 2xx — and it
        // is owed against the fee base alone.
        refund: ctx.charged && !delivered,
        // NEVER, and it is now a property rather than a branch outcome: the accrual arm above is
        // gone because no unit could reach it, so the tap is the one accrual of every unit and this
        // step is always the seal. The rehearsal asserts this, which is what keeps the deletion
        // honest — a step that started posting again would fail there.
        posted: false,
        report,
    }
}

/// One line, if the tier carries anything. A zero-quantity line is not a fact about anything.
fn push_line(
    lines: &mut Vec<UsageLine>,
    class: MeterClassId,
    direction: ClassDirection,
    quantity: u64,
) {
    if quantity == 0 {
        return;
    }
    lines.push(UsageLine {
        class,
        quantity,
        // The figure came from the destination's own response, read at the locator the dialect's
        // reader knows — not from a byte count of ours. The four directions are what partitions the
        // tiers: uncached input, the response, and the two additive cache sides.
        source: QuantitySource::Locator {
            direction,
            ptr: busbar_caps::LocatorPtr::new(class.as_str()),
        },
        estimated: false,
    });
}

#[cfg(test)]
#[path = "tests/meter.rs"]
mod tests;
