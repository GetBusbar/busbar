// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Step 6 — **Meter**: what the unit actually used, as the LLM plane's own step file.
//!
//! This is the plane half of the kernel's `Units::meter` row: the step's own unit token, the usage
//! token the report is sealed with, the request's context and the provisional end, answering with
//! `Decision<Meter>` carrying the `Usage` the exit path settles against.
//!
//! # The body is today's accrual, unchanged
//!
//! One call: `engine::usage::ledger_and_meter`, with the same four arguments the live taps pass —
//! the stream-end tap in `FirstByteBody`, its drop-time partial, and the buffered tap on the
//! cross-protocol path. Behind it are the two host seams, `meter_ledger` (the tier split against
//! the key's budget chain, in the window the pinned arrival epoch names) and `meter_series` (the
//! raw per-model consumption row). This step calls them once, in that order, exactly as today.
//!
//! # One posting per unit, and which side of the walk makes it
//!
//! Those taps are inside the walk, and they have to be: a streamed answer's usage is known at
//! stream end and nowhere earlier, which is after the Route step returned, after this step ran and
//! after the Audit step gave the client its bytes. So for a unit that reached the walk holding the
//! admission's meter half, the walk's tap IS this step's body — the same function, the same four
//! arguments — and what this step does is SEAL what was posted rather than post it a second time.
//! [`MeterFacts::accrued`] is Route saying which of the two happened, and it is the only thing
//! standing between one accrual and two. [`Metered::posted`] is this step saying which of the two
//! it did, and it is set inside the accrual arm: the row this step reports is filled either way, so
//! a row cannot answer that question and a caller that read one for the answer would call every
//! sealed unit a posting.
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

use std::sync::Arc;

use busbar_caps::{
    step::Meter, Decision, Hold, MeterClassId, Outcome, QuantitySource, UnitToken, Usage,
    UsageLine, UsageToken,
};
use busbar_contract::ClassDirection;
use busbar_substrate::plane_host::EngineHost;

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
pub struct MeterCtx<'a> {
    host: &'a Arc<dyn EngineHost>,
    sink: Option<&'a crate::engine::UsageSink>,
    lane: Option<&'a crate::engine::Lane>,
    usage: Option<&'a busbar_substrate::billing::TokenUsage>,
    status: u16,
    charged: bool,
    billing_failed: bool,
    accrued: bool,
}

impl<'a> MeterCtx<'a> {
    /// Bind the step to one response.
    ///
    /// `status` is the status the CLIENT saw, never the upstream's — the fee is decided from the
    /// client-facing frame. `charged` is the admit step's: whether the admission charge landed, and
    /// therefore whether there is anything a non-2xx could refund. `billing_failed` is the terminal-error/abort fact the stream taps
    /// read off the translator.
    ///
    /// `allow(dead_code)` while the module is dark: the Route step is what builds one of these on
    /// the request path, and it does not exist yet.
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn new(
        host: &'a Arc<dyn EngineHost>,
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        usage: Option<&'a busbar_substrate::billing::TokenUsage>,
        status: u16,
        charged: bool,
        billing_failed: bool,
    ) -> Self {
        MeterCtx {
            host,
            sink,
            lane,
            usage,
            status,
            charged,
            billing_failed,
            // The step is the posting unless something before it says otherwise; `bind` is what
            // says otherwise.
            accrued: false,
        }
    }

    /// Bind the step to what the ROUTE step observed.
    ///
    /// The expression that did not exist: a [`MeterFacts`] plus the two things the facts cannot
    /// own — the host seam and the borrowed lane the index names — is a context. `charged` is still
    /// the admit step's, because whether the admission charge landed is not a fact about the walk.
    #[allow(dead_code)]
    pub(crate) fn bind(
        host: &'a Arc<dyn EngineHost>,
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        facts: &'a MeterFacts,
        charged: bool,
    ) -> Self {
        MeterCtx {
            host,
            sink,
            lane,
            usage: facts.usage.as_ref(),
            status: facts.status,
            charged,
            billing_failed: facts.billing_failed,
            accrued: facts.accrued,
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
    /// The metering row this response accrued — one request for the serving model, with the token
    /// split preserved. `None` when there was no key or no serving lane to attribute it to, which
    /// is the only case in which nothing is metered at all.
    pub row: Option<busbar_api::MeteringRow>,
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
    /// WHAT THAT REPORT IS WORTH, in nano-units, as the holder of the card answered it.
    ///
    /// Carried rather than left inside the hold, because the two are different questions with
    /// different answers: this is what the unit consumed valued at the card the door pinned, and the
    /// hold's `accrued` is what a reservation this step may not even have been handed has absorbed
    /// of it. A caller that read the hold for the price got zero on every unit the loop kept its
    /// reservation in the cell for — which is every unit the composition root drives.
    ///
    /// Zero where there was nothing to report.
    pub priced: u64,
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
    // THE FEE IS NOT DECIDED HERE, and this comment is what used to be the decision. This step
    // answered `delivered && ctx.upstream_leg` — two booleans — and carried the count out on its
    // report, and that was the number that BILLED, while the kernel decided the same fee off seven
    // fields on the same request and had its answer discarded. One request, two deciders, and the
    // one that reached the money was the one that could not see the origin or the dispute.
    //
    // The fee is the kernel's one decision and nothing else. The composition root builds
    // its evidence once and prices both the settlement and the late report through it — see
    // the composition root's own `fee_evidence`. What this step still owns is what the unit
    // CONSUMED; what it is worth, and how many billable requests it is, are the kernel's and the
    // card holder's.
    // A stream whose end carried a terminal error, or whose translation aborted, bills ZERO: the
    // accrual is skipped, not floored. The figures seen before the error are evidence only.
    let bills = !ctx.billing_failed;
    let reported = if bills { ctx.usage } else { None };

    // THE LIVE ACCRUAL, unchanged: the tier split onto the key's budget chain in the pinned
    // window, then the raw per-model series row. Both through the one seam the stream-end tap,
    // its drop-time partial and the buffered tap already call.
    //
    // ONE POSTING PER UNIT. Where the Route step handed the admission's meter half to the walk, the
    // walk's own tap already made this call with these arguments — it is where a streamed answer's
    // usage becomes known — and making it again here would post the same tokens twice. So this step
    // SEALS that unit: it reports the same row and the same figures, and it does not accrue them a
    // second time. Where the walk held no sink, this step is the accrual and makes the call itself.
    let mut row = None;
    // Whether the accrual arm below was the one that ran. Reported rather than derived: `row` is
    // filled on both sides of the branch and cannot stand in for this.
    let mut posted = false;
    // WHAT THE UNIT CONSUMED, assembled for whoever keeps the books. `None` until there is a lane
    // and a meter half to attribute it to, which is the honest statement that there is nothing to
    // price — and it is the same `None` a unit that billed nothing reports.
    let mut report = None;
    if bills {
        if let (Some(sink), Some(lane)) = (ctx.sink, ctx.lane) {
            // The tier split, projected once and read twice: the ledger accrues against it, and the
            // card prices the same counts. Hoisted out of the accrual arm so a unit the walk already
            // posted still prices what it delivered — sealing is not a reason to spend nothing.
            let tier = reported
                .map(busbar_llm_codec::wire_shim::tier_usage)
                .unwrap_or_default();
            if !ctx.accrued {
                crate::engine::usage::ledger_and_meter(ctx.host, sink, lane, reported, &tier);
                posted = true;
            }
            row = Some(metering_row(sink, lane, reported));
            // THE REPORT, and it is where the money used to be. The step used to reach the legacy
            // host seam here and come back with an amount; what it hands over now is the tier split
            // it already projected, the billable count it already decided, and the two names the row
            // it belongs to is keyed by — and it is told a total by the one side that holds a card.
            //
            // The lane is the SERVING lane's config name, after any failover. That is the key space
            // rates are written in and the same key the metering row above attributes to, so the
            // line this reports and the entry that prices it are keyed by the same name with no
            // translation between them.
            report = Some(crate::unit::walk::LateReport {
                usage: tier,
                lane: lane.model.clone(),
                provider: lane.provider.clone(),
            });
        }
    }

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

    // WHAT THE HOLDER OF THE CARD SAYS THIS UNIT IS WORTH — asked ONCE, and asked whether or not
    // this unit is carrying its reservation through the step.
    //
    // The ask used to be written inside the `hold.map(..)` below, which made it a question only a
    // unit handed a hold ever got asked. On the composition root's loop no unit is: the reservation
    // goes into the kernel's own cell at the door and the exit is the one place it comes out again,
    // so the step is handed `None` on every live path and `None.map(..)` never runs the closure.
    // The [`Worth`] seam the root supplies was therefore never invoked on a production unit, and the
    // figure it answers did not exist anywhere in the shipped binary.
    //
    // It is hoisted because what a report is worth is a fact about the REPORT. Whether the unit is
    // also carrying its hold through this step is a fact about the loop driving it, and one plane
    // asking the card a different number of questions depending on which loop drives it is two
    // answers to what one request cost.
    //
    // A unit with nothing to report is worth zero, which is the honest figure for one that reached
    // no lane and for one that billed none.
    let priced = report.as_ref().map(worth).unwrap_or(0);

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
        // WHAT IS SPENT IS WHAT THE HOLDER OF THE CARD SAID, and nothing this file worked out. It is
        // the one figure above, asked once: a second `worth(..)` here would be the card asked twice
        // about one report, and two asks are two answers waiting to differ.
        h.spend(priced, 0);
        h
    });

    Metered {
        decision: Decision::proceed(unit_token, usage),
        hold,
        row,
        // The refund is owed only where a charge landed and the client did not see a 2xx — and it
        // is owed against the fee base alone.
        refund: ctx.charged && !delivered,
        posted,
        report,
        priced,
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

/// The metering row this response accrues, in the shape the flush writes to the store.
///
/// The MODEL is the config name of the SERVING lane — the lane that actually answered, after any
/// failover — because that is the key the rate card is written against; the wire name a lane sends
/// upstream is not an accounting key. A delivered response always counts its request, whatever it
/// consumed.
fn metering_row(
    sink: &crate::engine::UsageSink,
    lane: &crate::engine::Lane,
    usage: Option<&busbar_substrate::billing::TokenUsage>,
) -> busbar_api::MeteringRow {
    busbar_api::MeteringRow {
        key_id: sink.key.id.clone(),
        model: lane.model.clone(),
        provider: lane.provider.clone(),
        tokens_input: usage.map(|u| u.input).unwrap_or(0),
        tokens_output: usage.map(|u| u.output).unwrap_or(0),
        tokens_cache_read: usage.and_then(|u| u.cache_read).unwrap_or(0),
        tokens_cache_write: usage.and_then(|u| u.cache_creation).unwrap_or(0),
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    }
}

#[cfg(test)]
#[path = "tests/meter.rs"]
mod tests;
