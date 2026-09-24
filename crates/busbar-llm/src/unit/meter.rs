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
//! [`MeterFacts::tap_posts`] is Route saying which of the two happened, and it is the only thing
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
//! **The refund is not this step's.** A non-2xx end refunds the fee base (`billable_requests`) and
//! never the admission count (`requests`), only where the admission charge LANDED, in the window the
//! pinned arrival epoch names — and that decision is made in exactly ONE place: the admitted
//! terminal door (`EngineHost::finish_admitted`, reached through the Audit step with the admit
//! step's `charged`), which reads the client-facing status and refunds. This step used to compute a
//! second copy of the same rule that nothing read; a second decision with no consumer is a decision
//! that can drift from the one that is applied, so it is gone, and the rehearsal
//! (`unit/tests/chain.rs`) holds the door's refund on the ledger itself.
//!
//! **A stream that ends in an error bills the tokens it streamed.** A terminal error, a translate
//! abort, a transport cut or a timeout is an interruption, not a reversal of incurred cost: the
//! customer pays for what was actually delivered up to the cut, exactly as the live taps accrue it
//! (#62, owner-locked). The readers were fed only the frames that arrived before the end, so what
//! they report IS what streamed; a transfer that failed before a byte reached the client reported
//! nothing and bills nothing, with no gate of its own.
//!
//! **A response that reports no usage bills ZERO and still counts its request.** The token ledger
//! is untouched — nothing is charged to the key's budget — and the metering series records one
//! request for the serving model with every tier at zero. Dropping the row because the tiers were
//! empty would make the request count and the consumption disagree about the same response.
//!
//! # No hold, and no settle
//!
//! Meter counts; the kernel settles. The hold is the kernel's — opened at its admit, in the unit's
//! cell, and taken out only by the exit and the node's sweep (#43, #83 defs 5/6) — so this step is
//! handed none, carries none and spends against none. What it does own is the report of counts
//! the posting is made against.
//!
//! **What a unit consumed is not what it is WORTH, and this step does not turn one into the other.**
//! The report's lines are quantities in four different meter classes and their sum is a figure in no
//! unit at all. What those quantities are worth is a question about the deployment's rates, and the
//! rates belong to whoever keeps the books — so this step assembles the report and hands it over, in
//! the same report shape the late accrual hands back ([`crate::unit::walk::LateReport`]): one
//! statement of what a unit consumed, whether it is read at the step or after the body drained, and
//! one place — off this plane — that turns it into an amount.
//!
//! So there is no rate, no fee, no card and no price anywhere in this file. A plane says what it
//! did; the composition root says what it cost.

use std::sync::Arc;

use busbar_contract::caps::{
    step::Meter, Consumption, Decision, Grant, MeterClassId, Outcome, Pass, QuantitySource, Usage,
    UsageLine,
};
use busbar_contract::ClassDirection;
use busbar_kernel::plane_host::EngineHost;

/// WHAT THE ROUTE STEP OBSERVED — the facts this step is bound to, as the step before it hands
/// them over.
///
/// This is the value that was missing: `Routed` used to carry a response and nothing else, so no
/// expression a driver could write produced a [`MeterCtx`] from what Route returned. Every field
/// here is read off the walk that actually ran.
///
/// [`MeterFacts::tap_posts`] is the load-bearing one, and it says where this unit's ONE posting is
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
    pub(crate) usage: Option<busbar_substrate_values::billing::TokenUsage>,
    /// Every OPEN class the response billed beside the token split (a rerank's search units), as
    /// the tap reported it — the same map the governance ledger accrued. Same source and timing as
    /// `usage`, and empty until the tap has reported.
    pub(crate) open_units: std::collections::BTreeMap<String, u64>,
    /// The status the CLIENT saw — the fee basis, decided at the frame that carried it.
    pub(crate) status: u16,
    /// Whether the unit reached an upstream at all, which is what makes it a fee-bearing client
    /// request rather than a turn-away that never dialled.
    pub(crate) upstream_leg: bool,
    /// Whether the walk's own tap posts this unit's counts. When true this step seals; when false
    /// this step posts.
    pub(crate) tap_posts: bool,
}

impl MeterFacts {
    /// FOLD A TAP'S REPORT INTO THESE FACTS.
    ///
    /// The figures the Route step could not fill are the tap's, and this is where they land:
    /// the serving lane and the usage the dialect's reader found up to the end the response reached,
    /// which is the charge on every end (#62). Route calls it on the way out, which fills them for every end
    /// the tap had already reached — every buffered answer, and every transfer that failed before a
    /// body could flow. A stream's report does not exist yet at that moment, so nothing is folded and
    /// the facts stay as they were, `tap_posts` says the tap owns the posting, and the tap's own
    /// accrual is the unit's one accrual.
    ///
    /// A report is folded ONCE and never partially: reading two figures out of two different
    /// observations of the same response is the divergence this takes the whole report to avoid.
    pub(crate) fn fold(&mut self, report: &crate::engine::TapReport) {
        self.lane = Some(report.lane);
        self.usage = report.usage.clone();
        self.open_units = report.open_units.clone();
    }
}

/// **EVERY CLASS THE UNIT BILLED**, as one neutral class map: the reserved token split and every
/// open class beside it (#71: the ledger event is the raw counts per class — every class). Zero
/// counts are left off, as the token projection leaves them.
///
/// The one reading both reports are built from — the Meter step's at step 6 and the late reading
/// after the body drained — so a unit cannot report its search units at one and not the other. The
/// token split is projected exactly as before; an open class never collides with a reserved one (a
/// codec names its counted class, and none names a token tier), and if one ever did the TOKEN
/// figure stands, so no token figure can move through this function.
pub(crate) fn billed_classes(
    usage: Option<&busbar_substrate_values::billing::TokenUsage>,
    open_units: &std::collections::BTreeMap<String, u64>,
) -> busbar_substrate_values::billing::Usage {
    let mut billed = usage
        .map(busbar_llm_codec::wire_shim::tier_usage)
        .unwrap_or_default();
    for (class, count) in open_units {
        if *count > 0 {
            billed.usage_units.entry(class.clone()).or_insert(*count);
        }
    }
    billed
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
    usage: Option<&'a busbar_substrate_values::billing::TokenUsage>,
    /// The open classes beside the token split; `None` where nothing reported any.
    open_units: Option<&'a std::collections::BTreeMap<String, u64>>,
    status: u16,
    upstream_leg: bool,
    tap_posts: bool,
}

impl<'a> MeterCtx<'a> {
    /// Bind the step to one response.
    ///
    /// `status` is the status the CLIENT saw, never the upstream's — the fee is decided from the
    /// client-facing frame. `upstream_leg` says the unit
    /// routed to an upstream, which is what makes it a fee-bearing client request rather than a
    /// kernel verb or a delivery. How the response ENDED is not a parameter: a cut stream bills
    /// what it streamed (#62), so `usage` is the whole charge on every end.
    ///
    /// TEST-ONLY: production binds through [`MeterCtx::bind`] from what the Route step observed;
    /// this spelled-out form is what the step's own tests drive.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        host: &'a Arc<dyn EngineHost>,
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        usage: Option<&'a busbar_substrate_values::billing::TokenUsage>,
        status: u16,
        upstream_leg: bool,
    ) -> Self {
        MeterCtx {
            host,
            sink,
            lane,
            usage,
            open_units: None,
            status,
            upstream_leg,
            // The step is the posting unless something before it says otherwise; `bind` is what
            // says otherwise.
            tap_posts: false,
        }
    }

    /// Bind the step to what the ROUTE step observed.
    ///
    /// The expression that did not exist: a [`MeterFacts`] plus the two things the facts cannot
    /// own — the host seam and the borrowed lane the index names — is a context.
    pub(crate) fn bind(
        host: &'a Arc<dyn EngineHost>,
        sink: Option<&'a crate::engine::UsageSink>,
        lane: Option<&'a crate::engine::Lane>,
        facts: &'a MeterFacts,
    ) -> Self {
        MeterCtx {
            host,
            sink,
            lane,
            usage: facts.usage.as_ref(),
            open_units: Some(&facts.open_units),
            status: facts.status,
            upstream_leg: facts.upstream_leg,
            tap_posts: facts.tap_posts,
        }
    }

    /// Whether the client saw a success. The one reading the fee keys off.
    #[must_use]
    pub fn delivered(&self) -> bool {
        matches!(self.status, 200..=299)
    }
}

/// The step's answer, plus what the Audit step and the exit path read.
///
/// [`Metered::decision`] is exactly what the kernel's `Units::meter` returns.
pub struct Metered {
    /// The sealed step-6 answer: the usage report the posting is made against.
    pub decision: Decision<Meter>,
    /// The metering row this response accrued — one request for the serving model, with the token
    /// split preserved. `None` when there was no key or no serving lane to attribute it to, which
    /// is the only case in which nothing is metered at all.
    pub row: Option<busbar_api::MeteringRow>,
    /// Whether the flat per-request fee posts: 1 on a delivered 2xx from an upstream leg, 0
    /// otherwise. Decided here, from the client-facing status, and never reversed later.
    pub fee_count: u32,
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
    /// two names the row it belongs to is keyed by. No amount, no rate and no card — the step hands
    /// this over and the side that holds the card is the one that turns it into a total.
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

/// The shape of this step, as a value — the `Units::meter` row with the plane's own context.
///
/// The hold is not part of it: the kernel's row reaches the hold through the unit's cell, which a
/// plane never holds, and a plane-side step that carried one would be a plane doing money.
pub type MeterStep =
    for<'a> fn(&Pass<Meter>, &Grant<Consumption>, &MeterCtx<'a>, &Outcome) -> Metered;

/// The four reserved meter classes, in the canonical order the pricer prices them.
///
/// Named from the neutral reserved-unit spellings rather than any dialect's wire field, because the
/// readers already normalize every dialect onto them: input is UNCACHED input, and the two cache
/// tiers are ADDITIVE, so the four partition what the response consumed on every provider.
const CLASS_INPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_INPUT);
const CLASS_OUTPUT: MeterClassId = MeterClassId::new(busbar_api::UNIT_OUTPUT);
const CLASS_CACHE_READ: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_READ);
const CLASS_CACHE_WRITE: MeterClassId = MeterClassId::new(busbar_api::UNIT_CACHE_WRITE);

/// Step 6. Fold what the legs reported, post the counts, and say what the posting is made against.
///
/// The provisional end is carried for the record and does not lower the fee: the fee was decided
/// at the frame that carried the status, and a unit that ended badly after that still delivered
/// what the caller was billed for.
pub fn meter(
    unit_token: &Pass<Meter>,
    usage_token: &Grant<Consumption>,
    ctx: &MeterCtx<'_>,
    _provisional: &Outcome,
) -> Metered {
    let delivered = ctx.delivered();
    // The fee is the KIND of leg and the client-facing status, and nothing else: one per delivered
    // client request that routed to an upstream. Decided once, here, and carried on both the step's
    // own answer and the report handed over to be priced, so the two cannot come to different
    // answers about the same unit.
    let fee_count = u32::from(delivered && ctx.upstream_leg);
    // A stream whose end carried a terminal error, whose translation aborted or whose transport was
    // cut bills what it streamed up to that end (#62): the reported usage is the charge on every end,
    // and there is no end that turns it back into mere evidence.
    let reported = ctx.usage;

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
    if let (Some(sink), Some(lane)) = (ctx.sink, ctx.lane) {
        // The tier split, projected once and read twice: the ledger accrues against it, and the
        // card prices the same counts. Hoisted out of the accrual arm so a unit the walk already
        // posted still prices what it delivered — sealing is not a reason to spend nothing.
        //
        // EVERY class the unit billed, the open ones included (a rerank's search units): the same
        // map the walk's tap accrued, so a unit this step posts ledgers what a unit the tap posted
        // ledgers, and the report hands the card every count (#71).
        let no_open = std::collections::BTreeMap::new();
        let tier = billed_classes(reported, ctx.open_units.unwrap_or(&no_open));
        if !ctx.tap_posts {
            crate::engine::usage::ledger_and_meter(ctx.host, sink, lane, reported, &tier);
            posted = true;
        }
        row = Some(metering_row(sink, lane, reported));
        // THE REPORT, and it is where the money used to be. The step used to reach the legacy
        // host seam here and come back with an amount; what it hands over now is the tier split
        // it already projected, the billable count it already decided, and the two names the row
        // it belongs to is keyed by — and the side that holds a card turns that into a total.
        //
        // The lane is the SERVING lane's config name, after any failover. That is the key space
        // rates are written in and the same key the metering row above attributes to, so the
        // line this reports and the entry that prices it are keyed by the same name with no
        // translation between them.
        report = Some(crate::unit::walk::LateReport {
            usage: tier,
            fee_count,
            lane: lane.model.clone(),
            provider: lane.provider.clone(),
        });
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

    // This step settles nothing: what the unit consumed leaves on the report, and the side that
    // holds the card is the one that turns those quantities into an amount.
    Metered {
        decision: Decision::proceed(unit_token, usage),
        row,
        fee_count,
        posted,
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
            ptr: busbar_contract::caps::LocatorPtr::new(class.as_str()),
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
    usage: Option<&busbar_substrate_values::billing::TokenUsage>,
) -> busbar_api::MeteringRow {
    busbar_api::MeteringRow {
        usage_units: Default::default(),
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
        // NOT STAMPED HERE, and deliberately. This row is the unit's EVIDENCE of what the accrual
        // wrote, not the durable write itself — `ledger_and_meter` above is the write, and the
        // kernel stamps the instant there, where a rate seam may be named at all. A plane crate
        // asking when a card started would be a plane reaching a rate seam (#43: plugins are
        // pricing-blind), so this leaves the field at its default and the durable row carries the
        // instant. Owed: carry it back onto the evidence through the neutral facts seam.
        priced_from_ms: 0,
        pricing_version: String::new(),
    }
}

#[cfg(test)]
#[path = "tests/meter.rs"]
mod tests;
