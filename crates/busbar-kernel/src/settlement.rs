// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table and the flat-fee rule: what a unit's end posts, as pure functions of plain
//! evidence.
//!
//! Moved verbatim out of [`crate::teller`], which re-exports every item here under its old path.
//! The loop's [`exit`](crate::teller::exit), the node's sweep and the recovery path all settle by
//! these functions; none of them reads a clock, a seal or a cell, so the table can be read as a
//! table and tested as one, row by row.

use busbar_contract::caps::{MeterClassId, OriginKind, Outcome, PostingFlags};

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
