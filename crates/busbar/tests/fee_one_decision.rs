//! **THE FEE IS DECIDED ONCE, AND THE KERNEL DECIDES IT.**
//!
//! The flat per-request fee had two deciders on the llm plane and one everywhere else. The kernel's
//! is `busbar_kernel::teller::charge` over a `FeeEvidence` the composition root builds — the same
//! function `units_mcp`, `units_a2a` and `units_voice` already price their records through, under a
//! comment that states the rule out loud: *"The record does not decide the fee a second time. It
//! reads the same evidence the exit path settles from, through the same function, so a row that says
//! one fee and a posting that says none cannot both be true of one unit."*
//!
//! The llm plane decided it a second time. `busbar-llm/src/unit/meter.rs` answered
//! `u32::from(delivered && ctx.upstream_leg)` — two booleans — and carried that count out on the
//! late report, which is the number that reached `Posting::from_usage` and therefore the number that
//! BILLED. The kernel's answer was computed on the same request and discarded.
//!
//! This cell is the byte-identity proof that retiring the second decider does not move money.
//!
//! # What is asserted, and in which direction
//!
//! **Arm 1 — the recorded corpus (`recorded_cells_agree`).** Every recorded llm cell of the three
//! families where a status frame and a plane finish can disagree — 36 `upstream_down`, 30
//! `ok_stream` — READ from `testing/shadow-oracle/golden/1.5.5` at run time through
//! [`golden::family`], never transcribed. Both deciders are driven over every one and must answer
//! the same count, and that count must be the count the golden billed. This arm is the money
//! guarantee: while it is green, the MOVE is byte-identical on everything the node has ever
//! recorded.
//!
//! # WHY THE CORPUS IS READ AND NOT TYPED IN
//!
//! It used to be typed in: 78 `Cell { name: "…", … }` literals, each one spelling a golden cell id,
//! and a golden llm cell id is `<ingress dialect>__<upstream dialect>__request__<ending>`. That is
//! 146 vendor names in the crate that COMPOSES the node — and `kind-isolation` counted every one of
//! them, because a composition root naming a vendor is a root that has learned something about a
//! dialect.
//!
//! The name was the only thing in those literals that knew what a dialect was. This fee decision
//! reads four facts about an exchange — was it admitted, is the origin a client's, did a
//! destination resolve, what did the answer's head say — and not one of them is a fact about a
//! vendor. So the corpus is read: the ids come off the file names, the facts come off the
//! recordings, the root spells no vendor, and the transcription can no longer drift from the thing
//! it transcribes. The cross-check the old header claimed for the transcription is now a
//! cross-check on the DERIVATION, and it is asserted in arm 1 rather than described here.
//!
//! **Arm 2 — the fact cube (`the_two_rules_are_not_the_same_rule`).** The two rules are NOT the same
//! expression, and arm 1 passing is not evidence that they are — it is evidence that the corpus
//! never reaches the combinations where they part. This arm drives the full boolean cube of the
//! facts and names those combinations. It is the honest statement of what arm 1 does not cover.
//!
//! **Arm 3 — the mid-stream family (`recorded_stream_faults_agree`).** The twelve
//! `llm.stream|<dialect>|{cut,stream-error}` cells: the upstream fails AFTER the door has written
//! 200 and the first frames have gone out. This is the case where the two readings of one unit
//! genuinely disagree, and it was a named gap on the golden when the fee's landing went through.
//! It is recorded now, and it is driven here.
//!
//! # WHAT THE GOLDEN CAN AND CANNOT SAY ABOUT A FEE
//!
//! Stated plainly because the `billed` column below reads like a recording and is not one. The
//! oracle's own configuration — `oracle-config.sh`, quoted in the harness: *"prices every model at
//! input 100000 / output 200000 micro-units per token and sets no per-request fee"* — means the
//! flat fee is ZERO CENTS on every `llm` and `llm.stream` cell. So `effects.usage.spend_cents` on
//! those cells is token cost and only token cost, and no recording in that family discriminates a
//! fee COUNT of one from a fee count of zero. There is no fee-only cell anywhere in the golden to
//! calibrate against either.
//!
//! What `billed` therefore is: **1.5.5's own rule evaluated over the recorded facts** — the rule
//! `retired_plane_fee` holds verbatim, which is what the published binary ran. Its agreement with
//! the presence of `spend_cents` is a CROSS-CHECK on the derivation, not the source of the figure,
//! and it is asserted where it HOLDS: on all 66 cells of arm 1's family, and on none of arm 3's,
//! where eleven of the twelve recorded no spend at all for a fault the rule bills and the twelfth
//! recorded one because its partial frame happened to carry a usage block. That split is arm 3's
//! whole subject. The money statement this cell supports is exactly: the kernel's decider answers
//! what the shipped 1.5.5 decider answered, on every fact combination the node has recorded. It is
//! not, and cannot be, a claim that the golden recorded a fee.

use busbar_contract::{FinishClass, StatusLeg};
use busbar_kernel::teller::{charge, Charge, DisputePolicy, FeeEvidence, TariffCell};

mod golden;

/// One cell of the corpus, as the two deciders read it.
///
/// Built by [`recorded`] from the pinned golden and by [`the_two_rules_are_not_the_same_rule`] from
/// a boolean cube. `name` is the golden's own cell id where there is one, and it is carried for the
/// divergence message alone: no decider below reads it, which is precisely why it never needed to
/// be spelled in this file.
struct Cell {
    name: String,
    status: u16,
    upstream_leg: bool,
    upstream_candidate: bool,
    client_origin: bool,
    billed: u32,
    /// Whether the RECORDING carries a spend. Not a decision and not a fee — see the module header
    /// on what a recorded spend says. It rides on the cell so the corpus is read once.
    recorded_spend: bool,
}

/// THE RECORDED FACTS OF ONE FAMILY, read from the pinned golden.
///
/// `family` is the id prefix — the one segment of a cell id that is not a vendor's name — and
/// `endings` selects the recordings inside it whose ending this file is about. Every other field is
/// read by [`golden`], with its derivation stated there.
///
/// `client_origin` is `true` on every cell because the oracle drives no provider push, and a
/// constant is not a fact about a recording.
///
/// `billed` is 1.5.5's own rule over the recorded facts, held below as [`retired_plane_fee`]. It is
/// NOT read from the recording: see the module header on what a golden llm cell can and cannot say
/// about a fee.
fn recorded(family: &str, endings: &[&str]) -> Vec<Cell> {
    golden::family(family)
        .into_iter()
        .filter(|rec| {
            endings
                .iter()
                .any(|e| rec.name.ends_with(&format!("__{e}")))
        })
        .map(|rec| {
            let recorded_spend = rec.recorded_spend();
            let mut cell = Cell {
                name: rec.name,
                status: rec.status,
                upstream_leg: rec.upstream_leg,
                upstream_candidate: rec.upstream_candidate,
                client_origin: true,
                billed: 0,
                recorded_spend,
            };
            cell.billed = retired_plane_fee(&cell);
            cell
        })
        .collect()
}

/// **ARM 1's FAMILY** — the recorded `llm` cells where a status frame and a plane finish can
/// disagree: the upstream never answered, or it streamed a complete one.
fn recorded_exchanges() -> Vec<Cell> {
    recorded("llm__", &["ok_stream", "upstream_down"])
}

/// **THE MID-STREAM FAMILY.** The door writes 200, the first frames go out, and the upstream then
/// fails — announced in the dialect's own error shape (`stream-error`) or not announced at all
/// (`cut`).
///
/// Read by [`recorded_stream_faults`] from `golden/1.5.5/cells`. Every one of the twelve records
/// `status: 200`, a single `busbar_upstream_attempts_total` metric (the dial happened, the lane
/// answered), `effects.usage.requests: 1` — the slot, drawn and never released — and, on eleven of
/// the twelve, NO `spend_cents` key at all, because the tokens seen before the failure bill nothing
/// and the flat fee is configured to zero in this harness. See the module header on what that does
/// and does not license: `billed` here is 1.5.5's own rule over the recorded facts, which is 1, and
/// the recording neither confirms nor contradicts it.
///
/// The PLANE's finish on all twelve is an error — the tap saw a cut or a terminal error, which is
/// the same fact `billing_failed` carries — while the frame the client saw said 200. That is the
/// contradiction, and this is the family the kernel's dispute arm exists for.
fn recorded_stream_faults() -> Vec<Cell> {
    recorded("llm.stream__", &["cut", "stream-error"])
}

/// THE KERNEL'S DECIDER, reached over what the root leg actually builds for this plane — the
/// evidence (two facts about the UNIT) and the ANSWER'S HEAD: the status leg the plane DECLARES,
/// the class the transport reads at that frame, and the finish the plane gives.
///
/// The finish is an argument because this plane has two moments and they do not have the same
/// answer. At the exit the frame the client saw is the only reading that exists, and the leg
/// derives the finish from it; after the body has drained the tap knows how the stream really
/// ended, and the leg carries that instead. Arm 1's cells are driven at the first; arm 3's at the
/// second.
fn kernel_fee(c: &Cell, finish: FinishClass) -> (u32, busbar_caps::PostingFlags) {
    let charged = kernel_charge(c, finish, TariffCell::default());
    (charged.transaction, charged.flags)
}

/// The same evidence, under a NAMED schedule rather than the shipped one — what a deployment that
/// asked for the previous release's dispute rule back is charged.
fn kernel_charge(c: &Cell, finish: FinishClass, tariff: TariffCell) -> Charge {
    charge(
        &FeeEvidence {
            // Every cell below is a unit the golden recorded a request slot for, so every one of
            // them passed the door. The door's own count is not what this file is about — it reads
            // the exchange — but a visit that never happened would make the reading meaningless.
            admitted: true,
            chargeable_local:
                <busbar_plane_llm::LlmPlane as busbar_contract::plane::PlaneMeta>::CHARGEABLE_LOCAL,
            client_open_or_one_shot: c.client_origin,
            selected_upstream: c.upstream_candidate,
        },
        Some(&llm_head(c.status, finish)),
        &tariff,
    )
}

/// THE ANSWER'S HEAD this leg records, transcribed from `units_llm.rs`'s `head_facts`.
///
/// The status half of the old evidence did not disappear, it MOVED: what the transport reported is
/// the head, the head is recorded once by the step that saw the answer, and the kernel reads it
/// from the record. `at` is not a literal here either — it is the plane's own declaration, sealed
/// at registration, which is what makes the two readings capable of disagreeing at all.
fn llm_head(status: u16, finish: FinishClass) -> StatusLeg {
    StatusLeg {
        at: <busbar_plane_llm::LlmPlane as busbar_contract::plane::PlaneMeta>::STATUS_LEG,
        status: Some(busbar_transport_http::status_class(status)),
        finish: Some(finish),
        delivered: true,
        degraded: false,
        relayed_error: None,
    }
}

/// The finish the EXIT arm derives, when the frame the client saw is all there is to read.
fn finish_at_the_exit(c: &Cell) -> FinishClass {
    if (200..300).contains(&c.status) {
        FinishClass::Complete
    } else {
        FinishClass::Error
    }
}

/// THE PLANE'S SECOND DECIDER, verbatim as `busbar-llm/src/unit/meter.rs` answered it:
/// `u32::from(delivered && ctx.upstream_leg)`, where `delivered` is `matches!(status, 200..=299)`.
///
/// Kept here after the MOVE deletes it from the plane, because a byte-identity cell whose second
/// side has been removed proves nothing. This is the retired rule, held as a reference so the
/// identity stays checkable.
fn retired_plane_fee(c: &Cell) -> u32 {
    let delivered = matches!(c.status, 200..=299);
    u32::from(delivered && c.upstream_leg)
}

/// **ARM 1 — THE MONEY GUARANTEE.** Both deciders, over every recorded cell, against the golden.
///
/// A divergence here is a money finding and stops the MOVE: it would mean retiring the plane's
/// decider changes a count the node has actually billed.
#[test]
fn recorded_cells_agree_with_each_other_and_with_the_golden() {
    let recorded = recorded_exchanges();
    let mut diverged = Vec::new();
    for cell in &recorded {
        let (kernel, _) = kernel_fee(cell, finish_at_the_exit(cell));
        let plane = retired_plane_fee(cell);
        if kernel != plane || kernel != cell.billed {
            diverged.push(format!(
                "  {:<48} status={:<3} kernel={} plane={} golden={}",
                cell.name, cell.status, kernel, plane, cell.billed
            ));
        }
    }
    assert!(
        diverged.is_empty(),
        "the two fee deciders disagree on {} recorded cell(s), or disagree with what the golden \
         billed — this is a money finding and the MOVE stops here:\n{}",
        diverged.len(),
        diverged.join("\n")
    );
    // The corpus has to actually contain both answers, or the assertion above is vacuous.
    assert_eq!(recorded.len(), 66, "the recorded corpus changed size");
    assert_eq!(
        recorded.iter().filter(|c| c.billed == 1).count(),
        30,
        "the 30 ok_stream cells are the ones that bill"
    );
    // THE CROSS-CHECK ON THE DERIVATION. `billed` is 1.5.5's rule over facts this file READS out of
    // the recordings, so the thing worth checking is that those facts are the recording's. On this
    // family a spend was written exactly where the rule says a fee was charged, on all 66 — which
    // is the reading of `status`, of the dial and of the usage delta all agreeing at once. It is
    // asserted here and not on arm 3's family because there it is FALSE, on purpose: see arm 3.
    let crossed = recorded
        .iter()
        .filter(|cell| (cell.billed == 1) == cell.recorded_spend)
        .count();
    assert_eq!(
        crossed,
        recorded.len(),
        "the derived facts and the recorded spend disagree on this family; the derivation has \
         drifted from the corpus it reads"
    );
}

/// **ARM 2 — WHAT ARM 1 DOES NOT COVER.** The two rules are different expressions.
///
/// The kernel asks four things — the origin is a client's, a destination resolved, a first response
/// frame was relayed, and the finish was not an error. The retired plane rule asked two — the client
/// saw a 2xx, and a dial happened. They part in two directions:
///
/// * `origin != Client`: the plane rule bills, the kernel does not. The plane had no origin to read,
///   so it could not ask; the root leg's `evidence()` reads `ctx.origin` and does.
/// * a 2xx with a resolved destination but no dial: the kernel bills, the plane did not.
///
/// This test PINS that difference rather than asserting it away. If it ever comes back empty, the
/// two rules have converged and arm 1's guarantee has become an identity — which would be a better
/// world, and a deliberate change, not something to discover by accident.
#[test]
fn the_two_rules_are_not_the_same_rule() {
    let mut parted = Vec::new();
    for &status in &[200u16, 503] {
        for &upstream_leg in &[false, true] {
            for &upstream_candidate in &[false, true] {
                for &client_origin in &[false, true] {
                    let cell = Cell {
                        name: "cube".to_string(),
                        status,
                        upstream_leg,
                        upstream_candidate,
                        client_origin,
                        billed: 0,
                        recorded_spend: false,
                    };
                    if kernel_fee(&cell, finish_at_the_exit(&cell)).0 != retired_plane_fee(&cell) {
                        parted.push((status, upstream_leg, upstream_candidate, client_origin));
                    }
                }
            }
        }
    }
    assert!(
        !parted.is_empty(),
        "the two rules answer alike on the whole cube; they are one expression and this pin is stale"
    );
    // Every parting is a 2xx — below a 2xx both rules answer zero, whatever else is true.
    assert!(
        parted.iter().all(|p| p.0 == 200),
        "the rules part only on a delivered response: {parted:?}"
    );
    // And no recorded cell reaches any of them, which is exactly why arm 1 is green.
    for cell in &recorded_exchanges() {
        assert!(
            !parted.contains(&(
                cell.status,
                cell.upstream_leg,
                cell.upstream_candidate,
                cell.client_origin
            )),
            "{} reaches a fact combination the two rules disagree on",
            cell.name
        );
    }
}

/// **ARM 3 — THE MID-STREAM FAMILY, WHERE THE TWO READINGS REALLY DO DISAGREE.**
///
/// Driven at the LATE moment, which is the only moment this case exists at: the body has drained,
/// the tap has said how the stream ended, and the leg carries that finish instead of the one it
/// derived from the head. So the kernel is handed a 200 and an error about the same unit, which is
/// exactly the input the dispute arm is for and exactly the input no other arm in this file
/// produces.
///
/// **THIS IS THE ONE PLACE THE SHIPPED DEFAULT MOVED, AND IT MOVED ON PURPOSE.** The previous
/// release kept a mid-stream failure in its billable count and refunded nothing. It also billed the
/// same fault unevenly: of the twelve recorded cells, eleven charged nothing at all for the
/// half-delivered answer and ONE charged for the tokens, because its partial frame happened to
/// carry a complete usage block. Which one is not stated here and is not worth stating: the
/// difference is a property of a wire format, not a decision anybody made, and a root that named
/// the dialect it fell on would be recording the accident as if it were a rule. That it is exactly
/// one of twelve is asserted, off the recordings, in
/// [`every_dialect_is_charged_the_same_way_for_the_same_fault`]. A fee schedule that says every
/// plugin of a kind is billed identically cannot keep it. The default is now the visit and what was delivered: no transaction fee for an
/// exchange that did not complete, and the units the customer actually received, identically for
/// every dialect.
///
/// Four things are asserted about each of the twelve, and the order matters.
///
/// 1. **The previous release's rule is still a rule somebody can choose.** `DisputePolicy::Full`
///    answers exactly what `retired_plane_fee` answers and exactly what the golden billed, on all
///    twelve. So the change is a change of DEFAULT and not a capability that was taken away.
/// 2. **The shipped default charges no transaction.** One number, the same on all twelve.
/// 3. **The shipped default still charges the units.** The customer paid for what was delivered,
///    which is what makes the uniform rule the honest one rather than the cheap one.
/// 4. **The posting is marked, under both.** The count alone would say nothing was wrong. It was.
#[test]
fn recorded_stream_faults_are_disputed_and_the_default_charges_what_was_delivered() {
    let faults = recorded_stream_faults();
    assert_eq!(
        faults.len(),
        12,
        "six dialects, two fault shapes; the golden's own count"
    );
    let previous_release = TariffCell {
        dispute_policy: DisputePolicy::Full,
        ..TariffCell::default()
    };
    let mut diverged = Vec::new();
    for cell in &faults {
        // The plane's own verdict after the body drained: the stream did not finish.
        let under_previous = kernel_charge(cell, FinishClass::Error, previous_release);
        let under_default = kernel_charge(cell, FinishClass::Error, TariffCell::default());
        let plane = retired_plane_fee(cell);
        let marked = busbar_caps::PostingFlags::METER_DISPUTED;
        if under_previous.transaction != plane
            || under_previous.transaction != cell.billed
            || !under_previous.flags.contains(marked)
            || under_default.transaction != 0
            || !under_default.units_allowed
            || !under_default.flags.contains(marked)
        {
            diverged.push(format!(
                "  {:<28} previous={:?} default={:?} plane={plane} billed={}",
                cell.name, under_previous, under_default, cell.billed
            ));
        }
    }
    // AND WITH NO HEAD AT ALL, which is what a unit that never got an answer records. A missing
    // head is not a disagreement between two sources, it is the absence of the first one.
    for &client in &[false, true] {
        for &upstream in &[false, true] {
            let charged = charge(
                &FeeEvidence {
                    admitted: true,
                    chargeable_local: <busbar_plane_llm::LlmPlane as busbar_contract::plane::PlaneMeta>::CHARGEABLE_LOCAL,
                    client_open_or_one_shot: client,
                    selected_upstream: upstream,
                },
                None,
                &TariffCell::default(),
            );
            let (fee, flags) = (charged.transaction, charged.flags);
            assert_eq!(fee, 0, "a unit with no head was billed");
            assert!(
                !flags.contains(busbar_caps::PostingFlags::METER_DISPUTED),
                "a unit with no head raised METER_DISPUTED"
            );
        }
    }
    assert!(
        diverged.is_empty(),
        "a mid-stream failure after a good head is not decided by the schedule it is charged \
         under — either the previous release's rule has stopped answering what it answered, or \
         the shipped default has stopped charging the visit and the delivery. Either way it is a \
         money finding and stops here:\n{}",
        diverged.join("\n")
    );
}

/// **THE UNIFORMITY THE DEFAULT BUYS, COUNTED.**
///
/// The twelve recorded mid-stream cells, asked what the shipped schedule charges each of them for
/// the exchange. The answer must be ONE answer. Under the previous release it was one answer for
/// the transaction and a SECOND, uneven one for the units — and the unevenness is read here out of
/// the recordings rather than described: exactly one of the twelve carries a spend and eleven carry
/// none, for twelve occurrences of one fault. This cell does not re-open that recording; it pins
/// the rule that made it impossible to happen again, and it does not name the dialect the accident
/// landed on, because naming it would be the root treating a wire format's luck as a fact about a
/// vendor.
#[test]
fn every_dialect_is_charged_the_same_way_for_the_same_fault() {
    // THE UNEVENNESS, MEASURED. One fault, twelve recordings, and the previous release's units
    // answer differs across them. This is the recorded reason the default moved.
    let faults = recorded_stream_faults();
    let recorded_spends = faults.iter().filter(|cell| cell.recorded_spend).count();
    assert_eq!(
        recorded_spends, 1,
        "the previous release billed one fault twelve ways: {recorded_spends} of the twelve \
         recorded a spend, and the uniform rule exists because that number was neither 0 nor 12"
    );
    let answers: std::collections::BTreeSet<(u32, bool)> = faults
        .iter()
        .map(|cell| {
            let charged = kernel_charge(cell, FinishClass::Error, TariffCell::default());
            (charged.transaction, charged.units_allowed)
        })
        .collect();
    assert_eq!(
        answers.len(),
        1,
        "twelve cells, {} answers: the schedule is reading something about the dialect",
        answers.len()
    );
}
