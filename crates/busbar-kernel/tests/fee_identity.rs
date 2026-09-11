// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A UNIT SPENT, PER DIMENSION THE PLANE DECLARED — and the two sources the fee is decided
//! from.
//!
//! ## The shape that was wrong
//!
//! The kernel's settlement evidence carried ONE quantity against ONE class, and the exit built one
//! usage line out of the pair. A dimension is not a kernel word — `MeterClassDecl` is plane data
//! and the declarations are not one line each: the model plane declares four classes, the
//! streaming plane seven, the tool plane two, the agent plane one, the control plane none. One
//! layer further down, the usage unit's own settlement table is already written over LINES, plural,
//! per class. So the narrow shape was the kernel's alone, and it is the join that threw three of
//! the model plane's four numbers away before anything could price them.
//!
//! That is why the model plane's leg still reported nothing at all: there was no single class its
//! spend could honestly be reported in, and reporting the answer's byte count in place of it would
//! have settled bytes as money. The cell below states the answer — **a four-dimension plane's
//! spend reaches the settlement as four numbers** — and its sibling mutation drops one dimension
//! and watches the settlement come up one number short.
//!
//! ## The two sources, and why they could not disagree
//!
//! `fee_count` has two sources and is written to distrust both: where the transport's status class
//! and the plane's finish class disagree it posts the LOWER count and raises `METER_DISPUTED`.
//! P3 landed the head that carries them and said in the same breath that on the model plane's leg
//! the two were still ONE source — the finish was the status re-derived — so the arm was armed and
//! unreachable. A mid-stream cut is the case the arm exists for: a 200 the client saw and a stream
//! that died before the answer finished. With both sources derived from the status, that unit has a
//! `Success` status and a `Complete` finish and disputes nothing.
//!
//! **The mutation is the sibling**, and it is P3's mutation 2 made to bite: the identical cut with
//! the finish DERIVED FROM THE STATUS rather than read off the plane's own decode reaches no
//! dispute at all. That is the finding as a difference — the leg was not billing less, it was
//! billing the same and telling nobody there was anything to look at.
//!
//! RED at this base, and every error is the finding:
//!
//!   unresolved import `busbar_kernel::teller::settle_lines`
//!   struct `Evidence` has no field named `completed`
//!   struct `Evidence` has no field named `accrued_class`
//!
//! There is no per-dimension figure on the settlement evidence and no settlement that can answer
//! with more than one line.

use busbar_caps::{
    CompletedUnits, Completion, MeterClassId, Outcome, PostingFlags, QuantitySource,
};
use busbar_caps::{ReasonCode, StepName};
use busbar_kernel::teller::{
    fee_count, settle_lines, Evidence, FeeEvidence, FinishClass, StatusAt, StatusClass, StatusLeg,
    KERNEL_ACCRUAL_CLASS,
};

/// The four classes the model plane declares, in the order it declares them.
const TOKENS_IN: MeterClassId = MeterClassId::new("tokens_in");
const TOKENS_OUT: MeterClassId = MeterClassId::new("tokens_out");
const CACHE_READ: MeterClassId = MeterClassId::new("cache_read");
const CACHE_WRITE: MeterClassId = MeterClassId::new("cache_write");

fn live_end() -> Outcome {
    Outcome::Failed(StepName::Route, ReasonCode::ClientGone)
}

/// What a four-dimension answer carried, as the plane's own declared locators read it off the
/// decoded response and the relay recorded it on the unit.
fn four_dimensions() -> Completion {
    Completion::of(
        3,
        4_096,
        vec![
            CompletedUnits {
                class: TOKENS_IN,
                units: 11,
            },
            CompletedUnits {
                class: TOKENS_OUT,
                units: 7,
            },
            CompletedUnits {
                class: CACHE_READ,
                units: 512,
            },
            CompletedUnits {
                class: CACHE_WRITE,
                units: 64,
            },
        ],
    )
    .expect("four dimensions is inside the fixed-size usage record's own bound")
}

/// The same answer with one dimension never read. This is the mutation, written as data.
fn three_dimensions() -> Completion {
    let whole = four_dimensions();
    let kept: Vec<CompletedUnits> = whole
        .dimensions()
        .iter()
        .filter(|d| d.class != CACHE_READ)
        .copied()
        .collect();
    Completion::of(whole.frames(), whole.bytes(), kept).expect("three is fewer than four")
}

/// A FOUR-DIMENSION PLANE'S SPEND REACHES THE SETTLEMENT AS FOUR NUMBERS.
///
/// Not as a total, and not against a class the plane never declared. Each line carries the plane's
/// own key and the quantity that key's locator found, so the pricing one layer down can charge
/// four rates — which is the whole reason a dimension has a name.
#[test]
fn a_four_dimension_answer_settles_as_four_numbers() {
    let evidence = Evidence {
        completed: Some(four_dimensions()),
        accrued_floor: 90,
        ..Evidence::default()
    };
    let (lines, flags) = settle_lines(&Outcome::Completed, &evidence);

    assert_eq!(
        lines.len(),
        4,
        "the plane declared four classes and the answer carried four quantities: {lines:?}"
    );
    let seen: Vec<(MeterClassId, u64)> = lines.iter().map(|l| (l.class, l.quantity)).collect();
    assert_eq!(
        seen,
        vec![
            (TOKENS_IN, 11),
            (TOKENS_OUT, 7),
            (CACHE_READ, 512),
            (CACHE_WRITE, 64)
        ],
        "declaration order is the plane's and the settlement does not reorder or fold it"
    );
    assert_eq!(flags, PostingFlags::NONE);
    assert!(
        lines.iter().all(|l| !l.estimated),
        "a figure the destination reported is not the node's floor"
    );
    assert!(
        !seen.iter().any(|(class, _)| *class == KERNEL_ACCRUAL_CLASS),
        "the kernel's own accrual class is what a unit settles on when NOTHING was reported; a \
         reported answer never lands on it"
    );
}

/// THE MUTATION. One dimension never read, and the settlement is one number short.
///
/// It is the same unit, the same end and the same table. What the money side is told is three
/// quantities instead of four, and the fourth is not zero — it is absent, which is a different
/// statement and the one that would have silently under-billed every cached read on the plane.
#[test]
fn an_answer_missing_one_dimension_settles_one_number_short() {
    let evidence = Evidence {
        completed: Some(three_dimensions()),
        accrued_floor: 90,
        ..Evidence::default()
    };
    let (lines, _) = settle_lines(&Outcome::Completed, &evidence);
    assert_eq!(lines.len(), 3, "one dimension dropped, one line gone");
    assert!(
        !lines.iter().any(|l| l.class == CACHE_READ),
        "the missing line is the missing dimension and not some other one"
    );
    // And the difference is money: the whole reading and the maimed one are not the same figure.
    let (whole, _) = settle_lines(
        &Outcome::Completed,
        &Evidence {
            completed: Some(four_dimensions()),
            ..Evidence::default()
        },
    );
    assert_ne!(
        lines, whole,
        "dropping a declared dimension has to be visible in what settles, or a plane could \
         under-report one class for free"
    );
}

/// NOTHING REPORTED STILL SETTLES ONE LINE, AT THE CLASS THE KERNEL'S OWN FLOOR IS IN.
///
/// This is the row every plane in the tree takes today, and it is the reason the change can be
/// proved byte-identical: a leg that reported no completion settles exactly what the old pair of
/// `located: None` and a class settled — one line, one class, quantity zero.
#[test]
fn nothing_reported_settles_one_line_at_the_accrual_class() {
    let evidence = Evidence::default();
    let (lines, flags) = settle_lines(&Outcome::Completed, &evidence);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].class, KERNEL_ACCRUAL_CLASS);
    assert_eq!(lines[0].quantity, 0);
    assert_eq!(lines[0].source, QuantitySource::Count);
    assert_eq!(flags, PostingFlags::NONE);
}

/// A LEG THAT NAMES ITS OWN ACCRUAL CLASS KEEPS IT, whatever the completion says.
///
/// The class the kernel's floor is reported against is not the class an answer was reported in.
/// Three planes name one today and settle their byte-shaped figure against it; that is what the
/// field is, and calling it "which class the settled amount is in" is what made one class look
/// like enough for everybody.
#[test]
fn the_accrual_class_is_the_floors_and_not_the_answers() {
    let evidence = Evidence {
        completed: None,
        accrued_floor: 4_096,
        accrued_class: Some(MeterClassId::new("bytes")),
        ..Evidence::default()
    };
    let (lines, flags) = settle_lines(&live_end(), &evidence);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].class, MeterClassId::new("bytes"));
    assert_eq!(lines[0].quantity, 4_096);
    assert!(lines[0].estimated, "nobody reported this figure");
    assert!(flags.contains(PostingFlags::ESTIMATED));
}

/// A STREAM THAT DIED WITH AN ERROR SIGNAL BILLS NOTHING, whatever it had reported.
///
/// The row is the table's, unchanged; what is new is that the figure it refuses to bill is four
/// numbers rather than one, and the refusal is total rather than per-line. A partial refusal would
/// be the house choosing which of a plane's dimensions to keep.
#[test]
fn a_terminal_error_bills_none_of_the_dimensions() {
    let evidence = Evidence {
        completed: Some(four_dimensions()),
        terminal_error: true,
        ..Evidence::default()
    };
    let (lines, flags) = settle_lines(&live_end(), &evidence);
    assert_eq!(lines.len(), 1, "one line, and it is the zero");
    assert_eq!(lines[0].quantity, 0);
    assert_eq!(flags, PostingFlags::NONE);
}

// ── the two sources ─────────────────────────────────────────────────────────────────────────────

/// The identity of a client unit that selected an upstream. Neither field is a reading of the
/// answer, which is the whole point of the split P3 landed.
fn client_with_an_upstream() -> FeeEvidence {
    FeeEvidence {
        client_open_or_one_shot: true,
        selected_upstream: true,
    }
}

/// A MID-STREAM CUT REACHES THE DISPUTE ARM FROM TWO INDEPENDENT SOURCES.
///
/// The transport read `Success` off the first frame — the client saw a 200 and got part of an
/// answer. The plane read the ending off its OWN decode of the frames that followed, and what it
/// read was an error: the stream stopped before the answer was whole. Two sources, one number
/// each, disagreeing. The kernel posts the lower count and marks the posting, which is what makes a
/// plane that lies about its finish visible rather than profitable.
#[test]
fn a_mid_stream_cut_disputes_from_two_independent_sources() {
    let head = StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(StatusClass::Success),
        // NOT derived from the status above: this is what the plane's `decode_response` made of the
        // last frame it actually saw.
        finish: Some(FinishClass::Error),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    assert_eq!(
        fee_count(&client_with_an_upstream(), Some(&head)),
        (0, PostingFlags::METER_DISPUTED),
        "the lower count, and somebody is told to look at it"
    );
}

/// THE MUTATION — P3's second one, made to bite. Derive the finish from the status and the dispute
/// is gone.
///
/// This is exactly what the model plane's leg does today: `served_head` reads one number off the
/// walk and answers `Success`/`Complete` or `ServerError`/`Error` from it. Two sources that are one
/// source cannot disagree, so the arm is armed and unreachable, and a mid-stream cut after a good
/// head bills the same one fee a clean answer does and flags nothing.
#[test]
fn a_leg_that_derives_both_sources_from_the_status_never_disputes() {
    let status = 200_u16;
    let ok = (200..300).contains(&status);
    let head = StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(if ok {
            StatusClass::Success
        } else {
            StatusClass::ServerError
        }),
        // THE MUTATION: one number, read twice.
        finish: Some(if ok {
            FinishClass::Complete
        } else {
            FinishClass::Error
        }),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    let (fee, flags) = fee_count(&client_with_an_upstream(), Some(&head));
    assert_eq!(fee, 1, "the cut bills the full fee");
    assert_eq!(
        flags,
        PostingFlags::NONE,
        "and nothing is marked, which is the finding: the arm was not billing less, it was \
         billing the same and telling nobody there was anything to look at"
    );
}

/// A CLEAN ANSWER IS STILL ONE FEE AND NO DISPUTE, from two independent sources.
///
/// The other direction, so the cell above is a reading of the disagreement and not of the plane's
/// finish being present at all.
#[test]
fn a_whole_answer_from_two_agreeing_sources_bills_one_and_flags_nothing() {
    let head = StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(StatusClass::Success),
        finish: Some(FinishClass::Complete),
        delivered: true,
        degraded: false,
        relayed_error: None,
    };
    assert_eq!(
        fee_count(&client_with_an_upstream(), Some(&head)),
        (1, PostingFlags::NONE)
    );
}
