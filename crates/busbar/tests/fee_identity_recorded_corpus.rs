// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MONEY DOES NOT MOVE: the model plane's recorded corpus, derived through the kernel's own
//! fee decision and its own settlement.
//!
//! The fee decision and the settlement evidence both changed shape in this landing. The fee is now
//! read from the answer's head instead of three fields each leg wrote by hand, and the settlement
//! evidence carries what a unit spent PER DIMENSION THE PLANE DECLARED instead of one quantity
//! against one class. Either of those could have moved a recorded byte, and neither is allowed to.
//!
//! This is the proof, and it is a RECORDING rather than a number typed into this file. The pinned
//! shadow oracle holds 133 `llm__*` cells. Their recorded usage deltas partition three ways, and
//! the partition is by recorded HTTP status with no residue at all:
//!
//!   67 cells   status 200   {"requests":1,"spend_cents":250,"tokens":18}
//!   36 cells   status 503   {"requests":1}
//!   30 cells   4xx          {}
//!
//! **67 + 36 = 103 cells carry a usage delta**, and those are the money cells. For each one this
//! file builds the head the served leg records — from the cell's own recorded status and nothing
//! else — runs the kernel's `fee_count`, `requests_drawn`/`requests_settled` and `settle_lines`
//! over it, and demands the answer the recording holds:
//!
//!   * a fee of exactly 1 on the 67 and 0 on the 36 and 0 on the 30;
//!   * a settled request of 1 on all 103 and 0 on the 30;
//!   * ONE settlement line, at the kernel's own accrual class, quantity zero, on all 133 — because
//!     the model plane's served leg reports no completion, which is the same answer `located: None`
//!     gave and the reason this landing is identity rather than a cutover;
//!   * and `METER_DISPUTED` on none of them, because on this leg the transport's status and the
//!     plane's finish are still ONE source and cannot disagree.
//!
//! RED at this base, and both errors are the finding:
//!
//!   unresolved import `busbar_kernel::teller::settle_lines`
//!   struct `Evidence` has no field named `completed`
//!
//! There is no per-dimension figure on the settlement evidence, so there is nothing for this file
//! to prove the recording against.
//!
//! Nothing here leans on the six `stream_upstream_error` cells: they are `needs_fixture` on this
//! tree and record nothing, which is the gap TARIFF already owed and this file does not paper over.

use busbar_caps::{OriginKind, Outcome, PostingFlags};
use busbar_kernel::teller::{
    charge, requests_drawn, requests_settled, settle_lines, Evidence, FeeEvidence, FinishClass,
    StatusAt, StatusClass, StatusLeg, TariffCell, KERNEL_ACCRUAL_CLASS,
};

mod golden;

use golden::Recorded;

/// Every `llm__*` cell the pinned golden holds, read through the ONE reader of the corpus.
///
/// It used to be read here, by a private copy of the same directory walk and the same JSON
/// reduction. Two readers of one corpus is how two cells come to disagree about what a recording
/// says while both stay green, so the walk moved to [`golden`] and this is the one call.
fn recorded_llm_cells() -> Vec<Recorded> {
    golden::family("llm__")
}

/// The head the served leg records, built from the recorded status ALONE.
///
/// This is `units_llm.rs`'s own `served_head`, restated over the recording: the surface is HTTP and
/// HTTP reports its class on the first response frame, and this leg's finish is that same number
/// classified. Restating it here rather than reaching into the leg is deliberate — the point of the
/// cell is that the kernel's decision over this head is the recording, and a call into the leg
/// would be proving the leg against itself.
fn served_head(status: u16) -> StatusLeg {
    let ok = (200..300).contains(&status);
    StatusLeg {
        at: Some(StatusAt::FirstFrame),
        status: Some(if ok {
            StatusClass::Success
        } else if (400..500).contains(&status) {
            StatusClass::ClientError
        } else if (500..600).contains(&status) {
            StatusClass::ServerError
        } else {
            StatusClass::Other
        }),
        finish: Some(if ok {
            FinishClass::Complete
        } else {
            FinishClass::Error
        }),
        delivered: true,
        degraded: false,
        relayed_error: None,
    }
}

/// Whether the recorded unit ever selected an upstream. A 4xx on this plane is the door — the
/// refusal is the node's own, no destination was picked and the recording carries no delta at all.
/// A 503 is the upstream leg failing, which is a unit that drew its request slot and paid no fee.
fn selected_upstream(rec: &Recorded) -> bool {
    rec.recorded_requests() != 0
}

#[test]
fn every_recorded_model_plane_cell_settles_exactly_what_it_recorded() {
    let cells = recorded_llm_cells();
    assert_eq!(
        cells.len(),
        133,
        "the pinned golden holds 133 recorded model-plane cells; if this number moved the corpus \
         moved and the identity below is over a different thing"
    );

    let mut with_a_delta = 0_usize;
    let mut charged = 0_usize;
    let mut moved: Vec<String> = Vec::new();

    for rec in &cells {
        let head = served_head(rec.status);
        let upstream = selected_upstream(rec);
        let identity = FeeEvidence {
            // Every cell in this corpus is a unit the golden recorded a request slot for, so every
            // one of them passed the door.
            admitted: true,
            chargeable_local: false,
            // Every cell in this corpus is a caller's request; the oracle drives no provider push.
            client_open_or_one_shot: true,
            selected_upstream: upstream,
        };
        let (fee, fee_flags) = transaction_fee(&identity, Some(&head));

        // The model plane's served leg reports NO completion: what it spent is four declared
        // dimensions and it does not put them on the unit yet. That is the same answer the old
        // `located: None` gave, which is why this landing can be identity at all.
        let evidence = Evidence {
            completed: None,
            accrued_floor: 0,
            upstream_candidate: upstream,
            fee: identity,
            ..Evidence::default()
        };
        let (lines, table_flags) = settle_lines(&Outcome::Completed, &evidence);
        let requests = requests_settled(
            upstream,
            requests_drawn(OriginKind::Client, evidence.upstream_candidate),
        );

        let recorded_requests = rec.recorded_requests();
        let recorded_spend = rec.recorded_spend();

        // 1. The request slot.
        if i64::from(requests) != recorded_requests {
            moved.push(format!(
                "{}: settled {requests} request(s), recorded {recorded_requests}",
                rec.name
            ));
        }
        // 2. The fee. A recorded spend is a unit that paid one; a recorded request with no spend is
        //    one that drew a slot and paid none.
        let expected_fee = u32::from(recorded_spend);
        if fee != expected_fee {
            moved.push(format!(
                "{}: fee {fee}, recorded spend {recorded_spend} (status {})",
                rec.name, rec.status
            ));
        }
        // 3. The settlement, line for line.
        if lines.len() != 1
            || lines[0].class != KERNEL_ACCRUAL_CLASS
            || lines[0].quantity != 0
            || lines[0].estimated
        {
            moved.push(format!("{}: settled {lines:?}", rec.name));
        }
        // 4. Nothing on this leg is disputed, because nothing on it has two sources yet.
        let flags = table_flags.with(fee_flags);
        if flags.contains(PostingFlags::METER_DISPUTED) {
            moved.push(format!(
                "{}: disputed, and nothing recorded a dispute",
                rec.name
            ));
        }

        if !rec.usage.is_empty() {
            with_a_delta += 1;
        }
        if recorded_spend {
            charged += 1;
        }
    }

    assert!(
        moved.is_empty(),
        "A RECORDED BYTE MOVED. This is a money finding and it stops for a ruling; it is not \
         repaired inside the landing:\n  {}",
        moved.join("\n  ")
    );
    assert_eq!(
        with_a_delta, 103,
        "the money cells are the ones carrying a usage delta, and there are 103 of them"
    );
    assert_eq!(charged, 67, "67 of the 103 recorded a fee and a spend");
}

/// THE THIRTY THAT RECORDED NOTHING RECORD NOTHING HERE EITHER.
///
/// Stated on its own because "nothing changed" over a cell that already settles nothing is the
/// weakest half of the identity, and the cell above would pass it whatever the fee decision did to
/// a unit that reached an upstream. This one is the door: refused at authenticate, approve or
/// admit, no destination was ever picked, and the answer is zero on every axis.
#[test]
fn a_unit_refused_at_the_door_draws_no_slot_and_pays_no_fee() {
    let refused: Vec<Recorded> = recorded_llm_cells()
        .into_iter()
        .filter(|r| r.usage.is_empty())
        .collect();
    assert_eq!(refused.len(), 30, "30 recorded cells carry no usage delta");
    for rec in refused {
        let identity = FeeEvidence {
            admitted: true,
            chargeable_local: false,
            client_open_or_one_shot: true,
            selected_upstream: false,
        };
        assert_eq!(
            transaction_fee(&identity, Some(&served_head(rec.status))),
            (0, PostingFlags::NONE),
            "{} recorded no spend",
            rec.name
        );
        assert_eq!(
            requests_settled(false, requests_drawn(OriginKind::Client, false)),
            0,
            "{} recorded no request",
            rec.name
        );
    }
}

/// **THE TRANSACTION COUNT AND THE MARK, UNDER THE DEPLOYMENT'S DEFAULT SCHEDULE.**
///
/// Every cell in this corpus asks what one exchange costs, so every one is driven through the one
/// site a tariff is applied at, with the cell a node that has configured nothing is charged under.
fn transaction_fee(
    evidence: &FeeEvidence,
    head: Option<&StatusLeg>,
) -> (u32, busbar_caps::PostingFlags) {
    let charged = charge(evidence, head, &TariffCell::default());
    (charged.transaction, charged.flags)
}
