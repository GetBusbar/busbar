// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE SHIPPED SCHEDULE IS 1.5.5 EVERYWHERE EXCEPT WHERE THE RELEASE SAYS IT IS NOT.**
//!
//! A default that quietly moved money would be the worst possible outcome of adding a fee schedule,
//! so this file bounds the move: it names, from the recording itself, every cell the change can
//! reach, and proves the two schedules agree on everything else.
//!
//! # The argument, in two halves
//!
//! **Half one — the schedules differ on exactly one arm.** [`the_two_schedules_agree_except_where_the_two_readings_contradict`]
//! drives every combination of the evidence a unit can carry — the whole cube, not a sample — under
//! the previous release's schedule and under the shipped default, and asserts they answer the same
//! except where the transport's status and the plane's finish disagree. That is a statement about
//! the code and it holds whatever the corpus contains.
//!
//! **Half two — the corpus contains exactly twelve of those.** [`the_recorded_corpus_contains_twelve_contradicted_cells_and_no_more`]
//! reads the golden's recorded cells off disk and counts the ones whose recording says the two
//! readings disagreed: a `stream_fault`, which is the only shape a recording has for "the client
//! was handed the start of an answer and the answer then died". Twelve, all `llm.stream`, and the
//! CHANGELOG names them.
//!
//! Together: every OTHER recorded cell is charged by the shipped default exactly as the previous
//! release charged it, because the two schedules are the same function on every input those cells
//! carry.
//!
//! # What this file does NOT claim
//!
//! It does not claim the golden recorded a FEE. The oracle's own configuration prices every model
//! and sets no per-request fee, so `effects.usage.spend_cents` on every recorded cell is token cost
//! and only token cost, and no recording in the corpus can tell a fee count of one from a fee count
//! of zero. That is exactly why the twelve cells' bytes do not move under a change that is
//! nevertheless a break, and it is why the break is proven here and in `fee_one_decision.rs` rather
//! than by a diverging recording.

use busbar_contract::{FinishClass, StatusAt, StatusClass};
use busbar_kernel::teller::{charge, DisputePolicy, FeeEvidence, TariffCell};

/// Where the recording lives, from this crate rather than from a working directory.
fn golden_cells() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// The previous release's schedule, by name.
fn previous_release() -> TariffCell {
    TariffCell {
        dispute_policy: DisputePolicy::Full,
        ..TariffCell::default()
    }
}

/// Every combination of evidence a unit can carry. Written as a product rather than as a list, so
/// a field gaining a case cannot quietly leave the cube.
fn every_evidence() -> Vec<FeeEvidence> {
    let mut out = Vec::new();
    for admitted in [false, true] {
        for client_open_or_one_shot in [false, true] {
            for selected_upstream in [false, true] {
                for chargeable_local in [false, true] {
                    for relayed_first_response_frame in [false, true] {
                        for status_at in
                            [None, Some(StatusAt::FirstFrame), Some(StatusAt::Terminal)]
                        {
                            for status in [
                                None,
                                Some(StatusClass::Success),
                                Some(StatusClass::ClientError),
                                Some(StatusClass::ServerError),
                                Some(StatusClass::Other),
                            ] {
                                for finish in [
                                    None,
                                    Some(FinishClass::Complete),
                                    Some(FinishClass::TurnComplete),
                                    Some(FinishClass::Partial),
                                    Some(FinishClass::Error),
                                ] {
                                    out.push(FeeEvidence {
                                        admitted,
                                        client_open_or_one_shot,
                                        selected_upstream,
                                        chargeable_local,
                                        relayed_first_response_frame,
                                        status_at,
                                        status,
                                        finish,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// **THE MOVE IS BOUNDED BY THE CODE, NOT BY THE CORPUS.**
///
/// The whole evidence cube, both schedules. They differ only where the posting is marked disputed —
/// which is the definition of the arm the release changed — and on every other input they are the
/// same function.
#[test]
fn the_two_schedules_agree_except_where_the_two_readings_contradict() {
    let cube = every_evidence();
    assert_eq!(cube.len(), 2 * 2 * 2 * 2 * 2 * 3 * 5 * 5, "the whole cube");
    let mut differing = 0usize;
    for evidence in &cube {
        let previous = charge(evidence, &previous_release());
        let shipped = charge(evidence, &TariffCell::default());
        if previous == shipped {
            continue;
        }
        differing += 1;
        assert!(
            previous
                .flags
                .contains(busbar_caps::PostingFlags::METER_DISPUTED),
            "the schedules parted on a unit whose readings did not contradict: {evidence:?}"
        );
        assert_eq!(
            (previous.transaction, shipped.transaction),
            (1, 0),
            "the only difference the release names is the transaction on a contradicted unit"
        );
        assert_eq!(
            (previous.entry, shipped.entry),
            (0, 0),
            "the door is not charged for by either schedule until a deployment says so"
        );
        assert!(
            previous.units_allowed && shipped.units_allowed,
            "neither schedule refunds what was delivered"
        );
    }
    assert!(
        differing > 0,
        "if the schedules never part, the release's own breaking entry is describing nothing"
    );
}

/// **THE CORPUS CONTAINS TWELVE UNITS THE CHANGE CAN REACH.**
///
/// Counted off the recording rather than asserted: a recorded cell carries `effects.stream_fault`
/// exactly when the harness cut or errored a stream after its head went out, which is the one shape
/// a recording has for the two readings disagreeing. Every other recorded cell in the money
/// families is a unit both schedules charge identically, by the cell above.
#[test]
fn the_recorded_corpus_contains_twelve_contradicted_cells_and_no_more() {
    let dir = golden_cells();
    let mut compared = 0usize;
    let mut contradicted = Vec::new();
    let mut money_family = 0usize;
    for entry in std::fs::read_dir(&dir).expect("the recorded golden is in the tree") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a cell file name")
            .to_string();
        compared += 1;
        // The families where money is recorded at all. Named by the cell id's leading segment,
        // which is what the golden's own ledger keys on.
        if ["billing__", "ledger__", "llm__", "llm.stream__"]
            .iter()
            .any(|f| name.starts_with(f))
        {
            money_family += 1;
        }
        let text = std::fs::read_to_string(&path).expect("a recorded cell is readable");
        if text.contains("\"stream_fault\"") {
            contradicted.push(name);
        }
    }
    assert!(
        compared > 900,
        "only {compared} recorded cells read from {}; the corpus did not resolve",
        dir.display()
    );
    assert!(money_family > 0, "no money family resolved");
    contradicted.sort();
    assert_eq!(
        contradicted.len(),
        12,
        "the recording holds {} units whose two readings disagreed, not twelve: {contradicted:?}",
        contradicted.len()
    );
    assert!(
        contradicted.iter().all(|n| n.starts_with("llm.stream__")),
        "a contradicted unit outside the family the release names: {contradicted:?}"
    );
}
