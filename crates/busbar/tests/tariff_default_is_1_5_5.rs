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
use busbar_kernel::teller::{charge, Charge, DisputePolicy, FeeEvidence, TariffCell};
use busbar_unit_cost::FeeSchedule;

/// **THE PREVIOUS RELEASE'S AMOUNTS**: one configured figure, charged for the visit and for the
/// transaction alike, nothing per unit, no floor, no cap.
fn previous_amounts(fee: i64) -> FeeSchedule {
    FeeSchedule::flat(fee)
}

/// **THE SHIPPED DEFAULT'S AMOUNTS**, resolved through the real grammar from the same one figure.
///
/// Built by asking the section a deployment with no `tariff:` block has — and asking it at the same
/// scope a node-wide card is built at — rather than by writing a `FeeSchedule` literal here. A cell
/// that hand-built the answer would go on passing after the inheritance rule stopped inheriting.
fn shipped_amounts(fee: i64) -> FeeSchedule {
    busbar_core::cost::fee_schedule_of(
        &busbar_core::config::tariff::TariffCfg::default().amounts("", None, None, fee),
    )
}

/// What one unit's counts cost under a schedule, in minor units. No quantities: what the metered
/// classes cost is the card's per-(lane, class) rates, which this release does not touch and which
/// both schedules price identically because they ARE the same rates.
fn cents(schedule: &FeeSchedule, charged: Charge) -> i128 {
    schedule
        .charge_minor(
            u64::from(charged.entry),
            u64::from(charged.transaction),
            &|_| 0,
        )
        .total_minor
}

/// Every fee an operator could have configured that the argument has to hold for: nothing, the
/// figure the rate-card cells use, and one in between. Written as a list rather than as the
/// golden's own zero, because a claim that only holds where the fee is zero is not a claim about
/// the schedules at all — it is a claim about the corpus.
const CONFIGURED_FEES: [i64; 4] = [0, 1, 3, 250];

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
            // **THE SAME COUNTS AT THE SAME AMOUNTS.** The counts agreeing is half the claim; the
            // other half is that the two schedules PRICE those counts identically, which is what
            // the inheritance rule is for and what a second default figure would break silently.
            for fee in CONFIGURED_FEES {
                assert_eq!(
                    cents(&previous_amounts(fee), previous),
                    cents(&shipped_amounts(fee), shipped),
                    "one unit, two schedules, two figures at a configured fee of {fee}: {evidence:?}"
                );
            }
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
        // AND WHAT THE DIFFERENCE COSTS IS EXACTLY ONE TRANSACTION FEE, at every figure an
        // operator could have configured. The counts parting by one transaction and the money
        // parting by something else would be an amount decided somewhere this file cannot see.
        for fee in CONFIGURED_FEES {
            assert_eq!(
                cents(&previous_amounts(fee), previous) - cents(&shipped_amounts(fee), shipped),
                i128::from(fee),
                "the contradicted arm parts by one transaction fee and by nothing else: {evidence:?}"
            );
        }
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

/// **EVERY RECORDED CELL THAT MOVED MONEY IS CHARGED THE SAME CENTS BY BOTH SCHEDULES.**
///
/// The cube above is a statement about the CODE and holds whatever the corpus contains. This is the
/// statement about the CORPUS: it reads the recorded usage delta off every cell the published 1.5.5
/// recording carries one for, takes the counts that recording itself booked, and prices them under
/// the previous release's amounts and under the shipped default's. Those amounts are resolved
/// through the real grammar from one configured figure, so a release that stopped inheriting
/// `per_request_fee:` — or that quietly grew a second default for the same fee — turns this red on
/// every charged row at once.
///
/// The COUNT of money cells is read off the recording rather than written down as a literal, and
/// then asserted to be the figure measured today: a corpus that lost rows would otherwise make this
/// cell pass by having nothing left to compare.
///
/// **WHAT IT DOES NOT CLAIM.** It does not re-derive the recorded `spend_cents` — that is the
/// card's per-(lane, class) rates over the recorded tokens, which this release does not touch and
/// which both schedules read from the same card because they ARE the same card. What is under test
/// is the half a tariff can move: what the COUNTS cost.
#[test]
fn every_recorded_money_cell_is_charged_the_same_cents_under_both_schedules() {
    let dir = golden_cells();
    let mut money = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the recorded golden is in the tree") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a recorded cell is readable");
        let cell: serde_json::Value =
            serde_json::from_str(&text).expect("a recorded cell is a JSON document");
        let usage = &cell["effects"]["usage"];
        let Some(delta) = usage.as_object().filter(|d| !d.is_empty()) else {
            continue;
        };
        // `unavailable` is the recorder saying it could not measure the delta at all, which is a
        // gap in the recording and not a unit that moved money. Counted apart, never compared.
        if delta.contains_key("unavailable") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a cell file name")
            .to_string();
        let requests = delta
            .get("requests")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        money.push((name, requests));
    }
    money.sort();
    assert_eq!(
        money.len(),
        151,
        "the recording holds {} cells with a measurable money delta, not the 151 measured when \
         this cell was written; a corpus that lost rows must not make an identity claim pass by \
         having nothing left to compare",
        money.len()
    );

    for (name, requests) in &money {
        // THE COUNTS THE RECORDING ITSELF BOOKED. `requests` is the transaction count 1.5.5 wrote
        // for this cell; the visit count is zero on every one of them, because no recorded
        // deployment charged for the door and the shipped default does not either.
        let charged = Charge {
            entry: 0,
            transaction: u32::try_from(*requests).unwrap_or(u32::MAX),
            units_allowed: true,
            flags: busbar_caps::PostingFlags::NONE,
        };
        for fee in CONFIGURED_FEES {
            assert_eq!(
                cents(&previous_amounts(fee), charged),
                cents(&shipped_amounts(fee), charged),
                "{name} is charged two different figures by the two schedules at a configured \
                 fee of {fee}"
            );
        }
    }

    // AND THE DOOR IS FREE UNDER BOTH, which is the other half of "nothing moves": the shipped
    // default does not charge for a visit, so no recorded cell gains a line it did not have.
    assert!(!TariffCell::default().entry_fee_enabled);
    assert!(!previous_release().entry_fee_enabled);
}
