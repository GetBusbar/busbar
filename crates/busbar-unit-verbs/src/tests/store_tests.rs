// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money model, as the closed list it is — and the one money verb, exercised through the seam
//! that stands in for the rate table until that table lands.
//!
//! Two claims live here rather than beside the verb table, because both are about what the ADMIN
//! LEDGER surface is, and neither is a claim about the 66 legacy operations that surface also
//! carries. The first is the list: eight verbs, named, and five named absences. The second is the
//! behaviour that makes the list coherent — a rate amendment ADDS a row and never edits one, which
//! is the whole reason a correction verb is not needed to sit beside it.

use busbar_caps::{AdminToken, KernelSeal};

use crate::store::{DatedRateRow, RateHistory, RateRowAuthor, RateRowSeq, StoreError};
use crate::verb::{KernelVerb, IRREDUCIBLE_VERBS, NEW_VERBS, READ_ONLY_NEW_VERBS};

/// THE EIGHT. The admin ledger verbs the money model leaves standing, in the order the model names
/// them.
///
/// These are the members of [`NEW_VERBS`] that are about the LEDGER. The five that are not —
/// `set_operator_key`, `set_escrow`, `set_dual_control`, `export_keyset`, `approve` — are the
/// operator-key ceremony and the maker-checker step; they govern who may run a verb rather than
/// what the ledger holds, and they were never in scope for a money ruling.
const THE_EIGHT_LEDGER_VERBS: &[KernelVerb] = &[
    KernelVerb::Verify,
    KernelVerb::PlaneFacts,
    KernelVerb::PlaneRecordWrite,
    KernelVerb::ChainBreak,
    KernelVerb::StoreRestore,
    KernelVerb::ResealEpochFloor,
    KernelVerb::CommitUpgrade,
    KernelVerb::AmendRateHistory,
];

/// The five verbs that are not here, spelled out.
///
/// Written as their WIRE names rather than as enum variants for the reason the whole cut exists: the
/// variants are gone, so there is nothing left to name in Rust. A string is the only thing that can
/// still assert the absence of a thing that no longer has a type, and the day one of these comes
/// back it will come back under one of these spellings.
const THE_FIVE_THAT_LEFT: &[&str] = &[
    "adjust",
    "resolve_slice",
    "resolve_dispute",
    "set_dispute_max_age",
    "set_overdraft_ceiling",
];

/// The ceremony verbs: the members of `NEW_VERBS` the money ruling is not about.
const THE_CEREMONY_VERBS: &[KernelVerb] = &[
    KernelVerb::SetOperatorKey,
    KernelVerb::SetEscrow,
    KernelVerb::SetDualControl,
    KernelVerb::ExportKeyset,
    KernelVerb::Approve,
];

/// The two the design binds as `GET`, named here so the split is asserted from this side too.
const THE_TWO_READS: &[KernelVerb] = &[KernelVerb::Verify, KernelVerb::PlaneFacts];

#[test]
fn the_admin_ledger_verbs_are_exactly_the_eight_the_money_model_names() {
    // Derived, not written down: whatever is in NEW_VERBS and is not a ceremony verb IS a ledger
    // verb, so a thirteenth verb arriving in either category shows up here rather than in silence.
    let derived: Vec<KernelVerb> = NEW_VERBS
        .iter()
        .copied()
        .filter(|v| !THE_CEREMONY_VERBS.contains(v))
        .collect();
    assert_eq!(
        derived, THE_EIGHT_LEDGER_VERBS,
        "the admin ledger verbs are no longer the eight the money model names"
    );
    assert_eq!(derived.len(), 8);
    // And the two halves account for the whole list, so neither can grow at the other's expense.
    assert_eq!(
        NEW_VERBS.len(),
        THE_EIGHT_LEDGER_VERBS.len() + THE_CEREMONY_VERBS.len()
    );
}

#[test]
fn the_two_read_only_ledger_verbs_are_verify_and_plane_facts_and_the_other_six_are_mutations() {
    assert_eq!(READ_ONLY_NEW_VERBS, THE_TWO_READS);
    for verb in THE_EIGHT_LEDGER_VERBS {
        let is_read = READ_ONLY_NEW_VERBS.contains(verb);
        assert_eq!(
            is_read,
            THE_TWO_READS.contains(verb),
            "{verb:?} changed sides on the read/mutate split"
        );
    }
}

#[test]
fn no_correction_verb_survives_anywhere_in_the_closed_table() {
    // The whole enum, rendered, is the only place a resurrected variant could hide: `NEW_VERBS` is a
    // list a resurrected verb could be added to WITHOUT being added to, whereas a variant that
    // exists at all is spelled by `Debug` the moment it is named in any of these lists.
    let every_named: Vec<String> = NEW_VERBS
        .iter()
        .chain(IRREDUCIBLE_VERBS.iter())
        .chain(crate::verb::LEDGER_VERBS.iter())
        .map(|v| format!("{v:?}").to_ascii_lowercase().replace('_', ""))
        .collect();
    for gone in THE_FIVE_THAT_LEFT {
        let squashed = gone.replace('_', "");
        assert!(
            !every_named.iter().any(|n| n == &squashed),
            "`{gone}` is back: busbar is a meter and an audit trail, and a correction verb has \
             nothing here to correct — the calling app corrects against the exported sealed lines"
        );
    }
}

#[test]
fn every_member_of_the_irreducible_set_is_irreducible_unconditionally() {
    // The two amount-gated members the earlier list carried (`Adjust`, `ResolveDispute`) went with
    // the verbs. What is asserted is the consequence: every remaining member is a member of the
    // closed new-verb list or a legacy ceremony verb, and none of them needs a threshold to decide
    // how hard to gate it — there is no amount on any of them to compare a threshold against.
    for verb in IRREDUCIBLE_VERBS {
        assert!(
            NEW_VERBS.contains(verb),
            "{verb:?} is irreducible but is not one of the new verbs, so nothing gates it"
        );
    }
    assert_eq!(IRREDUCIBLE_VERBS.len(), 8);
}

#[test]
fn amend_rate_history_is_a_mutating_ledger_verb_and_not_irreducible() {
    // Not irreducible, and that is the design's own ruling rather than an omission: a single admin
    // may amend the rate history. The risk is real and it is bounded differently from the verbs that
    // left — an appended row is visible, dated, attributed and superseded rather than deleted, so
    // what it did can always be read back, which was never true of a verb that moved a posted figure.
    assert!(NEW_VERBS.contains(&KernelVerb::AmendRateHistory));
    assert!(!READ_ONLY_NEW_VERBS.contains(&KernelVerb::AmendRateHistory));
    assert!(!IRREDUCIBLE_VERBS.contains(&KernelVerb::AmendRateHistory));
}

// ── the seam, exercised ─────────────────────────────────────────────────────────────────────────

/// An add-only rate history: the smallest thing that can be an implementation of the seam, holding
/// its rows in the order they arrived and handing back the sequence it filed each under.
///
/// It has no `edit` and no `remove`, and that is not an economy — it is the property under test. A
/// fake with a mutator the trait does not have would let a test pass against a shape the seam cannot
/// express.
#[derive(Default)]
struct AddOnlyHistory {
    rows: std::cell::RefCell<Vec<DatedRateRow>>,
}

impl RateHistory for AddOnlyHistory {
    fn amend_rate_history(
        &self,
        _admin: &AdminToken,
        row: &DatedRateRow,
    ) -> Result<RateRowSeq, StoreError> {
        let mut rows = self.rows.borrow_mut();
        rows.push(row.clone());
        Ok(RateRowSeq(rows.len() as u64 - 1))
    }
}

fn admin() -> AdminToken {
    AdminToken::mint(&KernelSeal::acquire_for_kernel())
}

fn a_row(effective_from: u64, nanos_per_unit: u64) -> DatedRateRow {
    DatedRateRow {
        lane: "lane-a".to_string(),
        class: "tokens_input".to_string(),
        currency: *b"USD",
        nanos_per_unit,
        effective_from,
        author: RateRowAuthor::Amend {
            operator_fingerprint: "op-1".to_string(),
            reason_hash: [7u8; 32],
        },
    }
}

#[test]
fn amending_the_rate_history_adds_a_dated_row_and_leaves_the_rows_before_it_untouched() {
    let history = AddOnlyHistory::default();
    let admin = admin();

    let first = a_row(1_000, 250);
    let seq_first = history.amend_rate_history(&admin, &first).unwrap();

    // A SECOND row for the same cell, at a LATER instant and a different price. This is the reprice
    // the model keeps in place of a correction.
    let second = a_row(2_000, 400);
    let seq_second = history.amend_rate_history(&admin, &second).unwrap();

    assert_ne!(
        seq_first, seq_second,
        "two rows were filed under one sequence, so neither can be cited"
    );
    assert!(
        seq_first < seq_second,
        "the sequence is not the arrival order"
    );

    let rows = history.rows.borrow();
    assert_eq!(rows.len(), 2, "an amendment did not ADD a row");
    // THE CLAIM: the first row is byte-for-byte what it was. A correction verb would have moved it;
    // an amendment cannot, because the only thing the seam can do is append.
    assert_eq!(rows[0], first, "the earlier row was edited, not superseded");
    assert_eq!(rows[1], second);
}

#[test]
fn a_back_dated_row_is_admitted_because_price_is_never_stored() {
    let history = AddOnlyHistory::default();
    let admin = admin();

    history
        .amend_rate_history(&admin, &a_row(5_000, 250))
        .unwrap();
    // Effective BEFORE the row already added: a retroactive reprice. It costs nothing to allow,
    // because no posted line holds a price to contradict it — every read derives money afresh from
    // the rows in force at the instant it is asking about.
    let back_dated = a_row(1_000, 100);
    let seq = history.amend_rate_history(&admin, &back_dated).unwrap();

    assert_eq!(
        seq,
        RateRowSeq(1),
        "a back-dated row was not filed as an arrival"
    );
    let rows = history.rows.borrow();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].effective_from, 1_000);
    assert_eq!(
        rows[0].effective_from, 5_000,
        "the row the back-dated one precedes was rewritten rather than left standing"
    );
}

#[test]
fn the_author_distinguishes_an_amendment_from_a_row_the_config_produced() {
    // Provenance, not policy: nothing in the seam reads it, and this test is what keeps it from
    // being dropped as unused. A row that cannot say which act produced it makes the history an
    // unattributed price list rather than an audit trail.
    let config_row = DatedRateRow {
        author: RateRowAuthor::Config { policy_epoch: 4 },
        ..a_row(1_000, 250)
    };
    let amended = a_row(1_000, 250);
    assert_ne!(
        config_row, amended,
        "a boot-time row and a signed amendment are indistinguishable, so the history cannot say \
         who repriced anything"
    );
    match &amended.author {
        RateRowAuthor::Amend {
            operator_fingerprint,
            reason_hash,
        } => {
            assert_eq!(operator_fingerprint, "op-1");
            assert_eq!(reason_hash, &[7u8; 32]);
        }
        RateRowAuthor::Config { .. } => panic!("an amendment was recorded as a config row"),
    }
}
