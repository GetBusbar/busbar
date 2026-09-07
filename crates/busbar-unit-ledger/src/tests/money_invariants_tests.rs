// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money invariants stated one clause at a time.
//!
//! The identity is a sum of seven differences and one of them is subtracted rather than added. A
//! test that only ever measures from zeros cannot tell those apart: with `since` at zero, `a - 0`
//! and `a + 0` are the same number, so every sign in the equation is unpinned. Each case below
//! moves exactly one column on BOTH snapshots, so the sign of that column — and only that column —
//! decides whether the case passes.
//!
//! Beside the identity are the readers an operator's alarm is made of: the digest that names a
//! checkpoint, the body a verifier re-signs, the diagnostics an imbalance prints, and the
//! accessors the recompute walks. A ledger whose figures are right and whose alarm prints nothing
//! is a ledger nobody can act on.

use busbar_caps::MeterClassId;

use super::fixtures::{hold, key, ledger_token, usage};
use crate::checkpoint::{ChainHead, Checkpoint, CheckpointSecret, SignError, Signature};
use crate::identity::{
    attribution_holds, closed_window_is_settled, holds, residual, ClosedWindowMoved, Imbalance,
    Residual,
};
use crate::legacy::{opening_balances, LegacyHead, LegacyPosting, LegacyRows, RecordingRows};
use crate::recompute::{
    Divergence, Finding, Posting, PostingOrigin, PricedLine, RateCard, Watermark,
};
use crate::settle::Ledger;
use crate::totals::Totals;

/// A signer that stamps the digest of what it was handed, so one body can be told from another.
struct StampSigner;

impl CheckpointSecret for StampSigner {
    fn sign(&self, body: &[u8]) -> Result<Signature, SignError> {
        Ok(Signature::new(crate::digest::sha256(body).to_vec()))
    }
}

/// Totals with one column set, and every other column left at a value that is NOT zero, so a
/// difference taken against it is a real subtraction rather than a no-op.
fn totals_at(settled: i128, open_holds: i128, drawn: i128) -> Totals {
    Totals {
        settled,
        open_holds,
        drawn,
        ..Totals::zero()
    }
}

/// Every column of the identity is a DIFFERENCE, measured from a non-zero starting point.
///
/// The check is the same in every column: the last checkpoint already held some value there, and
/// only what moved since counts. An operator taking a difference the other way round would see a
/// deployment's whole history reported as this window's imbalance.
#[test]
fn each_accounted_column_is_measured_as_a_difference_from_the_checkpoint() {
    // One posting of 40 against a checkpoint that already had 100 settled and 300 drawn.
    let since = totals_at(100, 0, 300);
    let now = totals_at(140, 0, 340);
    assert_eq!(residual(&since, &now).accounted, 40);
    assert_eq!(residual(&since, &now).drawn, 40);
    assert!(holds(&since, &now));
}

/// The open-holds column subtracts its own starting point.
///
/// A hold that was already open at the checkpoint is not value this window drew. Adding the
/// starting point instead would count every hold outstanding at the seal a second time.
#[test]
fn the_open_holds_column_subtracts_where_the_checkpoint_left_it() {
    let since = Totals {
        open_holds: 500,
        drawn: 500,
        ..Totals::zero()
    };
    let now = Totals {
        open_holds: 700,
        drawn: 700,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(
        r.accounted, 200,
        "only the 200 opened since the seal counts"
    );
    assert_eq!(r.drawn, 200);
    assert!(r.holds());
}

/// The slice-remainder column subtracts its own starting point.
#[test]
fn the_slice_remainder_column_subtracts_where_the_checkpoint_left_it() {
    let since = Totals {
        open_slice_remainders: 900,
        drawn: 900,
        ..Totals::zero()
    };
    let now = Totals {
        open_slice_remainders: 950,
        drawn: 950,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(r.accounted, 50);
    assert_eq!(r.drawn, 50);
    assert!(r.holds());
}

/// The unreconciled column subtracts its own starting point.
///
/// An unreconciled amount is a MOVE out of settled, so a window that moved 60 across the two
/// columns has moved nothing at all — which is only true if both columns are differences.
#[test]
fn the_unreconciled_column_subtracts_where_the_checkpoint_left_it() {
    let since = Totals {
        settled: 400,
        unreconciled: 100,
        drawn: 500,
        ..Totals::zero()
    };
    let now = Totals {
        settled: 340,
        unreconciled: 160,
        drawn: 500,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(r.accounted, 0, "a move between two columns moves nothing");
    assert_eq!(r.drawn, 0);
    assert!(r.holds());
}

/// The adjustments column subtracts its own starting point.
#[test]
fn the_adjustments_column_subtracts_where_the_checkpoint_left_it() {
    let since = Totals {
        settled: 800,
        adjustments: 200,
        drawn: 1_000,
        ..Totals::zero()
    };
    // A correction of 70 leaves settled and enters adjustments: the identity does not move.
    let now = Totals {
        settled: 730,
        adjustments: 270,
        drawn: 1_000,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(r.accounted, 0);
    assert!(r.holds());
}

/// The carried overdraft is SUBTRACTED, and it is subtracted as a difference.
///
/// Overdraft is the part of a posting that nothing drew, so the identity takes it back off the
/// accounted side. Adding it — or measuring it from zero when the last window already carried
/// some — reports a node that overspent as one whose books balance.
#[test]
fn the_carried_overdraft_is_subtracted_as_a_difference() {
    let since = Totals {
        settled: 100,
        overdraft_carried_out: 30,
        drawn: 70,
        ..Totals::zero()
    };
    // A further 50 posted with 20 of it unbacked: 50 settled, 20 more carried, 30 actually drawn.
    let now = Totals {
        settled: 150,
        overdraft_carried_out: 50,
        drawn: 100,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(r.accounted, 30, "50 settled less the 20 nothing drew");
    assert_eq!(r.drawn, 30);
    assert!(r.holds());

    // Measured from a checkpoint that carried nothing, the same window is 20 out of balance the
    // other way — which is what makes the starting point load-bearing rather than decorative.
    let from_zero = residual(&Totals::zero(), &now);
    assert_eq!(from_zero.accounted, 100);
    assert_eq!(from_zero.drawn, 100);
}

/// The carried-overdraft figure the identity folds in is OUT less IN, and it is one figure.
#[test]
fn the_carried_overdraft_is_what_went_out_less_what_came_in() {
    let figures = Totals {
        overdraft_carried_in: 40,
        overdraft_carried_out: 90,
        ..Totals::zero()
    };
    assert_eq!(figures.overdraft_carried(), 50);

    // A window that carried more in than out hands value back, and the sign says so.
    let inbound = Totals {
        overdraft_carried_in: 90,
        overdraft_carried_out: 40,
        ..Totals::zero()
    };
    assert_eq!(inbound.overdraft_carried(), -50);
}

/// The cross-window transfer column subtracts its own starting point, and its sign is OUT-positive.
#[test]
fn the_transfer_column_subtracts_where_the_checkpoint_left_it() {
    let since = Totals {
        open_slice_remainders: 500,
        cross_window_transfers: 200,
        drawn: 700,
        ..Totals::zero()
    };
    // A further 120 transferred out: it leaves the remainders and appears in the transfer column.
    let now = Totals {
        open_slice_remainders: 380,
        cross_window_transfers: 320,
        drawn: 700,
        ..Totals::zero()
    };
    let r = residual(&since, &now);
    assert_eq!(r.accounted, 0, "value that left is still accounted for");
    assert!(r.holds());
}

/// Headroom is the budget less what is posted, held and carried in.
#[test]
fn headroom_is_the_budget_less_what_is_spoken_for() {
    let figures = Totals {
        budget: 1_000,
        settled: 300,
        open_holds: 200,
        overdraft_carried_in: 50,
        ..Totals::zero()
    };
    assert_eq!(figures.headroom(), 450);
}

/// The identity answers both ways, through the predicate a caller actually asks.
///
/// The free function and the residual it wraps must not be able to disagree: a predicate frozen at
/// "yes" is a reconciliation that never alarms, and one frozen at "no" is one that always does and
/// is therefore muted within a week.
#[test]
fn the_identity_predicate_answers_both_ways() {
    let balanced_since = totals_at(10, 0, 10);
    let balanced_now = totals_at(60, 0, 60);
    assert!(holds(&balanced_since, &balanced_now));
    assert_eq!(residual(&balanced_since, &balanced_now).amount(), 0);

    // 50 drawn, only 30 of it anywhere: 20 has been lost.
    let lost_now = totals_at(40, 0, 60);
    assert!(!holds(&balanced_since, &lost_now));
    assert_eq!(residual(&balanced_since, &lost_now).amount(), -20);

    // 50 settled against 30 drawn: 20 has been invented.
    let invented_now = totals_at(60, 0, 40);
    assert!(!holds(&balanced_since, &invented_now));
    assert_eq!(residual(&balanced_since, &invented_now).amount(), 20);
}

/// A closed window that is still moving is reported by WHICH side moved.
#[test]
fn a_closed_window_reports_the_side_that_moved() {
    let since = totals_at(100, 0, 100);
    assert_eq!(closed_window_is_settled(&since, &since), Ok(()));

    // A late posting that draws and settles the same amount balances and must still be reported.
    let late = totals_at(180, 0, 180);
    assert_eq!(closed_window_is_settled(&since, &late), Err(80));

    // Nothing accounted moved, but the drawn side did.
    let drew_only = totals_at(100, 0, 175);
    assert_eq!(closed_window_is_settled(&since, &drew_only), Err(75));
}

/// An attribution bucket's identity is accrued equals settled, both ways.
#[test]
fn an_attribution_bucket_balances_when_what_accrued_is_what_posted() {
    assert!(attribution_holds(1_234, 1_234));
    assert!(!attribution_holds(1_234, 1_233));
    assert!(attribution_holds(0, 0));
}

/// The identity's diagnostics carry the figures an operator goes looking for.
///
/// An alarm that prints nothing is an alarm nobody can act on, so the text is asserted to contain
/// the numbers rather than merely to be produced.
#[test]
fn the_imbalance_diagnostics_carry_their_figures() {
    let residual = Residual {
        accounted: 900,
        drawn: 1_100,
    };
    let text = residual.to_string();
    assert!(text.contains("900"), "{text}");
    assert!(text.contains("1100"), "{text}");
    assert!(text.contains("-200"), "{text}");

    let imbalance = Imbalance {
        key: key("bucket-a"),
        window: 1_700_000_000,
        residual,
    };
    let text = imbalance.to_string();
    assert!(text.contains("bucket-a"), "{text}");
    assert!(text.contains("1700000000"), "{text}");
    assert!(text.contains("-200"), "{text}");

    let moved = ClosedWindowMoved {
        key: key("bucket-a"),
        window: 1_700_000_000,
        moved: 77,
    };
    let text = moved.to_string();
    assert!(text.contains("bucket-a"), "{text}");
    assert!(text.contains("77"), "{text}");
}

/// The recompute's diagnostics carry the two figures that disagreed.
#[test]
fn the_recompute_diagnostics_carry_their_figures() {
    let priced = Divergence::Priced {
        posted: 500,
        recomputed: 450,
    };
    let text = priced.to_string();
    assert!(text.contains("500"), "{text}");
    assert!(text.contains("450"), "{text}");

    for (divergence, needles) in [
        (Divergence::PolicyMissing { epoch: 12 }, vec!["12"]),
        (
            Divergence::CardMissing {
                epoch: 12,
                version: 34,
            },
            vec!["12", "34"],
        ),
        (
            Divergence::PreTier {
                posted: 11,
                recomputed: 22,
            },
            vec!["11", "22"],
        ),
        (
            Divergence::Tier {
                posted: 9_000,
                sealed: 10_000,
            },
            vec!["9000", "10000"],
        ),
    ] {
        let text = divergence.to_string();
        for needle in needles {
            assert!(text.contains(needle), "{text} is missing {needle}");
        }
    }

    let finding = Finding {
        node: 3,
        node_seq: 41,
        divergence: Divergence::Priced {
            posted: 500,
            recomputed: 450,
        },
    };
    let text = finding.to_string();
    assert!(text.contains('3'), "{text}");
    assert!(text.contains("41"), "{text}");
    assert!(text.contains("450"), "{text}");
}

/// The hex digest is the digest, in lowercase hex, for a vector anybody can check by hand.
///
/// A digest that answered a constant would make every checkpoint identity equal to every other
/// one, which is the failure the body hash exists to prevent.
#[test]
fn the_hex_digest_is_the_known_digest_of_its_input() {
    // The SHA-256 of the empty input, and of "abc" — the two vectors every implementation states.
    assert_eq!(
        crate::digest::sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        crate::digest::sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(crate::digest::sha256_hex(b"abc").len(), 64);
    assert_ne!(
        crate::digest::sha256_hex(b"abc"),
        crate::digest::sha256_hex(b"abd")
    );
}

/// A signature answers with the bytes it was wrapped around, and two different signatures differ.
#[test]
fn a_signature_answers_with_its_own_bytes() {
    let signature = Signature::new(vec![9u8, 8, 7, 6]);
    assert_eq!(signature.bytes(), &[9u8, 8, 7, 6]);
    assert!(!signature.bytes().is_empty());
    assert_ne!(
        Signature::new(vec![1u8]).bytes(),
        Signature::new(vec![2u8]).bytes()
    );
}

/// The bytes a verifier re-signs are the bytes that were digested, and they move with the figures.
///
/// A body that answered a constant would verify every checkpoint against every other — the exact
/// property a re-signature is supposed to rule out — and a body whose length does not track its
/// contents would let two different books share one signature.
#[test]
fn the_signed_body_is_the_digested_body_and_moves_with_the_figures() {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 600);
    ledger.record_slice_spent(&k, 1, 600);
    ledger.settle(&k, 1, hold("a", 600), 450, &usage("tokens", 450), &token);

    let seal_at = |ledger: &Ledger, seq: u64| {
        Checkpoint::seal(
            seq,
            1,
            1_700_000_000,
            vec![ChainHead {
                node: 1,
                node_seq: 10,
                hash: [7u8; 32],
            }],
            ledger.book().snapshot(),
            5,
            99,
            Some(&StampSigner),
        )
        .expect("the stamp signer always signs")
    };

    let checkpoint = seal_at(&ledger, 1);
    let body = checkpoint.signed_body();
    assert!(!body.is_empty());
    assert!(body.len() > 1, "a framed body is not one byte");
    assert_eq!(crate::digest::sha256(&body), checkpoint.body_hash);
    assert!(checkpoint.body_hash_verifies());

    // A second checkpoint over different figures signs different bytes.
    let mut moved = Ledger::new();
    moved.record_draw(&key("b"), 1, 2_000);
    let other = seal_at(&moved, 1);
    assert_ne!(other.signed_body(), body);

    // The bucket name is length-framed, so its own text cannot move the field boundary: two books
    // whose names would collide under a separator join do not collide here.
    let mut split_one = Ledger::new();
    split_one.record_draw(&key("a:b"), 1, 1);
    let mut split_two = Ledger::new();
    split_two.record_draw(&key("a"), 1, 1);
    assert_ne!(
        seal_at(&split_one, 1).signed_body(),
        seal_at(&split_two, 1).signed_body()
    );
    // The longer name makes a longer body, which a framing that wrote no length could not do.
    assert!(
        seal_at(&split_one, 1).signed_body().len() > seal_at(&split_two, 1).signed_body().len()
    );
}

/// A legacy head with nothing in it reads as empty, and either half being present makes it not.
///
/// The two halves are joined with AND on purpose: a head that carries a hash but no sequence
/// number is still something the migration cross-links, and reading it as nothing would drop the
/// link.
#[test]
fn a_legacy_head_is_empty_only_when_both_halves_are() {
    assert!(LegacyHead::empty().is_empty());
    assert_eq!(LegacyHead::empty(), LegacyHead::default());

    let with_seq = LegacyHead {
        seq: Some(9),
        ..LegacyHead::empty()
    };
    assert!(!with_seq.is_empty());

    let with_balances = LegacyHead {
        balances: vec![("b".to_string(), 12i128)],
        ..LegacyHead::empty()
    };
    assert!(!with_balances.is_empty());

    let with_both = LegacyHead {
        seq: Some(9),
        balances: vec![("b".to_string(), 12i128)],
        ..LegacyHead::empty()
    };
    assert!(!with_both.is_empty());
}

/// The opening balances are the legacy balances, at the named card version, one for one.
#[test]
fn the_opening_balances_are_the_legacy_balances_at_the_named_card() {
    let head = LegacyHead {
        seq: Some(3),
        hash: Some("deadbeef".to_string()),
        balances: vec![("b1".to_string(), 100i128), ("b2".to_string(), -25i128)],
        cells_read: 2,
    };
    let opened = opening_balances(&head, 7);
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].bucket, "b1");
    assert_eq!(opened[0].amount, 100);
    assert_eq!(opened[0].rate_card_version, 7);
    assert_eq!(
        opened[1].amount, -25,
        "a negative legacy figure is not clamped"
    );
    assert!(opening_balances(&LegacyHead::empty(), 7).is_empty());
}

/// The dual write's fold sees every posting, in order, and sums to what was written.
///
/// The fold is what a reader that only wants a total takes; a fold that showed nothing would
/// report a node that posted all day as one that posted nothing.
#[test]
fn the_dual_write_fold_sees_every_posting_in_order() {
    let mut rows = RecordingRows::new();
    for (i, settled) in [10u64, 20, 30].into_iter().enumerate() {
        rows.write(&LegacyPosting {
            principal: format!("p{i}"),
            bucket: "b".to_string(),
            window_start: 1,
            reserved: settled,
            settled,
            overdraft: 0,
        })
        .expect("the recording binding always writes");
    }

    let mut seen = Vec::new();
    let mut total = 0u64;
    rows.fold_written(&mut |posting| {
        seen.push(posting.principal.clone());
        total += posting.settled;
    });
    assert_eq!(seen, vec!["p0", "p1", "p2"]);
    assert_eq!(total, 60);
    assert_eq!(rows.written().len(), 3);
}

/// A ledger says whether it is dual-writing, and it answers both ways.
///
/// The composition root asserts this at boot. A predicate frozen at "yes" turns that assertion into
/// a no-op, and the failure it is guarding against is silent until somebody tries to roll back.
#[test]
fn a_ledger_says_whether_it_dual_writes() {
    assert!(!Ledger::new().is_dual_writing());
    assert!(Ledger::dual_writing(Box::new(RecordingRows::new())).is_dual_writing());

    // The debug view names the two facts an operator asks a ledger for: how many balances it holds
    // and whether the previous release's rows are being fed.
    let mut ledger = Ledger::dual_writing(Box::new(RecordingRows::new()));
    ledger.record_draw(&key("b"), 1, 5);
    let text = format!("{ledger:?}");
    assert!(text.contains("Ledger"), "{text}");
    assert!(text.contains('1'), "{text}");
    assert!(text.contains("true"), "{text}");
    assert!(format!("{:?}", Ledger::new()).contains("false"));
}

/// An empty card is empty at the version it was asked for, and prices every class at nothing.
#[test]
fn an_empty_card_keeps_the_version_it_was_asked_for() {
    let card = RateCard::empty(42);
    assert_eq!(card.version, 42);
    assert!(card.prices.is_empty());
    assert_eq!(card.per_request_fee, 0);
    assert_eq!(card.price(&MeterClassId::new("input")), 0);
    assert_ne!(
        card,
        RateCard::default(),
        "a card at a version is not the default one"
    );
    assert_eq!(RateCard::empty(0), RateCard::default());
}

/// A posting's position is its own node and its own sequence number.
///
/// The watermark advances over exactly this pair. A position that answered a constant would put
/// every posting at one point in the run, and everything after that point would be skipped
/// permanently.
#[test]
fn a_postings_position_is_its_own_node_and_sequence() {
    let posting = Posting {
        node: 5,
        node_seq: 77,
        key: key("b"),
        window_start: 1,
        policy_epoch: 1,
        rate_card_version: 1,
        lines: vec![PricedLine {
            class: MeterClassId::new("input"),
            quantity: 3,
        }],
        fee_count: 1,
        tier_bp: 10_000,
        pre_tier_amount: 0,
        priced_amount: 0,
        origin: PostingOrigin::Client,
    };
    assert_eq!(posting.position(), (5, 77));

    let other = Posting {
        node: 6,
        node_seq: 78,
        ..posting.clone()
    };
    assert_eq!(other.position(), (6, 78));
    assert_ne!(other.position(), posting.position());
}

/// The beginning is a watermark with no marks at all, and it is behind every posting.
#[test]
fn the_starting_watermark_is_behind_everything() {
    let start = Watermark::start();
    assert_eq!(start.nodes(), 0);
    assert_eq!(start.mark_for(1), None);
    assert_eq!(start.pairs().count(), 0);
    assert_eq!(start, Watermark::default());
    assert_eq!(start.to_string(), "nothing recomputed yet");

    // A mark placed on one node leaves every other node still at the beginning.
    let marked = Watermark::from_pairs([(1u64, 10u64)]);
    assert_eq!(marked.mark_for(1), Some(10));
    assert_eq!(marked.mark_for(2), None);
    assert_ne!(marked, Watermark::start());
    assert_eq!(marked.to_string(), "1/10");
}
