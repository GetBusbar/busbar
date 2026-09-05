// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The independent recompute, and the watermark that decides what it looks at.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;

use crate::recompute::{
    apply_tier, recheck, recompute, Divergence, Posting, PostingOrigin, PricedLine, RateCard,
    SealedPolicy, Watermark, BASIS_POINTS,
};

use super::fixtures::key;

fn policy() -> BTreeMap<u64, SealedPolicy> {
    let mut prices = BTreeMap::new();
    prices.insert("tokens_in".to_string(), 2i128);
    prices.insert("tokens_out".to_string(), 5i128);
    let card = RateCard {
        version: 1,
        prices,
        per_request_fee: 100,
    };
    let mut cards = BTreeMap::new();
    cards.insert(1, card);
    let mut tiers = BTreeMap::new();
    tiers.insert(key("b"), 9_000);
    let mut archive = BTreeMap::new();
    archive.insert(
        7,
        SealedPolicy {
            epoch: 7,
            cards,
            tiers,
        },
    );
    archive
}

/// A correctly priced posting: 1,000 in at 2 and 200 out at 5, plus one request fee of 100,
/// discounted to nine thousand basis points.
fn correct_posting(node_seq: u64) -> Posting {
    let pre_tier = 1_000 * 2 + 200 * 5 + 100;
    Posting {
        node: 1,
        node_seq,
        key: key("b"),
        window_start: 1,
        policy_epoch: 7,
        rate_card_version: 1,
        lines: vec![
            PricedLine {
                class: MeterClassId::new("tokens_in"),
                quantity: 1_000,
            },
            PricedLine {
                class: MeterClassId::new("tokens_out"),
                quantity: 200,
            },
        ],
        fee_count: 1,
        tier_bp: 9_000,
        pre_tier_amount: pre_tier,
        priced_amount: apply_tier(pre_tier, 9_000),
        origin: PostingOrigin::Client,
    }
}

#[test]
fn a_correctly_priced_posting_passes() {
    assert!(recheck(&correct_posting(1), &policy()).is_empty());
}

#[test]
fn a_hand_corrupted_priced_amount_is_found() {
    let mut posting = correct_posting(1);
    posting.priced_amount += 1;
    let found = recheck(&posting, &policy());
    assert_eq!(found.len(), 1);
    assert!(matches!(found[0], Divergence::Priced { .. }));
}

#[test]
fn a_hand_corrupted_quantity_is_found_through_the_pre_tier_figure() {
    let mut posting = correct_posting(1);
    posting.lines[0].quantity += 1;
    let found = recheck(&posting, &policy());
    assert_eq!(
        found.len(),
        2,
        "the pre-tier figure and the priced one both move"
    );
    assert!(matches!(found[0], Divergence::PreTier { .. }));
    assert!(matches!(found[1], Divergence::Priced { .. }));
}

#[test]
fn a_tier_the_posting_invented_is_found() {
    let mut posting = correct_posting(1);
    posting.tier_bp = BASIS_POINTS;
    // Repricing at the sealed tier, not the claimed one, so the priced amount also disagrees.
    let found = recheck(&posting, &policy());
    assert!(found.iter().any(|d| matches!(d, Divergence::Tier { .. })));
}

#[test]
fn the_fee_line_is_zero_for_work_no_client_asked_for() {
    let mut posting = correct_posting(1);
    posting.origin = PostingOrigin::Internal;
    posting.pre_tier_amount -= 100;
    posting.priced_amount = apply_tier(posting.pre_tier_amount, 9_000);
    assert!(
        recheck(&posting, &policy()).is_empty(),
        "an internally originated posting must not be charged the request fee"
    );
}

#[test]
fn on_a_deployment_with_no_rate_card_the_fee_line_is_what_gets_checked() {
    // No class prices at all. Every class line prices at zero, so the fee line is the whole amount
    // and the recompute is checking exactly it.
    let mut cards = BTreeMap::new();
    cards.insert(
        1,
        RateCard {
            version: 1,
            prices: BTreeMap::new(),
            per_request_fee: 250,
        },
    );
    let mut archive = BTreeMap::new();
    archive.insert(
        7,
        SealedPolicy {
            epoch: 7,
            cards,
            tiers: BTreeMap::new(),
        },
    );

    let mut posting = correct_posting(1);
    posting.fee_count = 3;
    posting.tier_bp = BASIS_POINTS;
    posting.pre_tier_amount = 750;
    posting.priced_amount = 750;
    assert!(recheck(&posting, &archive).is_empty());

    posting.priced_amount = 751;
    assert!(!recheck(&posting, &archive).is_empty());
}

#[test]
fn a_posting_priced_under_a_policy_nobody_kept_is_itself_a_finding() {
    let mut posting = correct_posting(1);
    posting.policy_epoch = 999;
    assert_eq!(
        recheck(&posting, &policy()),
        vec![Divergence::PolicyMissing { epoch: 999 }]
    );

    let mut posting = correct_posting(1);
    posting.rate_card_version = 42;
    assert_eq!(
        recheck(&posting, &policy()),
        vec![Divergence::CardMissing {
            epoch: 7,
            version: 42
        }]
    );
}

#[test]
fn the_watermark_reaches_the_head_every_pass() {
    let postings: Vec<Posting> = (1..=50).map(correct_posting).collect();
    let pass = recompute(Watermark::start(), &postings, &policy());
    assert!(pass.is_clean());
    assert_eq!(pass.checked, 50);
    assert_eq!(
        pass.watermark,
        Watermark {
            node: 1,
            node_seq: 50
        }
    );

    // A second pass over the same postings checks nothing, because the watermark is already there.
    let again = recompute(pass.watermark, &postings, &policy());
    assert_eq!(again.checked, 0);
    assert_eq!(again.watermark, pass.watermark);
}

#[test]
fn a_posting_edited_before_the_last_checkpoint_still_alarms() {
    // The reason the watermark is a posting and not a checkpoint. A checkpoint here would be far
    // ahead of the edit, and repricing "since the last checkpoint" would never look at it again.
    let mut postings: Vec<Posting> = (1..=100).map(correct_posting).collect();
    postings[3].priced_amount -= 7;

    let pass = recompute(Watermark::start(), &postings, &policy());
    assert_eq!(
        pass.checked, 100,
        "the whole run is repriced, not a recent tail"
    );
    assert_eq!(pass.findings.len(), 1);
    assert_eq!(pass.findings[0].node_seq, 4);
    assert!(matches!(
        pass.findings[0].divergence,
        Divergence::Priced { .. }
    ));
    assert_eq!(
        pass.watermark,
        Watermark {
            node: 1,
            node_seq: 100
        },
        "the watermark reaches the head even though a posting diverged"
    );
}

#[test]
fn one_bad_posting_does_not_stop_the_ones_after_it_being_checked() {
    let mut postings: Vec<Posting> = (1..=10).map(correct_posting).collect();
    postings[2].priced_amount += 1;
    postings[8].priced_amount += 1;
    let pass = recompute(Watermark::start(), &postings, &policy());
    assert_eq!(
        pass.findings.len(),
        2,
        "an early alarm must not hide a later one"
    );
}

#[test]
fn a_watermark_that_survives_a_restart_resumes_where_it_stopped() {
    let postings: Vec<Posting> = (1..=20).map(correct_posting).collect();
    let first = recompute(Watermark::start(), &postings[..10], &policy());
    assert_eq!(first.checked, 10);
    // The reconciliation entry carried the watermark across the restart; the second pass sees the
    // whole run and checks only what is new.
    let second = recompute(first.watermark, &postings, &policy());
    assert_eq!(second.checked, 10);
    assert_eq!(second.watermark.node_seq, 20);
}

#[test]
fn the_tier_multiplies_before_it_divides() {
    // A tier applied by dividing first rounds small amounts to nothing, which is a real way to lose
    // money one nano-unit at a time.
    assert_eq!(apply_tier(1, 9_999), 0);
    assert_eq!(apply_tier(10_000, 9_999), 9_999);
    assert_eq!(apply_tier(3, 5_000), 1);
    assert_eq!(apply_tier(-10_000, 9_000), -9_000);
}

#[test]
fn a_run_across_two_nodes_orders_by_node_then_sequence() {
    let mut postings = Vec::new();
    for node in 1..=2u64 {
        for seq in 1..=3u64 {
            let mut p = correct_posting(seq);
            p.node = node;
            postings.push(p);
        }
    }
    let pass = recompute(Watermark::start(), &postings, &policy());
    assert_eq!(pass.checked, 6);
    assert_eq!(
        pass.watermark,
        Watermark {
            node: 2,
            node_seq: 3
        }
    );
}
