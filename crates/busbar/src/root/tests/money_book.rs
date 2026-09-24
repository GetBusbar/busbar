// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money-book seam is a PASS-THROUGH, and these tests lock the FIGURES it passes through.
//!
//! ## Every assertion here is against a pinned number, never against a second call
//!
//! Until 1.6.0 the settle/post/apply tests ran `Ledger::settle_recording` by name, ran it again
//! through [`PassThroughBook`], and asserted the two agreed. `PassThroughBook::settle` IS
//! `Ledger::settle_recording` — one line of delegation — so both sides of that equality were the
//! same function applied to the same arguments, and **no change to the money arithmetic could red
//! them**: any change moved both sides together. It was demonstrated rather than argued: corrupting
//! the settled-money identity in `busbar-kernel-ledger` (`figures.settled += settled` →
//! `+= settled * 7 + 13`) reddened ten tests in that crate and left all six tests in this module
//! green.
//!
//! So each test now states the books' EXPECTED state field-for-field — what was drawn, what
//! settled, what went back to the slice — derived by hand from the settlement identity in the
//! comment beside it, exactly as `metering_row_from_facts_matches_the_plane_row_shape` has always
//! built its expected row. An arithmetic change reds the pin; a seam that stopped delegating reds
//! it too, because a reimplementation that drifts one figure no longer produces these numbers.
//!
//! ## What is still true about the seam, and what is not
//!
//! These tests prove the seam's own shape: its arithmetic, and that a plane composing over it gets
//! the ledger's answer. They prove NOTHING about production money, because nothing in the shipped
//! binary constructs [`PassThroughBook`] — the serving path still calls `Ledger::settle_recording`,
//! `UsageLedger::apply_delta` and the planes' own row builders by name. A green here is evidence
//! about the seam, not about what a served request is billed.
//!
//! RED-BEFORE-GREEN: the pinned figures were proven red by the same mutation that used to leave
//! this module green — the settled-money identity corrupted in `busbar-kernel-ledger::settle` —
//! and by swapping two `MeteringRow` fields and returning early from `apply_usage`.

use busbar_api::{ModelTokens, ModelTokensDelta, UsageDelta, UsageLedger};
use busbar_contract::caps::{
    Admittance, Consumption, Grant, Hold, KernelSeal, MeterClassId, PostingFlags, PrincipalId,
    QuantitySource, Usage, UsageLine, WriteMoney,
};
use busbar_kernel_ledger::settle::Ledger;
use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, Totals, TotalsKey};

use crate::root::money_book::{AuditFacts, MeterCounts, MeteringFacts, MoneyBook, PassThroughBook};

// ── local props (the ledger crate's fixtures are private to it) ──────────────────────────────────

fn admit_token() -> Grant<Admittance> {
    Grant::<Admittance>::mint(&KernelSeal::acquire_for_kernel())
}
fn ledger_token() -> Grant<WriteMoney> {
    Grant::<WriteMoney>::mint(&KernelSeal::acquire_for_kernel())
}
fn usage_token() -> Grant<Consumption> {
    Grant::<Consumption>::mint(&KernelSeal::acquire_for_kernel())
}
fn hold(who: &str, reserved: u64) -> Hold {
    Hold::open(&admit_token(), PrincipalId::new(who), reserved)
}
fn usage(class: &'static str, quantity: u64) -> Usage {
    Usage::report(
        &usage_token(),
        vec![UsageLine {
            class: MeterClassId::new(class),
            quantity,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .unwrap()
}
fn key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// A ledger primed with a drawn, opened, spent hold — the state a settle expects.
fn primed(k: &TotalsKey, reserved: u64) -> Ledger {
    let mut ledger = Ledger::new();
    ledger.record_draw(k, 1, i128::from(reserved));
    ledger.record_hold_opened(k, 1, reserved);
    ledger.record_slice_spent(k, 1, i128::from(reserved));
    ledger
}

// ── settle: the seam moves the books to the figures the identity says, and they are pinned ──────

#[test]
fn settle_through_the_seam_matches_the_direct_ledger() {
    let k = key("b");

    let mut seam_ledger = primed(&k, 600);
    let settlement = PassThroughBook.settle(
        &mut seam_ledger,
        &k,
        1,
        hold("alice", 600),
        450,
        &usage("tokens", 450),
        &ledger_token(),
    );

    // THE POSTING, by hand. `Posted::settle` reads the reservation off the hold (600) and takes the
    // priced total as what settled (450). The hold was opened at the door and accrued nothing, so
    // its own overdraft counter is 0, and 450 is inside 600, so the posting is clean.
    assert_eq!(settlement.posted.reserved(), 600);
    assert_eq!(settlement.posted.settled(), 450);
    assert_eq!(settlement.posted.overdraft(), 0);
    assert!(settlement.posted.flags().is_clean());
    // The residual: reserved and never used, handed back to the slice. 600 - 450.
    assert_eq!(settlement.released, 150);
    assert!(
        settlement.overdraft.is_none(),
        "nothing ran past its reservation"
    );

    // THE BOOKS, by hand, field for field.
    //   primed():  drawn +600, open_slice_remainders +600 then -600, open_holds +600
    //   settle():  open_holds -600 -> 0, settled +450, open_slice_remainders +150, overdraft +0
    let expected = Totals {
        drawn: 600,
        settled: 450,
        open_slice_remainders: 150,
        ..Totals::zero()
    };
    assert_eq!(
        seam_ledger.book().get(&k, 1),
        expected,
        "the seam must move the books to the figures the settlement identity says"
    );
}

#[test]
fn settle_records_the_overdraft_through_the_seam() {
    // Reserve 100, spend 250 -> 150 of value delivered with nothing behind it.
    let k = key("od");

    let mut seam_ledger = primed(&k, 100);
    let settlement = PassThroughBook.settle(
        &mut seam_ledger,
        &k,
        1,
        hold("carol", 100),
        250,
        &usage("tokens", 250),
        &ledger_token(),
    );

    // The overdraft FIGURE is the settlement's excess over its reservation (250 - 100 = 150),
    // not the hold's spend counter, which a hold opened at the door with no accrual leaves at 0.
    // Before item 318 the posting carried the OVERDRAFT flag with a figure of 0 and the book
    // below closed unbalanced (drawn 100 vs settled 250, residual +150) — a broken derivation,
    // not a ledger or ratecard fault. The flag and the figure now agree, and the ledger writes
    // the `Overdraft` note.
    assert_eq!(settlement.posted.reserved(), 100);
    assert_eq!(settlement.posted.settled(), 250);
    assert_eq!(settlement.posted.overdraft(), 150);
    assert!(
        settlement.posted.flags().contains(PostingFlags::OVERDRAFT),
        "250 settled against 100 reserved is an overdrawn posting"
    );
    assert_eq!(settlement.overdraft.as_ref().map(|o| o.amount), Some(150));
    // A hold that ran past its reservation releases nothing: (100 - 250).max(0).
    assert_eq!(settlement.released, 0);

    //   primed():  drawn +100, open_slice_remainders +100 then -100, open_holds +100
    //   settle():  open_holds -100 -> 0, settled +250, open_slice_remainders +0, overdraft +150
    //   identity:  drawn 100 = settled 250 - overdraft_carried_out 150 — the book balances.
    let expected = Totals {
        drawn: 100,
        settled: 250,
        overdraft_carried_out: 150,
        ..Totals::zero()
    };
    assert_eq!(seam_ledger.book().get(&k, 1), expected);
}

// ── post: the posting-side door moves the same three figures ─────────────────────────────────────

#[test]
fn post_through_the_seam_matches_the_direct_ledger() {
    let k = key("p");
    let posted = busbar_contract::caps::Posted::settle(
        hold("dave", 500),
        400,
        &usage("tokens", 400),
        &ledger_token(),
    );

    let mut seam_ledger = primed(&k, 500);
    let settlement = PassThroughBook.post(&mut seam_ledger, &k, 1, posted);

    assert_eq!(settlement.posted.settled(), 400);
    // 500 reserved, 400 posted, 100 back to the slice.
    assert_eq!(settlement.released, 100);
    assert!(settlement.overdraft.is_none());

    let expected = Totals {
        drawn: 500,
        settled: 400,
        open_slice_remainders: 100,
        ..Totals::zero()
    };
    assert_eq!(seam_ledger.book().get(&k, 1), expected);
}

// ── apply_usage: the rate-limit ledger folds to the counts, and they are pinned ──────────────────

#[test]
fn apply_usage_through_the_seam_matches_apply_delta() {
    let delta = UsageDelta {
        requests: 3,
        billable_requests: 2,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), 10i64), ("output".to_string(), 20i64)]
                .into_iter()
                .collect(),
        }],
    };

    let mut seam_ledger = UsageLedger::default();
    PassThroughBook.apply_usage(&mut seam_ledger, &delta);

    // The fold, by hand: an empty ledger takes each signed counter at face value (floored at 0),
    // allocates the model row on first sight, and lands every keyed unit on its own key.
    let expected = UsageLedger {
        requests: 3,
        billable_requests: 2,
        models: vec![ModelTokens {
            model: "m".to_string(),
            usage_units: [("input".to_string(), 10u64), ("output".to_string(), 20u64)]
                .into_iter()
                .collect(),
        }],
    };
    assert_eq!(
        seam_ledger, expected,
        "the seam's apply_usage must fold exactly what UsageLedger::apply_delta folds"
    );
}

// ── metering_row: the neutral builder reproduces the plane's row field-for-field ──────────────────

#[test]
fn metering_row_from_facts_matches_the_plane_row_shape() {
    let facts = MeteringFacts {
        key_id: "vk_1".to_string(),
        model: "serving-model".to_string(),
        provider: "prov".to_string(),
        counts: MeterCounts {
            input: 11,
            output: 22,
            cache_read: 3,
            cache_write: 4,
        },
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };

    let row = PassThroughBook.metering_row(&facts);

    // The exact literal the LLM plane's `metering_row` produces for a delivered response with these
    // counts (busbar-llm/src/unit/meter.rs): serving model+provider, per-tier counts, one request,
    // one billable request, empty group + pricing version.
    let expected = busbar_api::MeteringRow {
        usage_units: Default::default(),
        key_id: "vk_1".to_string(),
        model: "serving-model".to_string(),
        provider: "prov".to_string(),
        tokens_input: 11,
        tokens_output: 22,
        tokens_cache_read: 3,
        tokens_cache_write: 4,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        // The neutral facts carry no instant yet, so the builder leaves it at its default; the
        // durable row the governance accrual writes carries the real one (DECISION #79).
        priced_from_ms: 0,
    };
    assert_eq!(row, expected);
    // And byte-identical on the wire the store persists it over.
    assert_eq!(
        serde_json::to_vec(&row).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}

// ── audit_record: the neutral builder reproduces the durable record field-for-field ──────────────

#[test]
fn audit_record_from_facts_matches_the_durable_record() {
    let facts = AuditFacts {
        seq: 7,
        ts: 1_700_000_000,
        action: "hook.register".to_string(),
        resource: "hook:compress".to_string(),
        outcome: "applied".to_string(),
        principal: "op-1".to_string(),
        prev_hash: "aa".to_string(),
        hash: "bb".to_string(),
    };

    let rec = PassThroughBook.audit_record(&facts);

    let expected = busbar_api::AuditRecord {
        seq: 7,
        ts: 1_700_000_000,
        action: "hook.register".to_string(),
        resource: "hook:compress".to_string(),
        outcome: "applied".to_string(),
        principal: "op-1".to_string(),
        prev_hash: "aa".to_string(),
        hash: "bb".to_string(),
    };
    assert_eq!(rec, expected);
    assert_eq!(
        serde_json::to_vec(&rec).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
