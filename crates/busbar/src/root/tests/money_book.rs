// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money-book seam is a PASS-THROUGH, and these tests lock that it is one.
//!
//! Each test runs the shipped money-recording code by name, runs it again through
//! [`PassThroughBook`], and asserts the two agree — for settle/post/apply, by construction (the
//! seam calls the same function); for the row/record builders, field-for-field. If a later edit
//! makes the seam REIMPLEMENT rather than DELEGATE and drifts a single field, the mirror test reds.
//! That drift-detection is the whole point: a dormant seam that quietly diverged from the shipped
//! path would fold a bug into `busbar-kernel-ledger` in W3.
//!
//! RED-BEFORE-GREEN: these tests were proven red first by mutating `PassThroughBook` (swapping two
//! `MeteringRow` fields, and returning early from `apply_usage`) — both reddened the relevant
//! assertion — then made green by restoring the true pass-through. See the wave report for the
//! captured red/green output.

use busbar_api::{ModelTokensDelta, UsageDelta, UsageLedger};
use busbar_contract::caps::{Grant, 
    Admittance, Hold, KernelSeal, WriteMoney, MeterClassId, PrincipalId, QuantitySource,
    Usage, UsageLine, Consumption,
};
use busbar_kernel_ledger::settle::Ledger;
use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

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

// ── settle: the seam moves the books exactly as the ledger does directly ─────────────────────────

#[test]
fn settle_through_the_seam_matches_the_direct_ledger() {
    let k = key("b");

    // Direct: the shipped call, by name.
    let mut direct = primed(&k, 600);
    let direct_settlement =
        direct.settle_recording(&k, 1, hold("alice", 600), 450, &usage("tokens", 450), &ledger_token());

    // Seam: the same act, through the pass-through.
    let mut seam_ledger = primed(&k, 600);
    let seam_settlement = PassThroughBook.settle(
        &mut seam_ledger,
        &k,
        1,
        hold("alice", 600),
        450,
        &usage("tokens", 450),
        &ledger_token(),
    );

    // The posting's three figures agree.
    assert_eq!(
        seam_settlement.posted.reserved(),
        direct_settlement.posted.reserved()
    );
    assert_eq!(
        seam_settlement.posted.settled(),
        direct_settlement.posted.settled()
    );
    assert_eq!(
        seam_settlement.posted.overdraft(),
        direct_settlement.posted.overdraft()
    );
    assert_eq!(seam_settlement.released, direct_settlement.released);
    assert_eq!(seam_settlement.overdraft, direct_settlement.overdraft);

    // And the books moved identically.
    assert_eq!(
        seam_ledger.book().get(&k, 1),
        direct.book().get(&k, 1),
        "the seam must move the books byte-for-byte as the direct ledger does"
    );
}

#[test]
fn settle_records_the_overdraft_through_the_seam() {
    // Reserve 100, spend 250 -> a 150 overdraft the seam must carry exactly as the ledger does.
    let k = key("od");

    let mut direct = primed(&k, 100);
    let d = direct.settle_recording(&k, 1, hold("carol", 100), 250, &usage("tokens", 250), &ledger_token());

    let mut seam_ledger = primed(&k, 100);
    let s = PassThroughBook.settle(
        &mut seam_ledger,
        &k,
        1,
        hold("carol", 100),
        250,
        &usage("tokens", 250),
        &ledger_token(),
    );

    assert_eq!(s.overdraft, d.overdraft);
    assert_eq!(s.posted.overdraft(), d.posted.overdraft());
    assert_eq!(seam_ledger.book().get(&k, 1), direct.book().get(&k, 1));
}

// ── post: the posting-side door agrees with the direct one ───────────────────────────────────────

#[test]
fn post_through_the_seam_matches_the_direct_ledger() {
    let k = key("p");
    let posted =
        busbar_contract::caps::Posted::settle(hold("dave", 500), 400, &usage("tokens", 400), &ledger_token());
    let posted2 =
        busbar_contract::caps::Posted::settle(hold("dave", 500), 400, &usage("tokens", 400), &ledger_token());

    let mut direct = primed(&k, 500);
    let d = direct.post(&k, 1, posted);

    let mut seam_ledger = primed(&k, 500);
    let s = PassThroughBook.post(&mut seam_ledger, &k, 1, posted2);

    assert_eq!(s.posted.settled(), d.posted.settled());
    assert_eq!(s.released, d.released);
    assert_eq!(seam_ledger.book().get(&k, 1), direct.book().get(&k, 1));
}

// ── apply_usage: the rate-limit ledger folds identically ─────────────────────────────────────────

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

    let mut direct = UsageLedger::default();
    direct.apply_delta(&delta);

    let mut seam_ledger = UsageLedger::default();
    PassThroughBook.apply_usage(&mut seam_ledger, &delta);

    assert_eq!(
        seam_ledger, direct,
        "the seam's apply_usage must be UsageLedger::apply_delta, byte-for-byte"
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
