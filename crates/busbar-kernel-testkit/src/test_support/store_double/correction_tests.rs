// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::{OpRefused, SyncStore};
use busbar_contract::abi::store::OpId;
use busbar_contract::records::correction::{Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, ModelTokensDelta, UNIT_INPUT};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

const KEY_ID: &str = "correction-key";
const GROUP_BUCKET: &str = "correction-group";
const MODEL: &str = "correction-model";
const PROVIDER: &str = "correction-provider";
const OPEN_UNIT: &str = "tool_calls";
const UNIT: &str = UNIT_INPUT;
const UTC_DAY_SECS: u64 = 86_400;
const MILLIS_PER_SECOND: u64 = 1000;
const BEFORE: u64 = 100;
const AFTER: u64 = 40;
const ACCRUAL: u64 = 7;
const FIRST_OP: OpId = OpId([1; 16]);
const SECOND_OP: OpId = OpId([2; 16]);

fn ledger(count: u64) -> UsageLedger {
    UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: MODEL.into(),
            usage_units: BTreeMap::from([(UNIT.into(), count)]),
        }],
    }
}

fn seeded() -> (MemoryStore, Request) {
    let store = MemoryStore::new();
    Store::put_key(
        &store,
        &VirtualKey {
            id: KEY_ID.into(),
            enabled: true,
            ..Default::default()
        },
    )
    .expect("live correction key");
    let window = now();
    let day = window / UTC_DAY_SECS * UTC_DAY_SECS;
    Store::add_metering(
        &store,
        &MeteringDelta {
            key_id: KEY_ID.into(),
            bucket: day,
            model: MODEL.into(),
            provider: PROVIDER.into(),
            tokens_input: BEFORE,
            tokens_output: 3,
            tokens_cache_read: 2,
            tokens_cache_write: 1,
            requests: 2,
            billable_requests: 1,
            key_group_at_use: GROUP_BUCKET.into(),
            pricing_version: "historical-card".into(),
            priced_from_ms: day * MILLIS_PER_SECOND,
            usage_units: BTreeMap::from([(OPEN_UNIT.into(), 5)]),
        },
    )
    .expect("complete metering row");
    let mut usage = Vec::new();
    for bucket in [GROUP_BUCKET, KEY_ID] {
        Store::put_usage(&store, bucket, window, &ledger(BEFORE)).expect("seed usage");
        usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: bucket.into(),
                window_start: window,
            },
            expected: ledger(BEFORE),
            replacement: ledger(AFTER),
        });
    }
    let request = Request {
        version: correction::VERSION,
        op_id: FIRST_OP,
        key_id: KEY_ID.into(),
        day_start: day,
        metering: Store::list_metering(&store, day).expect("metering"),
        usage,
    };
    request.validate().expect("canonical fixture");
    (store, request)
}

fn read(store: &MemoryStore, change: &UsageChange) -> UsageLedger {
    Store::get_usage(
        store,
        &change.address.bucket_id,
        change.address.window_start,
    )
    .expect("usage")
}

#[test]
fn every_expected_row_is_checked_before_any_replacement_or_receipt() {
    let (store, request) = seeded();
    let last = request.usage.last().expect("second row");
    Store::put_usage(
        &store,
        &last.address.bucket_id,
        last.address.window_start,
        &ledger(ACCRUAL),
    )
    .expect("concurrent writer");
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("decision"),
        Decision::ConditionConflict
    );
    assert_eq!(read(&store, &request.usage[0]), ledger(BEFORE));
    assert_eq!(read(&store, last), ledger(ACCRUAL));
    Store::put_usage(
        &store,
        &last.address.bucket_id,
        last.address.window_start,
        &last.expected,
    )
    .expect("restore comparison");
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("retry"),
        Decision::Applied
    );
    for change in &request.usage {
        assert_eq!(read(&store, change), change.replacement);
    }
}

#[test]
fn metering_compares_the_complete_selection_and_all_historical_fields() {
    let (store, request) = seeded();
    let mutations: &[fn(&mut MeteringRow)] = &[
        |row| row.model.push('x'),
        |row| row.provider.push('x'),
        |row| row.tokens_input += 1,
        |row| row.tokens_output += 1,
        |row| row.tokens_cache_read += 1,
        |row| row.tokens_cache_write += 1,
        |row| row.requests += 1,
        |row| row.billable_requests += 1,
        |row| row.key_group_at_use.push('x'),
        |row| row.pricing_version.push('x'),
        |row| row.priced_from_ms += 1,
        |row| {
            row.usage_units.insert(OPEN_UNIT.into(), BEFORE);
        },
    ];
    for mutate in mutations {
        let mut changed = request.clone();
        mutate(&mut changed.metering[0]);
        assert_eq!(
            Store::apply_usage_correction(&store, &changed).expect("decision"),
            Decision::ConditionConflict
        );
    }
    let mut omitted = request.clone();
    omitted.metering.clear();
    assert_eq!(
        Store::apply_usage_correction(&store, &omitted).expect("omitted row"),
        Decision::ConditionConflict
    );
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("no failed receipt"),
        Decision::Applied
    );
}

#[test]
fn receipt_replay_precedes_changed_rows_and_revocation_but_rejects_changed_body() {
    let (store, request) = seeded();
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("apply"),
        Decision::Applied
    );
    Store::delete_key(&store, KEY_ID).expect("revoke after lost reply");
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("receipt"),
        Decision::Applied
    );
    assert_eq!(read(&store, &request.usage[0]), ledger(AFTER));
    assert_eq!(
        read(&store, &request.usage[1]),
        UsageLedger::default(),
        "replay must not resurrect deleted usage"
    );
    let mut changed = request.clone();
    changed.usage[0].replacement = ledger(ACCRUAL);
    assert_eq!(
        SyncStore::apply_usage_correction(&store, &changed),
        Err(OpRefused::Conflict)
    );
    changed.op_id = SECOND_OP;
    assert_eq!(
        Store::apply_usage_correction(&store, &changed).expect("new op"),
        Decision::ConditionConflict
    );
}

#[test]
fn two_nodes_cannot_both_accept_the_same_expected_usage() {
    let (store, request) = seeded();
    let store = Arc::new(store);
    let start = Arc::new(Barrier::new(2));
    let answers = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for op_id in [FIRST_OP, SECOND_OP] {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            let mut candidate = request.clone();
            candidate.op_id = op_id;
            handles.push(scope.spawn(move || {
                start.wait();
                Store::apply_usage_correction(store.as_ref(), &candidate).expect("decision")
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("node"))
            .collect::<Vec<_>>()
    });
    assert_eq!(
        answers
            .iter()
            .filter(|answer| **answer == Decision::Applied)
            .count(),
        1
    );
    assert_eq!(
        answers
            .iter()
            .filter(|answer| **answer == Decision::ConditionConflict)
            .count(),
        1
    );
    for change in &request.usage {
        assert_eq!(read(&store, change), change.replacement);
    }
}

#[test]
fn concurrent_accrual_is_either_compared_or_preserved_after_acceptance() {
    let (store, request) = seeded();
    let start = Barrier::new(2);
    let outcome = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            start.wait();
            Store::add_usage(
                &store,
                KEY_ID,
                request.usage[1].address.window_start,
                &UsageDelta {
                    requests: 0,
                    billable_requests: 0,
                    models: vec![ModelTokensDelta {
                        model: MODEL.into(),
                        usage_units: BTreeMap::from([(UNIT.into(), ACCRUAL as i64)]),
                    }],
                },
            )
            .expect("accrual");
        });
        start.wait();
        let outcome = Store::apply_usage_correction(&store, &request).expect("decision");
        writer.join().expect("writer");
        outcome
    });
    let expected = match outcome {
        Decision::Applied => AFTER,
        Decision::ConditionConflict => BEFORE,
    };
    assert_eq!(read(&store, &request.usage[1]), ledger(expected + ACCRUAL));
    assert_eq!(read(&store, &request.usage[0]), ledger(expected));
}

#[test]
fn canonical_prestate_and_large_unsigned_counts_remain_exact() {
    let (store, mut request) = seeded();
    let large = u64::MAX - BEFORE;
    request.usage[0].expected = ledger(large);
    request.usage[0].replacement = ledger(large - AFTER);
    let mut stored = request.usage[0].expected.clone();
    stored.models.push(ModelTokens {
        model: "zero-model".into(),
        usage_units: BTreeMap::from([(UNIT.into(), 0)]),
    });
    stored.models.reverse();
    Store::put_usage(
        &store,
        GROUP_BUCKET,
        request.usage[0].address.window_start,
        &stored,
    )
    .expect("noncanonical legacy row");
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("canonical comparison"),
        Decision::Applied
    );
    assert_eq!(
        read(&store, &request.usage[0]),
        request.usage[0].replacement
    );
}

#[test]
fn absent_adjustment_rows_compare_empty_and_commit_with_the_ordinary_rows() {
    let (store, mut request) = seeded();
    let adjustment = UsageChange {
        address: UsageAddress {
            bucket_id: correction::ADJUST_DOWN_BUCKET.into(),
            window_start: request.usage[0].address.window_start,
        },
        expected: UsageLedger::default(),
        replacement: ledger(BEFORE - AFTER),
    };
    request.usage.insert(0, adjustment);
    request
        .validate()
        .expect("reserved adjustment precedes fixture addresses");
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("apply"),
        Decision::Applied
    );
    for change in &request.usage {
        assert_eq!(read(&store, change), change.replacement);
    }
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("replay"),
        Decision::Applied
    );
    for change in &request.usage {
        assert_eq!(read(&store, change), change.replacement);
    }
}

#[test]
fn reserved_rows_reject_a_whole_ordinary_batch_without_spending_its_identity() {
    let (store, request) = seeded();
    let window = request.usage[0].address.window_start;
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: Vec::new(),
    };
    let mixed = [
        (KEY_ID, window, delta.clone()),
        (correction::ADJUST_UP_BUCKET, window, delta.clone()),
    ];
    assert!(matches!(
        SyncStore::add_usage_batch(&store, FIRST_OP, &mixed),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(read(&store, &request.usage[1]), ledger(BEFORE));
    assert!(Store::put_usage(
        &store,
        correction::ADJUST_DOWN_BUCKET,
        window,
        &ledger(BEFORE)
    )
    .is_err());
    assert!(Store::add_usage(&store, correction::ADJUST_UP_BUCKET, window, &delta).is_err());
    assert_eq!(
        Store::apply_usage_correction(&store, &request).expect("unused identity"),
        Decision::Applied
    );
}
