// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::count::{Count, CountError};
use busbar_contract::records::{
    MeteringDelta, MeteringRow, ModelTokens, ModelTokensDelta, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn ledger(amount: i128) -> UsageLedger {
    UsageLedger {
        requests: u64::MAX,
        billable_requests: u64::MAX,
        models: vec![ModelTokens {
            scale: 6,
            model: "m".into(),
            usage_units: BTreeMap::from([("input".into(), amount)]),
        }],
    }
}

fn delta(amount: i128) -> UsageDelta {
    UsageDelta {
        requests: 0,
        billable_requests: 0,
        models: vec![ModelTokensDelta {
            scale: 6,
            model: "m".into(),
            usage_units: BTreeMap::from([("input".into(), amount)]),
        }],
    }
}

fn metering(amount: i128) -> MeteringRow {
    MeteringRow {
        scale: 6,
        key_id: "key".into(),
        model: "m".into(),
        provider: "provider".into(),
        tokens_input: amount,
        tokens_output: amount,
        tokens_cache_read: amount,
        tokens_cache_write: amount,
        requests: u64::MAX,
        billable_requests: u64::MAX,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), amount)]),
    }
}

#[test]
fn fullrange_numeric_wire_roundtrips_through_json_values() {
    for amount in [
        i128::from(i64::MAX) + 1,
        i128::from(u64::MAX) + 1,
        i128::MAX,
    ] {
        let original = ledger(amount);
        let bytes = serde_json::to_vec(&original).unwrap();
        assert!(String::from_utf8(bytes.clone())
            .unwrap()
            .contains(&format!("\"input\":{amount}")));
        assert_eq!(
            serde_json::from_slice::<UsageLedger>(&bytes).unwrap(),
            original
        );
        assert_eq!(
            serde_json::from_value::<UsageLedger>(serde_json::to_value(&original).unwrap())
                .unwrap(),
            original
        );
        assert_eq!(
            original.models[0].counts().unwrap()["input"],
            Count::from_micros(amount)
        );
        let row = metering(amount);
        assert_eq!(
            serde_json::from_value::<MeteringRow>(serde_json::to_value(&row).unwrap()).unwrap(),
            row
        );
    }
    for amount in [i128::MIN, i128::MAX] {
        let original = delta(amount);
        let bytes = serde_json::to_vec(&original).unwrap();
        assert_eq!(
            serde_json::from_slice::<UsageDelta>(&bytes).unwrap(),
            original
        );
        assert_eq!(
            serde_json::from_value::<UsageDelta>(serde_json::to_value(&original).unwrap()).unwrap(),
            original
        );
    }
}

#[test]
fn fullrange_usage_add_is_exact_and_overflow_is_atomic() {
    let mut row = ledger(i128::MAX - 1);
    row.checked_apply_delta(&delta(1)).unwrap();
    assert_eq!(row, ledger(i128::MAX));
    let before = row.clone();
    let mut overflow = delta(1);
    overflow.requests = -1;
    assert_eq!(
        row.checked_apply_delta(&overflow),
        Err(CountError::Overflow)
    );
    assert_eq!(row, before);
    row.checked_apply_delta(&delta(-i128::MAX)).unwrap();
    assert_eq!(row, ledger(0));
    // Ordinary refunds retain their established floor-at-zero behavior, even for MIN.
    row.checked_apply_delta(&delta(i128::MIN)).unwrap();
    assert_eq!(row, ledger(0));
}

#[test]
fn fullrange_legacy_conversion_and_negative_raw_counts_refuse_atomically() {
    let mut row = ledger(i128::MAX / 1_000_000);
    row.models[0].scale = 0;
    row.normalize_scale6().unwrap();
    assert_eq!(
        row.models[0].usage_units["input"],
        i128::MAX / 1_000_000 * 1_000_000
    );
    for amount in [i128::MAX / 1_000_000 + 1, -1] {
        let mut row = ledger(amount);
        row.models[0].scale = 0;
        let before = row.clone();
        assert!(row.normalize_scale6().is_err());
        assert_eq!(row, before);
        assert!(row.models[0].counts().is_err());
    }
    let mut signed = delta(i128::MIN);
    signed.normalize_scale6().unwrap();
    signed.models[0].scale = 0;
    let before = signed.clone();
    assert_eq!(signed.normalize_scale6(), Err(CountError::OutOfRange));
    assert_eq!(signed, before);
}

#[test]
fn fullrange_metering_add_checks_all_columns_and_open_counts() {
    let make_delta = |amount| {
        let mut wire = serde_json::to_value(metering(amount)).unwrap();
        wire["bucket"] = 0.into();
        serde_json::from_value::<MeteringDelta>(wire).unwrap()
    };
    let mut row = metering(i128::MAX - 1);
    row.checked_add_delta(&make_delta(1)).unwrap();
    assert_eq!(row, metering(i128::MAX));
    let before = row.clone();
    assert_eq!(
        row.checked_add_delta(&make_delta(1)),
        Err(CountError::Overflow)
    );
    assert_eq!(row, before);
    assert_eq!(
        row.checked_add_delta(&make_delta(-1)),
        Err(CountError::Negative)
    );
    assert_eq!(row, before);
    let mut open_overflow = make_delta(0);
    open_overflow.usage_units.insert("audio_seconds".into(), 1);
    assert_eq!(
        row.checked_add_delta(&open_overflow),
        Err(CountError::Overflow)
    );
    assert_eq!(row, before);
}

#[test]
fn fullrange_correction_fingerprint_and_numeric_encoding_are_lossless() {
    use busbar_contract::records::correction::{Request, UsageAddress, UsageChange, VERSION};
    use busbar_contract::records::OpId;
    let request = Request {
        version: VERSION,
        op_id: OpId::from_parts(91, 7),
        key_id: "key".into(),
        day_start: 0,
        metering: vec![metering(i128::MAX)],
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: "bucket".into(),
                window_start: 0,
            },
            expected: ledger(i128::MAX - 1),
            replacement: ledger(i128::MAX),
        }],
    };
    let bytes = request.encode().unwrap();
    assert!(String::from_utf8(bytes.clone())
        .unwrap()
        .contains(&format!("\"input\":{}", i128::MAX)));
    let decoded = Request::decode(&bytes).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(decoded.fingerprint(), request.fingerprint());
    let mut changed = request.clone();
    changed.usage[0].replacement.models[0]
        .usage_units
        .insert("input".into(), i128::MAX - 1);
    assert_ne!(changed.fingerprint(), request.fingerprint());
    changed.usage[0].replacement.models[0]
        .usage_units
        .insert("input".into(), -1);
    assert!(changed.encode().is_err());
    assert!(Request::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
}
