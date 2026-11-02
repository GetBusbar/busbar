// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::correction::{Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, RecordStore, UsageLedger, UNIT_INPUT};

const KEY: &str = "adjustment-view-key";
const LANE: &str = "adjustment-view-lane";
const ERA: u64 = 0;

fn raw(slot: &str, count: u64) -> UsageLedger {
    UsageLedger {
        models: if count == 0 {
            Vec::new()
        } else {
            vec![ModelTokens {
                model: slot.into(),
                usage_units: BTreeMap::from([(UNIT_INPUT.into(), count)]),
            }]
        },
        ..Default::default()
    }
}

fn publish(
    store: &busbar_plugin_loader::store_v3::LoadedStore,
    day: u64,
    lane: &str,
    up: u64,
    down: u64,
    op: OpId,
) {
    let slot = adjustment_slot(KEY, lane, ERA);
    let mut usage = Vec::new();
    for (bucket, count) in [(ADJUST_UP_BUCKET, up), (ADJUST_DOWN_BUCKET, down)] {
        usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: bucket.into(),
                window_start: day,
            },
            expected: store.get_usage(bucket, day).expect("raw prestate"),
            replacement: raw(&slot, count),
        });
    }
    usage.sort_by(|a, b| a.address.cmp(&b.address));
    let request = Request {
        version: busbar_contract::records::correction::VERSION,
        op_id: op,
        key_id: KEY.into(),
        day_start: day,
        metering: Vec::new(),
        usage,
    };
    assert_eq!(
        store
            .apply_usage_correction(&request)
            .expect("exact raw publication"),
        Decision::Applied
    );
}

fn state() -> (
    Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    GovState,
    u64,
) {
    let store = crate::real_store::store();
    store
        .put_key(&VirtualKey {
            id: KEY.into(),
            enabled: true,
            ..Default::default()
        })
        .expect("key");
    let gov = GovState::new(store.clone(), None).expect("governance");
    let day = crate::governance::metering_bucket(crate::store::now());
    (store, gov, day)
}

#[test]
fn raw_adjustment_view_preserves_the_full_difference_of_unsigned_rows() {
    let minimum_signed_magnitude = i64::MIN.unsigned_abs();
    for (up, down, expected) in [
        (u64::MAX, 0, i128::from(u64::MAX)),
        (0, u64::MAX, -i128::from(u64::MAX)),
        (0, minimum_signed_magnitude, i128::from(i64::MIN)),
        (u64::MAX, u64::MAX - 1, 1),
        (u64::MAX - 1, u64::MAX, -1),
    ] {
        let (store, gov, day) = state();
        publish(&store, day, LANE, up, down, OpId([1; 16]));
        assert_eq!(
            gov.usage_adjustments(day).expect("full range view"),
            vec![UsageAdjustment {
                key_id: KEY.into(),
                lane: LANE.into(),
                era: ERA,
                entry_id: None,
                delta: BTreeMap::from([(UNIT_INPUT.into(), expected)]),
            }]
        );
        assert!(gov
            .usage_adjustments(day - crate::governance::METERING_BUCKET_SECS)
            .expect("other day")
            .is_empty());
    }
}

#[test]
fn cumulative_raw_rows_can_reverse_sign_and_cancel_without_losing_the_slot() {
    let (store, gov, day) = state();
    assert!(gov.usage_adjustments(day).expect("empty rows").is_empty());
    let up = i64::MAX as u64;
    publish(&store, day, LANE, up, 0, OpId([1; 16]));
    assert_eq!(
        gov.usage_adjustments(day).expect("positive")[0].delta[UNIT_INPUT],
        i128::from(up)
    );
    publish(&store, day, LANE, up, u64::MAX, OpId([2; 16]));
    assert_eq!(
        gov.usage_adjustments(day).expect("reversed")[0].delta[UNIT_INPUT],
        i128::from(i64::MIN)
    );
    publish(&store, day, LANE, u64::MAX, u64::MAX, OpId([3; 16]));
    assert!(gov.usage_adjustments(day).expect("canceled").is_empty());
}

#[test]
fn an_empty_model_name_is_a_valid_adjustment_lane() {
    let (store, gov, day) = state();
    publish(&store, day, "", u64::MAX, 0, OpId([1; 16]));
    assert_eq!(
        gov.usage_adjustments(day).expect("empty lane"),
        vec![UsageAdjustment {
            key_id: KEY.into(),
            lane: String::new(),
            era: ERA,
            entry_id: None,
            delta: BTreeMap::from([(UNIT_INPUT.into(), i128::from(u64::MAX))]),
        }]
    );
}
