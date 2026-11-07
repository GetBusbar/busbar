// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::CoreStore;
use busbar_contract::records::OpId;
use busbar_contract::records::correction::{Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, UNIT_INPUT, UsageLedger};

const KEY: &str = "adjustment-view-key";
const LANE: &str = "adjustment-view-lane";
const ERA: u64 = 0;

fn raw(slot: &str, count: u64) -> UsageLedger {
    UsageLedger {
        models: if count == 0 {
            Vec::new()
        } else {
            vec![ModelTokens {
                scale: 0,
                model: slot.into(),
                usage_units: BTreeMap::from([(UNIT_INPUT.into(), i128::from(count))]),
            }]
        },
        ..Default::default()
    }
}

async fn publish(store: &CoreStore, day: u64, lane: &str, up: u64, down: u64, op: OpId) {
    let slot = adjustment_slot(KEY, lane, ERA);
    let mut usage = Vec::new();
    for (bucket, count) in [(ADJUST_UP_BUCKET, up), (ADJUST_DOWN_BUCKET, down)] {
        usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: bucket.into(),
                window_start: day,
            },
            expected: store
                .ledger()
                .get_usage(bucket, day)
                .await
                .expect("raw prestate"),
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
            .ledger()
            .apply_usage_correction(&request)
            .await
            .expect("exact raw publication"),
        Decision::Applied
    );
}

async fn state() -> (Arc<CoreStore>, GovState, u64) {
    let store = crate::real_store::core().await;
    store
        .identity()
        .put_key(&VirtualKey {
            id: KEY.into(),
            enabled: true,
            ..Default::default()
        })
        .await
        .expect("key");
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .expect("governance");
    let day = crate::governance::metering_bucket(crate::store::now());
    (store, gov, day)
}

#[tokio::test]
async fn raw_adjustment_view_preserves_the_full_difference_of_unsigned_rows() {
    let minimum_signed_magnitude = i64::MIN.unsigned_abs();
    for (up, down, expected) in [
        (u64::MAX, 0, i128::from(u64::MAX)),
        (0, u64::MAX, -i128::from(u64::MAX)),
        (0, minimum_signed_magnitude, i128::from(i64::MIN)),
        (u64::MAX, u64::MAX - 1, 1),
        (u64::MAX - 1, u64::MAX, -1),
    ] {
        let (store, gov, day) = state().await;
        publish(&store, day, LANE, up, down, OpId([1; 16])).await;
        assert_eq!(
            gov.usage_adjustments_async(day)
                .await
                .expect("full range view"),
            vec![UsageAdjustment {
                key_id: KEY.into(),
                lane: LANE.into(),
                era: ERA,
                entry_id: None,
                delta: BTreeMap::from([(UNIT_INPUT.into(), expected)]),
            }]
        );
        assert!(
            gov.usage_adjustments_async(day - crate::governance::METERING_BUCKET_SECS)
                .await
                .expect("other day")
                .is_empty()
        );
    }
}

#[tokio::test]
async fn cumulative_raw_rows_can_reverse_sign_and_cancel_without_losing_the_slot() {
    let (store, gov, day) = state().await;
    assert!(
        gov.usage_adjustments_async(day)
            .await
            .expect("empty rows")
            .is_empty()
    );
    let up = i64::MAX as u64;
    publish(&store, day, LANE, up, 0, OpId([1; 16])).await;
    assert_eq!(
        gov.usage_adjustments_async(day).await.expect("positive")[0].delta[UNIT_INPUT],
        i128::from(up)
    );
    publish(&store, day, LANE, up, u64::MAX, OpId([2; 16])).await;
    assert_eq!(
        gov.usage_adjustments_async(day).await.expect("reversed")[0].delta[UNIT_INPUT],
        i128::from(i64::MIN)
    );
    publish(&store, day, LANE, u64::MAX, u64::MAX, OpId([3; 16])).await;
    assert!(
        gov.usage_adjustments_async(day)
            .await
            .expect("canceled")
            .is_empty()
    );
}

#[tokio::test]
async fn an_empty_model_name_is_a_valid_adjustment_lane() {
    let (store, gov, day) = state().await;
    publish(&store, day, "", u64::MAX, 0, OpId([1; 16])).await;
    assert_eq!(
        gov.usage_adjustments_async(day).await.expect("empty lane"),
        vec![UsageAdjustment {
            key_id: KEY.into(),
            lane: String::new(),
            era: ERA,
            entry_id: None,
            delta: BTreeMap::from([(UNIT_INPUT.into(), i128::from(u64::MAX))]),
        }]
    );
}
