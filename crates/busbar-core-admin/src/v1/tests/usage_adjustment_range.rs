// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::{fold_adjustments, AdminService};
use crate::v1::contract::{AdminError, UsageView};
use busbar_contract::records::{MeteringDelta, MeteringRow, RecordStore, VirtualKey, UNIT_INPUT};
use busbar_kernel::cost::{CostModel, History, RateCard, TierRates};
use busbar_kernel::governance::{Adjustment, GovState, UsageAdjustment};
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use std::collections::BTreeMap;
use std::sync::Arc;

const KEY: &str = "adjustment-range-key";
const LANE: &str = "adjustment-range-model";
const PROVIDER: &str = "adjustment-range-provider";
const DISPLAY_NAME: &str = "adjustment range";
const OTHER_ERA: u64 = 1;

fn zero_cost() -> CostModel {
    let rates = BTreeMap::from([(
        LANE.into(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 0.0,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&rates), 0, &BTreeMap::new())
}

struct Fixture {
    gov: Arc<GovState>,
    key: VirtualKey,
    cost: CostModel,
    history: Arc<History>,
    day: u64,
    epoch: u64,
    era: u64,
}

impl Fixture {
    fn new(initial: u64) -> Self {
        let store = Arc::new(MemoryStore::new());
        let key = VirtualKey {
            id: KEY.into(),
            name: DISPLAY_NAME.into(),
            enabled: true,
            ..Default::default()
        };
        store.put_key(&key).expect("key");
        let epoch = busbar_kernel::store::now_ms();
        let now = std::time::Duration::from_millis(epoch).as_secs();
        let era = busbar_kernel::rate_apply::effective_from_at(epoch);
        let day = busbar_kernel::governance::metering_bucket(now);
        store
            .add_metering(&MeteringDelta {
                key_id: KEY.into(),
                bucket: day,
                model: LANE.into(),
                provider: PROVIDER.into(),
                tokens_input: initial,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: era,
                usage_units: BTreeMap::new(),
            })
            .expect("metering row");

        let cost = zero_cost();
        let card = RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: Some(0),
                    ..Default::default()
                },
            )]),
            0,
        );
        let history = Arc::new(History::opening(card, 0));
        let gov = Arc::new(GovState::new(store, None).expect("governance"));
        gov.record_usage(
            &cost,
            &key,
            "",
            LANE,
            &BTreeMap::from([(UNIT_INPUT.into(), initial)]),
            now,
        );
        Self {
            gov,
            key,
            cost,
            history,
            day,
            epoch,
            era,
        }
    }

    fn adjust(&self, change: i64) {
        let delta = BTreeMap::from([(UNIT_INPUT.into(), change)]);
        self.gov
            .adjust_usage(
                &self.cost,
                &Adjustment {
                    key_id: &self.key.id,
                    pool: "",
                    model: LANE,
                    entry_era: self.era,
                    entry_id: None,
                    card_epoch_ms: self.epoch,
                    delta: &delta,
                    now: busbar_kernel::store::now(),
                },
            )
            .expect("store accepts exact correction")
            .expect("valid correction");
    }

    async fn read(&self) -> Result<UsageView, AdminError> {
        let app = crate::new_test_app()
            .governance(self.gov.clone())
            .cost(zero_cost())
            .build();
        AdminService::new(app)
            .with_rate_history(self.history.clone())
            .get_usage(Some(self.day), None)
            .await
    }
}

fn assert_totals(view: &UsageView, count: u64) {
    assert_eq!(view.total.tokens_input, count);
    assert_eq!(view.total.spend_micros, 0);
    assert_eq!(view.by_model.len(), 1);
    assert_eq!(view.by_model[0].usage.tokens_input, count);
    assert_eq!(view.by_key.len(), 1);
    assert_eq!(view.by_key[0].usage.tokens_input, count);
    let json = serde_json::to_value(view).expect("usage wire view");
    assert_eq!(json["total"]["tokens_input"].as_u64(), Some(count));
}

#[tokio::test]
async fn cumulative_positive_corrections_reach_u64_max_in_every_admin_total() {
    let fixture = Fixture::new(0);
    for change in [i64::MAX, i64::MAX, 1] {
        fixture.adjust(change);
    }
    let adjustments = fixture
        .gov
        .usage_adjustments(fixture.day)
        .expect("wide view");
    assert_eq!(adjustments[0].delta[UNIT_INPUT], i128::from(u64::MAX));
    assert_totals(
        &fixture.read().await.expect("full range admin read"),
        u64::MAX,
    );
}

#[tokio::test]
async fn minimum_signed_delta_and_full_unsigned_downward_net_keep_their_magnitudes() {
    let fixture = Fixture::new(u64::MAX);
    fixture.adjust(i64::MIN);
    assert_eq!(
        fixture
            .gov
            .usage_adjustments(fixture.day)
            .expect("minimum signed view")[0]
            .delta[UNIT_INPUT],
        i128::from(i64::MIN)
    );
    assert_totals(
        &fixture.read().await.expect("minimum signed admin read"),
        i64::MAX as u64,
    );
    fixture.adjust(-i64::MAX);
    assert_eq!(
        fixture
            .gov
            .usage_adjustments(fixture.day)
            .expect("unsigned magnitude view")[0]
            .delta[UNIT_INPUT],
        -i128::from(u64::MAX)
    );
    assert_totals(
        &fixture.read().await.expect("fully corrected admin read"),
        0,
    );
}

#[tokio::test]
async fn reversal_changes_the_sign_without_repricing_the_historical_row() {
    let fixture = Fixture::new(1);
    fixture.adjust(i64::MAX);
    assert_totals(
        &fixture.read().await.expect("upward read"),
        i64::MIN.unsigned_abs(),
    );
    fixture.adjust(i64::MIN);
    let adjustments = fixture
        .gov
        .usage_adjustments(fixture.day)
        .expect("reversed view");
    assert_eq!(adjustments[0].era, fixture.era);
    assert_eq!(adjustments[0].delta[UNIT_INPUT], -1);
    assert_totals(&fixture.read().await.expect("reversed read"), 0);
}

fn row(model: &str, era: u64, count: u64) -> MeteringRow {
    MeteringRow {
        key_id: KEY.into(),
        model: model.into(),
        provider: PROVIDER.into(),
        tokens_input: count,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: era,
        usage_units: BTreeMap::new(),
    }
}

fn adjustment(lane: &str, delta: i128) -> UsageAdjustment {
    UsageAdjustment {
        key_id: KEY.into(),
        lane: lane.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(UNIT_INPUT.into(), delta)]),
    }
}

#[test]
fn adjustments_at_one_timestamp_only_change_rows_of_their_recorded_entry() {
    let first_history = History::opening(zero_cost().card().clone(), 0);
    let second_history = History::opening(zero_cost().card().clone(), 1);
    let first_id = first_history.entries()[0].id();
    let second_id = second_history.entries()[0].id();
    assert_ne!(first_id, second_id);
    let mut first = row(LANE, 0, 7);
    first.pricing_version = first_id.metering_version();
    let mut second = row(LANE, 0, 9);
    second.pricing_version = second_id.metering_version();
    let mut rows = vec![second, row(LANE, 0, 11), first];
    let mut exact = adjustment(LANE, -2);
    exact.entry_id = Some(first_id);
    fold_adjustments(&mut rows, &[exact]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [9, 11, 5]
    );
    fold_adjustments(&mut rows, &[adjustment(LANE, 3)]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [9, 14, 5]
    );
}

#[test]
fn full_unsigned_negative_fold_spans_rows_and_keeps_other_eras_unchanged() {
    let mut rows = vec![
        row(LANE, 0, i64::MIN.unsigned_abs()),
        row(LANE, 0, i64::MAX as u64),
        row(LANE, OTHER_ERA, 1),
    ];
    fold_adjustments(&mut rows, &[adjustment(LANE, -i128::from(u64::MAX))])
        .expect("distributed subtraction");
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        vec![0, 0, 1]
    );
}

#[test]
fn empty_model_fold_keeps_full_unsigned_counts_and_rejects_out_of_range_magnitudes() {
    let mut rows = vec![row("", 0, 0)];
    fold_adjustments(&mut rows, &[adjustment("", i128::from(u64::MAX))]).expect("empty model lane");
    assert_eq!(rows[0].tokens_input, u64::MAX);
    let unchanged = rows.clone();
    for invalid in [
        i128::from(u64::MAX) + 1,
        -(i128::from(u64::MAX) + 1),
        i128::MIN,
    ] {
        assert!(fold_adjustments(&mut rows, &[adjustment("", invalid)]).is_err());
        assert_eq!(
            rows, unchanged,
            "magnitude refusal must not truncate or touch a column"
        );
    }
    assert!(fold_adjustments(&mut rows, &[adjustment("", 1)]).is_err());
    assert_eq!(
        rows, unchanged,
        "checked positive overflow preserves the column"
    );
}
