// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::UNIT_INPUT;
use busbar_kernel::governance::{metering_bucket, SECS_PER_DAY, WINDOW_DAY};
use busbar_kernel_ledger::cost::RawRateEra;

const RAW_KEY: &str = "vk_raw_provenance";
const RAW_MODEL: &str = "m";
const RAW_PROVIDER: &str = "provider";
const RAW_COUNT: u64 = 100_000;
const OPENING_FEE: i64 = 5;
const FIRST_FEE: i64 = 7;
const SECOND_FEE: i64 = 11;
const TOTAL_CENTS: i64 = 83;
const OPEN_UNIT: &str = "bytes";
const OPEN_UNIT_MICROS: u64 = 2;

fn raw_cost(rate: f64, fee: i64) -> CostModel {
    let mut groups = BTreeMap::new();
    groups.insert(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![busbar_kernel::config::groups::LimitCfg {
                selected: None,
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount: 1_000,
                per: Some(busbar_kernel::config::groups::LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    );
    let card = BTreeMap::from([(
        RAW_MODEL.to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: rate,
            units: BTreeMap::from([(
                OPEN_UNIT.to_string(),
                busbar_kernel_ledger::cost::UnitRate::from_whole_micros(OPEN_UNIT_MICROS).unwrap(),
            )]),
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), fee, &groups)
}

fn raw_card(rate: f64, fee: i64) -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(RAW_MODEL, UNIT_INPUT), rate),
            (
                LaneClass::new(RAW_MODEL, OPEN_UNIT),
                OPEN_UNIT_MICROS as f64,
            ),
        ],
        fee,
    )
}

fn confirm(holder: &Holder, at: u64, rate: f64, fee: i64, epoch: u64) -> RawRateEra {
    let mut pinned = holder.0.lock().unwrap();
    let mut history = History::clone(&pinned);
    history.append(CardEntryDraft {
        effective_from: at,
        effective_until: None,
        card: raw_card(rate, fee),
        appended_at: at,
        author: Author::Config {
            policy_epoch: epoch,
        },
    });
    let entry = history.entries().last().unwrap();
    let era = RawRateEra::entry(entry.effective_from(), entry.id());
    *pinned = Arc::new(history);
    era
}

#[tokio::test]
async fn malformed_versioned_budget_provenance_refuses_instead_of_repricing_as_legacy() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let (_holder, _serial) = holder_opening(raw_card(1.0, 0)).await;
    let store = real_store::core().await;
    let key = team_key(store.as_ref(), "vk_bad_raw_provenance").await;
    store
        .ledger()
        .put_usage(
            &key.id,
            0,
            &UsageLedger {
                models: vec![ModelTokens {
                    scale: 0,
                    model: RAW_MODEL.into(),
                    usage_units: input(RAW_COUNT)
                        .into_iter()
                        .map(|(class, count)| (class, i128::from(count)))
                        .collect(),
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let digest = busbar_contract::crypto::sha256(key.id.as_bytes());
    let dated_bucket = format!("e:{}", hex::encode(&digest[..16]));
    store
        .ledger()
        .put_usage(
            &dated_bucket,
            0,
            &UsageLedger {
                models: vec![ModelTokens {
                    scale: 0,
                    model: "busbar.raw-era.v1:0:invalid\u{1f}m".into(),
                    usage_units: input(RAW_COUNT)
                        .into_iter()
                        .map(|(class, count)| (class, i128::from(count)))
                        .collect(),
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let cost = raw_cost(1.0, 0);
    let error = gov
        .usage_for_async(&cost, &key.id, busbar_kernel::store::now())
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("malformed versioned raw rate provenance"));
    assert!(gov
        .hydrate_budgets_async(&cost, busbar_kernel::store::now())
        .await
        .is_err());
}

