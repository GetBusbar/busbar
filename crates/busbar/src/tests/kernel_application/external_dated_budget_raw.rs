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

#[tokio::test]
async fn open_route_cancel_and_session_cleanup_keep_the_admissions_original_entry() {
    use busbar_contract::abi::plane::UnitCount;
    use busbar_contract::caps::{CallId, OriginKind, ReasonCode};
    use busbar_contract::measurement::UNITS_REPORTED;
    use busbar_contract::plane::codes::CANCEL_OK_PARTIAL;
    use busbar_contract::UnitKey;
    use busbar_kernel::config::groups::ExhaustionMode;
    use busbar_kernel::plane_driver::{
        CancelBill, EndPost, FeeRefund, MoneySeam, PlaneMoney, UnitMoney,
    };
    use busbar_kernel::registry::Generation;
    use busbar_kernel::teller::{Ended, UnitCtx};
    struct Post;
    impl EndPost for Post {
        fn post(&self, _: &UnitCtx, _: Ended) {}
    }
    let context = |key| UnitCtx {
        call: CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    const INPUT_INDEX: u32 = 0;
    let reported = [UnitCount {
        class: INPUT_INDEX,
        source: UNITS_REPORTED,
        amount: RAW_COUNT,
    }];
    let (holder, _serial) = holder_opening(raw_card(1.0, OPENING_FEE)).await;
    holder.1.store(true, std::sync::atomic::Ordering::Relaxed);
    let store = real_store::core().await;
    let key = Arc::new(team_key(store.as_ref(), "vk_open_raw_provenance").await);
    let gov = Arc::new(GovState::new_with_core(store, None, None).await.unwrap());
    let money = PlaneMoney::new(gov.clone(), Arc::new(Post));
    let old_cost = Arc::new(raw_cost(1.0, OPENING_FEE));
    let arrived = metering_bucket(busbar_kernel::store::now()) + SECS_PER_DAY;
    let mut original = None;
    for unit in 1..=3 {
        let grant = gov.try_admit(&old_cost, &key, "", arrived).unwrap();
        original = Some(grant.charge().raw_era());
        money.open(
            UnitKey::new(unit),
            UnitMoney {
                key: key.clone(),
                cost: old_cost.clone(),
                pool: String::new(),
                lane: RAW_MODEL.to_string(),
                classes: Arc::from(vec![UNIT_INPUT.to_string()]),
                arrived,
                mode: ExhaustionMode::FinishUnit,
                fee: FeeRefund::CallerStatus,
                charge: grant.charge().clone(),
            },
        );
        money.served(&context(unit), RAW_MODEL, RAW_PROVIDER);
        money.checkpoint(&context(unit), &reported);
    }
    money.session_opened(&context(3)).unwrap();
    let current_era = confirm(
        holder,
        busbar_kernel::store::now_ms().saturating_sub(1),
        3.0,
        SECOND_FEE,
        1,
    );
    let current = raw_cost(3.0, SECOND_FEE);
    money.settle_end(UnitKey::new(1), u32::from(http::StatusCode::OK.as_u16()));
    money.cancelled(
        &context(2),
        &CancelBill {
            cause: ReasonCode::ClientGone,
            disposition: CANCEL_OK_PARTIAL,
            far_end_answered: true,
            streamed: true,
            billed: vec![(INPUT_INDEX, RAW_COUNT.into())],
            unread: None,
        },
    );
    money.settle_end(
        UnitKey::new(2),
        u32::from(http::StatusCode::SERVICE_UNAVAILABLE.as_u16()),
    );
    money.session_ended(&context(3));
    money.session_ended(&context(3));
    money.settle_end(UnitKey::new(3), u32::from(http::StatusCode::OK.as_u16()));
    accrue(&gov, &current, &key, arrived);
    assert_eq!(money.open_units(), 0);
    let usage = gov
        .usage_for_async(&current, &key.id, arrived)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.tokens, usage.requests, usage.spend_cents),
        (busbar_contract::Count::from(4 * RAW_COUNT), 4, 81)
    );
    gov.flush_budgets_final().await;
    gov.flush_metering_final().await;
    let rows = gov
        .metering_for_async(metering_bucket(arrived))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (era, requests) in [(original.unwrap(), 3), (current_era, 1)] {
        let row = rows
            .iter()
            .find(|row| row.pricing_version == era.entry_id.unwrap().metering_version())
            .unwrap();
        assert_eq!(row.requests, requests);
        assert_eq!(row.scale, busbar_contract::count::SCALE_MICRO_UNITS);
        assert_eq!(
            row.tokens_input,
            busbar_contract::Count::from(requests * RAW_COUNT).micros()
        );
    }
}

