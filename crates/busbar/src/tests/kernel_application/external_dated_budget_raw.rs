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
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount: 1_000,
                per: Some(busbar_kernel::config::groups::LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
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

fn accrue(
    gov: &GovState,
    cost: &CostModel,
    key: &VirtualKey,
    now: u64,
) -> busbar_kernel::governance::AdmitGrant {
    let grant = gov.try_admit(cost, key, "", now).unwrap();
    let units = input(RAW_COUNT);
    gov.record_usage(cost, key, "", RAW_MODEL, &units, now);
    gov.record_lane_metering_in_era(
        key,
        RAW_MODEL,
        Some(RAW_PROVIDER),
        &units,
        now,
        grant.charge().raw_era(),
    );
    grant
}

#[test]
fn exact_opening_and_same_timestamp_cards_survive_later_day_and_restart() {
    let (holder, _serial) = holder_opening(raw_card(1.0, OPENING_FEE));
    holder.1.store(true, std::sync::atomic::Ordering::Relaxed);
    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), RAW_KEY);
    let gov = GovState::new_with_signer(store.clone(), None, None).unwrap();

    let later = metering_bucket(busbar_kernel::store::now());
    let opening = raw_cost(1.0, OPENING_FEE);
    let opening_grant = accrue(&gov, &opening, &key, later);
    let opening_era = opening_grant.charge().raw_era();
    assert_eq!(opening_era.effective_from, 0);
    assert!(opening_era.entry_id.is_some());

    let shared_start = later.saturating_sub(SECS_PER_DAY) * 1_000;
    let first_era = confirm(holder, shared_start, 2.0, FIRST_FEE, 1);
    let first = raw_cost(2.0, FIRST_FEE);
    let first_grant = accrue(&gov, &first, &key, later);
    assert_eq!(first_grant.charge().raw_era(), first_era);
    assert_eq!(
        gov.usage_for(&first, &key.id, later)
            .unwrap()
            .unwrap()
            .spend_cents,
        42
    );

    let second_era = confirm(holder, shared_start, 3.0, SECOND_FEE, 2);
    let second = raw_cost(3.0, SECOND_FEE);
    accrue(&gov, &second, &key, later);
    assert_eq!(first_era.effective_from, second_era.effective_from);
    assert_ne!(first_era.entry_id, second_era.entry_id);
    let reads = |gov: &GovState| {
        let key_read = gov.usage_for(&second, &key.id, later).unwrap().unwrap();
        let group = &second.groups()[0].buckets[0];
        let group_read = gov
            .derived_bucket_usage(&second, &group.bucket_id, WINDOW_DAY, true, later)
            .unwrap();
        assert_eq!(key_read, group_read);
        (key_read.tokens, key_read.requests, key_read.spend_cents)
    };
    assert_eq!(reads(&gov), (3 * RAW_COUNT, 3, TOTAL_CENTS));
    gov.refund_charge(opening_grant.charge());
    assert_eq!(reads(&gov), (3 * RAW_COUNT, 3, TOTAL_CENTS - OPENING_FEE));
    gov.flush_budgets();
    gov.flush_metering_final();
    let rows = gov.metering_for(metering_bucket(later)).unwrap();
    assert_eq!(rows.len(), 3);
    for era in [opening_era, first_era, second_era] {
        let row = rows
            .iter()
            .find(|row| row.pricing_version == era.entry_id.unwrap().metering_version())
            .unwrap();
        assert_eq!(row.priced_from_ms, era.effective_from);
        assert_eq!(row.tokens_input, RAW_COUNT);
        assert_eq!(row.requests, 1);
    }
    let delta = BTreeMap::from([(UNIT_INPUT.to_string(), -1)]);
    let ambiguous = busbar_kernel::governance::Adjustment {
        key_id: &key.id,
        pool: "",
        model: RAW_MODEL,
        entry_era: shared_start,
        entry_id: None,
        card_epoch_ms: later * 1_000,
        delta: &delta,
        now: later,
    };
    let future_epoch_ms = busbar_kernel::store::now_ms() + SECS_PER_DAY * 1_000;
    let future = busbar_kernel::governance::Adjustment {
        card_epoch_ms: future_epoch_ms,
        ..ambiguous
    };
    assert!(matches!(
        gov.adjust_usage(&second, &future).unwrap(),
        Err(busbar_kernel::governance::AdjustRefused::FutureEpoch { at, now })
            if at == future_epoch_ms && now < future_epoch_ms
    ));
    assert_eq!(reads(&gov), (3 * RAW_COUNT, 3, TOTAL_CENTS - OPENING_FEE));
    assert!(gov
        .adjust_usage(&second, &ambiguous)
        .unwrap_err()
        .to_string()
        .contains("multiple raw rate entries"));
    assert_eq!(reads(&gov), (3 * RAW_COUNT, 3, TOTAL_CENTS - OPENING_FEE));
    drop(gov);
    let restarted = GovState::new_with_signer(store.clone(), None, None).unwrap();
    assert_eq!(
        reads(&restarted),
        (3 * RAW_COUNT, 3, TOTAL_CENTS - OPENING_FEE)
    );
    restarted.hydrate_budgets(&second, later).unwrap();
    assert_eq!(
        reads(&restarted),
        (3 * RAW_COUNT, 3, TOTAL_CENTS - OPENING_FEE)
    );

    let legacy = team_key(store.as_ref(), "vk_legacy_zero");
    restarted.record_usage_served_in_era(
        &second,
        &legacy,
        "",
        RAW_MODEL,
        None,
        &input(RAW_COUNT),
        later,
        RawRateEra::legacy(0),
    );
    assert_eq!(
        restarted
            .usage_for(&second, &legacy.id, later)
            .unwrap()
            .unwrap()
            .spend_cents,
        10
    );
    let group = &second.groups()[0].buckets[0];
    assert_eq!(
        restarted
            .derived_bucket_usage(&second, &group.bucket_id, WINDOW_DAY, true, later)
            .unwrap()
            .spend_cents,
        TOTAL_CENTS - OPENING_FEE + 30
    );
    restarted.flush_budgets_final();
    drop(restarted);
    let mixed = GovState::new_with_signer(store, None, None).unwrap();
    mixed.hydrate_budgets(&second, later).unwrap();
    assert_eq!(
        mixed
            .derived_bucket_usage(&second, &group.bucket_id, WINDOW_DAY, true, later)
            .unwrap()
            .spend_cents,
        TOTAL_CENTS - OPENING_FEE + 30
    );
    assert_eq!(
        mixed
            .usage_for(&second, &legacy.id, later)
            .unwrap()
            .unwrap()
            .spend_cents,
        10
    );
}

#[test]
fn malformed_versioned_budget_provenance_refuses_instead_of_repricing_as_legacy() {
    use busbar_contract::records::{ModelTokens, UsageLedger};
    let (_holder, _serial) = holder_opening(raw_card(1.0, 0));
    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), "vk_bad_raw_provenance");
    store
        .put_usage(
            &key.id,
            0,
            &UsageLedger {
                models: vec![ModelTokens {
                    model: RAW_MODEL.into(),
                    usage_units: input(RAW_COUNT),
                }],
                ..Default::default()
            },
        )
        .unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, key.id.as_bytes());
    let dated_bucket = format!("e:{}", hex::encode(&digest.as_ref()[..16]));
    store
        .put_usage(
            &dated_bucket,
            0,
            &UsageLedger {
                models: vec![ModelTokens {
                    model: "busbar.raw-era.v1:0:invalid\u{1f}m".into(),
                    usage_units: input(RAW_COUNT),
                }],
                ..Default::default()
            },
        )
        .unwrap();
    let gov = GovState::new_with_signer(store, None, None).unwrap();
    let cost = raw_cost(1.0, 0);
    let error = gov
        .usage_for(&cost, &key.id, busbar_kernel::store::now())
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("malformed versioned raw rate provenance"));
    assert!(gov
        .hydrate_budgets(&cost, busbar_kernel::store::now())
        .is_err());
}

#[test]
fn open_route_cancel_and_session_cleanup_keep_the_admissions_original_entry() {
    use busbar_contract::abi::plane::{UnitCount, CANCEL_OK_PARTIAL, UNITS_REPORTED};
    use busbar_contract::caps::{CallId, OriginKind, ReasonCode};
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
    let (holder, _serial) = holder_opening(raw_card(1.0, OPENING_FEE));
    holder.1.store(true, std::sync::atomic::Ordering::Relaxed);
    let store: Arc<dyn RecordStore> = real_store::store();
    let key = Arc::new(team_key(store.as_ref(), "vk_open_raw_provenance"));
    let gov = Arc::new(GovState::new_with_signer(store, None, None).unwrap());
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
            billed: vec![(INPUT_INDEX, RAW_COUNT)],
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
    let usage = gov.usage_for(&current, &key.id, arrived).unwrap().unwrap();
    assert_eq!(
        (usage.tokens, usage.requests, usage.spend_cents),
        (4 * RAW_COUNT, 4, 81)
    );
    gov.flush_budgets_final();
    gov.flush_metering_final();
    let rows = gov.metering_for(metering_bucket(arrived)).unwrap();
    assert_eq!(rows.len(), 2);
    for (era, requests) in [(original.unwrap(), 3), (current_era, 1)] {
        let row = rows
            .iter()
            .find(|row| row.pricing_version == era.entry_id.unwrap().metering_version())
            .unwrap();
        assert_eq!(row.requests, requests);
        assert_eq!(row.tokens_input, requests * RAW_COUNT);
    }
}

#[test]
fn scoped_pool_and_ancestor_buckets_keep_exact_raw_counts_and_partial_corrections() {
    use busbar_contract::records::ScopeRef;
    use busbar_kernel::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
    const POOL: &str = "raw-pool";
    const OTHER_POOL: &str = "other-pool";
    const ANCESTOR: &str = "raw-ancestor";
    const CORRECTED_COUNT: u64 = 90_000;
    const OPEN_COUNT: u64 = 10_000;
    let (holder, _serial) = holder_opening(raw_card(1.0, OPENING_FEE));
    holder.1.store(true, std::sync::atomic::Ordering::Relaxed);
    let limit = |pool: Option<&str>| LimitCfg {
        metric: LimitMetric::Budget,
        amount: 1_000,
        per: Some(LimitWindow::Day),
        scope: pool.map(ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let groups = BTreeMap::from([
        (
            "team".to_string(),
            GroupCfg {
                enabled: true,
                parent: Some(ANCESTOR.to_string()),
                limits: vec![limit(Some(POOL)), limit(Some(OTHER_POOL))],
                ..Default::default()
            },
        ),
        (
            ANCESTOR.to_string(),
            GroupCfg {
                enabled: true,
                limits: vec![limit(None)],
                ..Default::default()
            },
        ),
    ]);
    let old = raw_cost(1.0, OPENING_FEE).with_groups(&groups);
    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), "vk_scoped_raw_identity");
    let gov = GovState::new_with_signer(store.clone(), None, None).unwrap();
    let now = busbar_kernel::store::now();
    let charged = gov.try_admit(&old, &key, POOL, now).unwrap();
    let era = charged.charge().raw_era();
    let units = BTreeMap::from([
        (UNIT_INPUT.to_string(), RAW_COUNT),
        (OPEN_UNIT.to_string(), OPEN_COUNT),
    ]);
    gov.record_usage_served_in_era(
        &old,
        &key,
        POOL,
        RAW_MODEL,
        Some(RAW_PROVIDER),
        &units,
        now,
        era,
    );
    gov.record_lane_metering_in_era(&key, RAW_MODEL, Some(RAW_PROVIDER), &units, now, era);
    confirm(
        holder,
        busbar_kernel::store::now_ms().saturating_sub(1),
        3.0,
        SECOND_FEE,
        1,
    );
    let current = raw_cost(3.0, SECOND_FEE).with_groups(&groups);
    gov.flush_budgets();
    gov.flush_metering_final();
    let metered = gov.metering_for(metering_bucket(now)).unwrap();
    assert_eq!(metered.len(), 1);
    assert_eq!(metered[0].usage_units.get(OPEN_UNIT), Some(&OPEN_COUNT));
    assert_eq!(
        metered[0].pricing_version,
        era.entry_id.unwrap().metering_version()
    );
    let delta = BTreeMap::from([
        (UNIT_INPUT.to_string(), -10_000),
        (OPEN_UNIT.to_string(), -(OPEN_COUNT as i64)),
    ]);
    gov.adjust_usage(
        &current,
        &busbar_kernel::governance::Adjustment {
            key_id: &key.id,
            pool: POOL,
            model: RAW_MODEL,
            entry_era: era.effective_from,
            entry_id: None,
            card_epoch_ms: now * 1_000,
            delta: &delta,
            now,
        },
    )
    .unwrap()
    .unwrap();
    gov.refund_charge(charged.charge());
    for bucket in current.groups().iter().flat_map(|group| &group.buckets) {
        let other = bucket
            .scope
            .as_ref()
            .is_some_and(|scope| scope.value == OTHER_POOL);
        let read = gov
            .derived_bucket_usage(&current, &bucket.bucket_id, WINDOW_DAY, true, now)
            .unwrap();
        assert_eq!(
            (read.tokens, read.requests, read.spend_cents),
            if other {
                (0, 0, 0)
            } else {
                (CORRECTED_COUNT, 1, 9)
            }
        );
    }
    let adjustment = gov.usage_adjustments(metering_bucket(now)).unwrap();
    assert_eq!(adjustment.len(), 1);
    assert_eq!(adjustment[0].entry_id, era.entry_id);
    assert_eq!(adjustment[0].era, era.effective_from);
    assert_eq!(adjustment[0].delta.get(UNIT_INPUT), Some(&-10_000));
    gov.flush_budgets_final();
    let restarted = GovState::new_with_signer(store, None, None).unwrap();
    restarted.hydrate_budgets(&current, now).unwrap();
    let usage = restarted
        .usage_for(&current, &key.id, now)
        .unwrap()
        .unwrap();
    assert_eq!(
        (usage.tokens, usage.requests, usage.spend_cents),
        (CORRECTED_COUNT, 1, 9)
    );
}
