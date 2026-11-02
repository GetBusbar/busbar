// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const MODEL: &str = "m";
const INITIAL_INPUT: u64 = 100;
const SUBTRACT_INPUT: i64 = -60;
const CORRECTED_INPUT: u64 = 40;
const CONCURRENT_INPUT: u64 = 7;
const NEXT_WINDOW_INPUT: u64 = 11;

fn correction<'a>(
    key: &'a VirtualKey,
    delta: &'a BTreeMap<String, i64>,
    now: u64,
) -> super::super::Adjustment<'a> {
    super::super::Adjustment {
        key_id: &key.id,
        pool: "",
        model: MODEL,
        entry_era: era_now(),
        entry_id: None,
        card_epoch_ms: u64::try_from(std::time::Duration::from_secs(now).as_millis()).unwrap(),
        delta,
        now,
    }
}
fn input(row: &UsageLedger) -> u64 {
    row.models
        .iter()
        .filter(|row| row.model == MODEL)
        .map(|row| {
            row.usage_units
                .get(busbar_contract::records::UNIT_INPUT)
                .copied()
                .unwrap_or(0)
        })
        .sum()
}
fn delta() -> BTreeMap<String, i64> {
    BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), SUBTRACT_INPUT)])
}

fn metered_entry(store: &dyn RecordStore, key: &VirtualKey, era: RawRateEra, now: u64) {
    store.add_metering(&MeteringDelta {
        key_id: key.id.clone(),
        bucket: super::super::metering_bucket(now),
        model: MODEL.into(),
        provider: String::new(),
        tokens_input: INITIAL_INPUT,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: era.entry_id.unwrap().metering_version(),
        priced_from_ms: era.effective_from,
        usage_units: Default::default(),
    }).unwrap();
}

#[test]
fn exact_entry_correction_cannot_take_counts_from_a_same_timestamp_sibling() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_exact_entry", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    let first = RawRateEra::entry(0, EntryId([3; 12]));
    let second = RawRateEra::entry(0, EntryId([4; 12]));
    gov.record_usage_served_in_era(&cm, &key, "", MODEL, None, &toks(INITIAL_INPUT, 0), now, first);
    metered_entry(store.as_ref(), &key, first, now);
    metered_entry(store.as_ref(), &key, second, now);
    let delta = delta();
    let mut adj = correction(&key, &delta, now);
    adj.entry_era = 0;
    adj.entry_id = second.entry_id;
    assert!(matches!(gov.adjust_usage(&cm, &adj).unwrap(), Err(super::super::AdjustRefused::Unplaced { .. })),
        "matching timestamp and metering do not give the sibling ownership of raw counts");
    adj.entry_id = first.entry_id;
    gov.adjust_usage(&cm, &adj).unwrap().unwrap();
    assert_eq!(input(&store.get_usage(&key.id, 0).unwrap()), CORRECTED_INPUT);
}

#[test]
fn resumed_correction_does_not_treat_a_different_exact_entry_as_the_original_intent() {
    let store = Arc::new(FlakyStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_exact_intent", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    let first = RawRateEra::entry(0, EntryId([5; 12]));
    let second = RawRateEra::entry(0, EntryId([6; 12]));
    gov.record_usage_served_in_era(&cm, &key, "", MODEL, None, &toks(INITIAL_INPUT, 0), now, first);
    metered_entry(store.as_ref(), &key, first, now);
    metered_entry(store.as_ref(), &key, second, now);
    store.lose_correction_reply.store(true, std::sync::atomic::Ordering::SeqCst);
    let delta = delta();
    let mut adj = correction(&key, &delta, now);
    adj.entry_era = 0;
    adj.entry_id = first.entry_id;
    assert!(gov.adjust_usage(&cm, &adj).is_err());
    adj.entry_id = second.entry_id;
    assert!(matches!(gov.adjust_usage(&cm, &adj).unwrap(), Err(super::super::AdjustRefused::Unplaced { .. })),
        "receipt for the first exact entry does not accept a second entry's intent");
    assert_eq!(input(&store.get_usage(&key.id, 0).unwrap()), CORRECTED_INPUT);
}

#[test]
fn correction_acceptance_durably_captures_unflushed_raw_counts_and_fee_epochs() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_capture", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    gov.adjust_usage(&cm, &correction(&key, &delta(), now))
        .unwrap()
        .unwrap();
    let row = store.get_usage(&key.id, 0).unwrap();
    assert_eq!(
        (row.requests, row.billable_requests, input(&row)),
        (1, 1, CORRECTED_INPUT)
    );
    let restarted = GovState::new(store.clone(), None).unwrap();
    restarted.hydrate_budgets(&cm, now).unwrap();
    assert_eq!(
        restarted
            .usage_for(&cm, &key.id, now)
            .unwrap()
            .unwrap()
            .tokens,
        CORRECTED_INPUT
    );
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap(),
        row,
        "captured facts are already acknowledged"
    );
    let era_row = store
        .get_usage(&super::super::era_bucket(&key.id), 0)
        .unwrap();
    if era_now() != 0 {
        assert!(era_row
            .models
            .iter()
            .any(|model| model.model == era_now().to_string()
                && model.usage_units.get(super::super::ERA_FEE_UNIT) == Some(&1)));
    }
}

#[test]
fn correction_captures_u64_local_facts_without_signed_saturation() {
    const ABOVE_SIGNED_COUNT: u64 = i64::MAX as u64 + 17;
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_unsigned_capture", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    gov.record_usage(&cm, &key, "", MODEL, &toks(ABOVE_SIGNED_COUNT, 0), now);
    metered(&gov, &key.id, MODEL, ABOVE_SIGNED_COUNT, now);
    let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), -1)]);
    gov.adjust_usage(&cm, &correction(&key, &delta, now))
        .unwrap()
        .unwrap();
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        ABOVE_SIGNED_COUNT - 1
    );
    gov.record_usage(&cm, &key, "", MODEL, &toks(CONCURRENT_INPUT, 0), now);
    gov.flush_budgets();
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        ABOVE_SIGNED_COUNT - 1 + CONCURRENT_INPUT
    );
}

#[test]
fn rolled_large_raw_debt_survives_legacy_flush_and_is_captured_by_correction() {
    const LARGE_INPUT: u64 = i64::MAX as u64 + INITIAL_INPUT;
    const GROUP_BUCKET: &str = "group:g@minute";
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_large_roll", Some("g"));
    store.put_key(&key).unwrap();
    let cm = minute_fee_model();
    let now = crate::governance::budget_window(super::super::WINDOW_MINUTE, crate::store::now());
    let next = super::super::window_end(super::super::WINDOW_MINUTE, now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(LARGE_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, LARGE_INPUT, now);
    gov.try_admit(&cm, &key, "", next).unwrap();
    gov.flush_budgets();
    assert_eq!(
        input(&store.get_usage(GROUP_BUCKET, now).unwrap()),
        LARGE_INPUT,
        "ordinary chunks persist the entire raw debt before correction"
    );
    gov.adjust_usage(&cm, &correction(&key, &delta(), now))
        .unwrap()
        .unwrap();
    assert_eq!(
        input(&store.get_usage(GROUP_BUCKET, now).unwrap()),
        LARGE_INPUT - SUBTRACT_INPUT.unsigned_abs()
    );
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        LARGE_INPUT - SUBTRACT_INPUT.unsigned_abs()
    );
    gov.flush_budgets();
    assert_eq!(
        input(&store.get_usage(GROUP_BUCKET, now).unwrap()),
        LARGE_INPUT - SUBTRACT_INPUT.unsigned_abs()
    );
    assert_eq!(store.get_usage(GROUP_BUCKET, next).unwrap().requests, 1);
}

#[test]
fn unknown_correction_retains_exact_identity_through_another_error_and_background_recovery() {
    let store = Arc::new(FlakyStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let key = key("vk_correction_unknown", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    store
        .lose_correction_reply
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let delta = delta();
    let adj = correction(&key, &delta, now);
    assert!(gov.adjust_usage(&cm, &adj).is_err());
    assert!(gov.usage_for(&cm, &key.id, now).is_err());
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT
    );
    gov.record_usage(&cm, &key, "", MODEL, &toks(CONCURRENT_INPUT, 0), now);
    store.set_down(true);
    assert!(gov.adjust_usage(&cm, &adj).is_err());
    assert!(
        gov.hydrate_budgets(&cm, now).is_err(),
        "hydration cannot replace unresolved facts"
    );
    store.set_down(false);
    gov.flush_budgets();

    gov.adjust_usage(&cm, &adj).unwrap().unwrap();
    gov.flush_budgets();
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT + CONCURRENT_INPUT
    );
    let calls = store.correction_calls.lock().unwrap();
    assert!(calls.len() > 1);
    assert!(
        calls.windows(2).all(|pair| pair[0] == pair[1]),
        "every replay keeps exact id and body"
    );
}

#[test]
fn accrual_refund_and_roll_update_both_reserved_raw_branches() {
    let store = Arc::new(FlakyStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let key = key("vk_correction_concurrent", Some("g"));
    store.put_key(&key).unwrap();
    let cm = minute_fee_model();
    let now = crate::governance::budget_window(super::super::WINDOW_MINUTE, crate::store::now());
    let next = super::super::window_end(super::super::WINDOW_MINUTE, now).unwrap();
    let charged = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    let (mutator, mutated_key) = (gov.clone(), key.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        let cm = minute_fee_model();
        mutator.record_usage(
            &cm,
            &mutated_key,
            "",
            MODEL,
            &toks(CONCURRENT_INPUT, 0),
            now,
        );
        mutator.refund_charge(charged.charge());
        mutator.try_admit(&cm, &mutated_key, "", next).unwrap();
        mutator.record_usage(
            &cm,
            &mutated_key,
            "",
            MODEL,
            &toks(NEXT_WINDOW_INPUT, 0),
            next,
        );
    }));
    gov.adjust_usage(&cm, &correction(&key, &delta(), now))
        .unwrap()
        .unwrap();
    gov.flush_budgets();
    gov.flush_budgets();
    const GROUP_BUCKET: &str = "group:g@minute";
    assert_eq!(
        minute_row(store.as_ref(), GROUP_BUCKET, now),
        (2, 1, CORRECTED_INPUT + CONCURRENT_INPUT, 0)
    );
    assert_eq!(
        minute_row(store.as_ref(), GROUP_BUCKET, next),
        (1, 1, NEXT_WINDOW_INPUT, 0)
    );
    let row = store.get_usage(&key.id, 0).unwrap();
    assert_eq!(
        (row.requests, row.billable_requests, input(&row)),
        (3, 2, CORRECTED_INPUT + CONCURRENT_INPUT + NEXT_WINDOW_INPUT)
    );
}

#[test]
fn correction_excludes_a_same_window_inflight_flush_without_changing_raw_facts() {
    let store = Arc::new(FlakyStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let key = key("vk_correction_flush_collision", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    let (corrector, corrected_key) = (gov.clone(), key.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        assert!(corrector
            .adjust_usage(&model(&[]), &correction(&corrected_key, &delta(), now))
            .is_err());
    }));
    gov.flush_budgets();
    assert_eq!(input(&store.get_usage(&key.id, 0).unwrap()), INITIAL_INPUT);
    assert!(gov
        .usage_adjustments(crate::governance::metering_bucket(now))
        .unwrap()
        .is_empty());
    gov.adjust_usage(&cm, &correction(&key, &delta(), now))
        .unwrap()
        .unwrap();
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT
    );
}

#[test]
fn a_future_usage_epoch_refuses_both_signs_without_changing_recorded_facts() {
    for change in [-1, 1] {
        let store = Arc::new(MemoryStore::new());
        let gov = GovState::new(store.clone(), None).unwrap();
        let key = key("vk_correction_future", None);
        store.put_key(&key).unwrap();
        let cm = model(&[]);
        let now = crate::store::now();
        let future = crate::store::now_ms() + 60_000;
        gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
        metered(&gov, &key.id, MODEL, INITIAL_INPUT, future / 1_000);
        gov.flush_budgets();
        let day = super::super::metering_bucket(future / 1_000);
        let facts = || {
            (
                store.get_usage(&key.id, 0).unwrap(),
                store
                    .get_usage(&super::super::era_bucket(&key.id), 0)
                    .unwrap(),
                store
                    .get_usage(super::super::ADJUST_UP_BUCKET, day)
                    .unwrap(),
                store
                    .get_usage(super::super::ADJUST_DOWN_BUCKET, day)
                    .unwrap(),
                store.list_metering(day).unwrap(),
                gov.usage_adjustments(day).unwrap(),
                gov.usage_for(&cm, &key.id, now).unwrap(),
            )
        };
        let before = facts();
        let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), change)]);
        let adj = super::super::Adjustment {
            card_epoch_ms: future,
            ..correction(&key, &delta, now)
        };
        let result = gov.adjust_usage(&cm, &adj).unwrap();
        assert!(
            result.is_err(),
            "a future epoch must be refused: {result:?}"
        );
        assert!(matches!(
            result,
            Err(super::super::AdjustRefused::FutureEpoch { at, now })
                if at == future && now < future
        ));
        assert_eq!(facts(), before, "no ledger or metering fact may change");
    }
}
