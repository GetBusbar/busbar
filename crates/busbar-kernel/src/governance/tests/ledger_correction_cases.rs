// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::recovery::{
    tests::Journal, RecoveryKind, RecoveryResolution, RecoveryState, RecoveryVerdict,
};

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
    store
        .add_metering(&MeteringDelta {
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
        })
        .unwrap();
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
    gov.record_usage_served_in_era(
        &cm,
        &key,
        "",
        MODEL,
        None,
        &toks(INITIAL_INPUT, 0),
        now,
        first,
    );
    metered_entry(store.as_ref(), &key, first, now);
    metered_entry(store.as_ref(), &key, second, now);
    let delta = delta();
    let mut adj = correction(&key, &delta, now);
    adj.entry_era = 0;
    adj.entry_id = second.entry_id;
    assert!(
        matches!(
            gov.adjust_usage(&cm, &adj).unwrap(),
            Err(super::super::AdjustRefused::Unplaced { .. })
        ),
        "matching timestamp and metering do not give the sibling ownership of raw counts"
    );
    adj.entry_id = first.entry_id;
    gov.adjust_usage(&cm, &adj).unwrap().unwrap();
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT
    );
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
    gov.record_usage_served_in_era(
        &cm,
        &key,
        "",
        MODEL,
        None,
        &toks(INITIAL_INPUT, 0),
        now,
        first,
    );
    metered_entry(store.as_ref(), &key, first, now);
    metered_entry(store.as_ref(), &key, second, now);
    store
        .lose_correction_reply
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let delta = delta();
    let mut adj = correction(&key, &delta, now);
    adj.entry_era = 0;
    adj.entry_id = first.entry_id;
    assert!(gov.adjust_usage(&cm, &adj).is_err());
    adj.entry_id = second.entry_id;
    assert!(
        matches!(
            gov.adjust_usage(&cm, &adj).unwrap(),
            Err(super::super::AdjustRefused::Unplaced { .. })
        ),
        "receipt for the first exact entry does not accept a second entry's intent"
    );
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT
    );
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

#[test]
fn conditional_conflict_revalidates_shared_rows_and_preserves_common_refund_and_usage() {
    const GROUP_BUCKET: &str = "group:g@minute";
    const FOREIGN_REQUESTS: i64 = 5;
    let store = Arc::new(FlakyStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let key = key("vk_correction_revalidation", Some("g"));
    store.put_key(&key).unwrap();
    let cm = minute_fee_model();
    let now = crate::governance::budget_window(super::super::WINDOW_MINUTE, crate::store::now());
    let grant = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    let (writer, mutator, mutated_key) = (store.clone(), gov.clone(), key.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        // Another node changes a shared row after this candidate captured its condition.
        writer
            .inner
            .add_usage(
                GROUP_BUCKET,
                now,
                &UsageDelta {
                    requests: FOREIGN_REQUESTS,
                    ..Default::default()
                },
            )
            .unwrap();
        mutator.record_usage(
            &minute_fee_model(),
            &mutated_key,
            "",
            MODEL,
            &toks(CONCURRENT_INPUT, 0),
            now,
        );
        mutator.refund_charge(grant.charge());
    }));
    gov.adjust_usage(&cm, &correction(&key, &delta(), now))
        .unwrap()
        .unwrap();
    gov.flush_budgets();
    assert_eq!(
        minute_row(store.as_ref(), GROUP_BUCKET, now),
        (
            1 + FOREIGN_REQUESTS as u64,
            0,
            CORRECTED_INPUT + CONCURRENT_INPUT,
            0
        )
    );
    let calls = store.correction_calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        2,
        "a changed conditional basis is rebuilt once"
    );
    assert_ne!(calls[0].op_id, calls[1].op_id);
    let group_row = |request: &busbar_contract::records::correction::Request| {
        request
            .usage
            .iter()
            .find(|change| change.address.bucket_id == GROUP_BUCKET)
            .unwrap()
            .clone()
    };
    assert_eq!(group_row(&calls[0]).expected.requests, 0);
    assert_eq!(
        group_row(&calls[1]).expected.requests,
        FOREIGN_REQUESTS as u64
    );
    assert_eq!(
        group_row(&calls[1]).replacement.requests,
        1 + FOREIGN_REQUESTS as u64
    );
    assert_eq!(group_row(&calls[1]).replacement.billable_requests, 0);
}

#[test]
fn correction_common_positives_keep_same_timestamp_fee_refunds_in_both_raw_branches() {
    let old = RawRateEra::entry(0, EntryId([1; 12]));
    let new = RawRateEra::entry(0, EntryId([2; 12]));
    for roll in [false, true] {
        let mut before = BudgetCell::fresh(0);
        before.requests = 1;
        before.billable_requests = 1;
        before.fee_eras.charge(old);
        before.accrue_raw(MODEL, old, &toks(INITIAL_INPUT, 0));
        let mut accepted = before.clone();
        accepted.models[0]
            .cur
            .insert(busbar_contract::records::UNIT_INPUT.into(), CORRECTED_INPUT);
        accepted.models[0].flushed = accepted.models[0].cur.clone();
        accepted.models[0].flushed_era = accepted.models[0].cur.clone();
        accepted.flushed_requests = 1;
        accepted.flushed_billable_requests = 1;
        accepted.flushed_fee_eras = accepted.fee_eras.clone();
        before.correction = Some(Box::new(CorrectionBranch {
            op_id: crate::door::op_id(),
            window: 0,
            accepted,
        }));
        before.mutate(|branch| {
            branch.requests += 1;
            branch.fee_eras.refund(old);
            branch.fee_eras.charge(new);
            branch.accrue_raw(MODEL, new, &toks(CONCURRENT_INPUT, 0));
        });
        if roll {
            before.roll(60);
        }
        let (positive, dated) = GovState::take_correction_positives(&mut before, 0)
            .unwrap()
            .unwrap();
        assert_eq!((positive.requests, positive.billable_requests), (1, 1));
        let units = |debt: &ExactUsageDelta, model: &str, unit: &str| {
            debt.models
                .iter()
                .find(|row| row.model == model)
                .and_then(|row| row.usage_units.get(unit))
                .copied()
                .unwrap_or(0)
        };
        assert_eq!(
            units(&positive, MODEL, busbar_contract::records::UNIT_INPUT),
            i128::from(CONCURRENT_INPUT)
        );
        assert_eq!(
            units(
                &dated,
                &era_model(new, MODEL),
                busbar_contract::records::UNIT_INPUT
            ),
            i128::from(CONCURRENT_INPUT)
        );
        assert_eq!(units(&dated, &era_tag(new), ERA_FEE_UNIT), 1);
        assert_eq!(units(&dated, &era_tag(old), ERA_FEE_UNIT), 0);
        let branch = &before.correction.as_ref().unwrap().accepted;
        let debt = if roll {
            branch
                .rolled_eras
                .iter()
                .find(|(window, _)| *window == 0)
                .unwrap()
                .1
                .clone()
        } else {
            ExactUsageDelta::of(branch, true)
        };
        assert_eq!(
            units(&debt, &era_tag(old), ERA_FEE_UNIT),
            -1,
            "the original fee refund remains dependent on the unknown correction"
        );
        let (again, dated_again) = GovState::take_correction_positives(&mut before, 0)
            .unwrap()
            .unwrap();
        assert!(
            again.is_zero() && dated_again.is_zero(),
            "positive custody transferred only once"
        );
    }
}

#[test]
fn restarted_unlanded_correction_revalidates_foreign_usage_before_reposting_and_refunding() {
    const FOREIGN_INPUT: u64 = 13;
    let store = Arc::new(MemoryStore::new());
    let journal = Arc::new(Journal::default());
    let first = GovState::new(store.clone(), None).unwrap();
    first.attach_recovery_sink(journal.clone()).unwrap();
    let key = key("vk_correction_quarantined_not_landed", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    let grant = first.try_admit(&cm, &key, "", now).unwrap();
    first.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&first, &key.id, MODEL, INITIAL_INPUT, now);
    journal
        .fail_after_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(first
        .adjust_usage(&cm, &correction(&key, &delta(), now))
        .is_err());
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        0,
        "Intent acknowledgement failed before backend submission"
    );
    let original = journal
        .selected
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == RecoveryKind::Correction)
        .unwrap()
        .clone();
    let count = journal.selected.lock().unwrap().len();
    let held = first
        .hold_foreign_correction_recovery(original.operation_id)
        .unwrap();
    assert!(held.is_some());
    assert!(
        first
            .adjust_usage(&cm, &correction(&key, &delta(), now))
            .is_err(),
        "the retained adoption guard prevents the real correction sender from restarting"
    );
    assert_eq!(journal.selected.lock().unwrap().len(), count);
    drop(held);
    let adoption = RecoveryResolution {
        operation_id: original.operation_id,
        body_fingerprint: original.body_fingerprint,
        expected_revision: original.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "adopter".into(),
        reason: "foreign sender retired and backend checked".into(),
    };
    let staged = GovState::stage_foreign_correction_verdict(&original, &adoption).unwrap();
    assert_eq!(staged.len(), 2);
    assert_eq!(
        (staged[0].state, staged[1].state),
        (
            RecoveryState::LandedUnknown,
            RecoveryState::VerdictNotLanded
        )
    );
    assert!(staged
        .iter()
        .all(|event| event.body_fingerprint == original.body_fingerprint
            && event.first_sent_at_ms == original.first_sent_at_ms));
    let repeated = GovState::stage_foreign_correction_verdict(
        &staged[1],
        &RecoveryResolution {
            expected_revision: staged[1].revision,
            actor: "another adopter".into(),
            ..adoption
        },
    )
    .unwrap();
    assert_eq!(
        repeated[0].payload, staged[1].payload,
        "handover does not replace the original verdict's audit provenance"
    );
    assert_eq!(
        journal.selected.lock().unwrap().len(),
        count,
        "foreign staging performs no Store I/O"
    );
    assert_eq!(input(&store.get_usage(&key.id, 0).unwrap()), 0);
    drop(grant);
    drop(first);
    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);
    store
        .add_usage(
            &key.id,
            0,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![busbar_contract::records::ModelTokensDelta {
                    model: MODEL.into(),
                    usage_units: BTreeMap::from([(
                        busbar_contract::records::UNIT_INPUT.into(),
                        FOREIGN_INPUT as i64,
                    )]),
                }],
            },
        )
        .unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(journal.clone()).unwrap();
    gov.hydrate_budgets(&cm, now).unwrap();
    assert_eq!(
        gov.usage_for(&cm, &key.id, now).unwrap().unwrap().tokens,
        FOREIGN_INPUT,
        "fresh Store counts remain authoritative while old branches are quarantined separately"
    );
    gov.flush_budgets();
    assert_eq!(
        gov.recovery_event(original.operation_id).unwrap().state,
        RecoveryState::LandedUnknown
    );
    let fresh_grant = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(CONCURRENT_INPUT, 0), now);
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().billable_requests,
        2,
        "the new runtime records its own positive fee while the old correction is quarantined"
    );
    gov.refund_charge(fresh_grant.charge());
    gov.flush_budgets();
    let fresh = store.get_usage(&key.id, 0).unwrap();
    assert_eq!(
        (input(&fresh), fresh.billable_requests),
        (FOREIGN_INPUT + CONCURRENT_INPUT, 2),
        "fresh positives post and their refund waits while the segment has quarantined positive custody"
    );
    let selected = gov.recovery_event(original.operation_id).unwrap();
    let resolution = RecoveryResolution {
        operation_id: selected.operation_id,
        body_fingerprint: selected.body_fingerprint,
        expected_revision: selected.revision,
        verdict: RecoveryVerdict::NotLanded,
        sender_quiesced: false,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "all senders retired; backend confirms no original write".into(),
    };
    let count = journal.selected.lock().unwrap().len();
    assert!(gov.recovery().resolve(&cm, resolution.clone()).is_err());
    assert_eq!(
        journal.selected.lock().unwrap().len(),
        count,
        "missing attestation causes no persisted verdict or effect"
    );
    let resolution = RecoveryResolution {
        sender_quiesced: true,
        ..resolution
    };
    gov.recovery().resolve(&cm, resolution.clone()).unwrap();
    let after = store.get_usage(&key.id, 0).unwrap();
    assert_eq!(
        (input(&after), after.requests, after.billable_requests),
        (CORRECTED_INPUT + FOREIGN_INPUT + CONCURRENT_INPUT, 3, 2)
    );
    assert_eq!(
        gov.usage_for(&cm, &key.id, now).unwrap().unwrap().tokens,
        CORRECTED_INPUT + FOREIGN_INPUT + CONCURRENT_INPUT
    );
    let events = journal.selected.lock().unwrap().clone();
    assert!(events
        .iter()
        .filter(|event| event.operation_id == original.operation_id)
        .all(|event| event.body_fingerprint == original.body_fingerprint));
    let successor = events
        .iter()
        .find(|event| {
            event.kind == RecoveryKind::Correction
                && event.operation_id != original.operation_id
                && event.revision == 0
        })
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&successor.payload).unwrap();
    let request = busbar_contract::records::correction::Request::decode(
        &serde_json::to_vec(&payload["request"]).unwrap(),
    )
    .unwrap();
    let row = request
        .usage
        .iter()
        .find(|row| row.address.bucket_id == key.id)
        .unwrap();
    assert_eq!(
        (input(&row.expected), input(&row.replacement)),
        (
            INITIAL_INPUT + FOREIGN_INPUT + CONCURRENT_INPUT,
            CORRECTED_INPUT + FOREIGN_INPUT + CONCURRENT_INPUT
        ),
        "fresh conditional basis preserves other writers instead of replaying the old replacement"
    );
    assert_ne!(request.op_id.0, original.operation_id);
    let count = events.len();
    gov.recovery().resolve(&cm, resolution).unwrap();
    assert_eq!(store.get_usage(&key.id, 0).unwrap(), after);
    assert_eq!(
        journal.selected.lock().unwrap().len(),
        count,
        "repeating the audited verdict does not re-post it"
    );
}

#[test]
fn restarted_landed_correction_keeps_foreign_basis_and_does_not_reapply_the_old_request() {
    let store = Arc::new(FlakyStore::new());
    let journal = Arc::new(Journal::default());
    let first = GovState::new(store.clone(), None).unwrap();
    first.attach_recovery_sink(journal.clone()).unwrap();
    let key = key("vk_correction_quarantined_landed", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    first.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&first, &key.id, MODEL, INITIAL_INPUT, now);
    store
        .lose_correction_reply
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(first
        .adjust_usage(&cm, &correction(&key, &delta(), now))
        .is_err());
    let original = journal
        .selected
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == RecoveryKind::Correction)
        .unwrap()
        .clone();
    drop(first);
    store
        .inner
        .add_usage(
            &key.id,
            0,
            &UsageDelta {
                models: vec![busbar_contract::records::ModelTokensDelta {
                    model: MODEL.into(),
                    usage_units: BTreeMap::from([(
                        busbar_contract::records::UNIT_INPUT.into(),
                        CONCURRENT_INPUT as i64,
                    )]),
                }],
                ..Default::default()
            },
        )
        .unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(journal).unwrap();
    gov.hydrate_budgets(&cm, now).unwrap();
    gov.flush_budgets();
    gov.record_usage(&cm, &key, "", MODEL, &toks(NEXT_WINDOW_INPUT, 0), now);
    let selected = gov.recovery_event(original.operation_id).unwrap();
    gov.recovery()
        .resolve(
            &cm,
            RecoveryResolution {
                operation_id: selected.operation_id,
                body_fingerprint: selected.body_fingerprint,
                expected_revision: selected.revision,
                verdict: RecoveryVerdict::Landed,
                sender_quiesced: true,
                backend_quiesced: true,
                actor: "operator".into(),
                reason: "all senders retired; original backend receipt checked".into(),
            },
        )
        .unwrap();
    assert_eq!(
        store.correction_calls.lock().unwrap().len(),
        1,
        "reboot and landed verdict never resubmit the expired/age-unknown conditional request"
    );
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT + CONCURRENT_INPUT
    );
    assert_eq!(
        gov.usage_for(&cm, &key.id, now).unwrap().unwrap().tokens,
        CORRECTED_INPUT + CONCURRENT_INPUT + NEXT_WINDOW_INPUT
    );
}

#[test]
fn a_known_correction_receipt_survives_a_lost_recovery_ack_without_backend_replay() {
    let store = Arc::new(FlakyStore::new());
    let journal = Arc::new(Journal::default());
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(journal.clone()).unwrap();
    let key = key("vk_correction_known_receipt", None);
    store.put_key(&key).unwrap();
    let cm = model(&[]);
    let now = crate::store::now();
    gov.record_usage(&cm, &key, "", MODEL, &toks(INITIAL_INPUT, 0), now);
    metered(&gov, &key.id, MODEL, INITIAL_INPUT, now);
    let fail_receipt_ack = journal.clone();
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        fail_receipt_ack
            .fail_after_write
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }));
    let delta = delta();
    let adj = correction(&key, &delta, now);
    assert!(gov.adjust_usage(&cm, &adj).is_err());
    assert_eq!(
        input(&store.get_usage(&key.id, 0).unwrap()),
        CORRECTED_INPUT
    );
    assert_eq!(store.correction_calls.lock().unwrap().len(), 1);
    let selected = gov
        .selected_recovery_events()
        .into_iter()
        .find(|event| event.kind == RecoveryKind::Correction)
        .unwrap();
    let hold = gov
        .hold_foreign_correction_recovery(selected.operation_id)
        .unwrap();
    let count = journal.selected.lock().unwrap().len();
    assert!(
        gov.validate_foreign_correction_verdict(&RecoveryResolution {
            operation_id: selected.operation_id,
            body_fingerprint: selected.body_fingerprint,
            expected_revision: selected.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "adopter".into(),
            reason: "incorrect not-landed choice".into(),
        })
        .is_err(),
        "a definitive host receipt cannot be replaced by an operator's opposite verdict"
    );
    assert_eq!(journal.selected.lock().unwrap().len(), count);
    drop(hold);
    store.set_down(true);
    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);
    gov.adjust_usage(&cm, &adj).unwrap().unwrap();
    assert_eq!(
        store.correction_calls.lock().unwrap().len(),
        1,
        "the definitive backend decision is retained while its immutable recovery event is retried"
    );
    assert_eq!(
        journal.selected.lock().unwrap().last().unwrap().state,
        RecoveryState::Settled
    );
}
