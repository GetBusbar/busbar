// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn correction_only_hydration_registers_its_group_for_reclamation() {
    const GROUP: &str = "correction-only";
    const MODEL: &str = "m";
    const REQUEST_CAP: u64 = 1;
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cm = model(&[(
        GROUP,
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::Requests,
                REQUEST_CAP,
                Some(LimitWindow::Total),
            )],
        ),
    )]);
    let key = key("vk_correction_only_owner", Some(GROUP));
    let now = crate::store::now();
    store.put_key(&key).unwrap();
    metered(&gov, &key.id, MODEL, REQUEST_CAP, now);
    let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), 1)]);

    gov.adjust_usage(
        &cm,
        &super::super::Adjustment {
            key_id: &key.id,
            pool: "",
            model: MODEL,
            entry_era: era_now(),
            card_epoch_ms: card_epoch_millis(now),
            delta: &delta,
            now,
        },
    )
    .unwrap()
    .unwrap();
    gov.flush_budgets();

    assert_eq!(gov.reclaim_group_cells(GROUP), 1);
}

#[test]
fn correction_registers_a_second_owner_of_a_shared_legacy_bucket() {
    const ORIGINAL_GROUP: &str = "correction-shared";
    const CORRECTED_GROUP: &str = "correction-shared@total#pool:p";
    const ORIGINAL_POOL: &str = "p@total";
    const MODEL: &str = "m";
    const REQUEST_CAP: u64 = 1;
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let original = model(&[(
        ORIGINAL_GROUP,
        group_cfg(
            None,
            true,
            vec![pooled(
                LimitMetric::Requests,
                REQUEST_CAP,
                LimitWindow::Total,
                ORIGINAL_POOL,
            )],
        ),
    )]);
    let corrected = model(&[(
        CORRECTED_GROUP,
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::Requests,
                REQUEST_CAP,
                Some(LimitWindow::Total),
            )],
        ),
    )]);
    let original_key = key("vk_correction_original_owner", Some(ORIGINAL_GROUP));
    let corrected_key = key("vk_correction_second_owner", Some(CORRECTED_GROUP));
    let now = crate::store::now();
    gov.try_admit(&original, &original_key, ORIGINAL_POOL, now)
        .unwrap();
    store.put_key(&corrected_key).unwrap();
    metered(&gov, &corrected_key.id, MODEL, REQUEST_CAP, now);
    let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), 1)]);

    gov.adjust_usage(
        &corrected,
        &super::super::Adjustment {
            key_id: &corrected_key.id,
            pool: "",
            model: MODEL,
            entry_era: era_now(),
            card_epoch_ms: card_epoch_millis(now),
            delta: &delta,
            now,
        },
    )
    .unwrap()
    .unwrap();
    gov.flush_budgets();

    assert_eq!(gov.reclaim_group_cells(ORIGINAL_GROUP), 0);
    assert!(gov.try_admit(&corrected, &corrected_key, "", now).is_err());
    assert_eq!(gov.reclaim_group_cells(CORRECTED_GROUP), 1);
}

#[test]
fn reclaiming_a_short_group_name_preserves_a_live_delimiter_named_groups_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let name = "team@day#pool:p";
    let cm = model(&[(
        name,
        group_cfg(
            None,
            true,
            vec![limit(LimitMetric::Requests, 1, Some(LimitWindow::Total))],
        ),
    )]);
    let key = key("vk_delimiter_owner", Some(name));
    let now = 1_700_000_040;
    gov.try_admit(&cm, &key, "", now).unwrap();
    gov.flush_budgets();

    gov.reclaim_group_cells("team");

    assert!(
        gov.try_admit(&cm, &key, "", now).is_err(),
        "removing another group must not reset this live group's request cap"
    );
}

#[test]
fn reclaim_during_a_failed_flush_keeps_the_retry_owned() {
    let store = Arc::new(FlakyStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cm = minute_fee_model();
    let key = key("vk_reclaim_inflight", Some("g"));
    let now = 1_700_000_040;
    gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", "m", &toks(17, 3), now);
    let (reclaimer, outage) = (gov.clone(), store.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        reclaimer.reclaim_group_cells("g");
        outage.set_down(true);
    }));

    gov.flush_budgets();
    store.set_down(false);
    gov.flush_budgets();

    assert_eq!(
        minute_row(store.as_ref(), "group:g@minute", now),
        (1, 1, 17, 3),
        "the failed in-flight write remains owed after group reclamation"
    );
    gov.flush_budgets();
    assert_eq!(
        minute_row(store.as_ref(), "group:g@minute", now),
        (1, 1, 17, 3)
    );
}

#[test]
fn a_failed_era_row_retries_without_repeating_the_successful_plain_row() {
    let store = Arc::new(FlakyStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let bucket = "vk_era_retry";
    let now = 1_700_000_040;
    let key = key(bucket, None);
    let cm = minute_fee_model();
    store.put_key(&key).unwrap();
    gov.try_admit(&cm, &key, "", now).unwrap();
    // An explicit dated fee is the same state admission creates when a dated card is active.
    // Keep this fixture independent of the process-global rate-history singleton.
    {
        let mut cells = gov.budget.write(bucket);
        let cell = cells.get_mut(bucket).unwrap();
        cell.fee_eras = Default::default();
        cell.fee_eras.charge(42);
    }
    store
        .era_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    gov.flush_budgets();
    store
        .era_down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    gov.flush_budgets();
    gov.flush_budgets();

    let plain = store.get_usage(bucket, 0).unwrap();
    assert_eq!((plain.requests, plain.billable_requests), (1, 1));
    let era = store
        .get_usage(&super::super::era_bucket(bucket), 0)
        .unwrap();
    assert_eq!(
        era.models
            .iter()
            .find(|row| row.model == "42")
            .and_then(|row| row.usage_units.get(super::super::ERA_FEE_UNIT))
            .copied(),
        Some(1),
        "fee attribution must survive a transient era-row write failure"
    );
}

#[test]
fn correction_hydration_preserves_an_older_inflight_eras_retry_and_group_owner() {
    let store = Arc::new(FlakyStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cm = minute_fee_model();
    let key = key("vk_era_hydrate", Some("g"));
    let now = crate::governance::budget_window(super::super::WINDOW_MINUTE, crate::store::now());
    let next = now + 60;
    let bucket = "group:g@minute";
    store.put_key(&key).unwrap();
    gov.try_admit(&cm, &key, "", now).unwrap();
    {
        let mut cells = gov.budget.write(bucket);
        let cell = cells.get_mut(bucket).unwrap();
        cell.fee_eras = Default::default();
        cell.fee_eras.charge(42);
    }
    metered(&gov, &key.id, "m", 1, next);
    store
        .era_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (corrector, correction_key) = (gov.clone(), key.clone());
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.to_string(), 1)]);
        corrector
            .adjust_usage(
                &minute_fee_model(),
                &super::super::Adjustment {
                    key_id: &correction_key.id,
                    pool: "",
                    model: "m",
                    entry_era: era_now(),
                    card_epoch_ms: card_epoch_millis(next),
                    delta: &delta,
                    now: next,
                },
            )
            .unwrap()
            .unwrap();
    }));

    gov.flush_budgets();
    store
        .era_down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    gov.flush_budgets();
    gov.flush_budgets();

    let era = store
        .get_usage(&super::super::era_bucket(bucket), now)
        .unwrap();
    assert_eq!(
        era.models
            .iter()
            .find(|row| row.model == "42")
            .and_then(|row| row.usage_units.get(super::super::ERA_FEE_UNIT))
            .copied(),
        Some(1),
    );
    assert_eq!(minute_row(store.as_ref(), bucket, now), (1, 1, 0, 0));
    assert_eq!(minute_row(store.as_ref(), bucket, next), (0, 0, 1, 0));
    assert_eq!(
        gov.reclaim_group_cells("g"),
        1,
        "hydration retains the actual group owner"
    );
}

fn card_epoch_millis(seconds: u64) -> u64 {
    u64::try_from(std::time::Duration::from_secs(seconds).as_millis()).unwrap()
}
