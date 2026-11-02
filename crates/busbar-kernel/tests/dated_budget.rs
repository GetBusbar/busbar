// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::records::{ModelTokens, RecordStore, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::door;
use busbar_kernel::governance::{budget_window, GovState, LimitBlocked, WINDOW_TOTAL};
use busbar_kernel::rate_apply::RateEpoch;
use busbar_kernel_ledger::cost::{
    price_in_view, Author, CardEntryDraft, History, LaneClass, LedgerEntry, RateCard,
};

#[path = "../src/tests/real_store.rs"]
mod real_store;

struct Holder(Mutex<Arc<History>>, std::sync::atomic::AtomicBool);

impl RateEpoch for Holder {
    fn era_at(&self, at_ms: u64) -> busbar_kernel_ledger::cost::RawRateEra {
        use busbar_kernel_ledger::cost::RawRateEra;
        let history = self.0.lock().unwrap().clone();
        let view = history.current();
        view.entry_at(at_ms).map_or(RawRateEra::legacy(0), |entry| {
            if self.1.load(std::sync::atomic::Ordering::Relaxed) {
                RawRateEra::entry(entry.effective_from(), entry.id())
            } else {
                RawRateEra::legacy(entry.effective_from())
            }
        })
    }

    fn effective_from_at(&self, at_ms: u64) -> u64 {
        let history = self.0.lock().unwrap().clone();
        let view = history.current();
        view.entry_at(at_ms).map_or(0, |e| e.effective_from())
    }

    fn history(&self) -> Option<Arc<History>> {
        Some(self.0.lock().unwrap().clone())
    }
}

static SERIAL: Mutex<()> = Mutex::new(());

#[path = "../../busbar/src/tests/kernel_application/external_dated_budget_raw.rs"]
mod raw_provenance;

fn holder_opening(card: RateCard) -> (&'static Holder, std::sync::MutexGuard<'static, ()>) {
    static HOLDER: std::sync::OnceLock<&'static Holder> = std::sync::OnceLock::new();
    let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let holder = *HOLDER.get_or_init(|| {
        let opening = Arc::new(History::opening(history_card(0.0), 0));
        let holder: &'static Holder = Box::leak(Box::new(Holder(
            Mutex::new(opening),
            std::sync::atomic::AtomicBool::new(false),
        )));
        busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
            rate_epoch: Some(holder),
            ..Default::default()
        });
        holder
    });
    *holder.0.lock().unwrap() = Arc::new(History::opening(card, 0));
    holder.1.store(false, std::sync::atomic::Ordering::Relaxed);
    (holder, serial)
}

fn history_card(input_utok: f64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", "input"), input_utok)], 0)
}

fn cost(input_utok: f64, cap: u64) -> CostModel {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let card = BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok,
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: cap,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), 0, &groups)
}

fn input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".to_string(), n)])
}

#[test]
fn a_card_edit_mid_window_prices_every_budget_read_and_the_gate_at_the_card_in_force() {
    let (holder, _serial) = holder_opening(history_card(20.0));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = VirtualKey {
        id: "vk_dated".to_string(),
        generation_hash: "hash-dated".to_string(),
        name: "dated".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let now = busbar_kernel::store::now();

    let before = cost(20.0, 1_300);
    gov.try_admit(&before, &key, "", now)
        .expect("under the cap");
    gov.record_usage(&before, &key, "", "m", &input(300_000), now);

    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: history_card(10.0),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }
    std::thread::sleep(std::time::Duration::from_millis(2));
    let after = cost(10.0, 1_300);
    gov.try_admit(&after, &key, "", now)
        .expect("600 spent, under the cap");
    gov.record_usage(&after, &key, "", "m", &input(900_000), now);

    let reference = {
        let history = holder.0.lock().unwrap().clone();
        price_in_view(
            &[
                LedgerEntry::new("m", 0).with_whole("input", 300_000),
                LedgerEntry::new("m", edit_ms).with_whole("input", 900_000),
            ],
            &history.current(),
        )
        .unwrap()
        .minor_i64()
        .unwrap()
    };
    assert_eq!(reference, 1_500, "the dated read of the worked example");

    let team = &after.group_named("team").expect("configured").buckets[0];
    let group_read = gov
        .derived_bucket_usage(&after, &team.bucket_id, team.window, true, now)
        .expect("priced");
    assert_eq!(
        group_read.spend_cents, reference,
        "GET /groups/team/usage and the group spend gauge (1,200 = the current card repricing the \
         window's first 300,000 tokens)"
    );
    let key_read = gov
        .usage_for(&after, &key.id, now)
        .expect("priced")
        .expect("the key exists");
    assert_eq!(
        key_read.spend_cents, reference,
        "GET /keys/vk_dated/usage and the key spend gauge"
    );
    let hook = gov.budget_state(&after, &key, now);
    let team_hook = hook
        .iter()
        .find(|b| b.bucket_id == team.bucket_id)
        .expect("the hook view includes the configured team's budget");
    assert_eq!(team_hook.budget_group.as_deref(), Some("team"));
    assert_eq!(
        team_hook.remaining_micros,
        Some(0),
        "the dated spend leaves the team's hook view no headroom"
    );
    assert!(
        hook.iter()
            .all(|b| b.spend_micros_at_current_rate == reference * 10_000),
        "the hook seam's budget_state: {hook:?}"
    );

    match gov.try_admit(&after, &key, "", now) {
        Err(LimitBlocked::Limit { metric, group, .. }) => {
            assert_eq!((metric, group.as_str()), ("budget", "team"));
        }
        other => panic!("the gate must refuse on the dated 1,500: {other:?}"),
    }

    gov.flush_budgets();
    let window = busbar_kernel::governance::budget_window(team.window, now);
    let row = store.get_usage(&team.bucket_id, window).unwrap();
    assert_eq!(row.models.len(), 1, "{row:?}");
    assert_eq!(row.models[0].usage_units.get("input"), Some(&1_200_000));
}

fn edit_card(holder: &Holder, card: RateCard) {
    let at = busbar_kernel::store::now_ms();
    let mut history = holder.0.lock().unwrap();
    let mut next = History::clone(&history);
    next.append(CardEntryDraft {
        effective_from: at,
        effective_until: None,
        card,
        appended_at: at,
        author: Author::Config { policy_epoch: 1 },
    });
    *history = Arc::new(next);
    drop(history);
    std::thread::sleep(std::time::Duration::from_millis(2));
}

#[test]
fn a_clean_restart_after_a_card_edit_keeps_identical_money_and_headroom() {
    let (holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), "vk_restart");
    let now = busbar_kernel::store::now();
    let reads = |gov: &GovState, cost: &CostModel| {
        let team = &cost.group_named("team").expect("configured").buckets[0];
        let group = (gov.derived_bucket_usage(cost, &team.bucket_id, team.window, true, now))
            .expect("priced")
            .spend_cents;
        let own = (gov.usage_for(cost, &key.id, now))
            .expect("priced")
            .expect("exists")
            .spend_cents;
        let headroom: Vec<_> = (gov.budget_state(cost, &key, now).into_iter())
            .map(|b| (b.bucket_id, b.remaining_micros))
            .collect();
        (group, own, headroom)
    };

    let before = cost(20.0, 1_000_000);
    let gov = GovState::new(store.clone(), None).unwrap();
    gov.try_admit(&before, &key, "", now).expect("admits");
    gov.record_usage(&before, &key, "", "m", &input(300_000), now);
    edit_card(holder, history_card(10.0));
    let after = cost(10.0, 1_000_000);
    gov.try_admit(&after, &key, "", now).expect("admits");
    gov.record_usage(&after, &key, "", "m", &input(900_000), now);
    let seen = reads(&gov, &after);
    assert_eq!((seen.0, seen.1), (1_500, 1_500), "the dated figure");
    gov.flush_budgets();
    drop(gov);

    let gov = GovState::new(store.clone(), None).unwrap();
    let cold = reads(&gov, &after);
    assert_eq!((cold.0, cold.1), (seen.0, seen.1), "read from the store");
    gov.hydrate_budgets(&after, now).expect("hydrate");
    assert_eq!(reads(&gov, &after), seen, "read from the hydrated cells");
}

fn row(tokens: u64) -> busbar_contract::records::UsageLedger {
    busbar_contract::records::UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: "m".to_string(),
            usage_units: BTreeMap::from([("input".to_string(), tokens)]),
        }],
    }
}

#[test]
fn a_durable_row_prices_as_the_cell_hydrated_from_it_after_a_card_edit() {
    let (holder, _serial) = holder_opening(history_card(20.0));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = VirtualKey {
        id: "vk_durable".to_string(),
        generation_hash: "hash-durable".to_string(),
        name: "durable".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let now = busbar_kernel::store::now();
    let current = cost(10.0, 1_000_000);
    let team = &current.group_named("team").expect("configured").buckets[0];
    let key_window = budget_window(WINDOW_TOTAL, now);
    let team_window = budget_window(team.window, now);
    store.put_usage(&key.id, key_window, &row(300_000)).unwrap();
    store
        .put_usage(&team.bucket_id, team_window, &row(300_000))
        .unwrap();

    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: history_card(10.0),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }

    let gov = GovState::new(store.clone(), None).unwrap();
    let reads = |gov: &GovState| {
        let key_read = gov
            .usage_for(&current, &key.id, now)
            .expect("priced")
            .expect("the key exists")
            .spend_cents;
        let team_read = gov
            .derived_bucket_usage(&current, &team.bucket_id, team.window, true, now)
            .expect("priced")
            .spend_cents;
        (key_read, team_read)
    };

    let from_store = reads(&gov);
    gov.hydrate_budgets(&current, now).expect("hydrate");
    let from_cell = reads(&gov);

    assert_eq!(
        from_cell,
        (600, 600),
        "the hydrated cell prices era zero at the card in force when the window opened"
    );
    assert_eq!(
        from_store, from_cell,
        "a read that reaches the store must answer what the cell hydrated from it answers \
         (300 = the current card repricing the stored window)"
    );
}

fn fee_cost(fee_cents: i64) -> CostModel {
    let card = BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            ..Default::default()
        },
    )]);
    let groups = BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), fee_cents, &groups)
}

fn fee_card(fee_cents: i64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", "input"), 1.0)], fee_cents)
}

#[test]
fn a_fee_refund_returns_the_fee_of_the_era_its_request_was_charged_in() {
    let (holder, _serial) = holder_opening(fee_card(5));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = VirtualKey {
        id: "vk_era_refund".to_string(),
        generation_hash: "hash-era-refund".to_string(),
        name: "era-refund".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let now = busbar_kernel::store::now();

    let before = fee_cost(5);
    let a = (gov.try_admit(&before, &key, "", now)).expect("A admits at fee 5");

    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: fee_card(10),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }
    std::thread::sleep(std::time::Duration::from_millis(2));
    let after = fee_cost(10);
    gov.try_admit(&after, &key, "", now)
        .expect("B admits at fee 10");
    let spend = |gov: &GovState| {
        (gov.usage_for(&after, &key.id, now))
            .expect("priced")
            .expect("the key exists")
            .spend_cents
    };
    assert_eq!(spend(&gov), 15, "A's 5 and B's 10");

    gov.refund_charge(a.charge());
    assert_eq!(spend(&gov), 10, "A's fee came back; B's 10 is owed");

    gov.flush_budgets();
    drop(gov);
    let gov = GovState::new(store.clone(), None).unwrap();
    assert_eq!(spend(&gov), 10, "read from the store after restart");
    gov.hydrate_budgets(&after, now).expect("hydrate");
    assert_eq!(spend(&gov), 10, "read from the hydrated cell");
}

#[test]
fn a_plane_fee_edit_prices_each_admission_at_the_plane_fee_in_force() {
    use busbar_kernel_ledger::cost::{PlaneFees, PLANE_LANE_SEP};
    let fees = |per_request| {
        busbar_kernel::config::PlaneFeesMap::from([(
            "tp".to_string(),
            PlaneFees {
                per_request,
                per_session: 0,
            },
        )])
    };
    let card = |per_request| {
        let fees = fees(per_request);
        fee_card(0).with_plane_fees(fees.iter().map(|(p, f)| (p.as_str(), *f)))
    };
    let (holder, _serial) = holder_opening(card(1));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = VirtualKey {
        id: "vk_plane_fee_epoch".to_string(),
        generation_hash: "hash-plane-fee-epoch".to_string(),
        name: "plane-fee-epoch".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let now = busbar_kernel::store::now();
    let pool = format!("tp{PLANE_LANE_SEP}probe");

    let before = fee_cost(0).with_plane_fees(&fees(1));
    gov.try_admit(&before, &key, &pool, now)
        .expect("A admits at the plane fee 1");
    let spend = |gov: &GovState, cost: &CostModel| {
        (gov.usage_for(cost, &key.id, now))
            .expect("priced")
            .expect("the key exists")
            .spend_cents
    };
    assert_eq!(spend(&gov, &before), 1, "A at the opening card's plane fee");

    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: card(7),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }
    let after = fee_cost(0).with_plane_fees(&fees(7));
    assert_eq!(
        spend(&gov, &after),
        1,
        "publishing a card never reprices the request admitted before it"
    );
    std::thread::sleep(std::time::Duration::from_millis(2));
    gov.try_admit(&after, &key, &pool, now)
        .expect("B admits at the plane fee 7");
    assert_eq!(
        spend(&gov, &after),
        8,
        "each request at the plane fee in force when it was admitted (2 = opening forever, 14 = \
         newest card)"
    );
}

fn metered(store: &dyn RecordStore, key_id: &str, at: u64, n: u64, era: u64) {
    store
        .add_metering(&busbar_contract::records::MeteringDelta {
            key_id: key_id.to_string(),
            bucket: busbar_kernel::governance::metering_bucket(at),
            model: "m".to_string(),
            provider: String::new(),
            tokens_input: n,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: String::new(),
            priced_from_ms: era,
            usage_units: Default::default(),
        })
        .unwrap();
}

fn team_key(store: &dyn RecordStore, id: &str) -> VirtualKey {
    let key = VirtualKey {
        id: id.to_string(),
        generation_hash: format!("hash-{id}"),
        name: id.to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.put_key(&key).unwrap();
    key
}

#[test]
fn a_correction_lands_in_its_units_own_window_and_card_entry() {
    use busbar_kernel::governance::{metering_bucket, Adjustment, UsageAdjustment};
    let (holder, _serial) = holder_opening(history_card(20.0));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), "vk_own_epoch");
    let gov = GovState::new(store.clone(), None).unwrap();
    let today = busbar_kernel::store::now();
    let yesterday = today - 86_400;

    let card_a = cost(20.0, 1_000_000);
    gov.record_usage(&card_a, &key, "", "m", &input(300_000), yesterday);
    metered(store.as_ref(), &key.id, yesterday, 300_000, 0);
    gov.flush_budgets();

    let edit_ms = busbar_kernel::store::now_ms();
    {
        let mut history = holder.0.lock().unwrap();
        let mut next = History::clone(&history);
        next.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: history_card(10.0),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        *history = Arc::new(next);
    }
    std::thread::sleep(std::time::Duration::from_millis(2));
    let card_b = cost(10.0, 1_000_000);
    gov.record_usage(&card_b, &key, "", "m", &input(100_000), today);
    metered(store.as_ref(), &key.id, today, 100_000, edit_ms);

    let delta = BTreeMap::from([("input".to_string(), -100_000i64)]);
    let correction = Adjustment {
        key_id: &key.id,
        pool: "",
        model: "m",
        entry_era: 0,
        entry_id: None,
        card_epoch_ms: yesterday * 1_000,
        delta: &delta,
        now: today,
    };
    gov.adjust_usage(&card_b, &correction)
        .expect("the store reads")
        .expect("the correction lands in its unit's own window and card entry");
    gov.flush_budgets();

    let team = &card_b.group_named("team").expect("configured").buckets[0];
    let window = |at: u64| {
        let read = gov
            .derived_bucket_usage(&card_b, &team.bucket_id, team.window, true, at)
            .expect("priced");
        (read.tokens, read.spend_cents)
    };
    assert_eq!(
        window(yesterday),
        (200_000, 400),
        "yesterday's window holds the corrected unit, priced at A"
    );
    assert_eq!(
        window(today),
        (100_000, 100),
        "today's window is not the unit's: untouched"
    );
    let key_read = gov
        .usage_for(&card_b, &key.id, today)
        .expect("priced")
        .expect("the key exists");
    assert_eq!(
        (key_read.tokens, key_read.spend_cents),
        (300_000, 500),
        "200,000 at A and 100,000 at B (600 = the correction taken off B's segment)"
    );
    assert_eq!(
        gov.usage_adjustments(metering_bucket(yesterday)).unwrap(),
        vec![UsageAdjustment {
            key_id: key.id.clone(),
            lane: "m".to_string(),
            era: 0,
            entry_id: None,
            delta: BTreeMap::from([("input".to_string(), -100_000)]),
        }],
        "the metered view carries the correction on the unit's own day"
    );
    assert!(
        gov.usage_adjustments(metering_bucket(today))
            .unwrap()
            .is_empty(),
        "and nothing on today's"
    );
}

#[test]
fn a_correction_whose_window_no_longer_holds_its_segment_is_refused_and_moves_nothing() {
    use busbar_kernel::governance::{metering_bucket, Adjustment};
    let (_holder, _serial) = holder_opening(history_card(20.0));

    let store: Arc<dyn RecordStore> = real_store::store();
    let key = team_key(store.as_ref(), "vk_gone_epoch");
    let gov = GovState::new(store.clone(), None).unwrap();
    let today = busbar_kernel::store::now();
    let yesterday = today - 86_400;
    let card = cost(20.0, 1_000_000);

    metered(store.as_ref(), &key.id, yesterday, 1_000, 0);

    gov.record_usage(&card, &key, "", "m", &input(1_000), today);
    metered(store.as_ref(), &key.id, today, 1_000, 0);

    let team = &card.group_named("team").expect("configured").buckets[0];
    let reads = |gov: &GovState| {
        let key_read = gov
            .usage_for(&card, &key.id, today)
            .expect("priced")
            .expect("the key exists");
        let team_read = gov
            .derived_bucket_usage(&card, &team.bucket_id, team.window, true, today)
            .expect("priced");
        (key_read.tokens, team_read.tokens, team_read.spend_cents)
    };
    assert_eq!(reads(&gov), (1_000, 1_000, 2));

    let delta = BTreeMap::from([("input".to_string(), -500i64)]);
    let correction = Adjustment {
        key_id: &key.id,
        pool: "",
        model: "m",
        entry_era: 0,
        entry_id: None,
        card_epoch_ms: yesterday * 1_000,
        delta: &delta,
        now: today,
    };
    let refused = gov
        .adjust_usage(&card, &correction)
        .expect("the store reads")
        .expect_err("a correction with nowhere to land in its own window is refused");
    let why = refused.to_string();
    assert!(
        why.contains(&team.bucket_id)
            && why.contains("may not take the \"input\" count below zero"),
        "the refusal names the bucket and why: {why}"
    );

    gov.flush_budgets();
    assert_eq!(reads(&gov), (1_000, 1_000, 2), "no count moved");
    let gone = store
        .get_usage(&team.bucket_id, budget_window(team.window, yesterday))
        .unwrap();
    assert!(
        gone.models.is_empty(),
        "yesterday's window gained nothing: {gone:?}"
    );
    for day in [yesterday, today] {
        assert!(
            gov.usage_adjustments(metering_bucket(day))
                .unwrap()
                .is_empty(),
            "no metered adjustment row was written"
        );
    }
}
