// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::records::{ModelTokens, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::{budget_window, GovState, LimitBlocked, WINDOW_TOTAL};
use busbar_kernel::persistence;
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

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[path = "../../busbar/src/tests/kernel_application/external_dated_budget_raw.rs"]
mod raw_provenance;

async fn holder_opening(card: RateCard) -> (&'static Holder, tokio::sync::MutexGuard<'static, ()>) {
    static HOLDER: std::sync::OnceLock<&'static Holder> = std::sync::OnceLock::new();
    let serial = SERIAL.lock().await;
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
                selected: None,
                metric: LimitMetric::Budget,
                amount: cap,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), 0, &groups)
}

fn input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".to_string(), n)])
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

fn row(tokens: u64) -> busbar_contract::records::UsageLedger {
    busbar_contract::records::UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            scale: 0,
            model: "m".to_string(),
            usage_units: BTreeMap::from([("input".to_string(), i128::from(tokens))]),
        }],
    }
}

#[tokio::test]
async fn a_durable_row_prices_as_the_cell_hydrated_from_it_after_a_card_edit() {
    let (holder, _serial) = holder_opening(history_card(20.0)).await;

    let store = real_store::core().await;
    let key = VirtualKey {
        id: "vk_durable".to_string(),
        generation_hash: "hash-durable".to_string(),
        name: "durable".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.identity().put_key(&key).await.unwrap();
    let now = busbar_kernel::store::now();
    let current = cost(10.0, 1_000_000);
    let team = &current.group_named("team").expect("configured").buckets[0];
    let key_window = budget_window(WINDOW_TOTAL, now);
    let team_window = budget_window(team.window, now);
    store
        .ledger()
        .put_usage(&key.id, key_window, &row(300_000))
        .await
        .unwrap();
    store
        .ledger()
        .put_usage(&team.bucket_id, team_window, &row(300_000))
        .await
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

    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    let reads = async |gov: &GovState| {
        let key_read = gov
            .usage_for_async(&current, &key.id, now)
            .await
            .expect("priced")
            .expect("the key exists")
            .spend_cents;
        let team_read = gov
            .derived_bucket_usage_async(&current, &team.bucket_id, team.window, true, now)
            .await
            .expect("priced")
            .spend_cents;
        (key_read, team_read)
    };

    let from_store = reads(&gov).await;
    gov.hydrate_budgets_async(&current, now)
        .await
        .expect("hydrate");
    let from_cell = reads(&gov).await;

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

#[tokio::test]
async fn a_fee_refund_returns_the_fee_of_the_era_its_request_was_charged_in() {
    let (holder, _serial) = holder_opening(fee_card(5)).await;

    let store = real_store::core().await;
    let key = VirtualKey {
        id: "vk_era_refund".to_string(),
        generation_hash: "hash-era-refund".to_string(),
        name: "era-refund".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.identity().put_key(&key).await.unwrap();
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
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
    let spend = async |gov: &GovState| {
        (gov.usage_for_async(&after, &key.id, now).await)
            .expect("priced")
            .expect("the key exists")
            .spend_cents
    };
    assert_eq!(spend(&gov).await, 15, "A's 5 and B's 10");

    gov.refund_charge(a.charge());
    assert_eq!(spend(&gov).await, 10, "A's fee came back; B's 10 is owed");

    gov.flush_budgets().await;
    drop(gov);
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(spend(&gov).await, 10, "read from the store after restart");
    gov.hydrate_budgets_async(&after, now)
        .await
        .expect("hydrate");
    assert_eq!(spend(&gov).await, 10, "read from the hydrated cell");
}

#[tokio::test]
async fn a_plane_fee_edit_prices_each_admission_at_the_plane_fee_in_force() {
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
    let (holder, _serial) = holder_opening(card(1)).await;

    let store = real_store::core().await;
    let key = VirtualKey {
        id: "vk_plane_fee_epoch".to_string(),
        generation_hash: "hash-plane-fee-epoch".to_string(),
        name: "plane-fee-epoch".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.identity().put_key(&key).await.unwrap();
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    let now = busbar_kernel::store::now();
    let pool = format!("tp{PLANE_LANE_SEP}probe");

    let before = fee_cost(0).with_plane_fees(&fees(1));
    gov.try_admit(&before, &key, &pool, now)
        .expect("A admits at the plane fee 1");
    let spend = async |gov: &GovState, cost: &CostModel| {
        (gov.usage_for_async(cost, &key.id, now).await)
            .expect("priced")
            .expect("the key exists")
            .spend_cents
    };
    assert_eq!(
        spend(&gov, &before).await,
        1,
        "A at the opening card's plane fee"
    );

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
        spend(&gov, &after).await,
        1,
        "publishing a card never reprices the request admitted before it"
    );
    std::thread::sleep(std::time::Duration::from_millis(2));
    gov.try_admit(&after, &key, &pool, now)
        .expect("B admits at the plane fee 7");
    assert_eq!(
        spend(&gov, &after).await,
        8,
        "each request at the plane fee in force when it was admitted (2 = opening forever, 14 = \
         newest card)"
    );
}

async fn metered(store: &persistence::facade::CoreStore, key_id: &str, at: u64, n: u64, era: u64) {
    store
        .ledger()
        .add_metering(&busbar_contract::records::MeteringDelta {
            pricing: None,
            scale: 0,
            key_id: key_id.to_string(),
            bucket: busbar_kernel::governance::metering_bucket(at),
            model: "m".to_string(),
            provider: String::new(),
            tokens_input: i128::from(n),
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
        .await
        .unwrap();
}

async fn team_key(store: &persistence::facade::CoreStore, id: &str) -> VirtualKey {
    let key = VirtualKey {
        id: id.to_string(),
        generation_hash: format!("hash-{id}"),
        name: id.to_string(),
        enabled: true,
        group: Some("team".to_string()),
        ..Default::default()
    };
    store.identity().put_key(&key).await.unwrap();
    key
}

