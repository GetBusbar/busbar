// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MONEY-DESIGN §3b-§3d, PR-B2: counts recorded off the request path, segmented by the card entry
//! that priced them, survive a kill and a restart with the SAME money and headroom, and give one
//! node exactly 1.5.5's cap answers.
//!
//! A test BINARY of its own: the dated history is reached through the process-wide rate-epoch
//! holder, which this file installs once and every test re-opens under one lock.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::records::{RecordStore, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::{GovState, LimitBlocked, MemoryStore};
use busbar_kernel::posting::recorder::{Medium, PostStore, Recorder, RecordsOnly};
use busbar_kernel::posting::{spool::DataSync, TmpDir};
use busbar_kernel::rate_apply::RateEpoch;
use busbar_kernel::test_support::rate_holders::install_rate_epoch;
use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History, LaneClass, RateCard};

struct Holder(Mutex<Arc<History>>);

impl RateEpoch for Holder {
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

fn holder_opening(card: RateCard) -> (&'static Holder, std::sync::MutexGuard<'static, ()>) {
    static HOLDER: std::sync::OnceLock<&'static Holder> = std::sync::OnceLock::new();
    let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let holder = *HOLDER.get_or_init(|| {
        let opening = Arc::new(History::opening(history_card(0.0), 0));
        let holder: &'static Holder = Box::leak(Box::new(Holder(Mutex::new(opening))));
        install_rate_epoch(holder);
        holder
    });
    *holder.0.lock().unwrap() = Arc::new(History::opening(card, 0));
    (holder, serial)
}

fn history_card(input_utok: f64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", "input"), input_utok)], 0)
}

fn edit_card(holder: &Holder, input_utok: f64) {
    let at = busbar_kernel::store::now_ms();
    let mut history = holder.0.lock().unwrap();
    let mut next = History::clone(&history);
    next.append(CardEntryDraft {
        effective_from: at,
        effective_until: None,
        card: history_card(input_utok),
        appended_at: at,
        author: Author::Config { policy_epoch: 1 },
    });
    *history = Arc::new(next);
    drop(history);
    std::thread::sleep(Duration::from_millis(2));
}

/// One group `team` capped at `cap` cents a day, and `requests` requests a day when given.
fn cost(input_utok: f64, cap: u64, requests: Option<u64>) -> CostModel {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let card = BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok,
            ..Default::default()
        },
    )]);
    let limit = |metric, amount| LimitCfg {
        metric,
        amount,
        per: Some(LimitWindow::Day),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let mut limits = vec![limit(LimitMetric::Budget, cap)];
    if let Some(n) = requests {
        limits.push(limit(LimitMetric::Requests, n));
    }
    let groups = BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&card), 0, &groups)
}

fn input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".to_string(), n)])
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

/// A node: a GovState over `store` with its recorder on `medium`, the spool replayed before
/// hydrate, as boot does.
async fn boot(store: &Arc<dyn RecordStore>, medium: &Medium, cost: &CostModel) -> Arc<GovState> {
    let gov = Arc::new(GovState::new(Arc::clone(store), None).unwrap());
    let post: Arc<dyn PostStore> = Arc::new(RecordsOnly(Arc::clone(store)));
    let (rec, recovered) = Recorder::open(
        gov.ledger(),
        post,
        medium,
        false,
        Duration::from_millis(20),
        Arc::new(DataSync),
    )
    .unwrap();
    assert!(rec.drain(false, recovered.deadline()).await, "boot replay");
    gov.attach_recorder(rec);
    gov.hydrate_budgets(cost, busbar_kernel::store::now())
        .unwrap();
    gov.absorb_dead(&recovered.refused_cells);
    gov
}

/// Every money read of the key and its group, and the cap's headroom.
fn reads(gov: &GovState, cost: &CostModel, key: &VirtualKey) -> (i64, i64, Vec<(String, Option<i64>)>) {
    let now = busbar_kernel::store::now();
    let team = &cost.group_named("team").expect("configured").buckets[0];
    let group = gov
        .derived_bucket_usage(cost, &team.bucket_id, team.window, true, now)
        .expect("priced")
        .spend_cents;
    let own = gov
        .usage_for(cost, &key.id, now)
        .expect("priced")
        .expect("exists")
        .spend_cents;
    let headroom = gov
        .budget_state(cost, key, now)
        .into_iter()
        .map(|b| (b.bucket_id, b.remaining_micros))
        .collect();
    (group, own, headroom)
}

/// T1 (DURABILITY and RESTART): spend, edit the card mid-window, spend, then KILL the node after its
/// spool synced and before the store answered, and restart. The reported money and the cap
/// headroom are identical: each segment is priced at its own entry's card, from the sibling row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_spend_survives_a_kill_and_restart_with_identical_money_and_headroom() {
    let (holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t1");
    let dir = TmpDir::new();
    let medium = Medium::Dir(dir.path().to_path_buf());
    let now = busbar_kernel::store::now();

    let before = cost(20.0, 1_000_000, None);
    let gov = boot(&store, &medium, &before).await;
    gov.try_admit(&before, &key, "", now).expect("admits");
    gov.record_usage(&before, &key, "", "m", &input(300_000), now);
    edit_card(holder, 10.0);
    let after = cost(10.0, 1_000_000, None);
    gov.try_admit(&after, &key, "", now).expect("admits");
    gov.record_usage(&after, &key, "", "m", &input(900_000), now);
    let seen = reads(&gov, &after, &key);
    assert_eq!(seen.0, 1_500, "the dated figure before the kill");

    // Half the spend reaches the store; the rest is only spooled when the node dies.
    let rec = gov.recorder().expect("attached");
    assert!(rec.drain(true, Duration::from_secs(5)).await);
    gov.record_usage(&after, &key, "", "m", &input(100_000), now);
    let seen = reads(&gov, &after, &key);
    rec.drain(true, Duration::ZERO).await; // the take is spooled; nothing more is sent
    rec.stop().await;
    drop(gov);

    let gov = boot(&store, &medium, &after).await;
    assert_eq!(reads(&gov, &after, &key), seen, "identical money and headroom after restart");
}

/// T1 without a data directory: identical after a CLEAN shutdown (the drain).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t1_without_a_data_directory_a_clean_shutdown_keeps_identical_money() {
    let (holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t1m");
    let now = busbar_kernel::store::now();
    let before = cost(20.0, 1_000_000, None);
    let gov = boot(&store, &Medium::Memory, &before).await;
    gov.try_admit(&before, &key, "", now).expect("admits");
    gov.record_usage(&before, &key, "", "m", &input(300_000), now);
    edit_card(holder, 10.0);
    let after = cost(10.0, 1_000_000, None);
    gov.record_usage(&after, &key, "", "m", &input(900_000), now);
    let seen = reads(&gov, &after, &key);
    let rec = gov.recorder().expect("attached");
    assert!(rec.drain(true, Duration::from_secs(5)).await, "the clean shutdown drain");
    rec.stop().await;
    drop(gov);
    let gov = boot(&store, &Medium::Memory, &after).await;
    assert_eq!(reads(&gov, &after, &key), seen);
}

/// T12: hydrated counts on one node read as no foreign spend, so the cap answers equal the RAM-only
/// path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_hydrated_counts_on_one_node_are_never_foreign() {
    let (_holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t12");
    let now = busbar_kernel::store::now();
    let c = cost(20.0, 1_000, None);
    let gov = boot(&store, &Medium::Memory, &c).await;
    gov.try_admit(&c, &key, "", now).expect("admits");
    gov.record_usage(&c, &key, "", "m", &input(400_000), now); // 800 cents
    let rec = gov.recorder().unwrap();
    assert!(rec.drain(true, Duration::from_secs(5)).await);
    rec.stop().await;
    drop(gov);

    let gov = boot(&store, &Medium::Memory, &c).await;
    let post = gov.recorder().unwrap().store();
    gov.refresh_snapshot(&c, post.as_ref()).await;
    assert!(
        gov.snapshot().get("group:team@day").is_none_or(|f| f.counts.is_zero()),
        "no foreign spend on one node"
    );
    // 800 spent, cap 1,000: one more request admits, as in RAM.
    let reference = GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
    let rk = team_key(reference.store().as_ref(), "vk_t12");
    reference.try_admit(&c, &rk, "", now).unwrap();
    reference.record_usage(&c, &rk, "", "m", &input(400_000), now);
    assert_eq!(
        gov.try_admit(&c, &key, "", now).is_ok(),
        reference.try_admit(&c, &rk, "", now).is_ok()
    );
}

/// T5: two nodes on one store: B's capped admission sees A's spend after one snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t5_a_second_node_sees_the_first_nodes_spend_after_one_snapshot() {
    let (_holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t5");
    let now = busbar_kernel::store::now();
    let c = cost(20.0, 1_000, None);
    let a = boot(&store, &Medium::Memory, &c).await;
    let b = boot(&store, &Medium::Memory, &c).await;
    // B touches the bucket first (so it has a cell, and the snapshot reads it).
    b.try_admit(&c, &key, "", now).expect("B admits");
    a.try_admit(&c, &key, "", now).expect("A admits");
    a.record_usage(&c, &key, "", "m", &input(600_000), now); // 1,200 cents: over the cap
    assert!(a.recorder().unwrap().drain(true, Duration::from_secs(5)).await);
    assert!(b.try_admit(&c, &key, "", now).is_ok(), "before a snapshot, B sees only itself");
    let post = b.recorder().unwrap().store();
    b.refresh_snapshot(&c, post.as_ref()).await;
    match b.try_admit(&c, &key, "", now) {
        Err(LimitBlocked::Limit { metric, .. }) => assert_eq!(metric, "budget"),
        other => panic!("B must refuse on A's spend: {other:?}"),
    }
}

/// T6 and T6b (CAP PARITY): a concurrent stress of admissions and settlements against a requests
/// and a budget cap, with a card edit mid-window, gives the same accept and refuse counts as the
/// RAM-only path. On one node the recorder changes no answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t6_t6b_concurrent_admissions_and_settlements_match_the_ram_only_path() {
    let (holder, _serial) = holder_opening(history_card(20.0));
    let run = |recorded: bool| {
        let holder = holder;
        async move {
            *holder.0.lock().unwrap() = Arc::new(History::opening(history_card(20.0), 0));
            let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
            let key = team_key(store.as_ref(), "vk_t6");
            let c = Arc::new(cost(20.0, 2_000, Some(150)));
            let gov = if recorded {
                let g = boot(&store, &Medium::Memory, &c).await;
                g.recorder().unwrap().spawn();
                g
            } else {
                Arc::new(GovState::new(store, None).unwrap())
            };
            let now = busbar_kernel::store::now();
            let (ok, refused) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(Vec::new())));
            let mut joins = Vec::new();
            for t in 0..8 {
                let (gov, key, c, ok, refused) =
                    (Arc::clone(&gov), key.clone(), Arc::clone(&c), Arc::clone(&ok), Arc::clone(&refused));
                joins.push(std::thread::spawn(move || {
                    for i in 0..30 {
                        match gov.try_admit(&c, &key, "", now) {
                            Ok(grant) => {
                                *ok.lock().unwrap() += 1;
                                gov.record_usage(&c, &key, "", "m", &input(1_000), now);
                                if (t + i) % 5 == 0 {
                                    gov.refund_charge(grant.charge());
                                }
                            }
                            Err(e) => refused.lock().unwrap().push(format!("{e:?}")),
                        }
                    }
                }));
                if t == 4 {
                    edit_card(holder, 10.0);
                }
            }
            for j in joins {
                j.join().unwrap();
            }
            let mut refused = refused.lock().unwrap().clone();
            refused.sort();
            let ok = *ok.lock().unwrap();
            (ok, refused)
        }
    };
    let ram = run(false).await;
    let recorded = run(true).await;
    assert_eq!(ram.0 + ram.1.len(), 240);
    assert!(ram.1.iter().any(|r| r.contains("requests")), "the requests cap bit: {ram:?}");
    assert_eq!(recorded.0, ram.0, "the same accepts");
    assert_eq!(recorded.1, ram.1, "the same refusals, the same bodies");
}

/// T20 and T24: an admission refused after its charge (NoDestination: the fee refunded, the request
/// kept), and a unit straddling a window boundary (its refund after the roll lands on ITS window):
/// after a restart the store matches RAM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t20_t24_refunds_and_straddles_restart_to_what_ram_applied() {
    let (_holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t20");
    let c = cost(20.0, 1_000_000, None);
    let gov = boot(&store, &Medium::Memory, &c).await;
    let now = busbar_kernel::store::now();
    // T20: charged, then refused after the charge: the fee comes back, the request stays.
    let g = gov.try_admit(&c, &key, "", now).unwrap();
    gov.refund_charge(g.charge());
    let before = reads(&gov, &c, &key);
    assert!(gov.recorder().unwrap().drain(true, Duration::from_secs(5)).await);
    let team = &c.group_named("team").unwrap().buckets[0];
    let window = busbar_kernel::governance::budget_window(team.window, now);
    let row = store.get_usage(&team.bucket_id, window).unwrap();
    assert_eq!((row.requests, row.billable_requests), (1, 0), "T20: the store matches RAM");
    drop(gov);
    let gov = boot(&store, &Medium::Memory, &c).await;
    assert_eq!(reads(&gov, &c, &key), before);

    // T24: admitted in window W, the cell rolled to W+1 by another admission, then refunded: the -1
    // lands on W's row, never on W+1's.
    let w = window;
    let w1 = w + busbar_kernel::governance::SECS_PER_DAY;
    let g = gov.try_admit(&c, &key, "", w).unwrap();
    gov.try_admit(&c, &key, "", w1).unwrap();
    gov.refund_charge(g.charge());
    assert!(gov.recorder().unwrap().drain(true, Duration::from_secs(5)).await);
    let row_w = store.get_usage(&team.bucket_id, w).unwrap();
    let row_w1 = store.get_usage(&team.bucket_id, w1).unwrap();
    assert_eq!((row_w.requests, row_w.billable_requests), (2, 0), "T24: W's refund on W");
    assert_eq!((row_w1.requests, row_w1.billable_requests), (1, 1), "W+1 untouched");
}

/// T26: a key deleted while its spend is still unrecorded: all of it is still recorded, and its
/// in-flight unit's refund (no cell any more) still nets out; a re-created group starts at zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t26_a_delete_loses_no_counts_and_a_recreated_group_starts_at_zero() {
    let (_holder, _serial) = holder_opening(history_card(20.0));
    let store: Arc<dyn RecordStore> = Arc::new(MemoryStore::new());
    let key = team_key(store.as_ref(), "vk_t26");
    let c = cost(20.0, 1_000_000, None);
    let gov = boot(&store, &Medium::Memory, &c).await;
    let now = busbar_kernel::store::now();
    gov.try_admit(&c, &key, "", now).unwrap();
    let inflight = gov.try_admit(&c, &key, "", now).unwrap();
    gov.record_usage(&c, &key, "", "m", &input(1_000), now);
    gov.delete_key(&key.id).unwrap();
    gov.reclaim_group_cells("team");
    // The in-flight unit ends after the delete: its fee comes back though no cell is left.
    gov.refund_charge(inflight.charge());
    assert!(gov.recorder().unwrap().drain(true, Duration::from_secs(5)).await);
    let team = &c.group_named("team").unwrap().buckets[0];
    let window = busbar_kernel::governance::budget_window(team.window, now);
    let row = store.get_usage(&team.bucket_id, window).unwrap();
    assert_eq!((row.requests, row.billable_requests), (2, 1), "nothing discarded, refund netted");
    // A re-created group starts at zero in RAM, and its old rows are not foreign spend.
    let other = team_key(store.as_ref(), "vk_t26b");
    let post = gov.recorder().unwrap().store();
    gov.try_admit(&c, &other, "", now).unwrap();
    gov.refresh_snapshot(&c, post.as_ref()).await;
    let usage = gov
        .derived_bucket_usage(&c, &team.bucket_id, team.window, true, now)
        .unwrap();
    assert_eq!(usage.requests, 1, "the re-created group counts only its own request");
}
