// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission reads the unit-checkpoint custody book without walking it (throughput-decay).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use busbar_contract::Count;

use super::*;
use crate::governance::recovery::{RecoveryError, RecoveryEvent, RecoverySink};
use crate::governance::{LimitBlocked, VirtualKey};

const AT: u64 = 1_700_000_000;
const LIVE: usize = 10_000;

#[derive(Default)]
struct Journal(Mutex<Vec<RecoveryEvent>>);
#[async_trait::async_trait]
impl RecoverySink for Journal {
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let mut events = self.0.lock().unwrap();
        if !events.contains(event) {
            events.push(event.clone());
        }
        Ok(())
    }
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Replays the given units once and refuses removal while `stuck` holds, so recovered custody
/// stays unresolved.
struct Sink {
    replay: Mutex<Vec<UnitCheckpoint>>,
    stuck: AtomicBool,
}
#[async_trait::async_trait]
impl UnitCheckpointSink for Sink {
    async fn persist(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
    async fn remove(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        if self.stuck.load(Ordering::SeqCst) {
            return Err(error("test sink keeps custody unresolved"));
        }
        Ok(())
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        Ok(std::mem::take(&mut *self.replay.lock().unwrap()))
    }
}

fn id(n: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_be_bytes());
    id
}

fn unit(n: u64, unit: u64, targets: &[(&str, u64)], units: &[(&str, Count)]) -> UnitCheckpoint {
    UnitCheckpoint {
        id: id(n),
        revision: 0,
        unit,
        principal: "p".into(),
        group: "A".into(),
        arrived: AT,
        lane: "m".into(),
        provider: None,
        era_at: 0,
        era_entry: None,
        units: units.iter().map(|(c, n)| ((*c).into(), *n)).collect(),
        targets: targets
            .iter()
            .map(|(bucket, window)| UnitTarget {
                bucket: (*bucket).to_owned(),
                window: *window,
                group: None,
            })
            .collect(),
        metered: false,
        ended: false,
        terminal: None,
        audit: None,
        measurement: None,
        unread: None,
    }
}

/// A recovered, ended, already-persisted unit with no outstanding operations.
fn recovered(n: u64, bucket: &str) -> UnitCheckpoint {
    UnitCheckpoint {
        ended: true,
        terminal: Some(Vec::new()),
        ..unit(n, n, &[(bucket, 0)], &[])
    }
}

fn key(group: &str) -> VirtualKey {
    VirtualKey {
        id: format!("vk_{group}"),
        generation_hash: format!("gen-{group}"),
        name: "k".into(),
        enabled: true,
        created_at: AT,
        group: Some(group.into()),
        revision: 1,
        ..Default::default()
    }
}

fn cost(groups: &[&str]) -> crate::cost::CostModel {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let groups = groups
        .iter()
        .map(|name| {
            (
                (*name).to_string(),
                crate::config::GroupCfg {
                    enabled: true,
                    limits: vec![LimitCfg {
                        metric: LimitMetric::Budget,
                        amount: u64::MAX / 4,
                        per: Some(LimitWindow::Total),
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                        admission: None,
                        on_exhaustion: None,
                    }],
                    ..Default::default()
                },
            )
        })
        .collect();
    crate::cost::CostModel::resolve_parts(None, 0, &groups)
}

fn budget_refusal(group: &str) -> LimitBlocked {
    LimitBlocked::Limit {
        group: group.into(),
        metric: "budget",
        window: Some("total"),
        pool: None,
        downgrade_to: None,
        retry_after: None,
    }
}

async fn gov(replay: Vec<UnitCheckpoint>) -> (GovState, Arc<Sink>) {
    let gov = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(Arc::new(Journal::default()))
        .await
        .unwrap();
    let sink = Arc::new(Sink {
        replay: Mutex::new(replay),
        stuck: AtomicBool::new(true),
    });
    gov.attach_unit_checkpoint_sink(sink.clone()).await.unwrap();
    (gov, sink)
}

fn stage_live(gov: &GovState, from: u64, count: usize) {
    for n in from..from + count as u64 {
        gov.stage_unit_checkpoint(unit(n, n, &[("group:C@total", 0)], &[]));
    }
}

type Admit = Result<(), LimitBlocked>;

/// Admit each key on another thread while this thread holds the book. A walk under the book's
/// lock cannot answer until the hold ends, so it fails here instead of hanging.
fn admit_while_book_held(
    gov: &GovState,
    cost: &crate::cost::CostModel,
    keys: &[&VirtualKey],
) -> Vec<Admit> {
    let expected = std::collections::BTreeMap::new();
    let held = gov.hold_unit_checkpoint_book();
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        scope.spawn(move || {
            for key in keys {
                let answer = gov
                    .try_admit_estimated_counts(cost, key, "", AT, &[], &expected)
                    .map(drop);
                let _ = tx.send(answer);
            }
        });
        let answers: Vec<_> = keys
            .iter()
            .map(|_| rx.recv_timeout(Duration::from_secs(1)))
            .collect();
        drop(held);
        answers
            .into_iter()
            .map(|answer| answer.expect("admission waited on the unit-checkpoint book"))
            .collect()
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_skips_pending_book_without_recovered_units() {
    let (gov, _sink) = gov(Vec::new()).await;
    stage_live(&gov, 1_000, LIVE);
    let cost = cost(&["A", "B", "C", "D"]);
    let a = key("A");
    assert_eq!(admit_while_book_held(&gov, &cost, &[&a]), vec![Ok(())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_with_one_recovered_unit_ignores_live_book() {
    let (gov, _sink) = gov(vec![recovered(1, "group:A@total")]).await;
    assert!(
        gov.unit_checkpoint_pending(&id(1)),
        "recovered custody stays unresolved"
    );
    stage_live(&gov, 1_000, LIVE);
    let cost = cost(&["A", "B", "C", "D"]);
    let (a, b) = (key("A"), key("B"));
    assert_eq!(
        admit_while_book_held(&gov, &cost, &[&b, &a]),
        vec![Ok(()), Err(budget_refusal("A"))]
    );
}

/// Rebuilds every derived structure from the map, then checks admission's answer against a walk.
fn assert_index_matches(gov: &GovState) {
    gov.check_unit_checkpoint_book();
    for bucket in [
        "group:A@total",
        "group:B@total",
        "group:C@total",
        "group:D@total",
    ] {
        for window in [0, 60] {
            assert_eq!(
                gov.unresolved_unit_target(bucket, window),
                gov.reference_unresolved_unit_target(bucket, window),
                "{bucket}@{window}"
            );
        }
    }
}

/// Make the next hot apply to `bucket` fail: its raw `work` count is already at the maximum.
fn preload_overflow(gov: &GovState, bucket: &str) {
    let mut cells = gov.budget.write(bucket);
    let cell = cells
        .entry(bucket.to_string())
        .or_insert_with(|| crate::governance::BudgetCell::fresh(0));
    cell.accrue_raw(
        "m",
        busbar_kernel_ledger::cost::RawRateEra::default(),
        &[("work".to_string(), busbar_contract::count::MAX)]
            .into_iter()
            .collect(),
    )
    .unwrap();
}

type Counts = Vec<Vec<(String, Count)>>;

/// The bucket's raw unit counts (admissions change only its request counters).
fn hot_cell(gov: &GovState, bucket: &str) -> Option<Counts> {
    gov.budget.read(bucket).get(bucket).map(|cell| {
        cell.models
            .iter()
            .flat_map(|m| [&m.cur, &m.flushed, &m.flushed_era])
            .map(|units| units.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .collect()
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn recovered_index_matches_book_after_every_mutation() {
    let (gov, sink) = gov(vec![recovered(1, "group:A@total")]).await;
    let cost = cost(&["A", "B", "C", "D"]);
    let (a, b) = (key("A"), key("B"));
    let admit = |key: &VirtualKey| {
        gov.try_admit_estimated_counts(&cost, key, "", AT, &[], &Default::default())
            .map(drop)
    };
    assert_index_matches(&gov);
    assert_eq!(admit(&a), Err(budget_refusal("A")));
    assert_eq!(admit(&b), Ok(()));

    // Live entries never block, whatever their targets.
    gov.stage_unit_checkpoint(unit(2, 2, &[("group:B@total", 0)], &[]));
    gov.stage_unit_checkpoint(unit(2, 2, &[("group:D@total", 0)], &[]));
    assert_index_matches(&gov);
    assert_eq!(admit(&b), Ok(()));

    // A stage on a recovered (ended) entry changes nothing.
    gov.stage_unit_checkpoint(unit(1, 1, &[("group:B@total", 0)], &[]));
    assert_index_matches(&gov);
    assert_eq!(admit(&b), Ok(()));

    // A failed hot apply at finish: live over live becomes recovered, and blocks its target.
    gov.stage_unit_checkpoint(unit(3, 3, &[("group:B@total", 0)], &[]));
    preload_overflow(&gov, "group:B@total");
    let before = hot_cell(&gov, "group:B@total");
    assert_eq!(admit(&b), Ok(()));
    assert!(gov.finish_unit_checkpoint(unit(
        3,
        3,
        &[("group:B@total", 0)],
        &[("work", Count::ONE)]
    )));
    assert_eq!(
        hot_cell(&gov, "group:B@total"),
        before,
        "a failed apply changes no count"
    );
    assert_index_matches(&gov);
    assert_eq!(admit(&b), Err(budget_refusal("B")));
    // Finishing it again is a no-op: it is already ended.
    assert!(gov.finish_unit_checkpoint(unit(3, 3, &[("group:B@total", 0)], &[])));
    assert_index_matches(&gov);

    // Race: admissions for D run while a finish fails for D.
    gov.stage_unit_checkpoint(unit(4, 4, &[("group:D@total", 0)], &[]));
    preload_overflow(&gov, "group:D@total");
    let before = hot_cell(&gov, "group:D@total");
    let d = key("D");
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| loop {
                let done = finished.load(Ordering::SeqCst);
                let answer = gov
                    .try_admit_estimated_counts(&cost, &d, "", AT, &[], &Default::default())
                    .map(drop);
                if done {
                    assert_eq!(answer, Err(budget_refusal("D")));
                    break;
                }
                assert!(
                    answer.is_ok() || answer == Err(budget_refusal("D")),
                    "{answer:?}"
                );
            });
        }
        std::thread::sleep(Duration::from_millis(5));
        assert!(gov.finish_unit_checkpoint(unit(
            4,
            4,
            &[("group:D@total", 0)],
            &[("work", Count::ONE)]
        )));
        finished.store(true, Ordering::SeqCst);
    });
    assert_eq!(hot_cell(&gov, "group:D@total"), before);
    assert_index_matches(&gov);

    // Settle: release custody and drain the book through the flusher.
    sink.stuck.store(false, Ordering::SeqCst);
    for bucket in ["group:B@total", "group:D@total"] {
        gov.budget.write(bucket).remove(bucket);
    }
    gov.flush_unit_checkpoints().await.ok();
    assert_index_matches(&gov);
    assert!(
        !gov.unit_checkpoint_pending(&id(1)),
        "recovered custody settled"
    );
    assert_eq!(admit(&a), Ok(()), "A admits again once its custody settles");
    assert_eq!(
        gov.check_unit_checkpoint_book(),
        0,
        "no recovered entry left"
    );
}

/// Every book mutation keeps the recovered index and the unit index exact.
#[tokio::test(flavor = "multi_thread")]
async fn book_mutations_keep_derived_indexes_exact() {
    use super::book::Pending;
    let (gov, _sink) = gov(Vec::new()).await;
    let cost = cost(&["A", "B", "C", "D"]);
    let c = key("C");
    let admit = || {
        gov.try_admit_estimated_counts(&cost, &c, "", AT, &[], &Default::default())
            .map(drop)
    };
    let book = gov.unit_checkpoint_book();
    let blocked_c = recovered(10, "group:C@total");

    book.lock()
        .insert(id(10), Pending::recovered(blocked_c.clone(), Some(0)));
    assert_index_matches(&gov);
    assert_eq!(admit(), Err(budget_refusal("C")));

    // Live over recovered unblocks; recovered over live blocks again.
    let live_c = unit(10, 10, &[("group:C@total", 0)], &[]);
    assert!(book.lock().insert(id(10), Pending::live(live_c)).is_some());
    assert_index_matches(&gov);
    assert_eq!(admit(), Ok(()));
    assert!(book
        .lock()
        .insert(id(10), Pending::recovered(blocked_c.clone(), Some(0)))
        .is_some());
    assert_index_matches(&gov);
    assert_eq!(admit(), Err(budget_refusal("C")));

    // A replaced snapshot with another unit and other targets re-keys both indexes.
    {
        let mut guard = book.lock();
        let mut edit = guard.edit(&id(10)).expect("entry present");
        edit.replace_snapshot(unit(10, 11, &[("group:C@total", 60)], &[]));
    }
    assert_index_matches(&gov);
    assert_eq!(admit(), Ok(()), "C@total no longer blocked");
    assert!(gov.unresolved_unit_target("group:C@total", 60));

    {
        let mut guard = book.lock();
        let mut edit = guard.edit(&id(10)).expect("entry present");
        edit.set_terminal(Vec::new(), 7);
        edit.set_persisted(7);
    }
    assert_index_matches(&gov);

    assert!(book.lock().remove(&id(10)).is_some());
    assert!(book.lock().remove(&id(99)).is_none());
    assert_index_matches(&gov);
    assert_eq!(gov.check_unit_checkpoint_book(), 0);

    // The unit index: zero, one and two live entries for a unit.
    assert!(
        gov.note_unit_audit(20, 1, [0; 32]).is_err(),
        "no entry for the unit"
    );
    gov.stage_unit_checkpoint(unit(20, 20, &[], &[]));
    assert_eq!(gov.note_unit_audit(20, 2, [0; 32]), Ok(()));
    assert_eq!(gov.unit_checkpoint_audit_seq(&id(20)), Some(2));
    gov.stage_unit_checkpoint(unit(21, 20, &[], &[]));
    assert!(
        gov.note_unit_audit(20, 3, [0; 32]).is_err(),
        "two live entries: a miss, never a guess"
    );
    assert_eq!(gov.unit_checkpoint_audit_seq(&id(20)), Some(2));
    book.lock().insert(
        id(30),
        Pending::recovered(recovered(30, "group:D@total"), Some(0)),
    );
    assert!(
        gov.note_unit_audit(30, 4, [0; 32]).is_err(),
        "recovered entries are skipped"
    );
    assert_eq!(gov.unit_audit_misses(), 3);
    assert_index_matches(&gov);
}

/// `A` and `B` each sit under the same seven ancestors: eight budget buckets per admission.
fn chain_cost() -> crate::cost::CostModel {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let group = |parent: Option<&str>| crate::config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Budget,
            amount: u64::MAX / 4,
            per: Some(LimitWindow::Total),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }],
        ..Default::default()
    };
    let mut groups = std::collections::BTreeMap::new();
    groups.insert("P1".to_string(), group(None));
    for n in 2..=7 {
        groups.insert(format!("P{n}"), group(Some(&format!("P{}", n - 1))));
    }
    groups.insert("A".to_string(), group(Some("P7")));
    groups.insert("B".to_string(), group(Some("P7")));
    crate::cost::CostModel::resolve_parts(None, 0, &groups)
}

/// Book visits of one admission of `B` (and of `A`, refused, when a recovered unit blocks it).
async fn admission_visits(live: usize, recovered_unit: bool) -> u64 {
    let replay = if recovered_unit {
        vec![recovered(1, "group:A@total")]
    } else {
        Vec::new()
    };
    let (gov, _sink) = gov(replay).await;
    stage_live(&gov, 1_000, live);
    let cost = chain_cost();
    let (a, b) = (key("A"), key("B"));
    let expected = std::collections::BTreeMap::new();
    let before = gov.unit_checkpoint_visits();
    assert_eq!(
        gov.try_admit_estimated_counts(&cost, &b, "", AT, &[], &expected)
            .map(drop),
        Ok(())
    );
    if recovered_unit {
        assert_eq!(
            gov.try_admit_estimated_counts(&cost, &a, "", AT, &[], &expected)
                .map(drop),
            Err(budget_refusal("A"))
        );
    }
    gov.unit_checkpoint_visits() - before
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_visits_flat() {
    assert_eq!(
        admission_visits(10, false).await,
        admission_visits(100_000, false).await
    );
    assert_eq!(
        admission_visits(10, true).await,
        admission_visits(100_000, true).await
    );
}

async fn stage_finish_visits(live: usize) -> u64 {
    let (gov, _sink) = gov(Vec::new()).await;
    stage_live(&gov, 1_000, live);
    let before = gov.unit_checkpoint_visits();
    gov.stage_unit_checkpoint(unit(7, 7, &[], &[]));
    assert!(gov.finish_unit_checkpoint(unit(7, 7, &[], &[])));
    gov.unit_checkpoint_visits() - before
}

#[tokio::test(flavor = "multi_thread")]
async fn stage_finish_visits_flat() {
    assert_eq!(
        stage_finish_visits(10).await,
        stage_finish_visits(100_000).await
    );
}

/// SHUTDOWN-HANG 8.13: the gate's terminal backlog is exactly the book's `ended` entries; a
/// running entry never changes it; the cap refuses new governed admission (never a running or
/// terminal unit), and a closed gate refuses with `Draining` and never counts again.
#[tokio::test(flavor = "multi_thread")]
async fn the_terminal_mirror_feeds_the_admission_gate() {
    let (gov, _sink) = gov(vec![
        recovered(1, "group:Z@total"),
        recovered(2, "group:Z@total"),
    ])
    .await;
    assert_eq!(
        gov.admissions().terminal(),
        2,
        "recovered entries are inserted ended"
    );
    gov.check_unit_checkpoint_book();
    stage_live(&gov, 1_000, 3);
    assert_eq!(
        gov.admissions().terminal(),
        2,
        "a running entry is not backlog"
    );
    gov.stage_unit_checkpoint(unit(1_000, 1_000, &[("group:C@total", 0)], &[]));
    assert_eq!(
        gov.admissions().terminal(),
        2,
        "a moved revision is not backlog"
    );
    assert!(gov.finish_unit_checkpoint(unit(1_001, 1_001, &[("group:C@total", 0)], &[])));
    assert_eq!(gov.admissions().terminal(), 3);
    assert!(gov.finish_unit_checkpoint(unit(1_001, 1_001, &[("group:C@total", 0)], &[])));
    assert_eq!(
        gov.admissions().terminal(),
        3,
        "an already-ended unit is not counted twice"
    );
    gov.check_unit_checkpoint_book();

    let cost = cost(&["A"]);
    let a = key("A");
    let held = gov
        .try_admit(&cost, &a, "", AT)
        .expect("below the cap admits");
    assert_eq!(gov.admissions().live(), 1);
    drop(held);
    assert_eq!(gov.admissions().live(), 0, "the count falls with the grant");
    gov.admissions().set_cap(3);
    match gov.try_admit(&cost, &a, "", AT) {
        Err(LimitBlocked::CustodyFull { backlog, cap }) => assert_eq!((backlog, cap), (3, 3)),
        other => panic!("expected CustodyFull, got {other:?}"),
    }
    assert_eq!(gov.admissions().live(), 0, "a refusal leaks no count");
    gov.admissions().set_cap(1_000);
    gov.admissions().close();
    assert!(matches!(
        gov.try_admit(&cost, &a, "", AT),
        Err(LimitBlocked::Draining)
    ));
    assert_eq!(gov.admissions().live(), 0);
}

/// SHUTDOWN-HANG 8.13: the removal after settlement takes each entry out of the terminal
/// mirror, so the mirror equals the book's `ended` entries after removals too.
#[tokio::test(flavor = "multi_thread")]
async fn the_terminal_mirror_falls_with_each_removal() {
    let (gov, sink) = gov(vec![
        recovered(1, "group:Y@total"),
        recovered(2, "group:Y@total"),
    ])
    .await;
    assert!(gov.finish_unit_checkpoint(unit(3, 3, &[("group:C@total", 0)], &[])));
    stage_live(&gov, 4_000, 2);
    assert_eq!(gov.admissions().terminal(), 3);
    gov.check_unit_checkpoint_book();
    sink.stuck.store(false, Ordering::SeqCst);
    gov.flush_unit_checkpoints().await.ok();
    gov.check_unit_checkpoint_book();
    assert!(
        !gov.unit_checkpoint_pending(&id(1)) && !gov.unit_checkpoint_pending(&id(2)),
        "the recovered entries settled and were removed"
    );
    let ended = gov
        .unit_checkpoint_states()
        .iter()
        .filter(|state| state.ended)
        .count() as u64;
    assert_eq!(
        gov.admissions().terminal(),
        ended,
        "the mirror equals the ended entries after removal"
    );
    assert!(ended <= 1, "only the finished unit may remain ended");
}

/// SHUTDOWN-HANG 8.13: `close()` racing 32 threads of real governed admissions: every
/// admission was either counted before the close or refused with `Draining`, and once closed
/// the live count never rises again.
#[tokio::test(flavor = "multi_thread")]
async fn close_racing_governed_admissions_counts_each_once() {
    let cost = cost(&["A"]);
    let a = key("A");
    for _ in 0..50 {
        let (gov, _sink) = gov(Vec::new()).await;
        let barrier = std::sync::Barrier::new(33);
        let (admitted, live_at_close) = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..32)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        match gov.try_admit(&cost, &a, "", AT) {
                            Ok(grant) => Some(grant),
                            Err(LimitBlocked::Draining) => None,
                            Err(other) => panic!("only a drain refusal is expected: {other:?}"),
                        }
                    })
                })
                .collect();
            barrier.wait();
            gov.admissions().close();
            let live_at_close = gov.admissions().live();
            let grants: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
            (grants, live_at_close)
        });
        let counted = admitted.iter().filter(|grant| grant.is_some()).count() as u64;
        assert_eq!(
            gov.admissions().live(),
            counted,
            "each admission counted once"
        );
        assert!(
            counted <= live_at_close,
            "no admission is counted after close"
        );
        assert!(matches!(
            gov.try_admit(&cost, &a, "", AT),
            Err(LimitBlocked::Draining)
        ));
        drop(admitted);
        assert_eq!(
            gov.admissions().live(),
            0,
            "every count falls with its grant"
        );
    }
}
