// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native asynchronous crossings hold no per-scope thread claim. Contention is
//! resolved by the immutable candidate's atomic conditions and explicit replanning.
use super::journal_tests::{append, records, FRAMING, INSTANCE, SCHEMA};
use crate::host_chains::{ChainBook, OrdinaryChain, CHAIN_LIFE_SCHEMA};
use crate::host_records_async::AsyncRecords;
use crate::persistence::host_records::Outcome;
use busbar_contract::persistence::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

const WAIT: Duration = Duration::from_secs(5);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Crossing {
    Read,
    Commit,
}
struct Pause {
    crossing: Crossing,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}
type Reenter = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;
struct GateBackend {
    inner: Arc<dyn PersistenceBackend>,
    pause: Mutex<Option<Pause>>,
    reenter: Mutex<Option<Reenter>>,
}
impl GateBackend {
    fn pause(&self, crossing: Crossing) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, observed) = oneshot::channel();
        let (release, released) = oneshot::channel();
        assert!(self
            .pause
            .lock()
            .unwrap()
            .replace(Pause {
                crossing,
                entered,
                release: released
            })
            .is_none());
        (observed, release)
    }
    async fn crossing(&self, crossing: Crossing) {
        let pause = {
            let mut held = self.pause.lock().unwrap();
            if held
                .as_ref()
                .is_some_and(|pause| pause.crossing == crossing)
            {
                held.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            let _ = pause.release.await;
        }
        let reenter = if crossing == Crossing::Commit {
            self.reenter.lock().unwrap().take()
        } else {
            None
        };
        if let Some(reenter) = reenter {
            reenter().await;
        }
    }
}
impl PersistenceBackend for GateBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            self.crossing(Crossing::Read).await;
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            self.crossing(Crossing::Commit).await;
            self.inner.commit(candidate).await
        })
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
}
async fn fixture() -> (Arc<GateBackend>, Arc<AsyncRecords>) {
    let backend = Arc::new(GateBackend {
        inner: crate::real_store::native_backend().await,
        pause: Mutex::new(None),
        reenter: Mutex::new(None),
    });
    let core = crate::real_store::core_over(backend.clone()).await;
    let rows = Arc::new(
        AsyncRecords::authorized(
            core,
            INSTANCE,
            [SCHEMA.as_str().into(), CHAIN_LIFE_SCHEMA.as_str().into()],
        )
        .unwrap(),
    );
    (backend, rows)
}
fn start(
    rows: Arc<AsyncRecords>,
    scope: &'static str,
    content: &'static [u8],
) -> tokio::task::JoinHandle<Outcome> {
    tokio::spawn(async move { append(&ChainBook::default(), &rows, scope, content).await })
}
async fn finish(task: tokio::task::JoinHandle<Outcome>) -> Outcome {
    tokio::time::timeout(WAIT, task)
        .await
        .expect("native crossing completed without a held scope lock")
        .unwrap()
}

#[tokio::test]
async fn an_append_to_another_scope_completes_while_one_scopes_native_commit_is_parked() {
    let (backend, rows) = fixture().await;
    let (entered, release) = backend.pause(Crossing::Commit);
    let first = start(rows.clone(), "one", b"first");
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    assert_eq!(
        finish(start(rows.clone(), "two", b"independent")).await,
        Outcome::Applied
    );
    release.send(()).unwrap();
    assert_eq!(finish(first).await, Outcome::Applied);
    assert_eq!(records(&rows, "one").await.len(), 1);
    assert_eq!(records(&rows, "two").await.len(), 1);
}

#[tokio::test]
async fn a_native_backend_can_reenter_another_scope_without_holding_a_core_lock() {
    let (backend, rows) = fixture().await;
    let nested = rows.clone();
    *backend.reenter.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            assert_eq!(
                append(&ChainBook::default(), &nested, "inner", b"nested").await,
                Outcome::Applied
            );
        })
    }));
    assert_eq!(
        finish(start(rows.clone(), "outer", b"outer")).await,
        Outcome::Applied
    );
    assert_eq!(records(&rows, "inner").await.len(), 1);
    assert_eq!(records(&rows, "outer").await.len(), 1);
}

#[tokio::test]
async fn a_native_reentry_to_the_same_scope_conflicts_instead_of_deadlocking() {
    let (backend, rows) = fixture().await;
    let nested = rows.clone();
    *backend.reenter.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            assert_eq!(
                append(&ChainBook::default(), &nested, "same", b"nested").await,
                Outcome::Applied
            );
        })
    }));
    assert_eq!(
        finish(start(rows.clone(), "same", b"outer")).await,
        Outcome::ConditionConflict
    );
    assert_eq!(
        append(&ChainBook::default(), &rows, "same", b"outer").await,
        Outcome::Applied
    );
    let restored = records(&rows, "same").await;
    assert_eq!(restored.len(), 2);
    assert!(crate::audit::verify_chain(&restored).is_ok());
    assert_eq!(restored[0].content, b"nested");
    assert_eq!(restored[1].content, b"outer");
}

#[tokio::test]
async fn concurrent_candidates_for_one_scope_conflict_then_replan_gap_free() {
    let (_, rows) = fixture().await;
    let book_a = ChainBook::default();
    let book_b = ChainBook::default();
    let mut operation_a = [0; 16];
    let mut operation_b = [0; 16];
    getrandom::fill(&mut operation_a).unwrap();
    getrandom::fill(&mut operation_b).unwrap();
    let (request_a, _) = book_a
        .prepare_ordinary_async(
            &rows,
            OrdinaryChain {
                instance: INSTANCE,
                schema: SCHEMA,
                scope: "race",
                content: b"a",
                framing: FRAMING,
            },
            operation_a,
        )
        .await
        .unwrap();
    let (request_b, _) = book_b
        .prepare_ordinary_async(
            &rows,
            OrdinaryChain {
                instance: INSTANCE,
                schema: SCHEMA,
                scope: "race",
                content: b"b",
                framing: FRAMING,
            },
            operation_b,
        )
        .await
        .unwrap();
    let (a, b) = tokio::join!(rows.conditional(&request_a), rows.conditional(&request_b));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(matches!(
        (a, b),
        (Outcome::Applied, Outcome::ConditionConflict)
            | (Outcome::ConditionConflict, Outcome::Applied)
    ));
    let missing = if a == Outcome::ConditionConflict {
        b"a"
    } else {
        b"b"
    };
    assert_eq!(
        append(&ChainBook::default(), &rows, "race", missing).await,
        Outcome::Applied
    );
    let restored = records(&rows, "race").await;
    assert_eq!(restored.len(), 2);
    assert!(crate::audit::verify_chain(&restored).is_ok());
}

#[tokio::test]
async fn an_append_completes_while_another_scope_is_parked_reading_its_resume() {
    let (backend, rows) = fixture().await;
    assert_eq!(
        append(&ChainBook::default(), &rows, "resume", b"old").await,
        Outcome::Applied
    );
    let (entered, release) = backend.pause(Crossing::Read);
    let resuming = start(rows.clone(), "resume", b"new");
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    assert_eq!(
        finish(start(rows.clone(), "other", b"independent")).await,
        Outcome::Applied
    );
    release.send(()).unwrap();
    assert_eq!(finish(resuming).await, Outcome::Applied);
    assert_eq!(records(&rows, "resume").await.len(), 2);
}

#[tokio::test]
async fn a_parked_native_commit_never_holds_a_thread_claim_over_its_scope() {
    let (backend, rows) = fixture().await;
    let (entered, release) = backend.pause(Crossing::Commit);
    let blocked = start(rows.clone(), "same", b"delayed");
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    assert_eq!(
        finish(start(rows.clone(), "same", b"winner")).await,
        Outcome::Applied
    );
    release.send(()).unwrap();
    assert_eq!(finish(blocked).await, Outcome::ConditionConflict);
    assert_eq!(records(&rows, "same").await.len(), 1);
    assert_eq!(
        append(&ChainBook::default(), &rows, "same", b"delayed").await,
        Outcome::Applied
    );
    assert!(crate::audit::verify_chain(&records(&rows, "same").await).is_ok());
}
