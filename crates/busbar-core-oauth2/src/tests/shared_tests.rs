// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn shared(store: Arc<busbar_kernel::persistence::facade::CoreStore>) -> Arc<Shared> {
    Arc::new(Shared::new(Arc::new(
        ScopedStore::host_private(store, "oauth-as", Shared::schemas()).unwrap(),
    )))
}

fn client(id: &str) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth: oauth_as::client::ClientAuth::Public,
        grant_types: vec![oauth_as::grant::GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example/cb".into()],
        allowed_scopes: oauth_as::scope::ScopeSet::default(),
        default_scopes: oauth_as::scope::ScopeSet::default(),
        name: Some(id.into()),
        registration: None,
    }
}

/// The racers of one `take_*` race in the storage contract.
const RACERS: usize = 8;

/// The waker a racer leaves at the harness's rendezvous gate while it is held there.
///
/// The gate holds the only clone of it, so once the racer's first poll has returned, the next
/// wake of it is the gate opening (the gate wakes every waker left with it, from inside the poll
/// of the racer that arrives last).
struct LeftAtTheGate {
    wakes: std::sync::atomic::AtomicUsize,
    woken: tokio::sync::Notify,
}

impl std::task::Wake for LeftAtTheGate {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.woken.notify_one();
    }
}

/// A spawner under which no racer of a race can run out of the harness's gate budget, and the
/// racers still meet in the store at the same moment.
///
/// The harness's gate (`oauth-as` 1.1.0, `storage_conformance::GateWait`) does not wait for the
/// others to arrive: a racer that is not the last to arrive wakes itself and is polled again, and
/// gives up after a fixed number of polls (`GATE_POLL_BUDGET`), after which the run reports
/// `harness/race_setup` ("the racers never overlapped"). A spawned racer spends that budget as
/// fast as its worker thread polls it, well inside one scheduler time slice, so it runs out
/// whenever the host leaves the last racer unpolled for that long. On a small, loaded runner that
/// is common, and no pause on the test thread prevents it.
///
/// So the racers are polled by hand, in two steps, and the gate's budget is never counted down:
///
/// 1. Every racer of a race but the last handed over is polled exactly once, with a waker of its
///    own. The gate is each racer's first await, so that poll counts the racer in at the gate and
///    leaves that waker with the gate. It cannot open the gate: the last racer has not been
///    polled. The racer is then held, unpolled, having spent one poll of its budget whatever the
///    core count, the load or the order the runtime runs the tasks in.
/// 2. When all of those are counted in (a barrier of `racers` tasks), the last racer is polled
///    for the first time. It is the last to arrive, so that poll opens the gate, and the gate
///    wakes every waker left with it before the last racer goes on into the store. Each held
///    racer goes on, as an ordinary task of the multi-threaded runtime, when the gate wakes it:
///    its second poll finds the gate open. So every racer is released by the gate itself, at the
///    moment it opens, and the race in the store is a parallel one.
///
/// The harness runs one race at a time and hands exactly `racers` tasks over for each, so every
/// `racers` hand-overs are one race and each barrier generation is one race.
fn counted_in_then_released_by_the_gate(
    racers: usize,
) -> impl Fn(oauth_as::storage_conformance::Task) + Send + Sync + 'static {
    use std::sync::atomic::Ordering;

    let counted_in = Arc::new(tokio::sync::Barrier::new(racers));
    let handed = std::sync::atomic::AtomicUsize::new(0);
    move |mut task| {
        let counted_in = Arc::clone(&counted_in);
        let arrives_last = (handed.fetch_add(1, Ordering::SeqCst) + 1) % racers == 0;
        tokio::spawn(async move {
            if arrives_last {
                counted_in.wait().await;
                task.await;
                return;
            }
            let left = Arc::new(LeftAtTheGate {
                wakes: std::sync::atomic::AtomicUsize::new(0),
                woken: tokio::sync::Notify::new(),
            });
            let waker = std::task::Waker::from(Arc::clone(&left));
            let first = std::future::Future::poll(
                task.as_mut(),
                &mut std::task::Context::from_waker(&waker),
            );
            // The gate's wake of the racer itself, made inside that poll: not the gate opening.
            let own_wakes = left.wakes.load(Ordering::SeqCst);
            counted_in.wait().await;
            if first.is_ready() {
                return;
            }
            while left.wakes.load(Ordering::SeqCst) == own_wakes {
                left.woken.notified().await;
            }
            task.await;
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_backed_server_holds_the_storage_contract() {
    let violations = oauth_as::storage_conformance::StorageConformance::new(|| async {
        SharedStorage::new(shared(crate::testkit::memory_store().await))
    })
    .racers(RACERS)
    .with_spawn(counted_in_then_released_by_the_gate(RACERS))
    .run()
    .await;
    assert!(violations.is_empty(), "{violations:#?}");
}

#[tokio::test]
async fn native_records_exceed_the_plane_bound_and_survive_reopen() {
    let store = crate::testkit::memory_store().await;
    let a = SharedStorage::new(shared(store.clone()));
    let mut value = client("large");
    value.name = Some("x".repeat(8192));
    a.put_client(value.clone()).await.unwrap();
    let b = SharedStorage::new(shared(store));
    assert_eq!(
        *b.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
}

#[tokio::test]
async fn signing_key_is_shared_between_fresh_owners() {
    let store = crate::testkit::memory_store().await;
    assert_eq!(
        shared(store.clone())
            .signing_key(|| Ok(vec![1, 2, 3]))
            .await
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        shared(store)
            .signing_key(|| panic!("existing key must be read"))
            .await
            .unwrap(),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn ambiguous_record_commit_settles_the_original_candidate() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let store = crate::testkit::memory_store_on(backend.clone()).await;
    let s = shared(store.clone());
    crate::testkit::lose_next_reply(&backend);
    let a = SharedStorage::new(s.clone());
    let value = client("unknown");
    assert!(a.put_client(value.clone()).await.is_err());
    assert!(!s.pending.lock().unwrap().is_empty());
    assert_eq!(
        *a.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
    assert!(s.pending.lock().unwrap().is_empty());
    let b = SharedStorage::new(shared(store));
    assert!(b.get_client(&value.client_id).await.unwrap().is_some());
}

#[tokio::test]
async fn native_claim_expiry_and_single_use_apply_across_fresh_owners() {
    let store = crate::testkit::memory_store().await;
    let a = shared(store.clone());
    let b = shared(store);
    assert!(!a
        .claim("replay", "expired", now_secs().saturating_sub(1))
        .await
        .unwrap());
    let until = now_secs() + 60;
    let (first, second) = tokio::join!(
        a.claim("replay", "once", until),
        b.claim("replay", "once", until)
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(|won| *won)
            .count(),
        1
    );
}

#[tokio::test]
async fn ambiguous_claim_is_retried_with_its_original_expiry() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let expiry = now_secs() + 60;
    crate::testkit::lose_next_reply(&backend);
    assert!(s.claim("spent", "single", expiry).await.is_err());
    assert!(s.claim("spent", "single", expiry + 1).await.is_err());
    assert!(s.claim("spent", "single", expiry).await.unwrap());
    assert!(!s.claim("spent", "single", expiry).await.unwrap());
}

#[tokio::test]
async fn cancelled_record_submission_retains_original_request() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let value = client("cancelled");
    backend
        .hang
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let storage = SharedStorage::new(s.clone());
    {
        let mut write = Box::pin(storage.put_client(value.clone()));
        assert!(futures::poll!(&mut write).is_pending());
    }
    assert!(!s.pending.lock().unwrap().is_empty());
    backend
        .hang
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        *storage.get_client(&value.client_id).await.unwrap().unwrap(),
        value
    );
    assert!(s.pending.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelled_claim_retains_original_expiry_and_native_candidate() {
    let backend = Arc::new(crate::testkit::MemoryBackend::default());
    let s = shared(crate::testkit::memory_store_on(backend.clone()).await);
    let expiry = now_secs() + 60;
    backend
        .hang
        .store(true, std::sync::atomic::Ordering::SeqCst);
    {
        let mut claim = Box::pin(s.claim("spent", "cancelled", expiry));
        assert!(futures::poll!(&mut claim).is_pending());
    }
    backend
        .hang
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(s.claim("spent", "cancelled", expiry + 1).await.is_err());
    assert!(s.claim("spent", "cancelled", expiry).await.unwrap());
    assert!(!s.claim("spent", "cancelled", expiry).await.unwrap());
}

#[tokio::test]
async fn prior_logical_cell_boundary_remains_writable_and_scannable() {
    let shared = shared(crate::testkit::memory_store().await);
    let schema = atomic_schema("key");
    assert_eq!(
        shared
            .submit(Shared::candidate(
                &schema,
                "boundary",
                None,
                vec![b'x'; MAX_LOGICAL_CELL_BYTES]
            ))
            .await
            .unwrap(),
        Decision::Applied
    );
    let page = shared.store.page(&schema, b"", None).await.unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        page.rows[0].1.expose(&busbar_kernel::seal::lend()).len(),
        MAX_LOGICAL_CELL_BYTES
    );
    assert!(shared
        .submit(Shared::candidate(
            &schema,
            "oversize",
            None,
            vec![b'x'; MAX_LOGICAL_CELL_BYTES + 1]
        ))
        .await
        .is_err());
    assert!(shared
        .store
        .get(&schema, b"oversize")
        .await
        .unwrap()
        .is_none());
}

/// A stake row's nonce rides on the stack-built spend token: one this store writes (32 hex
/// digits) is spent; a stored one longer than the token holds (65 bytes) is refused with an error,
/// never spent.
#[tokio::test]
async fn a_stake_spends_with_a_written_nonce_and_refuses_an_overlong_one() {
    let shared = shared(crate::testkit::memory_store().await);
    let until = now_secs() + 60;
    for (session, nonce) in [("s-ok", "a".repeat(32)), ("s-long", "b".repeat(65))] {
        let id = StakeId::of(session, "key");
        let row = StakeRow {
            approve: true,
            until,
            id: id.as_str().to_owned(),
            nonce,
        };
        shared.put("stake", id.as_str(), &row).await.unwrap();
    }
    assert_eq!(shared.spend("s-ok", "key").await.unwrap(), Some(true));
    let refused = shared.spend("s-long", "key").await.unwrap_err();
    assert!(
        refused
            .to_string()
            .contains("nonce is longer than any this store writes"),
        "{refused}"
    );
}
