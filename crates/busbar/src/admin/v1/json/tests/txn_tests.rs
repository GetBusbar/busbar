//! THE CLASS-LEVEL HARNESS for the config-mutation transaction guard (design C §5).
//!
//! These are not per-site regression tests. Each asserts a property of the CHOKE POINT that, once
//! true, holds for every mutation funnelling through it — including ones written later:
//!
//! - §5.1 no dangling-group bind — a bind's existence check and its store write share one lock hold;
//! - §5.2 no stale snapshot — a body reads the config the lock froze, never one captured before it;
//! - §5.3 no blocking under the async lock — a slow store cannot stall the reactor, asserted by a
//!   liveness probe on a SINGLE-worker runtime (the compile fence is `scripts/txn-fence.sh`);
//! - §5.4 install/remove/reload/rollback share ONE mutation domain, so no plugin write can land
//!   inside another plugin op's validate→rebuild window;
//! - §5.5 the swap lost-update invariant, modelled under loom in `tests/txn_loom.rs`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use super::{config_transaction, Outcome};
use crate::admin::v1::contract::AdminError;
use crate::admin::v1::json::{delete_group, install_plugin};
use crate::governance::{GovState, MemoryStore};
use crate::state::AppHandle;
use crate::test_support::TestApp;

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────

/// A `Store` whose `list_keys()` BLOCKS for `delay`, standing in for a slow disk / remote DB behind
/// the store-plugin boundary. Everything else delegates to the in-memory store.
///
/// `list_keys` is the exact call the group-delete bound-key guard and the mint's anti-sprawl cap
/// make, so this double turns "does a store round-trip stall the reactor?" into an observable,
/// deterministic question.
struct SlowStore {
    inner: MemoryStore,
    delay: Duration,
    /// How many times the blocking read was entered — proves the test really exercised it.
    reads: AtomicU64,
}

impl SlowStore {
    fn new(delay: Duration) -> Self {
        Self {
            inner: MemoryStore::new(),
            delay,
            reads: AtomicU64::new(0),
        }
    }
}

impl busbar_api::Store for SlowStore {
    fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
    fn put_key_with_aws_credential(
        &self,
        key: &busbar_api::VirtualKey,
        cred: &busbar_api::AwsCredential,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_key_with_aws_credential(key, cred)
    }
    fn list_aws_credentials(&self) -> busbar_api::StoreResult<Vec<busbar_api::AwsCredential>> {
        self.inner.list_aws_credentials()
    }
}

/// Governance with a deterministic token signer, so `POST /keys` actually mints.
fn gov(store: Arc<dyn crate::governance::Store>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("gov"),
    )
}

/// A groups tree with RUNTIME (non-base) groups, so the write paths (delete, auto-provision,
/// rebind) are not short-circuited by the base-config shadow guard.
fn tree(names: &[&str]) -> std::collections::BTreeMap<String, crate::config::GroupCfg> {
    names
        .iter()
        .map(|n| (n.to_string(), crate::config::GroupCfg::default()))
        .collect()
}

fn handle_for(app: Arc<crate::state::App>) -> Arc<AppHandle> {
    Arc::new(AppHandle::new(app))
}

fn anon() -> axum::Extension<crate::auth::AuthPrincipal> {
    axum::Extension(crate::auth::AuthPrincipal(None))
}

/// Mint one key bound to `group` through the REAL `POST /keys` handler.
async fn mint(handle: &Arc<AppHandle>, name: &str, group: Option<&str>) -> StatusCode {
    let body = match group {
        Some(g) => json!({ "name": name, "group": g }),
        None => json!({ "name": name }),
    };
    crate::admin::create_key(
        State(handle.clone()),
        anon(),
        HeaderMap::new(),
        axum::body::Bytes::from(body.to_string()),
    )
    .await
    .status()
}

async fn delete_team(handle: Arc<AppHandle>) -> StatusCode {
    delete_group(
        State(handle),
        anon(),
        Path("team".to_string()),
        HeaderMap::new(),
    )
    .await
    .status()
}

// ── §5.3 no blocking under the async lock (the executor-not-stalled assertion) ───────────────────

/// THE SHARPEST TEST. A store whose `list_keys()` blocks for 400ms is installed, then
/// `DELETE /groups/team` — which MUST count bound keys through exactly that call — runs while a
/// liveness probe repeatedly `yield_now().await`s and timestamps each tick.
///
/// The runtime has ONE worker thread, so a synchronous store call made on the async side genuinely
/// wedges the executor and the probe's tick gap jumps to the full store latency. `spawn_blocking`
/// has its own separate thread pool, so a read deferred through `txn.read_store` leaves the reactor
/// scheduling and the gap stays in the noise.
///
/// RED before the guard: `build_without_group` held a `&GovState` and called `all_keys()` inline
/// under the async mutation lock — the probe stalls for the whole read. GREEN after: the builder has
/// no store handle at all (the count is an ARGUMENT), so the read can only happen inside the
/// deferred closure, on a blocking thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_store_read_does_not_stall_the_executor() {
    crate::metrics::init();
    let delay = Duration::from_millis(400);
    let store = Arc::new(SlowStore::new(delay));
    let probe_store = store.clone();
    let app = TestApp::new()
        .governance(gov(store))
        .groups_tree(tree(&["team"]))
        .build();
    let handle = handle_for(app);

    // The liveness probe: tick as fast as the executor allows, recording the worst gap.
    let stop = Arc::new(AtomicBool::new(false));
    let worst = Arc::new(AtomicU64::new(0));
    let probe = {
        let (stop, worst) = (stop.clone(), worst.clone());
        tokio::spawn(async move {
            let mut last = Instant::now();
            let mut ticks = 0u64;
            while !stop.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
                let now = Instant::now();
                worst.fetch_max(
                    now.duration_since(last).as_millis() as u64,
                    Ordering::SeqCst,
                );
                last = now;
                ticks += 1;
            }
            ticks
        })
    };
    // Let the probe establish a baseline before the mutation starts.
    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

    // SPAWNED, not awaited inline: `#[tokio::test]` drives the test body with `block_on` on the
    // MAIN thread, so an inline await would run the handler off the worker pool and a blocking call
    // inside it could not stall the single worker the probe lives on. Spawning puts the handler and
    // the probe on the SAME one worker — which is exactly the condition that makes a synchronous
    // store call on the async side observable.
    let status = tokio::spawn(delete_team(handle.clone()))
        .await
        .expect("delete joins");
    stop.store(true, Ordering::SeqCst);
    let ticks = probe.await.expect("probe joins");

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "no keys are bound, so the delete succeeds"
    );
    assert!(
        probe_store.reads.load(Ordering::SeqCst) >= 1,
        "the test must actually have gone through the slow `list_keys` it is measuring"
    );
    assert!(ticks > 0, "the probe must have run");
    let worst_gap = worst.load(Ordering::SeqCst);
    assert!(
        worst_gap < delay.as_millis() as u64 / 2,
        "EXECUTOR STALLED: the liveness probe's worst tick gap was {worst_gap}ms while a {}ms store \
         read ran under the config-mutation lock. A blocking store call reached the async thread — \
         it must be deferred through `Txn::read_store` onto spawn_blocking.",
        delay.as_millis()
    );
}

// ── §5.2 no stale snapshot: the body reads the config the lock froze ────────────────────────────

/// A config change that COMMITS BEFORE this mint acquires the lock must be the config the mint
/// enforces. Deterministic by construction rather than by racing: transaction A takes the lock and
/// holds it (its blocking step sleeps) while lowering `max_keys_per_principal` from 5 to 1; the mint
/// is fired while A still holds the lock, so it necessarily queues behind A and its post-lock
/// snapshot is A's result.
///
/// RED with a pre-lock read: the mint's snapshot was captured by the extractor before A committed,
/// so it would enforce the OLD cap of 5 and admit a second key. GREEN under the txn: `txn.app()` is
/// the post-lock snapshot and there is no older one in scope, so the mint sees cap 1 and 409s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_is_read_from_the_post_lock_snapshot() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let mut app = TestApp::new()
        .governance(gov(store))
        .groups_tree(tree(&["team"]))
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .max_keys_per_principal = 5;
    let handle = handle_for(app);

    // One key already bound to `team`: a cap of 1 is already reached, a cap of 5 is not.
    assert_eq!(
        mint(&handle, "first", Some("team")).await,
        StatusCode::CREATED
    );

    // A: hold the section open, then lower the cap to 1.
    let lowering = {
        let handle = handle.clone();
        tokio::spawn(async move {
            config_transaction(&handle, |txn| {
                let current = txn.app().clone();
                Ok(txn.read_store(move || {
                    // Hold the section long enough for the mint below to queue behind it.
                    std::thread::sleep(Duration::from_millis(300));
                    let mut next = (*current).clone();
                    next.config_version = current.config_version.wrapping_add(1);
                    next.max_keys_per_principal = 1;
                    let installed = Arc::new(next);
                    Ok(Outcome::swap(installed.clone(), installed))
                }))
            })
            .await
        })
    };
    // Give A time to acquire the lock, then fire the mint: it blocks on the lock and therefore
    // observes A's committed snapshot.
    tokio::time::sleep(Duration::from_millis(80)).await;
    let status = mint(&handle, "second", Some("team")).await;
    lowering.await.expect("join").expect("cap change commits");

    assert_eq!(
        handle.load().max_keys_per_principal,
        1,
        "the cap change committed"
    );
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "STALE CAP: the mint admitted a key against a `max_keys_per_principal` read from a snapshot \
         older than its own lock acquisition. `txn.app()` is the only config a body can see, so \
         this must enforce the post-lock cap of 1."
    );
}

// ── §5.1 no dangling-group bind ─────────────────────────────────────────────────────────────────

/// Mints binding `team` run concurrently with `DELETE /groups/team`. Whatever the interleaving, the
/// TERMINAL store state must hold no key bound to a group that does not exist: either a bind lands
/// first (and the delete's bound-key guard then 409s) or the delete lands first (and the bind fails
/// closed). Both orders are legal; a durable key pointing at a deleted group is not — it would fail
/// every request on that key CLOSED at admission.
///
/// This is the class property, not a per-site check: the existence test and the store write are the
/// same `config_transaction` section for EVERY bind path, so a bind path added later inherits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mints_never_bind_a_deleted_group() {
    crate::metrics::init();
    for round in 0..10u32 {
        let store = Arc::new(MemoryStore::new());
        let g = gov(store);
        let app = TestApp::new()
            .governance(g.clone())
            .groups_tree(tree(&["team"]))
            .build();
        let handle = handle_for(app);

        // The DELETE is launched in the MIDDLE of the mint fan-out, so it lands in the lock queue
        // between mints that have already loaded a snapshot and mints that have not. That is exactly
        // the window a pre-lock existence read would bind through.
        let mut minting = Vec::new();
        let mut deleting = None;
        for i in 0..8 {
            let h = handle.clone();
            minting.push(tokio::spawn(async move {
                mint(&h, &format!("k{round}-{i}"), Some("team")).await
            }));
            if i == 2 {
                deleting = Some(tokio::spawn(delete_team(handle.clone())));
            }
        }
        let deleting = deleting.expect("delete spawned");
        for m in minting {
            m.await.expect("mint task joins");
        }
        deleting.await.expect("delete task joins");

        let live = handle.load();
        for key in g.all_keys().expect("keys readable") {
            if let Some(bound) = key.group.as_deref() {
                assert!(
                    live.groups_registry.contains_key(bound)
                        && live.cost.group_named(bound).is_some(),
                    "DANGLING BIND: key `{}` is durably bound to group `{bound}`, which no longer \
                     exists. A bind's existence check and its store write must share one \
                     transaction.",
                    key.id
                );
            }
        }
    }
}

/// The same property for the REBIND verb (`PATCH /keys/{id}` with `group`) — a second bind path into
/// the same class, closed for the same structural reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rebinds_never_bind_a_deleted_group() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let g = gov(store);
    let app = TestApp::new()
        .governance(g.clone())
        .groups_tree(tree(&["team", "other"]))
        .build();
    let handle = handle_for(app);

    let mut ids = Vec::new();
    for i in 0..6 {
        let (key, _tok) = g
            .mint_signed(
                crate::governance::NewKeySpec {
                    name: format!("r{i}"),
                    allowed_pools: None,
                    group: Some("other".to_string()),
                    labels: Default::default(),
                },
                u64::MAX,
                0,
            )
            .expect("mint");
        ids.push(key.id);
    }
    let mut rebinding = Vec::new();
    for id in ids {
        let handle = handle.clone();
        rebinding.push(tokio::spawn(async move {
            crate::admin::update_key(
                State(handle),
                anon(),
                Path(id),
                HeaderMap::new(),
                axum::body::Bytes::from(json!({ "group": "team" }).to_string()),
            )
            .await
            .status()
        }));
    }
    let deleting = tokio::spawn(delete_team(handle.clone()));
    for r in rebinding {
        r.await.expect("rebind joins");
    }
    deleting.await.expect("delete joins");

    let live = handle.load();
    for key in g.all_keys().expect("keys readable") {
        if let Some(bound) = key.group.as_deref() {
            assert!(
                live.groups_registry.contains_key(bound),
                "DANGLING REBIND: key `{}` points at removed group `{bound}`",
                key.id
            );
        }
    }
}

// ── §5.4 one plugin mutation domain: install cannot interleave a validate→rebuild ───────────────

/// `install_plugin` used to take NO lock at all, so a tarball write could land between a rollback's
/// `resolve_plugin_rollback` (validate) and its `rebuild_app_from_disk` (read back) — the rollback
/// would load bytes nothing validated. Per-plugin locks cannot close that: the rebuild reads the
/// WHOLE plugin directory to build one `App`.
///
/// The fix is membership in one global mutation domain, and membership is what this asserts: while a
/// transaction holds the section, an install cannot make progress. Before the change the install
/// completed immediately regardless (RED); now it necessarily lands after the holder releases, so no
/// plugin write can appear inside another plugin op's validate→rebuild window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugin_install_is_serialized_by_the_mutation_domain() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!(
        "busbar-txn-plugins-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let handle = handle_for(TestApp::new().plugins_dir(dir.clone()).build());

    let hold = Duration::from_millis(300);
    let holder = {
        let handle = handle.clone();
        tokio::spawn(async move {
            config_transaction(&handle, |txn| {
                Ok(txn.read_store(move || {
                    std::thread::sleep(hold);
                    Ok(Outcome::Value(()))
                }))
            })
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(80)).await;
    let started = Instant::now();
    // A WELL-FORMED request whose tarball is not a valid plugin: the body parse and the base64
    // decode succeed (both are pre-section by design — they cannot corrupt anything), so the
    // rejection can only happen INSIDE the section, which is the property under test.
    let _ = install_plugin(
        State(handle.clone()),
        anon(),
        axum::body::Bytes::from(
            json!({ "file": "x.tar.gz", "tarball_b64": "bm90IGEgdGFyYmFsbA==" }).to_string(),
        ),
    )
    .await;
    let waited = started.elapsed();
    holder.await.expect("join").expect("holder commits");

    assert!(
        waited >= hold / 2,
        "INSTALL OUTSIDE THE DOMAIN: the install returned after only {}ms while a transaction held \
         the section for {}ms. Plugin writes must enter the same `config_transaction` section \
         rollback/reload validate-and-rebuild in, or an install can overwrite the artifact between \
         a rollback's validate and its rebuild.",
        waited.as_millis(),
        hold.as_millis()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── the primitive's own contract ────────────────────────────────────────────────────────────────

/// FAIL-CLOSED BY CONSTRUCTION: a body that declares no plan mutates nothing. It cannot swap out of
/// band either — it never receives the `AppHandle`.
#[tokio::test]
async fn a_txn_that_declares_no_plan_swaps_nothing() {
    let handle = handle_for(TestApp::new().build());
    let before = handle.load().config_version;
    let seen: u64 = config_transaction(&handle, |txn| Ok(txn.done(txn.app().config_version)))
        .await
        .expect("read-only txn succeeds");
    assert_eq!(seen, before, "the body reads the post-lock snapshot");
    assert_eq!(handle.load().config_version, before, "no plan ⇒ no swap");
}

/// FAIL-CLOSED ON PERSIST: `commit` is persist-THEN-swap, so a persist failure leaves the running
/// engine exactly as it was and surfaces the site's own message.
#[tokio::test]
async fn a_failed_persist_swaps_nothing() {
    let handle = handle_for(TestApp::new().build());
    let before = handle.load().config_version;
    let err = config_transaction(&handle, |txn| {
        let mut next = (**txn.app()).clone();
        next.config_version = before.wrapping_add(1);
        Ok(txn.commit(Arc::new(next), || Err("disk said no".to_string()), ()))
    })
    .await
    .expect_err("a failed persist fails the transaction");
    assert!(
        matches!(&err, AdminError::Validation(m) if m == "disk said no"),
        "the persist closure owns the operator-facing message: {err:?}"
    );
    assert_eq!(
        handle.load().config_version,
        before,
        "persist failed ⇒ the live engine is untouched"
    );
}

/// SERIALIZATION: N transactions that read-modify-write the same field cannot lose an update — each
/// one's `txn.app()` already carries its predecessor's swap. (`tests/txn_loom.rs` proves the same
/// invariant over the full interleaving space.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_transactions_never_lose_a_swap() {
    let handle = handle_for(TestApp::new().build());
    let before = handle.load().config_version;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            config_transaction(&handle, |txn| {
                let current = txn.app();
                let mut next = (**current).clone();
                next.config_version = current.config_version.wrapping_add(1);
                Ok(txn.swap(Arc::new(next), ()))
            })
            .await
        }));
    }
    for t in tasks {
        t.await.expect("join").expect("txn commits");
    }
    assert_eq!(
        handle.load().config_version,
        before + 16,
        "every transaction's build read the previous one's swap — no lost update"
    );
}
