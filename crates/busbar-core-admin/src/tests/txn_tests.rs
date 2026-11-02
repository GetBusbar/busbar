use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::v1::contract::AdminError;
use crate::v1::json::{delete_group, install_plugin};
use busbar_kernel::config::transaction::{config_transaction, Outcome};
use busbar_kernel::governance::GovState;
use busbar_kernel::state::AppHandle;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

struct SlowStore {
    inner: MemoryStore,
    delay: Duration,

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

impl busbar_contract::records::RecordStore for SlowStore {
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    fn put_key_with_credential(
        &self,
        key: &busbar_contract::records::VirtualKey,
        secret: &busbar_contract::records::CredentialSecret,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(
        &self,
        key_id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::CredentialMeta>>
    {
        self.inner.list_credentials(key_id)
    }
}

fn gov(store: Arc<dyn busbar_kernel::governance::RecordStore>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("gov"),
    )
}

fn tree(names: &[&str]) -> std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> {
    names
        .iter()
        .map(|n| (n.to_string(), busbar_kernel::config::GroupCfg::default()))
        .collect()
}

fn handle_for(app: Arc<busbar_kernel::state::App>) -> Arc<AppHandle> {
    Arc::new(AppHandle::new(app))
}

fn anon() -> axum::Extension<busbar_kernel::auth::AuthPrincipal> {
    axum::Extension(busbar_kernel::auth::AuthPrincipal(None))
}

async fn mint(handle: &Arc<AppHandle>, name: &str, group: Option<&str>) -> StatusCode {
    let body = match group {
        Some(g) => json!({ "name": name, "group": g }),
        None => json!({ "name": name }),
    };
    crate::keys::create_key(
        State(handle.clone()),
        anon(),
        HeaderMap::new(),
        axum::Extension(std::sync::Arc::new(crate::keys::KeyReplayCache::new())),
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

fn spawn_liveness_probe() -> (
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<u64>,
) {
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
    (stop, worst, probe)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_store_read_does_not_stall_the_executor() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let delay = Duration::from_millis(400);
    let store = Arc::new(SlowStore::new(delay));
    let probe_store = store.clone();
    let app = crate::new_test_app()
        .governance(gov(store))
        .groups_tree(tree(&["team"]))
        .build();
    let handle = handle_for(app);

    let (stop, worst, probe) = spawn_liveness_probe();

    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_is_read_from_the_post_lock_snapshot() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let mut app = crate::new_test_app()
        .governance(gov(store))
        .groups_tree(tree(&["team"]))
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .max_keys_per_principal = 5;
    let handle = handle_for(app);

    assert_eq!(
        mint(&handle, "first", Some("team")).await,
        StatusCode::CREATED
    );

    let lowering = {
        let handle = handle.clone();
        tokio::spawn(async move {
            config_transaction::<_, _, AdminError>(&handle, |txn| {
                let current = txn.app().clone();
                Ok(txn.read_store(move || {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mints_never_bind_a_deleted_group() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    {
        let g = gov(Arc::new(MemoryStore::new()));
        let app = crate::new_test_app()
            .governance(g.clone())
            .groups_tree(tree(&["team"]))
            .build();
        let handle = handle_for(app);
        assert_eq!(
            mint(&handle, "bound-control", Some("team")).await,
            StatusCode::CREATED
        );
        let keys = g.all_keys().expect("control key readable");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].group.as_deref(), Some("team"));
    }
    for round in 0..10u32 {
        let store = Arc::new(MemoryStore::new());
        let g = gov(store);
        let app = crate::new_test_app()
            .governance(g.clone())
            .groups_tree(tree(&["team"]))
            .build();
        let handle = handle_for(app);

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
        let mut created = 0;
        for m in minting {
            match m.await.expect("mint task joins") {
                StatusCode::CREATED => created += 1,
                StatusCode::BAD_REQUEST => {}
                status => panic!("mint must create or refuse the deleted group, got {status}"),
            }
        }
        let deleted = deleting.await.expect("delete task joins");
        assert_eq!(
            deleted,
            if created == 0 {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CONFLICT
            },
            "deletion succeeds only if no bound mint committed"
        );

        let live = handle.load();
        let keys = g.all_keys().expect("keys readable");
        assert_eq!(keys.len(), created, "every successful mint is durable");
        assert_eq!(
            live.groups_registry.contains_key("team"),
            created != 0,
            "the group remains exactly when a bound mint prevented deletion"
        );
        for key in keys {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rebinds_never_bind_a_deleted_group() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let g = gov(store);
    let app = crate::new_test_app()
        .governance(g.clone())
        .groups_tree(tree(&["team", "other"]))
        .build();
    let handle = handle_for(app);

    let mut ids = Vec::new();
    for i in 0..6 {
        let (key, _tok) = g
            .mint_signed(
                busbar_kernel::governance::NewKeySpec {
                    name: format!("r{i}"),
                    allowed_pools: None,
                    group: Some("other".to_string()),
                    labels: Default::default(),
                    ..Default::default()
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
            crate::keys::update_key(
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

fn parking_secret_hook_env(delay: Duration) -> busbar_kernel::hooks::HookEnv {
    busbar_kernel::hooks::HookEnv::with_axis(
        busbar_kernel_testkit::test_support::rows::Rows::new()
            .with_dropped_secret_slots(
                busbar_kernel_testkit::test_support::rows::row("some-hook-plugin", "", "hook"),
                &["licenseKey"],
            )
            .into_rows(),
        busbar_kernel_testkit::test_support::hook_double::HookAxisDouble::new(&[
            "some-hook-plugin",
        ]),
        Arc::new(busbar_kernel::config::secret::SecretResolver::with_plugin(
            Box::new(move |_module: &str, _settings: &str| {
                std::thread::sleep(delay);
                Ok(busbar_contract::redacted::Secret::new(b"resolved".to_vec()))
            }),
        )),
    )
}

async fn register_secret_hook(handle: Arc<AppHandle>) -> (StatusCode, String) {
    let body = json!({
        "name": "compliance-gate",
        "config": {
            "module": "some-hook-plugin",
            "kind": "gate",
            "global": true,
            "settings": { "licenseKey": { "module": "acme-vault", "settings": { "path": "kv/busbar" } } }
        }
    });
    let response = crate::v1::json::register_hook(
        State(handle),
        anon(),
        HeaderMap::new(),
        axum::body::Bytes::from(body.to_string()),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .expect("the hook response body is bounded");
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_secret_plugin_does_not_stall_the_executor() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let delay = Duration::from_millis(400);
    let app = crate::new_test_app()
        .hook_env(parking_secret_hook_env(delay))
        .build();
    let handle = handle_for(app);

    let (stop, worst, probe) = spawn_liveness_probe();
    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

    let (status, body) = tokio::spawn(register_secret_hook(handle.clone()))
        .await
        .expect("register joins");
    stop.store(true, Ordering::SeqCst);
    let ticks = probe.await.expect("probe joins");

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the hook registers: {status}: {body}"
    );
    assert!(ticks > 0, "the probe must have run");
    let worst_gap = worst.load(Ordering::SeqCst);
    assert!(
        worst_gap < delay.as_millis() as u64 / 2,
        "EXECUTOR STALLED: the liveness probe's worst tick gap was {worst_gap}ms while a {}ms \
         `kind: secret` PLUGIN resolve ran under the config-mutation lock. Blocking plugin FFI \
         reached the async thread — the snapshot build must be deferred through `Txn::read_store` \
         onto spawn_blocking.",
        delay.as_millis()
    );
}
