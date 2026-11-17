// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use busbar_contract::json::{json, JsonValueTrait as _, Value};
use busbar_contract::persistence::*;
use busbar_kernel::state::AppHandle;
use tokio::sync::Notify;

use crate::root::test_plugins as plugins;
use crate::test_common as common;

#[derive(Default)]
struct Pause {
    entered: Notify,
    released: Mutex<bool>,
    resume: Condvar,
}

impl Pause {
    fn wait(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.resume.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.resume.notify_all();
    }
}

struct ReleaseOnDrop(Arc<Pause>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct Store {
    inner: Arc<dyn PersistenceBackend>,
    core: std::sync::OnceLock<Arc<busbar_kernel::persistence::facade::CoreStore>>,
    pause_write: AtomicBool,
    write: Arc<Pause>,
    claimed: Notify,
    settled: Notify,
    fail_read: AtomicBool,
    fail_delete: AtomicBool,
    lose_write_reply: AtomicBool,
    fail_refresh_after_write: AtomicBool,
    fail_list: AtomicBool,
    refuse_write: AtomicBool,
    refuse_replay: AtomicBool,
    pause_replay: AtomicBool,
    replay_write: Arc<Pause>,
    held_reads: AtomicUsize,
    lose_head_reply: AtomicBool,
    fail_head_read: AtomicBool,
}

impl Store {
    fn new(inner: Arc<dyn PersistenceBackend>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            core: std::sync::OnceLock::new(),
            pause_write: AtomicBool::new(false),
            write: Arc::new(Pause::default()),
            claimed: Notify::new(),
            settled: Notify::new(),
            fail_read: AtomicBool::new(false),
            fail_delete: AtomicBool::new(false),
            lose_write_reply: AtomicBool::new(false),
            fail_refresh_after_write: AtomicBool::new(false),
            fail_list: AtomicBool::new(false),
            refuse_write: AtomicBool::new(false),
            refuse_replay: AtomicBool::new(false),
            pause_replay: AtomicBool::new(false),
            replay_write: Arc::new(Pause::default()),
            held_reads: AtomicUsize::new(0),
            lose_head_reply: AtomicBool::new(false),
            fail_head_read: AtomicBool::new(false),
        })
    }
}

impl PersistenceBackend for Store {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if self.fail_head_read.load(Ordering::SeqCst)
                && request.addresses.iter().any(|address| {
                    address
                        .key
                        .windows(b"held-head:".len())
                        .any(|part| part == b"held-head:")
                })
            {
                return Err(Failure::Unavailable);
            }
            self.held_reads.fetch_add(
                request
                    .addresses
                    .iter()
                    .filter(|address| {
                        address.key.first() == Some(&b'R')
                            && address
                                .key
                                .windows(b"held:".len())
                                .any(|part| part == b"held:")
                    })
                    .count(),
                Ordering::SeqCst,
            );
            if request.addresses.iter().any(identity_key) && self.fail_read.load(Ordering::SeqCst) {
                return Err(Failure::Unavailable);
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.namespace.0 == *b"busbar.identity1" && self.fail_list.load(Ordering::SeqCst)
            {
                return Err(Failure::Unavailable);
            }
            self.inner.scan(request).await
        })
    }
    fn commit(
        &self,
        candidate: PreparedCandidate,
        commit_key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            let key = key_mutation(&candidate);
            if key && self.refuse_write.load(Ordering::SeqCst) {
                return Err(Failure::Refused);
            }
            if self.fail_delete.load(Ordering::SeqCst) && candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { address, value } if identity_key(address) && busbar_contract::json::parse_value(value.expose(&busbar_kernel::seal::lend())).is_ok_and(|row| !row["record"]["deleted_at"].is_null()))) {
                return Err(Failure::Refused);
            }
            if key && self.pause_write.swap(false, Ordering::SeqCst) {
                self.write.entered.notify_one();
                loop {
                    if *self.write.released.lock().unwrap() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            let replay = candidate.candidate().mutations.iter().any(|m| match m {
                Mutation::Put { address, .. } => {
                    address.key.first() == Some(&b'R')
                        && !address
                            .key
                            .windows(b"binding:".len())
                            .any(|x| x == b"binding:")
                        && address
                            .key
                            .windows(b"busbar.admin-idempotency".len())
                            .any(|x| x == b"busbar.admin-idempotency")
                }
                _ => false,
            });
            let claim = candidate.candidate().mutations.iter().any(|m| match m {
                Mutation::Put { address, .. } => {
                    address.key.first() == Some(&b'C')
                        && address
                            .key
                            .windows(b"busbar.admin-idempotency".len())
                            .any(|x| x == b"busbar.admin-idempotency")
                }
                _ => false,
            });
            if replay && self.pause_replay.swap(false, Ordering::SeqCst) {
                self.replay_write.entered.notify_one();
                while !*self.replay_write.released.lock().unwrap() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            if replay && self.refuse_replay.load(Ordering::SeqCst) {
                return Err(Failure::Refused);
            }
            let head = candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. } if address.key.windows(b"held-head:".len()).any(|part| part == b"held-head:"))
            });
            let answer = self.inner.commit(candidate, commit_key).await?;
            if matches!(answer, Decision::Applied(_)) {
                if head && self.lose_head_reply.load(Ordering::SeqCst) {
                    self.fail_head_read.store(true, Ordering::SeqCst);
                    return Err(Failure::Unknown);
                }
                if claim {
                    self.claimed.notify_one();
                }
                if replay {
                    self.settled.notify_one();
                }
                if key && self.fail_refresh_after_write.load(Ordering::SeqCst) {
                    self.fail_list.store(true, Ordering::SeqCst);
                }
                if key && self.lose_write_reply.load(Ordering::SeqCst) {
                    return Err(Failure::Unknown);
                }
            }
            Ok(answer)
        })
    }
}

fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_CUSTODY_OUTCOME_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current().name().unwrap().to_string();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let until = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read;
            let mut output = String::new();
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut output)
                .unwrap();
            assert!(
                status.success(),
                "actual custody child failed: {status}: {output}"
            );
            assert!(
                output.contains("custody assertions completed"),
                "missing actual custody completion witness: {output}"
            );
            return true;
        }
        assert!(
            std::time::Instant::now() < until,
            "actual custody child timed out"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

async fn app() -> (
    Arc<Store>,
    Arc<AppHandle>,
    axum::Router,
    crate::root::durability::NodeBook,
) {
    busbar_kernel::snapshot::init_for_test(Duration::from_secs(3600));
    crate::dist_root_install::install();
    let library = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library).name;
    let manifest = crate::root::test_plugins::native_manifest("store", &library, "third-party");
    let directory = plugins::scratch("admin-custody-outcomes");
    let archive = plugins::signed(
        &plugins::key(0x33),
        manifest,
        &std::fs::read(library).unwrap(),
    );
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(settings.is_object());
    let oidc_path = common::plugins::token_verifier_cdylib_path().expect("actual OIDC artifact");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .unwrap()
        .unwrap();
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .unwrap()
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "custody-auth", false);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32])).unwrap();
    let deploy=busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers":{},"models":{},
        "identity-providers":{"custody-auth":{"module":oidc_module,"max_admin_scope":"full","settings":common::credentials::settings("api://admin-custody")}},
        "auth":{"chain":[],"admin_auth":["custody-auth"],"signing_key":{"file":signing},"role_bindings":{"custody-auth":{"custodians":{"admin_scope":"full"}}}},
        "store":{"module":module,"settings":settings},"advanced":{}
    }), &crate::root::boot::axis_test_grammar()).unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "http://127.0.0.1:9/store.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            plugins: vec![module.clone()],
            keys: vec![busbar_kernel::config::PluginPublisherKey {
                public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
                revoked: false,
            }],
        });
    let mut observed = None;
    let fresh = crate::root::test_plugins::provision_fresh_application_store_with_backend(
        &config,
        &plugin_config,
        &directory,
        |backend| {
            let store = Store::new(backend);
            observed = Some(store.clone());
            store
        },
    )
    .await
    .expect("the custody fixture exclusively provisions its wrapped native Store");
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = fresh
        .initialize_principal_format(&config, &plugin_config)
        .await
        .expect("the new custody namespace receives its principal baseline before serving");
    let store = observed.expect("the primitive custody fault wrapper was installed");
    store.core.set(anchor.clone()).ok().unwrap();
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone()).unwrap();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .unwrap();
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module).await.unwrap();
    limits.keep().await.unwrap();
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual root hydrates its audit stream");
    let (router, handle) = busbar_kernel::build_router_with_limits(app, 1 << 20, 0, false);
    (store, handle, router, book)
}

async fn request(
    router: axum::Router,
    method: &'static str,
    path: String,
    actor: &'static str,
    token: Option<&'static str>,
    value: Value,
) -> axum::response::Response {
    let credential = common::credentials::token_for(actor, &["custodians"], "api://admin-custody");
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(format!("/api/v1/admin/keys{path}"))
        .header("authorization", format!("Bearer {credential}"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("idempotency-key", token);
    }
    tower::ServiceExt::oneshot(
        router,
        request
            .body(axum::body::Body::from(value.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn mint(
    router: axum::Router,
    actor: &'static str,
    token: &'static str,
) -> axum::response::Response {
    request(
        router,
        "POST",
        String::new(),
        actor,
        Some(token),
        json!({"name":actor}),
    )
    .await
}

fn create_replay_key(header: &str) -> String {
    format!("create:{}:{}", header.len(), header)
}

async fn body(response: axum::response::Response) -> Value {
    busbar_contract::json::parse_value(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn signal(notify: &Notify) {
    tokio::time::timeout(Duration::from_secs(10), notify.notified())
        .await
        .expect("the operation must finish after its blocked store is released");
}

fn audit_rows(actor: &str, action: &str, outcome: &str) -> usize {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(
            0,
            busbar_kernel::audit_ring::MAX_AUDIT_ENTRIES,
            Some(action),
            None,
        )
        .iter()
        .filter(|entry| {
            entry.principal == common::credentials::principal_id(actor) && entry.outcome == outcome
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_mint_finishes_replay_and_durable_settlement() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(mint(router.clone(), "custody:mint", "mint"));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;

    let response = mint(router.clone(), "custody:mint", "mint").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let answer = body(response).await;
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()[0]
            .id,
        answer["id"]
    );
    assert_eq!(audit_rows("custody:mint", "key.create", "applied"), 1);
    assert!(matches!(
        busbar_core_admin::idempotency::durable::claim(
            &busbar_core_admin::idempotency::durable::scoped_store(
                store.core.get().unwrap().clone()
            )
            .unwrap(),
            &(
                common::credentials::principal_id("custody:mint"),
                create_replay_key("mint")
            ),
            busbar_kernel::store::now(),
        )
        .await,
        Err(busbar_core_admin::idempotency::durable::Refused::Applied(_))
    ));
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_mint_queued_behind_config_write_still_settles() {
    if isolated() {
        return;
    }
    use busbar_kernel::config::transaction::{config_transaction, Outcome};
    let (store, handle, router, _book) = app().await;
    let pause = Arc::new(Pause::default());
    let release = ReleaseOnDrop(pause.clone());
    let transaction_handle = handle.clone();
    let blocked = pause.clone();
    let holder = tokio::spawn(async move {
        config_transaction::<_, _, busbar_core_admin::v1::contract::AdminError>(
            &transaction_handle,
            move |txn| {
                Ok(txn.store_write(move || {
                    blocked.wait();
                    Ok(Outcome::Value(()))
                }))
            },
        )
        .await
    });
    signal(&pause.entered).await;
    let caller = tokio::spawn(mint(router.clone(), "custody:queued", "queued"));
    signal(&store.claimed).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    holder.await.unwrap().unwrap();
    signal(&store.settled).await;
    let response = mint(router.clone(), "custody:queued", "queued").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()
            .len(),
        1
    );
    // Durable replay settlement does not imply that the separate native audit
    // drain has accepted its queued event into the live ring yet.
    tokio::time::timeout(
        Duration::from_secs(10),
        busbar_kernel::audit::auditlog::flush_pending(),
    )
    .await
    .expect("the queued mint audit settles within its bound")
    .expect("the queued mint audit is durably accepted");
    assert_eq!(audit_rows("custody:queued", "key.create", "applied"), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn abandoned_rotate_finishes_replay_without_a_second_generation() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    let seeded = body(mint(router.clone(), "custody:rotate-seed", "seed").await).await;
    signal(&store.settled).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.pause_write.store(true, Ordering::SeqCst);
    let release = ReleaseOnDrop(store.write.clone());
    let caller = tokio::spawn(request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate",
        Some("rotate"),
        Value::new(),
    ));
    signal(&store.write.entered).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    drop(release);
    signal(&store.settled).await;
    let generation = store
        .core
        .get()
        .unwrap()
        .identity()
        .get_key(&id)
        .await
        .unwrap()
        .unwrap()
        .generation_hash;
    let response = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate",
        Some("rotate"),
        Value::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(body(response).await["token"], seeded["token"]);
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .get_key(&id)
            .await
            .unwrap()
            .unwrap()
            .generation_hash,
        generation
    );
    assert_eq!(audit_rows("custody:rotate", "key.rotate", "applied"), 1);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn key_mutation_store_failures_each_record_a_refusal() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    let seeded = body(mint(router.clone(), "custody:errors-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_read.store(true, Ordering::SeqCst);
    let update = request(
        router.clone(),
        "PATCH",
        format!("/{id}"),
        "custody:patch-error",
        None,
        json!({"enabled":false}),
    )
    .await;
    let rotate = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:rotate-error",
        None,
        Value::new(),
    )
    .await;
    let revoke = request(
        router.clone(),
        "POST",
        format!("/{id}/revoke"),
        "custody:revoke-error",
        None,
        Value::new(),
    )
    .await;
    let delete = request(
        router.clone(),
        "DELETE",
        format!("/{id}"),
        "custody:delete-error",
        None,
        Value::new(),
    )
    .await;
    for (actor, action, response) in [
        ("custody:patch-error", "key.patch", update),
        ("custody:rotate-error", "key.rotate", rotate),
        ("custody:revoke-error", "key.revoke", revoke),
        ("custody:delete-error", "key.delete", delete),
    ] {
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(audit_rows(actor, action, "rejected"), 1);
        assert_eq!(audit_rows(actor, action, "applied"), 0);
    }
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_delete_records_the_revocation_that_already_applied() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    let seeded = body(mint(router.clone(), "custody:delete-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.fail_delete.store(true, Ordering::SeqCst);
    let response = request(
        router.clone(),
        "DELETE",
        format!("/{id}"),
        "custody:partial-delete",
        None,
        Value::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let key = store
        .core
        .get()
        .unwrap()
        .identity()
        .get_key(&id)
        .await
        .unwrap()
        .unwrap();
    assert!(!key.enabled);
    assert!(key.deleted_at.is_none());
    assert!(store
        .core
        .get()
        .unwrap()
        .identity()
        .list_denylist()
        .await
        .unwrap()
        .contains(&id));
    assert_eq!(
        audit_rows("custody:partial-delete", "key.revoke", "applied"),
        1
    );
    assert_eq!(
        audit_rows("custody:partial-delete", "key.delete", "rejected"),
        1
    );
    assert_eq!(
        audit_rows("custody:partial-delete", "key.delete", "applied"),
        0
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_mint_reply_does_not_release_a_committed_claim() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = mint(router.clone(), "custody:lost-mint", "lost").await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let deferred = store
        .core
        .get()
        .unwrap()
        .identity()
        .list_keys()
        .await
        .expect_err("an unresolved native mint cannot publish an identity snapshot");
    assert!(
        deferred
            .to_string()
            .contains("identity publication deferred"),
        "the original mint retains native custody: {deferred}"
    );
    store.lose_write_reply.store(false, Ordering::SeqCst);
    store
        .core
        .get()
        .unwrap()
        .identity()
        .settle_pending()
        .await
        .expect("confirm the exact original mint after native replies resume");
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()
            .len(),
        1
    );
    let retry = mint(router.clone(), "custody:lost-mint", "lost").await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()
            .len(),
        1
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_rotate_reply_does_not_release_a_committed_claim() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    let seeded = body(mint(router.clone(), "custody:lost-rotate-seed", "seed").await).await;
    let id = seeded["id"].as_str().unwrap().to_string();
    store.lose_write_reply.store(true, Ordering::SeqCst);
    let first = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:lost-rotate",
        Some("lost"),
        Value::new(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let deferred = store
        .core
        .get()
        .unwrap()
        .identity()
        .get_key(&id)
        .await
        .expect_err("the original uncertain rotation blocks publication of this key");
    assert!(
        deferred
            .to_string()
            .contains("same-key native outcome unresolved"),
        "the original rotation retains native custody: {deferred}"
    );
    store.lose_write_reply.store(false, Ordering::SeqCst);
    store
        .core
        .get()
        .unwrap()
        .identity()
        .settle_pending()
        .await
        .expect("confirm the exact original rotation after native replies resume");
    let generation = store
        .core
        .get()
        .unwrap()
        .identity()
        .get_key(&id)
        .await
        .unwrap()
        .unwrap()
        .generation_hash;
    let retry = request(
        router.clone(),
        "POST",
        format!("/{id}/rotate"),
        "custody:lost-rotate",
        Some("lost"),
        Value::new(),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .get_key(&id)
            .await
            .unwrap()
            .unwrap()
            .generation_hash,
        generation
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_mint_publishes_without_refresh_and_same_idempotency_cannot_mint_again() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    store.fail_refresh_after_write.store(true, Ordering::SeqCst);
    let response = mint(router.clone(), "custody:applied-refresh", "applied-refresh").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let answer = body(response).await;
    let id = answer["id"].as_str().unwrap().to_string();
    assert!(answer["token"].is_string());
    // Applied carries the exact committed rows into governance's cache. A failed
    // full refresh cannot erase confirmation or manufacture an unknown outcome.
    let listed = request(
        router.clone(),
        "GET",
        format!("/{id}"),
        "custody:applied-refresh",
        None,
        Value::new(),
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        audit_rows("custody:applied-refresh", "key.create", "applied"),
        1
    );
    assert_eq!(
        audit_rows("custody:applied-refresh", "key.create", "rejected"),
        0
    );
    assert!(matches!(busbar_core_admin::idempotency::durable::claim(
        &busbar_core_admin::idempotency::durable::scoped_store(store.core.get().unwrap().clone()).unwrap(),
        &(common::credentials::principal_id("custody:applied-refresh"), create_replay_key("applied-refresh")),
        busbar_kernel::store::now(),
    ).await, Err(busbar_core_admin::idempotency::durable::Refused::Applied(what)) if what == format!("key:{id}")));
    store.fail_list.store(false, Ordering::SeqCst);
    store
        .fail_refresh_after_write
        .store(false, Ordering::SeqCst);

    let fresh_cache = Arc::new(busbar_core_admin::keys::KeyReplayCache::new());
    let retry = mint(
        router.clone().layer(axum::Extension(fresh_cache)),
        "custody:applied-refresh",
        "applied-refresh",
    )
    .await;
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    let retry = body(retry).await;
    assert_eq!(retry["error"]["code"], "mutation_applied");
    assert_eq!(retry["effect"], "applied");
    assert_eq!(retry["resource"], format!("key:{id}"));
    assert_eq!(retry["credential_recoverable"], false);
    assert!(retry.get("token").is_none());
    assert_eq!(
        store
            .core
            .get()
            .unwrap()
            .identity()
            .list_keys()
            .await
            .unwrap()
            .len(),
        1
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_store_error_cannot_spoof_the_typed_committed_mint_outcome() {
    if isolated() {
        return;
    }
    let (store, _handle, router, _book) = app().await;
    store.refuse_write.store(true, Ordering::SeqCst);
    let response = mint(router.clone(), "custody:spoofed-applied", "spoofed-applied").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let answer = body(response).await;
    assert!(!answer.to_string().contains("MINT APPLIED"));
    assert!(store
        .core
        .get()
        .unwrap()
        .identity()
        .list_keys()
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        audit_rows("custody:spoofed-applied", "key.create", "applied"),
        0
    );
    assert!(matches!(
        busbar_core_admin::idempotency::durable::claim(
            &busbar_core_admin::idempotency::durable::scoped_store(
                store.core.get().unwrap().clone()
            )
            .unwrap(),
            &(
                common::credentials::principal_id("custody:spoofed-applied"),
                create_replay_key("spoofed-applied")
            ),
            busbar_kernel::store::now(),
        )
        .await,
        Err(busbar_core_admin::idempotency::durable::Refused::InFlight)
    ));
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_effect_receipt_refusal_prevents_handler_dispatch() {
    if isolated() {
        return;
    }
    use tower::ServiceExt as _;

    let (store, handle, _router, _book) = app().await;
    store.refuse_replay.store(true, Ordering::SeqCst);
    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/receipt-before-effect",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );
    let router = busbar_core_admin::test_support::with_idempotency(effect, handle.load());
    let request = || {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/receipt-before-effect")
            .header("idempotency-key", "receipt-refused")
            .body(axum::body::Body::from("exact request"))
            .unwrap()
    };
    let response = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    store.refuse_replay.store(false, Ordering::SeqCst);
    let retry = router.oneshot(request()).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn held_history_cursor_bounds_reads_without_a_lifetime_reuse_cap() {
    if isolated() {
        return;
    }
    use busbar_core_admin::idempotency::durable::{self, Settled};

    let (store, handle, _router, _book) = app().await;
    let scoped = durable::scoped_store(
        handle
            .load()
            .governance
            .as_ref()
            .unwrap()
            .core_store_handle()
            .unwrap(),
    )
    .unwrap();
    let now = busbar_kernel::store::now();
    let key = ("cursor-owner".into(), "op:reuse".into());
    for _ in 0..70 {
        let claim = durable::claim_held(&scoped, &key, now).await.unwrap();
        durable::settle(&scoped, &claim, now, &Settled::Released)
            .await
            .unwrap();
    }
    store.held_reads.store(0, Ordering::SeqCst);
    let current = durable::claim_held(&scoped, &key, now).await.unwrap();
    assert!(
        store.held_reads.load(Ordering::SeqCst) <= 2,
        "admission must start at its retained current-generation cursor"
    );
    durable::settle(&scoped, &current, now, &Settled::Retained(vec![3; 49]))
        .await
        .unwrap();
    store.held_reads.store(0, Ordering::SeqCst);
    assert!(durable::lookup(&scoped, &key, now).await.unwrap().is_some());
    assert!(
        store.held_reads.load(Ordering::SeqCst) <= 1,
        "lookup must not traverse retired generations"
    );
    let framed = format!("{}:{}:{}", key.0.len(), key.0, key.1);
    let head = format!(
        "held-head:{}",
        busbar_contract::redacted::sha256_hex(framed.as_bytes())
    );
    scoped
        .delete("busbar.admin-idempotency", head.as_bytes())
        .await
        .unwrap();
    store.held_reads.store(0, Ordering::SeqCst);
    assert!(
        durable::lookup(&scoped, &key, now).await.is_err(),
        "a pre-index history beyond the read budget is unavailable, not absent"
    );
    assert_eq!(store.held_reads.load(Ordering::SeqCst), 64);
    assert!(
        scoped
            .get("busbar.admin-idempotency", head.as_bytes())
            .await
            .unwrap()
            .is_none(),
        "lookup never publishes an index"
    );
    store.held_reads.store(0, Ordering::SeqCst);
    assert!(matches!(
        durable::claim_held(&scoped, &key, now).await,
        Err(durable::Refused::Unavailable(_))
    ));
    assert_eq!(store.held_reads.load(Ordering::SeqCst), 64);
    let checkpoint = scoped
        .get("busbar.admin-idempotency", head.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        checkpoint.expose(&busbar_kernel::seal::lend()),
        &[1, 0, 0, 0, 64]
    );
    assert_eq!(
        durable::claim_held(&scoped, &key, now).await,
        Err(durable::Refused::Retained(vec![3; 49])),
        "bounded progress cannot skip the unresolved current generation"
    );
    scoped
        .put(
            "busbar.admin-idempotency",
            head.as_bytes(),
            busbar_contract::Secret::new(vec![255]),
        )
        .await
        .unwrap();
    assert!(matches!(
        durable::claim_held(&scoped, &key, now).await,
        Err(durable::Refused::Unavailable(_))
    ));
    assert!(durable::lookup(&scoped, &key, now).await.is_err());
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn cursor_persistence_refusal_cannot_admit_a_successor() {
    if isolated() {
        return;
    }
    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};

    let (store, handle, _router, _book) = app().await;
    let scoped = durable::scoped_store(
        handle
            .load()
            .governance
            .as_ref()
            .unwrap()
            .core_store_handle()
            .unwrap(),
    )
    .unwrap();
    let now = busbar_kernel::store::now();
    let key = ("cursor-owner".into(), "op:refused-cursor".into());
    let first = durable::claim_held(&scoped, &key, now).await.unwrap();
    durable::settle(&scoped, &first, now, &Settled::Released)
        .await
        .unwrap();
    store.refuse_replay.store(true, Ordering::SeqCst);
    assert!(
        matches!(
            durable::claim_held(&scoped, &key, now).await,
            Err(Refused::Unavailable(_))
        ),
        "an unconfirmed cursor publication must not return an effect capability"
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn uncertain_cursor_write_cannot_grant_until_its_state_is_observed() {
    if isolated() {
        return;
    }
    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};
    let (store, handle, _router, _book) = app().await;
    let scoped = durable::scoped_store(
        handle
            .load()
            .governance
            .as_ref()
            .unwrap()
            .core_store_handle()
            .unwrap(),
    )
    .unwrap();
    let now = busbar_kernel::store::now();
    let key = ("cursor-owner".into(), "op:uncertain-cursor".into());
    let first = durable::claim_held(&scoped, &key, now).await.unwrap();
    durable::settle(&scoped, &first, now, &Settled::Released)
        .await
        .unwrap();
    store.lose_head_reply.store(true, Ordering::SeqCst);
    let uncertain = tokio::time::timeout(
        Duration::from_secs(10),
        durable::claim_held(&scoped, &key, now),
    )
    .await
    .expect("unknown cursor outcome returns without dispatch");
    assert!(matches!(uncertain, Err(Refused::Unavailable(_))));
    store.lose_head_reply.store(false, Ordering::SeqCst);
    store.fail_head_read.store(false, Ordering::SeqCst);
    assert!(durable::claim_held(&scoped, &key, now).await.is_ok());
    assert_eq!(
        durable::claim_held(&scoped, &key, now).await,
        Err(Refused::InFlight)
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_cursor_advances_still_grant_exactly_one_claim() {
    if isolated() {
        return;
    }
    use busbar_core_admin::idempotency::durable::{self, Refused, Settled};
    let (_store, handle, _router, _book) = app().await;
    let scoped = Arc::new(
        durable::scoped_store(
            handle
                .load()
                .governance
                .as_ref()
                .unwrap()
                .core_store_handle()
                .unwrap(),
        )
        .unwrap(),
    );
    let now = busbar_kernel::store::now();
    let key = ("cursor-owner".into(), "op:concurrent-cursor".into());
    let first = durable::claim_held(&scoped, &key, now).await.unwrap();
    durable::settle(&scoped, &first, now, &Settled::Released)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut callers = Vec::new();
    for _ in 0..8 {
        let scoped = scoped.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        callers.push(tokio::spawn(async move {
            barrier.wait().await;
            durable::claim_held(&scoped, &key, now).await
        }));
    }
    let mut grants = 0;
    for caller in callers {
        match caller.await.unwrap() {
            Ok(_) => grants += 1,
            Err(Refused::InFlight | Refused::Unavailable(_)) => {}
            other => panic!("unexpected cursor contender: {other:?}"),
        }
    }
    assert_eq!(
        grants, 1,
        "cursor publication does not itself grant an effect capability"
    );
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_answer_persistence_keeps_the_acknowledged_intent() {
    if isolated() {
        return;
    }
    use tower::ServiceExt as _;
    let (store, handle, _router, _book) = app().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let handler_store = store.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/answer-persistence",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            let store = handler_store.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                store.refuse_replay.store(true, Ordering::SeqCst);
                (StatusCode::OK, "effect committed")
            }
        }),
    );
    let router = busbar_core_admin::test_support::with_idempotency(effect, handle.load());
    let request = || {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/answer-persistence")
            .header("idempotency-key", "answer-persistence")
            .body(axum::body::Body::from("original"))
            .unwrap()
    };
    assert_eq!(
        router.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    store.refuse_replay.store(false, Ordering::SeqCst);
    let retry = router.oneshot(request()).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    println!("custody assertions completed");
}

fn precondition_request(if_match: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("PUT")
        .uri("/api/v1/admin/config/settings")
        .header("if-match", if_match)
        .header("idempotency-key", "stale-precondition-release")
        .body(axum::body::Body::from("exact request"))
        .unwrap()
}

fn counted_settings(effects: Arc<AtomicUsize>) -> axum::Router {
    axum::Router::new().route(
        "/api/v1/admin/config/settings",
        axum::routing::put(move || {
            let effects = effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_precondition_failed_release_never_dispatches_or_grants_retry() {
    if isolated() {
        return;
    }
    use tower::ServiceExt as _;
    let (store, handle, _router, _book) = app().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let router = busbar_core_admin::test_support::with_idempotency(
        counted_settings(effects.clone()),
        handle.load(),
    );
    store.refuse_replay.store(true, Ordering::SeqCst);
    let refused = router
        .clone()
        .oneshot(precondition_request("\"stale\""))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(body(refused).await["error"]["reason"], "stale_if_match");
    store.refuse_replay.store(false, Ordering::SeqCst);
    let retry = router.oneshot(precondition_request("*")).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(retry).await["error"]["reason"],
        "idempotency_in_flight"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    println!("custody assertions completed");
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_stale_precondition_keeps_exclusion_while_release_is_unknown() {
    if isolated() {
        return;
    }
    use tower::ServiceExt as _;
    let (store, handle, _router, _book) = app().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let router = busbar_core_admin::test_support::with_idempotency(
        counted_settings(effects.clone()),
        handle.load(),
    );
    let _release = ReleaseOnDrop(store.replay_write.clone());
    store.pause_replay.store(true, Ordering::SeqCst);
    let first_router = router.clone();
    let first = tokio::spawn(async move {
        first_router
            .oneshot(precondition_request("\"stale\""))
            .await
            .unwrap()
    });
    tokio::time::timeout(
        Duration::from_secs(10),
        store.replay_write.entered.notified(),
    )
    .await
    .unwrap();
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let retry = router.oneshot(precondition_request("*")).await.unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(retry).await["error"]["reason"],
        "idempotency_in_flight"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    store.replay_write.release();
    println!("custody assertions completed");
}

fn identity_key(address: &Address) -> bool {
    address.namespace == *b"busbar.identity1" && address.key.first() == Some(&b'K')
}
fn key_mutation(candidate: &PreparedCandidate) -> bool {
    candidate.candidate().mutations.iter().any(|m| match m {
        Mutation::Put { address, .. } | Mutation::Delete(address) => identity_key(address),
        _ => false,
    })
}
