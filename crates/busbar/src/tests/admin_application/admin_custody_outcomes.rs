// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use busbar_contract::persistence::*;
use busbar_kernel::state::AppHandle;
use serde_json::{json, Value};
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
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let key = key_mutation(&candidate);
            if key && self.refuse_write.load(Ordering::SeqCst) {
                return Err(Failure::Refused);
            }
            if self.fail_delete.load(Ordering::SeqCst) && candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { address, value } if identity_key(address) && serde_json::from_slice::<Value>(value.expose(&busbar_kernel::seal::lend())).is_ok_and(|row| !row["record"]["deleted_at"].is_null()))) {
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
            let answer = self.inner.commit(candidate).await?;
            if matches!(answer, Decision::Applied(_)) {
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
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .unwrap()
        .unwrap();
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .unwrap()
        .name;
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("admin-custody-outcomes");
    let archive = plugins::signed(
        &plugins::key(0x33),
        manifest,
        &std::fs::read(library).unwrap(),
    );
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let settings: Value = crate::root::test_plugins::application_store_settings(&directory);
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
    let deploy=busbar_kernel::config::deploy_from_deserializer(json!({
        "providers":{},"models":{},
        "identity-providers":{"custody-auth":{"module":oidc_module,"max_admin_scope":"full","settings":common::credentials::settings("api://admin-custody")}},
        "auth":{"chain":[],"admin_auth":["custody-auth"],"signing_key":{"file":signing},"role_bindings":{"custody-auth":{"custodians":{"admin_scope":"full"}}}},
        "store":{"module":module,"settings":settings},"advanced":{"allow_destinations":["127.0.0.1"]}
    })).unwrap();
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
            public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
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
    let anchor = fresh
        .initialize_principal_format(&config, &plugin_config)
        .await
        .expect("the new custody namespace receives its principal baseline before serving");
    let store = observed.expect("the primitive custody fault wrapper was installed");
    store.core.set(anchor.clone()).ok().unwrap();
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone()).unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
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
    serde_json::from_slice(
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
        Value::Null,
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
        Value::Null,
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
        Value::Null,
    )
    .await;
    let revoke = request(
        router.clone(),
        "POST",
        format!("/{id}/revoke"),
        "custody:revoke-error",
        None,
        Value::Null,
    )
    .await;
    let delete = request(
        router.clone(),
        "DELETE",
        format!("/{id}"),
        "custody:delete-error",
        None,
        Value::Null,
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
        Value::Null,
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
        Value::Null,
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
        Value::Null,
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
        Value::Null,
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

fn identity_key(address: &Address) -> bool {
    address.namespace == *b"busbar.identity1" && address.key.first() == Some(&b'K')
}
fn key_mutation(candidate: &PreparedCandidate) -> bool {
    candidate.candidate().mutations.iter().any(|m| match m {
        Mutation::Put { address, .. } | Mutation::Delete(address) => identity_key(address),
        _ => false,
    })
}
