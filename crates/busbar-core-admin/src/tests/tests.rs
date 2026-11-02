use busbar_kernel::audit_ring;
use busbar_kernel::config::migrated_store_module;
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel_testkit::test_support::governance::GovStateFixtures;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
use busbar_kernel_testkit::test_support::TestOverlayStore;
use std::sync::Arc;

#[path = "cache_flush_tests.rs"]
mod cache_flush_tests;

#[path = "store_overlay_tests.rs"]
mod store_overlay_tests;

#[path = "price_activation_tests.rs"]
mod price_activation_tests;

#[path = "config_boundary_tests.rs"]
mod config_boundary_tests;

const OAS_OPERATION_STATUSES: &str =
    include_str!("../../tests/fixtures/openapi_operation_statuses_key.txt").trim_ascii();

const LOCKED_CONFIG_MUTATION_MESSAGE: &str = "config mutation refused: this busbar has no writable Store-backed config overlay; edit config.yaml and reload a locked deployment";

fn gov_with_signer(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    let gov = gov_without_at_rest_key(store, admin_token);
    gov.set_at_rest_keys(Some(busbar_kernel::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
    gov
}

fn gov_without_at_rest_key(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

fn audit_principal(app: &mut Arc<busbar_kernel::state::App>, role: &str) {
    let inner = Arc::get_mut(app).expect("sole owner");
    let module = "test-scope-module";
    inner.admin_chain.insert(0, module.to_string());
    inner
        .role_bindings
        .entry(module.to_string())
        .or_default()
        .insert(
            role.to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
    inner
        .auth_scope_caps
        .insert(module.to_string(), "full".to_string());
}

async fn spin_up(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, reqwest::Client::new())
}

async fn serve_with_gov(gov: Arc<GovState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (addr, handle)
}

#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let env =
        busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], Default::default());
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let env_for_warm = env.clone();
    let app = crate::new_test_app().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let (addr, serve, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "cfg-hook",
                "config": {"kind": "gate", "module": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let warm: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "settings": {"ratio": 0.4}
    }))
    .expect("hook cfg");
    assert!(
        busbar_kernel_testkit::test_support::hooks::await_transport_published(
            "cfg-hook",
            &warm,
            &env_for_warm
        )
        .await,
        "the loader must publish a transport for the hook the PATCH is about to configure"
    );
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"ratio": 0.4}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);
    let got: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(
        got["settings_keys"],
        serde_json::json!(["ratio"]),
        "committed settings visible as KEY NAMES: {got}"
    );
    assert!(
        got.get("settings").is_none(),
        "the raw settings bag must never be on this wire: {got}"
    );

    let schema: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook/schema")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        schema["schema"]["properties"]["order"]["type"], "array",
        "describe schema extracted, single nest: {schema}"
    );

    serve.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_plugin_schema_falls_back_to_manifest_when_describe_answers_null() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let manifest_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"order": {"type": "array"}},
    });
    let env = busbar_kernel_testkit::test_support::test_hook_env_with_schema(
        &["test-hook-fallback"],
        Default::default(),
        Some(&manifest_schema.to_string()),
    );
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let env_for_warm = env.clone();
    let app = crate::new_test_app().governance(gov).hook_env(env).build();
    let router = crate::build_router(app);
    let (addr, serve, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "fallback-hook",
                "config": {"kind": "gate", "module": "test-hook-fallback"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);

    let warm: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook-fallback", "settings": {"empty_management": true}
    }))
    .expect("hook cfg");
    assert!(
        busbar_kernel_testkit::test_support::hooks::await_transport_published(
            "fallback-hook",
            &warm,
            &env_for_warm
        )
        .await,
        "the loader must publish a transport for the hook the PATCH is about to configure"
    );
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/fallback-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"empty_management": true}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);

    let got: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/plugins/fallback-hook/schema"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        got["source"], "manifest",
        "describe answered null -> falls back to the manifest baseline: {got}"
    );
    assert_eq!(
        got["schema"], manifest_schema,
        "the ACTUAL manifest schema comes back, not just a source label: {got}"
    );
    assert_eq!(got["schema_error"], serde_json::Value::Null);

    serve.abort();
}

#[tokio::test]
async fn test_admin_v1_scope_ladder_e2e_with_group_mapped_principals() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            busbar_kernel::config::operator_provider().to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );

        table.insert(
            "admins".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);

        let mut other = std::collections::BTreeMap::new();
        other.insert(
            "sneaky".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("other-module".to_string(), other);

        inner
            .auth_scope_caps
            .insert("test-scope-module".to_string(), "full".to_string());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let with = |tok: &'static str, req: reqwest::RequestBuilder| {
        req.header("x-admin-token", tok)
            .header("content-type", "application/json")
    };
    let hook_body = serde_json::json!({
        "name": "scoped-hook",
        "config": {"kind": "tap", "module": "test-hook"}
    })
    .to_string();
    let key_body = serde_json::json!({"name": "k"}).to_string();

    let r = with(
        "grp:viewers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "read-only can read");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "read-only cannot mint (Full)");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "read-only cannot register hooks (Full)"
    );

    let r = with(
        "grp:admins",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "full registers hooks");
    let r = with(
        "grp:admins",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "full mints keys");

    let r = with(
        "grp:strangers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "unmapped groups grant nothing");

    let r = with(
        "grp:sneaky",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "a role bound under another module grants nothing through this one"
    );

    let r = with(
        "admintok",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "operator token stays full");

    handle.abort();
}

struct CachingDoor(std::sync::atomic::AtomicUsize);

const FLUSHED: u64 = 3;

struct Passed;

impl std::future::Future for Passed {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::Verifying for Passed {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
}

impl busbar_contract::auth_calls::AuthCalls for CachingDoor {
    fn name(&self) -> &str {
        "caching-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(Passed)
    }
    fn refresh(&self) -> Result<u64, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(FLUSHED)
    }
}

#[tokio::test]
async fn test_admin_v1_credential_cache_and_flush_endpoint() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let door = Arc::new(CachingDoor(std::sync::atomic::AtomicUsize::new(0)));

    let operator = busbar_kernel::config::operator_provider();
    let mut app = crate::new_test_app()
        .governance(gov)
        .admin_door("ext-idp", door.clone())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec![
            "test-scope-module".to_string(),
            "ext-idp".to_string(),
            operator.to_string(),
        ];
        let mut table = std::collections::BTreeMap::new();
        table.insert(
            "viewers".to_string(),
            busbar_kernel::config::RoleBindingCfg {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner
            .role_bindings
            .insert("test-scope-module".to_string(), table);
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let flush = |token: &'static str, body: Option<serde_json::Value>| {
        let mut r = client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", token);
        if let Some(body) = body {
            r = r
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        r.send()
    };

    let r = flush("grp:viewers", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 0);

    let r = flush("admintok", Some(serde_json::json!({"module": "ext-idp"})))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["flushed"], FLUSHED,
        "what the plugin reported dropping"
    );
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", Some(serde_json::json!({"module": operator})))
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], 0);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 1);

    let r = flush("admintok", None).await.unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["flushed"], FLUSHED);
    assert_eq!(door.0.load(std::sync::atomic::Ordering::SeqCst), 2);

    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"module\": 7}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    handle.abort();
}

struct GatedKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    entered: tokio::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    landed: tokio::sync::mpsc::Sender<String>,
    fired: std::sync::atomic::AtomicBool,
}
impl busbar_kernel::governance::RecordStore for GatedKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        if self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return self.inner.put_key(key);
        }

        let _ = self.entered.try_send(());
        if let Some(rx) = self
            .release
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(30));
        }
        let out = self.inner.put_key(key);
        if out.is_ok() {
            let _ = self.landed.try_send(key.id.clone());
        }
        out
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

struct SlowNthPutKeyStore {
    inner: Arc<dyn busbar_kernel::governance::RecordStore>,
    delay: std::time::Duration,
    calls: std::sync::atomic::AtomicUsize,
    slow_on_call: usize,
}
impl busbar_kernel::governance::RecordStore for SlowNthPutKeyStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == self.slow_on_call {
            std::thread::sleep(self.delay);
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test]
async fn an_idempotency_key_survives_a_client_disconnect_mid_mint() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let inner = Arc::new(MemoryStore::new());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (landed_tx, mut landed_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let gated_store: Arc<dyn busbar_kernel::governance::RecordStore> = Arc::new(GatedKeyStore {
        inner,
        entered: entered_tx,
        release: std::sync::Mutex::new(Some(release_rx)),
        landed: landed_tx,
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let gov = gov_with_signer(gated_store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    let keys_url = format!("http://{addr}/api/v1/admin/keys");
    let post = |client: &reqwest::Client, url: &str| {
        client
            .post(url)
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "dc-1")
            .body(r#"{"name": "disconnector"}"#)
            .send()
    };
    let count_disconnector = |v: &serde_json::Value| -> usize {
        v["items"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|k| k["name"].as_str() == Some("disconnector"))
                    .count()
            })
            .unwrap_or(0)
    };

    let doomed_url = keys_url.clone();
    let doomed = tokio::spawn(async move {
        let client = reqwest::Client::new();
        post(&client, &doomed_url).await
    });

    const RENDEZVOUS_BACKSTOP: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::time::timeout(RENDEZVOUS_BACKSTOP, entered_rx.recv())
        .await
        .expect(
            "waited 60s for the mint to enter the store's put_key and it never did. The request \
             did not get as far as the blocking mint, so there is no mid-mint window to disconnect \
             inside and this test would be asserting nothing.",
        )
        .expect("the gated store was dropped before the mint entered put_key");

    doomed.abort();
    let joined = doomed.await;
    assert!(
        joined.as_ref().is_err_and(|e| e.is_cancelled()),
        "the doomed request must have been cancelled mid-flight; it instead completed, which means \
         the store gate did not hold the mint open and there was no mid-mint disconnect: {:?}",
        joined.map(|r| r.map(|resp| resp.status()))
    );

    let probe = reqwest::Client::new();
    let mid: serde_json::Value = probe
        .get(&keys_url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        count_disconnector(&mid),
        0,
        "the mint must still be parked in put_key at this point, so no key should exist yet; \
         found one already committed, so the disconnect was not mid-mint: {mid:?}"
    );

    release_tx
        .send(())
        .expect("the parked mint hung up on its release channel");
    let committed_id = tokio::time::timeout(RENDEZVOUS_BACKSTOP, landed_rx.recv())
        .await
        .expect(
            "waited 60s after releasing the parked mint and its write never committed. A mint \
             whose client disconnected must still run to completion on the uncancellable blocking \
             task; observed instead: released, then silence.",
        )
        .expect("the gated store was dropped before the released mint could commit");

    let normal_client = reqwest::Client::new();
    let retry = post(&normal_client, &keys_url).await.unwrap();

    assert!(
        matches!(retry.status().as_u16(), 201 | 409),
        "a retry must replay the first answer or refuse the held claim: {}",
        retry.status()
    );
    if retry.status().as_u16() == 201 {
        let replay: serde_json::Value = retry.json().await.unwrap();
        assert_eq!(
            replay["id"].as_str(),
            Some(committed_id.as_str()),
            "a cached 201 must name the first committed key, never a second mint"
        );
    }

    let keys: serde_json::Value = normal_client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = keys["items"].as_array().unwrap();
    let disconnector_count = items
        .iter()
        .filter(|k| k["name"].as_str() == Some("disconnector"))
        .count();
    assert_eq!(
        disconnector_count, 1,
        "exactly one key must exist after a client disconnect mid-mint + retry, got: {items:?}"
    );
    assert!(
        items
            .iter()
            .any(|key| key["id"].as_str() == Some(committed_id.as_str())),
        "the one retained key must be the first committed key"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let inner = Arc::new(MemoryStore::new());

    let slow_store: Arc<dyn busbar_kernel::governance::RecordStore> =
        Arc::new(SlowNthPutKeyStore {
            inner,
            delay: std::time::Duration::from_millis(500),
            calls: std::sync::atomic::AtomicUsize::new(0),
            slow_on_call: 1,
        });
    let gov = gov_with_signer(slow_store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "r"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let rotate_url = format!("{keys_url}/{id}/rotate");

    let first_client = client.clone();
    let first_url = rotate_url.clone();
    let first = tokio::spawn(async move {
        first_client
            .post(&first_url)
            .header("x-admin-token", "admintok")
            .header("idempotency-key", "rot-inflight")
            .send()
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let second = client
        .post(&rotate_url)
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "rot-inflight")
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status().as_u16(),
        409,
        "a concurrent same-key rotate while the first is still landing must be refused as \
         already-in-flight, not replayed as a completed response: {}",
        second.text().await.unwrap_or_default()
    );

    let first = first.await.unwrap();
    assert_eq!(
        first.status().as_u16(),
        200,
        "the reserving (first) rotation itself must still succeed"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_put_hook_replaces_live_with_guards() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "rep",
                "config": {"kind": "tap", "module": "test-hook"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook-v2"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status().as_u16(), 200);
    let got: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("test-hook-v2"),
        "the replacement is live: {got}"
    );

    let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(
            serde_json::json!({"config": {"kind": "gate", "module": "test-hook", "prompt": "rw"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "module": "test-hook"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

    let live = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap();
    let etag = live
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("config-plane reads emit the ETag")
        .to_string();
    let fresh = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", etag)
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "module": "test-hook"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");
    assert!(
        fresh.headers().get(reqwest::header::ETAG).is_some(),
        "the mutation response carries the NEW ETag for chaining"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_versions_rollback_and_diff() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    let body = serde_json::json!({
        "name": "rbk",
        "config": {"kind": "tap", "module": "test-hook"}
    });
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let versions: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let list = versions["items"].as_array().unwrap();
    assert_eq!(list.len(), 3, "boot + register + delete: {versions}");
    assert_eq!(list[0]["version"], 2);
    assert!(list[0]["summary"]
        .as_str()
        .unwrap()
        .contains("hook.delete hook:rbk"));
    assert_eq!(list[0]["principal"], "admin");

    let diff: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/config/diff?from=1&to=2"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(diff["hooks"]["removed"][0], "rbk", "{diff}");

    let rb = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(rb.status().as_u16(), 200);
    let rb_body: serde_json::Value = rb.json().await.unwrap();
    assert_eq!(rb_body["restored_version"], 1);
    assert_eq!(rb_body["config_version"], 3);
    let restored = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        restored.status().as_u16(),
        200,
        "the rolled-back hook is live again"
    );

    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 999}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .header("if-match", "\"0\"")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_register_hook_takes_effect_live() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let before: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 0);

    let body = serde_json::json!({
        "name": "compress",
        "config": {
            "kind": "gate",
            "module": "test-hook",
            "prompt": "rw",
            "global": true
        }
    });
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "hook registered");
    let created_body: serde_json::Value = created.json().await.unwrap();
    assert_eq!(created_body["name"], "compress");
    assert_eq!(created_body["kind"], "gate");
    assert_eq!(created_body["global"], true);

    let after: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = after["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "the registered hook is now in the live config"
    );
    assert_eq!(items[0]["name"], "compress");

    let info: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        info["config_version"], 1,
        "one apply bumped the config version"
    );

    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    for reserved in [
        "reject",
        "weighted",
        "nothing",
        "cheapest",
        busbar_kernel::config::operator_provider(),
    ] {
        let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": reserved,
                    "config": {"kind": "gate", "module": "test-hook"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            shadow.status().as_u16(),
            400,
            "hook name `{reserved}` is reserved and must reject"
        );
        assert_eq!(
            shadow.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );
    }

    let bad = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "bad",
                "config": {"kind": "tap", "module": "test-hook", "prompt": "rw"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    assert_eq!(
        bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );

    let escalate = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "compress",
                "config": {"kind": "gate", "module": "test-hook", "prompt": "ro"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        escalate.status().as_u16(),
        409,
        "grant change must conflict"
    );
    assert_eq!(
        escalate.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "conflict"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_audit_records_mutations() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let name = "audit_probe_hook_x7";
    client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": name,
                "config": {"kind": "tap", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = audit["items"].as_array().unwrap();
    let mine = entries
        .iter()
        .find(|e| e["resource"] == format!("hook:{name}"))
        .expect("the registration is recorded in the audit log");
    assert_eq!(mine["action"], "hook.register");
    assert_eq!(mine["outcome"], "applied");
    assert!(mine["seq"].is_number() && mine["ts"].is_number());

    let filtered: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let f = filtered["items"].as_array().unwrap();
    assert!(!f.is_empty());
    assert!(
        f.iter().all(|e| e["resource"] == format!("hook:{name}")),
        "the resource filter returns only matching entries"
    );

    let none: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}&action=key.create"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_plane_golden_path() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("t".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, c) = spin_up(router).await;
    let base = format!("http://{addr}");
    let get = |p: String| {
        let (c, url) = (c.clone(), format!("{base}{p}"));
        async move {
            c.get(url)
                .header("x-admin-token", "t")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };
    let name = "golden_gate";

    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let info0 = get("/api/v1/admin/info".into()).await;
    assert_eq!(info0["config_version"], 0);
    assert_eq!(info0["config_persistence"], true);

    let created = c
        .post(format!("{base}/api/v1/admin/hooks"))
        .header("x-admin-token", "t")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": name, "config":
                    {"kind": "gate", "module": "test-hook", "global": true}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    assert!(get("/api/v1/admin/hooks".into()).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == name));
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 1);
    assert_eq!(get("/api/v1/admin/config".into()).await["version"], 1);
    assert!(busbar_kernel::config::overlay::read(&overlay.backend())
        .unwrap()
        .hooks
        .contains_key(name));

    assert!(
        get(format!("/api/v1/admin/audit?resource=hook:{name}")).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "hook.register" && e["outcome"] == "applied")
    );

    let deleted = c
        .delete(format!("{base}/api/v1/admin/hooks/{name}"))
        .header("x-admin-token", "t")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 2);
    assert!(!busbar_kernel::config::overlay::read(&overlay.backend())
        .unwrap()
        .hooks
        .contains_key(name));

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_hook_register_persists_to_overlay() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "persisted_gate",
                "config": {"kind": "gate", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay written");
    assert!(doc.hooks.contains_key("persisted_gate"));
    assert!(doc.global_hooks.iter().any(|g| g == "persisted_gate"));

    let fresh_deploy: busbar_kernel::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    let mut fresh =
        busbar_kernel::config::resolve(&fresh_deploy, &std::collections::HashMap::new())
            .expect("minimal config resolves");
    busbar_kernel::config::overlay::merge_into(&mut fresh, doc);
    assert!(
        fresh.hooks.contains_key("persisted_gate"),
        "the runtime-registered hook survives a restart via the overlay"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_config_apply_preserves_the_persisted_overlay() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = TestOverlayStore::new();
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;

    let create_group = |name: &'static str| {
        let c = client.clone();
        async move {
            c.post(format!("http://{addr}/api/v1/admin/groups"))
                .header("x-admin-token", "admintok")
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "name": name,
                        "config": {"limits": [{"requests": 10, "per": "minute"}]}
                    })
                    .to_string(),
                )
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(create_group("api_team").await, 201);

    let applied = client
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"config": {"providers": {}, "models": {}, "store": {"module": migrated_store_module()}}}).to_string())
        .send()
        .await
        .unwrap();
    let st = applied.status().as_u16();
    let body = applied.text().await.unwrap_or_default();
    assert_eq!(st, 200, "the apply itself succeeds: {body}");

    let got = client
        .get(format!("http://{addr}/api/v1/admin/groups/api_team"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        got.status().as_u16(),
        200,
        "an API-created group survives an apply that does not name it"
    );

    assert_eq!(create_group("second_team").await, 201);
    let doc =
        busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay still readable");
    assert!(
        doc.groups.contains_key("api_team"),
        "the next group write must not erase the earlier one from the overlay"
    );
    assert!(
        doc.groups.contains_key("second_team"),
        "and records the new one"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_base_hook_is_read_only_via_api() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = crate::new_test_app()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let (addr, _handle, client) = spin_up(router).await;

    let shadow = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "pii-guard",
                "config": {"kind": "gate", "module": "test-hook", "prompt": "no", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        shadow.status().as_u16(),
        409,
        "POST cannot shadow a base hook"
    );

    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        409,
        "DELETE cannot remove a base hook"
    );

    let got: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("test-hook"),
        "base hook untouched: {got}"
    );
}

#[tokio::test]
async fn base_hook_delete_conflict_outranks_a_stale_if_match() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let base: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = crate::new_test_app()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let (addr, _handle, client) = spin_up(router).await;

    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .header("if-match", "\"999\"")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 409);
    let body: serde_json::Value = del.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], "conflict",
        "the terminal base-hook conflict must win over the retryable version_conflict: {body}"
    );
}

#[tokio::test]
async fn test_admin_v1_delete_hook_takes_effect_live() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let tok = ("x-admin-token", "admintok");

    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header(tok.0, tok.1)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "logger",
                "config": {"kind": "tap", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let absent = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status().as_u16(), 404);

    let deleted = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let after = client
        .get(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the hook is gone from the live config"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_hook_health_best_effort() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mk = |plugin: &str| busbar_kernel::config::HookCfg {
        kind: busbar_kernel::config::HookKind::Gate,
        plugin: plugin.to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: busbar_kernel::config::PromptAccess::No,
        user: busbar_kernel::config::UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    };
    let app = crate::new_test_app()
        .governance(gov)
        .hook("web", mk("web-hook-plugin"))
        .hook("sock", mk("sock-hook-plugin"))
        .build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let get = |name: &str| {
        let url = format!("http://{addr}/api/v1/admin/hooks/{name}/health");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
        }
    };

    let missing = get("nope").await;
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    let web: serde_json::Value = get("web").await.json().await.unwrap();
    assert_eq!(web["name"], "web");
    assert_eq!(web["transport"]["kind"], "plugin");
    assert_eq!(
        web["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );

    let sock: serde_json::Value = get("sock").await.json().await.unwrap();
    assert_eq!(sock["transport"]["kind"], "plugin");
    assert_eq!(
        sock["reachable"],
        serde_json::json!(false),
        "uninstalled plugin is unreachable"
    );

    handle.abort();
}

/// ROUTER ↔ DOCUMENT PARITY FOR THE WHOLE ADMIN SURFACE (item 370), in both directions, over the
/// document the node actually SERVES (`GET /openapi.json`, every plane configured so nothing is
/// filtered out) — never a hand-kept list of paths.
///
/// The test checks that every documented operation resolves on its method, including named-map section routes and plane trust verbs, and that the router exposes no undocumented operation:
///
///
///
/// 1. DOCUMENT → ROUTER: every documented `(method, path)` this crate's router answers is asked
///    live, and must answer neither the router's unmatched-path fallback nor a 405 — and the status
///    it answers must be one of the operation's documented response codes. The kernel loop's
///    operations (the closed-table rows the NODE's administrative loop answers, not this router)
///    are excluded by the table, never by anything the document says about itself.
/// 2. ROUTER → DOCUMENT, per path: on every documented path, every method the document does NOT
///    list must answer the router's 405 (or the unmatched fallback) — a handler hung on an extra
///    method of a documented path is an undocumented operation.
/// 3. ROUTER → DOCUMENT, per route: every `(method, path)` the JSON transport mounts by literal
///    `.route(..)` (read out of the router's own source, `v1/json/mod.rs`) is documented. The
///    loop-mounted routes (named-map sections, plane trust verbs) come from the same registries the
///    document is generated from and are reconciled by `served_surface.rs`.
///
/// Also pins the document's identity and the stable error-code enum.
#[tokio::test]
async fn test_admin_v1_openapi_paths_all_resolve() {
    use std::collections::{BTreeMap, BTreeSet};
    const PREFIX: &str = crate::v1::contract::ADMIN_PREFIX;
    const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::ensure_seam();

    let every_plane: Vec<&'static str> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| d.config_section)
        .collect();

    let spawn = || {
        let gov = gov_with_signer(Arc::new(MemoryStore::new()), Some("admintok".to_string()));
        let app = crate::new_test_app()
            .governance(gov)
            .plane_sections(&every_plane)
            .build();
        let router = crate::build_router(app);
        async move {
            let (addr, handle, _) = spin_up(router).await;
            (addr, handle)
        }
    };
    let client = reqwest::Client::new();
    let ask = |addr: std::net::SocketAddr, method: &str, path: &str| {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let req = client
            .request(method.clone(), format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok");

        let req = if method == reqwest::Method::GET {
            req
        } else {
            req.header("content-type", "application/json").body("{")
        };
        async move {
            let resp = req.send().await.unwrap();
            (resp.status().as_u16(), resp.text().await.unwrap())
        }
    };

    let (addr, handle) = spawn().await;
    let doc: serde_json::Value =
        serde_json::from_str(&ask(addr, "GET", &format!("{PREFIX}/openapi.json")).await.1)
            .expect("the served openapi.json parses");
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Busbar Admin API");
    let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]
        ["enum"]
        .as_array()
        .unwrap();
    assert!(codes.iter().any(|c| c == "not_found"));

    let mut documented: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for (path, item) in doc["paths"].as_object().expect("paths") {
        for (key, op) in item.as_object().expect("path item") {
            if key.starts_with("x-") {
                continue;
            }
            let method = key.to_ascii_uppercase();
            assert!(
                METHODS.contains(&method.as_str()),
                "{path} documents `{key}`, which is no admin operation method"
            );
            let statuses = op[OAS_OPERATION_STATUSES]
                .as_object()
                .unwrap_or_else(|| panic!("{method} {path} documents no status"))
                .keys()
                .cloned()
                .collect();
            documented.insert((method, path.clone()), statuses);
        }
    }

    for (rel, _) in crate::v1::json::V1_GET_PATHS {
        assert!(
            documented.contains_key(&("GET".to_string(), format!("{PREFIX}{rel}"))),
            "GET {PREFIX}{rel} is missing from the served document"
        );
    }
    for m in METHODS {
        assert!(
            documented.keys().any(|(dm, _)| dm == m),
            "the served document documents no {m} operation at all"
        );
    }

    let loop_verbs: BTreeSet<&'static str> = crate::verb::NEW_VERBS
        .iter()
        .chain(crate::verb::LEDGER_VERBS)
        .chain(crate::verb::AUDIT_VERBS)
        .filter_map(|v| crate::verb::verb_name(*v))
        .collect();
    let kernel_loop: BTreeSet<(String, String)> = crate::admin_codec::verbs::table()
        .into_iter()
        .filter(|row| loop_verbs.contains(row.verb))
        .map(|row| (row.method.to_string(), row.template.to_string()))
        .collect();
    let concrete = |path: &str| {
        path.split('/')
            .map(|seg| {
                if seg.starts_with('{') {
                    "resolve-probe"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut fallback: BTreeMap<&str, (u16, String)> = BTreeMap::new();
    for m in METHODS {
        fallback.insert(
            m,
            ask(addr, m, &format!("{PREFIX}/no-such-admin-route/resolve")).await,
        );
    }
    assert_eq!(
        fallback["GET"].0, 404,
        "the unmatched-path control is the router's 404"
    );

    let mut failures: Vec<String> = Vec::new();

    handle.abort();

    let mut probed = 0usize;
    let paths: BTreeSet<&String> = documented.keys().map(|(_, p)| p).collect();
    for path in paths {
        let (addr, handle) = spawn().await;
        for m in METHODS {
            let op = (m.to_string(), path.clone());
            let answer = match documented.get(&op) {
                Some(_) if kernel_loop.contains(&op) => continue,
                _ => ask(addr, m, &concrete(path)).await,
            };
            let Some(statuses) = documented.get(&op) else {
                if answer.0 != 405 && answer != fallback[m] {
                    failures.push(format!(
                        "{m} {path} is NOT documented but the router serves it ({}): {}",
                        answer.0, answer.1
                    ));
                }
                continue;
            };

            probed += 1;
            if answer == fallback[m] {
                failures.push(format!(
                    "{m} {path} is documented but the router answers its unmatched-path \
                     fallback: nothing serves it (phantom endpoint)"
                ));
            } else if answer.0 == 405 {
                failures.push(format!(
                    "{m} {path} is documented but the router mounts the path without this method"
                ));
            } else if !statuses.contains(&answer.0.to_string()) {
                failures.push(format!(
                    "{m} {path} answered {} which its documented statuses {statuses:?} do not \
                     list: {}",
                    answer.0, answer.1
                ));
            }
        }
        handle.abort();
    }
    assert!(
        probed > crate::v1::json::V1_GET_PATHS.len() * 4,
        "only {probed} documented operations were probed on the router"
    );

    let literal = literal_admin_routes(include_str!("../v1/json/mod.rs"));
    assert!(
        literal.len() >= 50,
        "only {} literal admin routes were read out of v1/json/mod.rs — the scanner lost the \
         router",
        literal.len()
    );
    for (method, rel) in &literal {
        let path = format!("{PREFIX}{rel}");
        if !documented.contains_key(&(method.clone(), path.clone())) {
            failures.push(format!(
                "{method} {path} is mounted by v1/json/mod.rs but is in NO served document"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "admin router / OpenAPI document disagree:\n  {}",
        failures.join("\n  ")
    );
}

fn literal_admin_routes(src: &str) -> Vec<(String, String)> {
    use crate::v1::contract as c;
    let consts: [(&str, &str); 5] = [
        ("PATH_HOOKS", c::PATH_HOOKS),
        ("PATH_GROUPS", c::PATH_GROUPS),
        ("PATH_PLUGINS_INSPECT", c::PATH_PLUGINS_INSPECT),
        ("PATH_ADMIN_AUTH", c::PATH_ADMIN_AUTH),
        ("PATH_CONFIG_VALIDATE", c::PATH_CONFIG_VALIDATE),
    ];
    let start = src
        .find("impl AdminTransport for JsonV1")
        .expect("v1/json/mod.rs implements the JSON transport");
    let body = &src[start..];
    let body = &body[..body
        .find(".fallback(")
        .expect("the router ends in its fallback")];
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find(".route(") {
        let after = &rest[at + ".route(".len()..];

        let mut depth = 1usize;
        let mut end = 0usize;
        for (i, ch) in after.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let args = &after[..end];
        rest = &after[end..];
        let (first, second) = args.split_once(',').expect(".route(path, method_router)");
        let first = first.trim();
        let rel = if let Some(lit) = first.strip_prefix('"') {
            lit.trim_end_matches('"').to_string()
        } else {
            consts
                .iter()
                .find(|(name, _)| *name == first)
                .unwrap_or_else(|| {
                    panic!("v1/json/mod.rs mounts a route at `{first}`, a path this scanner cannot resolve — name its value here")
                })
                .1
                .to_string()
        };

        let mut depth = 0usize;
        let mut ident = String::new();
        let mut methods = Vec::new();
        for ch in second.chars() {
            match ch {
                '(' => {
                    if depth == 0
                        && ["get", "post", "put", "patch", "delete"].contains(&ident.as_str())
                    {
                        methods.push(ident.to_ascii_uppercase());
                    }
                    depth += 1;
                    ident.clear();
                }
                ')' => {
                    depth = depth.saturating_sub(1);
                    ident.clear();
                }
                c if c.is_ascii_alphanumeric() || c == '_' => ident.push(c),
                _ => ident.clear(),
            }
        }
        assert!(
            !methods.is_empty(),
            "the route at {rel} mounts no method this scanner recognises: {second}"
        );
        for m in methods {
            out.push((m, rel.clone()));
        }
    }
    out
}

#[test]
fn test_create_key_unconfigured_allowed_pool_is_nonfatal_and_quiet() {
    use tracing_subscriber::layer::SubscriberExt as _;

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));

    let app = crate::new_test_app()
        .lane(busbar_kernel_testkit::test_support::LaneSpec::new(
            "m",
            crate::linked_protocol(),
            "http://127.0.0.1:0",
        ))
        .pool("smart", &[(0, 1)])
        .governance(gov)
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let (unknown_status, known_status) = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            let body1 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-typo",
                    "allowed_pools": ["smart", "smrt"]
                })
                .to_string(),
            );
            let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
            let r1 = super::create_key(
                axum::extract::State(handle.clone()),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
                body1,
            )
            .await;
            let s1 = r1.status().as_u16();

            let body2 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-ok",
                    "allowed_pools": ["smart"]
                })
                .to_string(),
            );
            let r2 = super::create_key(
                axum::extract::State(handle),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                axum::Extension(std::sync::Arc::new(super::KeyReplayCache::new())),
                body2,
            )
            .await;
            let s2 = r2.status().as_u16();
            (s1, s2)
        })
    });

    assert_eq!(
        unknown_status, 201,
        "an unconfigured allowed_pool must NOT 400 — the key is still minted"
    );
    assert_eq!(
        known_status, 201,
        "a configured allowed_pool creates the key"
    );

    let msgs = cap.messages();

    let pool_warns: Vec<&String> = msgs
        .iter()
        .filter(|m| m.contains("allowed_pools entry names no configured pool"))
        .collect();
    assert_eq!(
        pool_warns.len(),
        0,
        "the unconfigured allowed_pool hint is benign (debug), so it must NOT surface at WARN: {msgs:?}"
    );
}

struct CountingStore {
    inner: MemoryStore,
    list_keys_calls: std::sync::atomic::AtomicUsize,
    get_key_calls: std::sync::atomic::AtomicUsize,
}
impl CountingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            list_keys_calls: std::sync::atomic::AtomicUsize::new(0),
            get_key_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn reset(&self) {
        self.list_keys_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.get_key_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }
}
impl busbar_kernel::governance::RecordStore for CountingStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.get_key_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.list_keys_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    fn add_denylist(
        &self,
        sub: &str,
        reason: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> busbar_kernel::governance::RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[tokio::test]
async fn test_single_key_reads_use_get_key_not_list_keys() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (key_b, _) = gov
        .create_key(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (key_c, _) = gov
        .create_key(
            NewKeySpec {
                name: "c".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    store.reset();
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}} must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}} must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .get(format!(
            "http://{addr}/api/v1/admin/keys/{}/usage",
            key_b.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "GET /keys/{{id}}/usage must not scan the whole table"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "GET /keys/{{id}}/usage must resolve the key via Store::get_key"
    );

    store.reset();
    let resp = client
        .post(format!(
            "http://{addr}/api/v1/admin/keys/{}/revoke",
            key_c.id
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "POST /keys/{{id}}/revoke must not scan the whole table to check existence"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "POST /keys/{{id}}/revoke must resolve the key via Store::get_key"
    );
    handle.abort();
}

#[tokio::test]
async fn test_single_key_writes_use_get_key_for_their_existence_check() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(CountingStore::new());
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key_a, _) = gov
        .create_key(
            NewKeySpec {
                name: "a".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (key_b, _) = gov
        .create_key(
            NewKeySpec {
                name: "b".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    store.reset();
    let resp = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", key_a.id))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "PATCH /keys/{{id}} must call list_keys only once, for the post-write cache refresh — \
         not a second time to locate the row"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "PATCH /keys/{{id}} must resolve the pre-image via Store::get_key"
    );

    store.reset();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key_b.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 204);
    assert_eq!(
        store
            .list_keys_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "DELETE /keys/{{id}} must call list_keys only once, for the post-write cache refresh — \
         not a second time to locate the row"
    );
    assert!(
        store
            .get_key_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "DELETE /keys/{{id}} must resolve the pre-image via Store::get_key"
    );
    handle.abort();
}

struct BarrierStore {
    inner: MemoryStore,
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl busbar_kernel::governance::RecordStore for BarrierStore {
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<bool> {
        self.inner.redeem_plane_token(kind, token, expires_at, now)
    }
    fn get_plane_record(
        &self,
        kind: &str,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<Vec<u8>>> {
        self.inner.get_plane_record(kind, id)
    }
    fn upsert_plane_record(
        &self,
        record: busbar_contract::records::PlaneRecordRef<'_>,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.upsert_plane_record(record)
    }
    fn purge_plane_records_before(
        &self,
        kind: &str,
        before: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<u64> {
        self.inner.purge_plane_records_before(kind, before)
    }
    fn put_key(
        &self,
        key: &busbar_kernel::governance::VirtualKey,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.entered.send(());

            let _ = self.release.lock().unwrap().recv();
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<Option<busbar_kernel::governance::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::VirtualKey>>
    {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_kernel::governance::MeteringDelta,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_kernel::governance::RecordStoreResult<Vec<busbar_kernel::governance::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }

    fn add_denylist(
        &self,
        sub: &str,
        reason: &str,
    ) -> busbar_kernel::governance::RecordStoreResult<()> {
        self.inner.add_denylist(sub, reason)
    }
    fn list_denylist(&self) -> busbar_kernel::governance::RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_patch_interleaved_with_delete_never_resurrects_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = patch_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let rotate_url = format!("http://{addr}/api/v1/admin/keys/{}/rotate", key.id);
    let rotate_task = tokio::spawn(async move {
        reqwest::Client::new()
            .post(&rotate_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("ROTATE must reach the instrumented put_key");

    let delete_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = rotate_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "rotate must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

#[test]
fn test_existence_gate_is_claimable_without_runtime() {
    let first = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(first);
    let again = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(again);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await;
    });

    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    patch_task.abort();
    let _ = patch_task.await;

    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
    while std::time::Instant::now() < deadline {
        assert!(
            !delete_task.is_finished(),
            "a cancelled PATCH must keep the EXISTENCE_GATE held for its full blocking mutation; \
             the DELETE must remain blocked on the gate (old async-guard code releases it on \
             cancel)"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    release_tx.send(()).unwrap();
    let del_status = delete_task.await.unwrap();

    assert_eq!(
        del_status, 204,
        "the DELETE runs after the gate frees and revokes the (now-present) key"
    );
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_of_another_key_is_not_held_behind_a_patch_parked_in_the_store() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = gov_with_signer(store.clone(), Some("admintok".to_string()));
    let mint = |name: &str| {
        gov.create_key(
            NewKeySpec {
                name: name.to_string(),
                ..Default::default()
            },
            0,
        )
        .unwrap()
        .0
    };
    let (parked_key, other_key) = (mint("parked"), mint("other"));
    let (addr, handle) = serve_with_gov(gov).await;
    let url = |id: &str| format!("http://{addr}/api/v1/admin/keys/{id}");

    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let patch_url = url(&parked_key.id);
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });
    tokio::task::spawn_blocking(move || {
        entered_rx.recv_timeout(std::time::Duration::from_secs(10))
    })
    .await
    .unwrap()
    .expect("the PATCH reached the instrumented put_key");

    let delete = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::Client::new()
            .delete(url(&other_key.id))
            .header("x-admin-token", "admintok")
            .send(),
    )
    .await;
    release_tx.send(()).unwrap();
    let patch_status = patch_task.await.unwrap();
    let delete_status = delete
        .expect("a DELETE of another key waited on a PATCH parked in the store")
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(delete_status, 204);
    assert_eq!(patch_status, 200);
    handle.abort();
}

fn write_reset_fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "busbar-reset-{}-{}-{}",
        tag,
        std::process::id(),
        busbar_kernel::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
groups:
  team:
    limits:
      - { budget: 20000, per: month }
",
    )
    .unwrap();
    (dir, config_path, providers_path)
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_hooks_reverts_to_base() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture("hooks");
    let overlay = TestOverlayStore::new();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "runtime_gate",
                "config": {"kind": "gate", "module": "test-hook", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "{:?}", created.text().await);
    assert!(
        busbar_kernel::config::overlay::read(&overlay.backend())
            .expect("overlay written")
            .hooks
            .contains_key("runtime_gate"),
        "runtime hook in the overlay before the reset"
    );

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/hooks")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    assert_eq!(
        reset.json::<serde_json::Value>().await.unwrap()["reset"],
        "hooks"
    );

    let hooks: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        hooks["items"].as_array().unwrap().is_empty(),
        "the runtime hook is discarded, base hooks restored: {hooks}"
    );
    let doc = busbar_kernel::config::overlay::read(&overlay.backend()).expect("overlay present");
    assert!(
        doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty(),
        "the overlay hooks section is cleared"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_install_limits() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let _limits_lock = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    let (dir, config_path, providers_path) = write_reset_fixture("limits-persist-fail");
    let overlay = TestOverlayStore::new();
    overlay.fail_writes(true);

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    let before = busbar_kernel::config::limits::installed();

    let rejected_cap: usize = 7_654_321;
    let put = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "limits": { "request_body_max_bytes": rejected_cap } }).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    let after = busbar_kernel::config::limits::installed();
    assert_ne!(
        after.as_ref().map(|l| l.request_body_max_bytes),
        Some(rejected_cap),
        "a persist failure must leave the REJECTED config's limits uninstalled — the response just \
         claimed nothing was changed, and these are process-wide values the old (still-serving) App \
         reads through"
    );
    assert_eq!(
        after.map(|l| l.request_body_max_bytes),
        before.map(|l| l.request_body_max_bytes),
        "the limits installed before the rejected apply are the ones still installed after it"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let dir = std::env::temp_dir().join(format!(
        "busbar-settings-gov-rotate-persist-fail-{}-{}",
        std::process::id(),
        busbar_kernel::store::now()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    let token_path = dir.join("admin.token");
    std::fs::write(&token_path, "admintok-v1").unwrap();
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {}
  base_url: http://127.0.0.1:1/
",
            crate::linked_protocol()
        ),
    )
    .unwrap();

    std::fs::write(
        &config_path,
        format!(
            "listen: 127.0.0.1:0
store: {{module: memory}}
providers:
  test-provider:
    api_key: none
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
auth:
  admin_auth:
    - {operator}: {{ token: {{ file: {token_path:?} }} }}
",
            operator = busbar_kernel::config::operator_provider()
        ),
    )
    .unwrap();
    let overlay = TestOverlayStore::new();

    overlay.fail_writes(true);

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok-v1".to_string()));
    let before_hash = gov.admin_token_hash();
    let mut app = crate::new_test_app()
        .governance(gov.clone())
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
    }
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    std::fs::write(&token_path, "admintok-v2").unwrap();

    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok-v1")
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    assert_eq!(
        gov.admin_token_hash(),
        before_hash,
        "a persist failure must leave the shared GovState's admin-token digest untouched — the \
         response just claimed nothing was changed, and this is the process-lifetime object the \
         OLD (still-serving) App snapshot also points at"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_get_config_settings_warns_when_overlay_is_unreadable() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = std::env::temp_dir().join(format!(
        "busbar-get-settings-corrupt-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = TestOverlayStore::new();
    overlay.seed_bytes(b"{ not json");

    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut app = crate::new_test_app()
        .governance(gov)
        .overlay_backend(overlay.backend())
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = None;
        inner.providers_path = None;
    }
    let handle = std::sync::Arc::new(busbar_kernel::state::AppHandle::new(app));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let resp = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(crate::v1::json::get_config_settings(axum::extract::State(
            handle,
        )))
    });
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a corrupt overlay must not brick the read; it renders no overrides"
    );

    assert!(
        cap.contains("/config/settings"),
        "GET /config/settings on a corrupt overlay must emit a warn naming THIS endpoint, not just \
         overlay.rs's generic boot-time warn: {:?}",
        cap.messages()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_persist_root_without_an_overlay_errs() {
    let result = busbar_kernel::config::overlay::persist_root(
        None,
        &busbar_kernel::config::overlay::RootSettings::default(),
    );
    assert!(
        result.is_err(),
        "persist_root(None, ..) must NOT silently succeed — a None backend means a locked config, so \
         the mutation is refused, never falsely reported as persisted"
    );
    let msg = result.unwrap_err();
    assert_eq!(
        msg, LOCKED_CONFIG_MUTATION_MESSAGE,
        "the error must explain the locked/no-overlay posture: {msg}"
    );
}

#[test]
fn test_config_settings_scope_matrix() {
    use axum::http::Method;
    assert_eq!(
        crate::v1::contract::required_scope(&Method::PUT, "/api/v1/admin/config/settings").as_str(),
        "full",
        "PUT /config/settings is a full-scope mutation"
    );
    assert_eq!(
        crate::v1::contract::required_scope(&Method::GET, "/api/v1/admin/config/settings").as_str(),
        "read-only",
        "GET /config/settings is read-only"
    );

    assert_eq!(
        crate::v1::contract::required_scope(&Method::DELETE, "/api/v1/admin/overlay/root").as_str(),
        "full",
        "a root reset is a full-scope mutation"
    );
}

#[tokio::test]
async fn limit_zero_does_not_produce_a_self_referential_cursor() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    for n in ["ka", "kb"] {
        let resp = admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
            .header("content-type", "application/json")
            .body(serde_json::json!({"name": n}).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201);
    }
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": "lz-hook", "config": {"kind": "tap", "module": "test-hook"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/lz-hook")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let assert_not_self_referential = |label: &str, body: &serde_json::Value| {
        let next = body.get("next_cursor").and_then(|c| c.as_str());
        match next {
            None => {}
            Some(c) => {
                let decoded = crate::v1::contract::decode_offset_cursor(c)
                    .unwrap_or_else(|| panic!("{label}: cursor did not decode: {c}"));
                assert!(
                    decoded > 0,
                    "{label}: limit=0 produced a self-referential cursor (offset {decoded}): {body}"
                );
            }
        }
    };

    let audit_body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/audit?limit=0")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_not_self_referential("get_audit", &audit_body);

    let versions_body: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/config/versions?limit=0"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_not_self_referential("list_config_versions", &versions_body);

    let keys_body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/keys?limit=0")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_not_self_referential("list_keys", &keys_body);

    handle.abort();
}

#[tokio::test]
async fn a_stuck_mint_or_rotate_is_refused_in_flight_however_old_its_sentinel() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov.clone()).build();
    let cache: Arc<crate::keys::KeyReplayCache> = Arc::new(crate::keys::KeyReplayCache::new());
    let router = crate::build_router(app).layer(axum::Extension(cache.clone()));
    let (addr, handle, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "rotated"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let generation = || {
        gov.all_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.id == id)
            .map(|k| k.generation_hash)
    };
    let before = generation();
    for key in [
        (
            "admin".to_string(),
            crate::idempotency::create_replay_key("stuck-mint"),
        ),
        (
            "admin".to_string(),
            crate::idempotency::rotate_replay_key(&id, "stuck-rotate"),
        ),
    ] {
        match cache.probe(key, 1) {
            crate::idempotency::Probe::Reserved(r) => r.leak(),
            _ => panic!("a fresh cache reserves the first sighting"),
        }
    }

    let mint = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("idempotency-key", "stuck-mint")
        .body(serde_json::json!({"name": "k"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        mint.status().as_u16(),
        409,
        "the retry of a mint still in flight is refused, not minted a second time"
    );
    let rotate = client
        .post(format!("{keys_url}/{id}/rotate"))
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "stuck-rotate")
        .send()
        .await
        .unwrap();
    assert_eq!(
        rotate.status().as_u16(),
        409,
        "the retry of a rotate still in flight is refused, not rotated a second time"
    );
    assert_eq!(
        gov.all_keys().unwrap().len(),
        1,
        "the retried mint minted nothing"
    );
    assert_eq!(
        generation(),
        before,
        "the retried rotate issued no new credential"
    );

    handle.abort();
}

fn free_open_units() -> serde_json::Value {
    crate::ensure_seam();
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .find(|decl| decl.fallback)
        .expect("the linked test planes carry the fallback plane")
        .billable_classes
        .iter()
        .map(|c| c.class)
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .map(|c| (c.to_string(), serde_json::json!(0)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}
