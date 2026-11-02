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
fn test_existence_gate_is_claimable_without_runtime() {
    let first = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(first);
    let again = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(again);
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
