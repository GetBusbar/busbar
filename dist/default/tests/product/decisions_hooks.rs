// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decisions hook cells through the shipped root, signed Store and dropped webrequest products.

use busbar_contract::json::JsonValueTrait as _;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use busbar_kernel::state::AppHandle;
use serde_json::{json, Value};
use tower::ServiceExt as _;

use crate::root::test_plugins as plugins;

fn isolated_case() -> bool {
    const CHILD: &str = "BUSBAR_DECISIONS_HOOKS_CHILD";
    const WITNESS: &str = "actual Decisions hook assertions completed";
    let name = std::thread::current()
        .name()
        .expect("the exact test is named")
        .to_owned();
    if std::env::var(CHILD).ok().as_deref() == Some(name.as_str()) {
        return false;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, &name)
        .stdout(std::process::Stdio::piped());
    let mut settings: Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings");
    if settings.get("db_path").is_some() {
        let directory = plugins::scratch("decisions-child-store");
        settings["db_path"] = json!(directory.join("governance.sqlite"));
        command.env(
            "BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS",
            settings.to_string(),
        );
    }
    let mut child = Child(
        command
            .spawn()
            .expect("start the exact isolated Decisions case"),
    );
    let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
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
                "the actual Decisions child failed: {status}: {output}"
            );
            assert!(
                output.contains(WITNESS),
                "the exact child did not complete its assertions: {output}"
            );
            return true;
        }
        assert!(
            std::time::Instant::now() < until,
            "the actual Decisions child timed out"
        );
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
}

#[derive(Clone, Copy)]
enum Bound {
    Global,
    Section,
}

#[derive(Clone)]
enum Reply {
    Reject(u16, &'static str),
    Rewrite,
    Empty,
}

fn required_artifact(variable: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
            panic!("{variable} must name the freshly built actual product cdylib")
        }));
    assert!(path.is_absolute(), "{variable} must be absolute");
    assert!(
        path.is_file(),
        "{variable} artifact missing: {}",
        path.display()
    );
    path
}

fn stage(directory: &Path, file: &str, variable: &str, kind: &str) -> (String, String) {
    let path = if kind == "store" {
        plugins::application_store_library()
    } else {
        required_artifact(variable)
    };
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual product statement reads")
        .expect("the actual product exports its statement");
    let facts = busbar_contract::rendering::read(&statement)
        .expect("the actual product statement is valid");
    let mut manifest = plugins::manifest(kind, &facts.name, "third-party");
    manifest.version = facts.version;
    manifest.statement = Some(hex::encode(statement));
    if kind == "hook" {
        assert_eq!(
            facts.name, "busbar-hook-webrequest",
            "the supplied hook must be the actual webrequest product"
        );

        manifest.needs = busbar_plugin_loader::sign::HookNeeds {
            prompt: busbar_plugin_loader::sign::NeedLevel::Rw,
            user: busbar_plugin_loader::sign::NeedLevel::Ro,
        };
    }
    let library = std::fs::read(path).expect("read the actual product cdylib");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
    let hash = busbar_contract::redacted::sha256_hex(&archive);
    std::fs::write(directory.join(file), archive).expect("stage the signed actual product");
    (facts.name, hash)
}

async fn provider() -> (
    u16,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("provider listener");
    let port = listener.local_addr().unwrap().port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    let routes = Router::new().fallback(move |body: Bytes| {
        let sent = sent.clone();
        async move {
            sent.send(String::from_utf8(body.to_vec()).expect("provider request JSON"))
                .unwrap();
            Json(json!({"id":"d-1","decision":"approve","usage":{"units":1}}))
        }
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, routes)
            .await
            .expect("provider HTTP service");
    });
    (port, heard, task)
}

async fn hook_target(
    reply: Reply,
) -> (
    String,
    tokio::sync::mpsc::UnboundedReceiver<Value>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("hook target listener");
    let port = listener.local_addr().unwrap().port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    let routes = Router::new().fallback(move |Json(envelope): Json<Value>| {
        sent.send(envelope.clone()).expect("record actual hook invocation");
        let reply = reply.clone();
        async move {
            let answer = match (envelope["op"].as_str(), reply) {
                (Some("decide"), Reply::Reject(status, message)) => json!({"reject":{"status":status,"message":message}}),
                (Some("transform"), Reply::Rewrite) => json!({"rewrite":{"messages":[{"role":"user","content":{"state":{"amount":0}}}]}}),
                _ => json!({}),
            };
            Json(answer)
        }
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, routes)
            .await
            .expect("actual webrequest HTTP far end");
    });
    (format!("http://127.0.0.1:{port}/"), heard, task)
}

struct Served {
    router: Router,
    admin: Router,
    overlay: Option<Arc<busbar_kernel::config::overlay::OverlayStore>>,
    token: String,
    heard: tokio::sync::mpsc::UnboundedReceiver<String>,
    hook_heard: tokio::sync::mpsc::UnboundedReceiver<Value>,
    attached: bool,
    _fixture: crate::root::min3_boot::fixture::PlaneFixture,
    _workers: crate::root::boot::workers::RunningWorkers,
    _handle: Arc<AppHandle>,
    _book: crate::root::durability::NodeBook,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Served {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn served(instance: &str, reply: Reply, bound: Bound, prompt: &str, attach: bool) -> Served {
    served_with_overlay(instance, reply, bound, prompt, attach, false).await
}

async fn served_with_overlay(
    instance: &str,
    reply: Reply,
    bound: Bound,
    prompt: &str,
    attach: bool,
    writable: bool,
) -> Served {
    crate::dist_root_install::install();
    let (provider_port, heard, provider_task) = provider().await;
    let (hook_url, hook_heard, hook_task) = hook_target(reply).await;
    let directory = plugins::scratch(&format!("decisions-root-hooks-{instance}"));
    let (store, store_pin) = stage(
        &directory,
        "store.tar.gz",
        "BUSBAR_TEST_SQLITE_CDYLIB",
        "store",
    );
    let (webrequest, _) = stage(
        &directory,
        "webrequest.tar.gz",
        "BUSBAR_TEST_WEBREQUEST_CDYLIB",
        "hook",
    );
    let signing_key = directory.join("signing.key");
    let provider_key = directory.join("provider.key");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    std::fs::write(&provider_key, "sk-decisions-hooks").unwrap();
    let store_settings = plugins::application_store_settings(&directory);
    assert!(store_settings.is_object());
    let mut document = json!({
        "store":{"module":store,"settings":store_settings},
        "providers":{"typesafe":{"api_key":{"file":provider_key}}},
        "models":{},
        // This synthetic hook-test model was defined with this fixture contract on 2026-11-09.
        "decisions":{
            "models":{"m":{"provider":"typesafe"}},
            "catalog":{"m":{"description":"Busbar Decisions hook test fixture (not a provider model)","release_date":"2026-11-09"}},
            "ingress":{"listen":"127.0.0.1:0"}
        },
        "auth":{"chain":["keys"],"signing_key":{"file":signing_key},"admin_auth":[]},
        "advanced":{},
    });
    if attach {
        document["hooks"] = json!({"cell":{
            "kind":"gate","module":webrequest,"timeout_ms":10_000,"on_error":"weighted",
            "prompt":prompt,"user":"ro","priority":0,
            "groups":[],"phase":[],"settings":{"url":hook_url}
        }});
        if matches!(bound, Bound::Section) {
            document["decisions"]["hooks"] = json!(["cell"]);
        } else {
            document["pools"] = json!({"hooks":["cell"]});
        }
    }
    let mut plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: serde_json::from_value(
            json!([{"url":"https://plugins.example/store.tar.gz","sha256":store_pin}]),
        )
        .expect("actual Store archive pin"),
        ..Default::default()
    };
    plugins
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            plugins: vec![store.clone(), webrequest.clone()],
            keys: vec![busbar_kernel::config::PluginPublisherKey {
                public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
                revoked: false,
            }],
        });
    document["plugins"] = serde_json::to_value(plugins::config_document(&plugins))
        .expect("the plugins document is JSON");
    let catalog = json!({"typesafe": {
        "protocol":"jev", "base_url":format!("http://127.0.0.1:{provider_port}")
    }});
    let config_path = directory.join("config.json");
    let providers_path = directory.join("providers.json");
    if writable {
        std::fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
        std::fs::write(&providers_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("actual decisions deployment parses");
    let definitions = serde_json::from_value(catalog).expect("actual provider definitions parse");
    let base_hook_names: HashSet<_> = deploy.hooks.keys().cloned().collect();
    let base_group_names: HashSet<_> = deploy.groups.keys().cloned().collect();
    let cfg = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("actual decisions deployment resolves");
    let judge = crate::root::connector::dest_judge(&cfg);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (admitted, serving) = crate::root::min3_boot::fixture::open(&cfg, &plugins, rules)
        .await
        .expect("actual Registry and signed Store open")
        .admit_serving()
        .await;
    let overlay = writable.then(|| {
        busbar_kernel::config::overlay::OverlayStore::from_core(admitted.core.clone())
            .expect("the admitted actual Store supplies config persistence")
    });
    if let Some(overlay) = overlay.as_ref() {
        busbar_kernel::config::overlay::write_async(overlay, &Default::default())
            .await
            .expect("settle the initial empty configuration overlay");
    }
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        // RootCfg is not Clone (3e5b860ca5): the app takes its own resolution of the same document.
        busbar_kernel::config::resolve(&deploy, &definitions)
            .expect("actual decisions deployment resolves"),
        plugins,
        overlay.clone(),
        base_hook_names,
        base_group_names,
        (
            writable.then_some(config_path),
            writable.then_some(providers_path),
        ),
        None,
        &admitted.rules,
        Some(admitted.core),
        false,
    )
    .await
    .expect("the production root builds the decisions application");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &store)
        .await
        .expect("the actual Store binds root card history before activation");
    limits
        .keep()
        .await
        .expect("commit actual application limits");
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_book) {
        step(&ctx);
    }
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("actual signed Store governance")
        .clone();
    let (_, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "decider".into(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
        .expect("mint actual signed caller");
    let declarations: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| &d.declaration)
        .collect();
    let core = gov
        .core_store_handle()
        .expect("actual signed Store custody");
    let services = crate::root::serve::compose(judge, &app, core, &declarations);
    let dispatcher = Arc::new(crate::root::dispatch::build(2, &services));
    crate::root::connector::install_io(&dispatcher);
    let mut fixture = serving
        .plane(
            &cfg,
            "decisions",
            &app,
            services.kernel().expect("complete native kernel services"),
        )
        .await
        .expect("actual Decisions and hook ports bind before seat publication");
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(book.durability.clone());
    let keys = node.kernel_and_keys().1;
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    let billing = busbar_kernel::plane_driver::port_billing::PortBilling::new(
        Arc::new(PlaneMoney::new(
            gov.clone(),
            post.clone() as Arc<dyn EndPost>,
        )),
        gov,
        keys,
        Arc::new(busbar_kernel::plane_driver::CoreAudit),
    )
    .with_journal(post.clone());
    let composed = crate::root::serve::Served {
        ports: vec![fixture.seat.clone()],
        billing: Some(billing),
        post: Some(post),
        tables: app.serve_tables.clone(),
        ..Default::default()
    };
    let doors = crate::root::serve::door_routes(
        composed,
        || crate::root::kernel::ROOT_CARD.pin(),
        &[],
        &[],
    )
    .expect("actual decisions routes mount");
    let (router, admin, handle) =
        busbar_kernel::build_split_routers_serving(app, doors, 1 << 20, 0, false);
    let workers = std::mem::replace(
        fixture
            .workers
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        crate::root::boot::workers::PreparedWorkers::new(),
    )
    .start();
    Served {
        router,
        admin,
        overlay,
        hook_heard,
        attached: attach,
        _fixture: fixture,
        _workers: workers,
        token: token.expose(&busbar_kernel::seal::lend()).to_owned(),
        heard,
        _handle: handle,
        _book: book,
        tasks: vec![provider_task, hook_task],
    }
}

impl Served {
    async fn admin_request(&self, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        // The existing Decisions fixture explicitly configures admin_auth: []; exercise that
        // real open-admin route, without injecting a principal or substituting an auth provider.
        let response = self
            .admin
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/api/v1/admin{path}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("the actual Admin router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn decide(&mut self) -> (StatusCode, Value, Option<String>) {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/systemone")
                    .header("authorization", format!("Bearer {}", self.token))
                    .body(Body::from(r#"{"state":{"amount":7}}"#))
                    .unwrap(),
            )
            .await
            .expect("the root router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("decision response body");
        assert_eq!(
            self.hook_heard.try_recv().is_ok(),
            self.attached,
            "the actual native hook attachment is invoked exactly when configured"
        );
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            self.heard.try_recv().ok(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_file_hook_mutations_keep_actual_native_callers_and_behavior() {
    if isolated_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    let mut s = served_with_overlay(
        "decisions-hooks-file-authority",
        Reply::Reject(409, "file-owned policy"),
        Bound::Section,
        "ro",
        true,
        true,
    )
    .await;
    let (status, body, provider) = s.decide().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        provider.is_none(),
        "the configured native gate refuses before forwarding"
    );

    let original = s._handle.load();
    assert!(original.base_hook_names.contains("cell"));
    let opened = s._fixture.hooks().await.unwrap();
    let hook = opened
        .get("cell")
        .expect("the actual configured HookPort opened")
        .clone();
    let plane_driver = s._fixture.seat.driver.clone();
    let plane_who = s._fixture.seat.who.clone();
    let overlay = s.overlay.as_ref().unwrap().clone();
    let stored = overlay.read_bytes_async().await.unwrap();
    assert!(stored.is_some(), "the actual Store has a settled overlay");
    let publications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = publications.clone();
    s._handle.on_apply(Box::new(move |_| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    let mut replacement = serde_json::to_value(
        original.hook_registry["cell"].authoring(&busbar_kernel::seal::acquire()),
    )
    .unwrap();
    replacement["settings"]["url"] = json!("http://127.0.0.1:1/rejected-target");

    for (method, path, request) in [
        (
            "POST",
            "/hooks",
            json!({"name":"cell", "config":replacement.clone()}),
        ),
        ("PUT", "/hooks/cell", json!({"config":replacement})),
        (
            "PATCH",
            "/hooks/cell/settings",
            json!({"settings":{"url":"http://127.0.0.1:1/rejected-target"}}),
        ),
        ("DELETE", "/hooks/cell", json!({})),
    ] {
        let (status, refusal) = s.admin_request(method, path, request).await;
        assert_eq!(status, StatusCode::CONFLICT, "{method} {path}: {refusal}");
        assert!(
            refusal
                .to_string()
                .contains("defined in the base config file"),
            "{refusal}"
        );
        let current = s._handle.load();
        assert!(Arc::ptr_eq(&original, &current));
        assert_eq!(current.config_version, original.config_version);
        assert_eq!(overlay.read_bytes_async().await.unwrap(), stored);
        assert_eq!(publications.load(std::sync::atomic::Ordering::SeqCst), 0);
        let current_hooks = s._fixture.hooks().await.unwrap();
        let current_hook = current_hooks.get("cell").unwrap();
        assert!(Arc::ptr_eq(&hook.port, &current_hook.port));
        assert!(
            hook.who.instance == current_hook.who.instance && hook.who.slot == current_hook.who.slot,
            "the refused edit leaves the hook's opened binding (its runtime instance and slot) in place"
        );
        assert!(Arc::ptr_eq(&plane_driver, &s._fixture.seat.driver));
        assert!(
            plane_who.instance == s._fixture.seat.who.instance
                && plane_who.slot == s._fixture.seat.who.slot,
            "the refused edit leaves the plane seat's opened binding (its runtime instance and slot) in place"
        );
        let (status, body, provider) = s.decide().await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["detail"]["message"],
            "the request was refused by policy"
        );
        assert!(
            provider.is_none(),
            "rejected config changed actual forwarding: {provider:?}"
        );
    }
    println!("actual Decisions hook assertions completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_global_gate_refuses_a_decisions_request_before_its_dial() {
    if isolated_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    let mut s = served(
        "decisions-hooks-gate",
        Reply::Reject(409, "no decisions today"),
        Bound::Global,
        "ro",
        true,
    )
    .await;
    let (status, body, heard) = s.decide().await;
    assert_eq!(status.as_u16(), 409, "the hook's own status: {body}");
    assert_eq!(
        body["detail"]["message"], "the request was refused by policy",
        "{body}"
    );
    assert_eq!(body["detail"]["error_type"], "api_usage_error", "{body}");
    assert!(
        heard.is_none(),
        "the gated unit reached the provider: {heard:?}"
    );
    println!("actual Decisions hook assertions completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_hooks_rewrite_alters_the_request_the_provider_receives() {
    if isolated_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    let mut s = served(
        "decisions-hooks-rewrite",
        Reply::Rewrite,
        Bound::Section,
        "rw",
        true,
    )
    .await;
    let (status, body, heard) = s.decide().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = heard.expect("the provider was dialled");
    assert!(
        head.ends_with(r#"{"state":{"amount":0}}"#),
        "the provider received the hook's document, not the caller's: {head}"
    );
    println!("actual Decisions hook assertions completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gate_named_in_decisions_hooks_refuses_the_unit() {
    if isolated_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    let mut s = served(
        "decisions-hooks-section-gate",
        Reply::Reject(403, "decisions closed"),
        Bound::Section,
        "ro",
        true,
    )
    .await;
    let (status, body, heard) = s.decide().await;
    assert_eq!(status.as_u16(), 403, "{body}");
    assert_eq!(
        body["detail"]["message"], "the request was refused by policy",
        "{body}"
    );
    assert_eq!(body["detail"]["error_type"], "permission_denied", "{body}");
    assert!(heard.is_none(), "{heard:?}");
    println!("actual Decisions hook assertions completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_hook_bound_the_provider_receives_the_callers_bytes() {
    if isolated_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    let mut s = served(
        "decisions-hooks-none",
        Reply::Empty,
        Bound::Global,
        "ro",
        false,
    )
    .await;
    let (status, body, heard) = s.decide().await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let head = heard.expect("the provider was dialled");
    assert!(head.ends_with(r#"{"state":{"amount":7}}"#), "{head}");
    println!("actual Decisions hook assertions completed");
}
