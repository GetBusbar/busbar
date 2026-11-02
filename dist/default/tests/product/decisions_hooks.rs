// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decisions hook cells through the shipped root, signed Store and dropped webrequest products.
//! The four original names/oracles remain in the plugin source until this replacement is ACKed.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use busbar_kernel::state::{App, AppHandle};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NoSink};
use serde_json::{json, Value};
use tower::ServiceExt as _;

#[path = "../../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        let history = crate::root::kernel::RootHistory::default();
        history.apply(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                true,
            ),
            1_000,
        );
        history
    });

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
    let path = required_artifact(variable);
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual product statement reads")
        .expect("the actual product exports its statement");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual product statement is valid");
    let mut manifest = plugins::manifest(
        kind,
        &facts.name,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.version = facts.version;
    manifest.statement = Some(hex::encode(statement));
    if kind == "hook" {
        // The real webrequest module asks for prompt:rw/user:ro; the operator grant below
        // determines what each configured instance receives.
        manifest.needs = busbar_plugin_loader::sign::HookNeeds {
            prompt: busbar_plugin_loader::sign::NeedLevel::Rw,
            user: busbar_plugin_loader::sign::NeedLevel::Ro,
        };
    }
    let library = std::fs::read(path).expect("read the actual product cdylib");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
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

async fn hook_target(reply: Reply) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("hook target listener");
    let port = listener.local_addr().unwrap().port();
    let routes = Router::new().fallback(move |Json(envelope): Json<Value>| {
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
    (format!("http://127.0.0.1:{port}/"), task)
}

struct Served {
    router: Router,
    token: String,
    heard: tokio::sync::mpsc::UnboundedReceiver<String>,
    _handle: Arc<AppHandle>,
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
    crate::dist_root_install::install();
    let (provider_port, heard, provider_task) = provider().await;
    let (hook_url, hook_task) = hook_target(reply).await;
    let directory = plugins::scratch(&format!("decisions-root-hooks-{instance}"));
    let (store, store_pin) = stage(
        &directory,
        "store.tar.gz",
        "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN",
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
    std::fs::write(
        &signing_key,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    std::fs::write(&provider_key, "sk-decisions-hooks").unwrap();
    let store_settings: Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings JSON");
    assert!(store_settings.is_object());
    let mut document = json!({
        "store":{"module":store,"settings":store_settings},
        "providers":{"typesafe":{"protocol":"jev","base_url":format!("http://127.0.0.1:{provider_port}"),"api_key":{"file":provider_key}}},
        "models":{},
        "decisions":{"models":{"m":{"provider":"typesafe"}}},
        "auth":{"chain":["keys"],"signing_key":{"file":signing_key},"admin_auth":[]},
        "advanced":{"allow_destinations":["127.0.0.1"]},
    });
    if attach {
        document["hooks"] = json!({"cell":{
            "kind":"gate","module":webrequest,"timeout_ms":10_000,"on_error":"weighted",
            "prompt":prompt,"user":"ro","priority":0,"global":matches!(bound,Bound::Global),
            "default":false,"signals":[],"groups":[],"phase":[],"settings":{"url":hook_url}
        }});
        if matches!(bound, Bound::Section) {
            document["decisions"]["hooks"] = json!(["cell"]);
        }
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("actual decisions deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual decisions deployment resolves");
    let providers = crate::root::door_steps::provider_routes(
        &cfg.providers,
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let sections: BTreeMap<_, _> = deploy.door_sections();
    let judge = crate::root::connector::dest_judge(&cfg);
    let late = crate::root::serve::LateServices::new();
    let (credentials, credential_handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(judge, &late, credentials);
    let dispatcher = Arc::new(crate::root::dispatch::build(2, &late));
    crate::root::connector::install_io(&dispatcher);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: serde_json::from_value(
            json!([{"url":"https://plugins.example/store.tar.gz","sha256":store_pin}]),
        )
        .expect("actual Store archive pin"),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugins,
        None,
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the production root builds the decisions application");
    limits.keep().expect("commit actual application limits");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("actual signed Store governance")
        .clone();
    let (_, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "decider".into(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint actual signed caller");
    let declarations: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| &d.declaration)
        .collect();
    crate::root::serve::attach(
        &late,
        Some(&gov),
        Some(gov.clone()),
        &app.demotion_record,
        &declarations,
    );
    let connector = crate::root::connector::the();
    let row =
        LinkedRow::of(busbar_plane_decisions::door).expect("the actual decisions door statement");
    let plane = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Host(connector.clone() as Arc<dyn DeclaredConns>),
            },
        )
        .expect("the actual decisions door binds"),
    );
    let node = Arc::new(crate::root::plane_node::Node::new());
    let book = crate::root::durability::node_book();
    node.bind_book(book.durability.clone());
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    let money_gov = gov.clone();
    let money_post = post.clone();
    let money = move || {
        Arc::new(PlaneMoney::new(
            money_gov.clone(),
            money_post.clone() as Arc<dyn EndPost>,
        ))
    };
    let stage = crate::root::serve::HookStage {
        host: {
            let app = app.clone();
            Arc::new(move || busbar_kernel::plane_driver::engine_host(&app))
        },
        gov: gov.clone(),
        journal: None,
    };
    let auths = crate::root::door_steps::OutboundAuths::new(
        dispatcher.clone(),
        crate::LINKED.auths,
        None,
        ConnTable::Host(connector.clone()),
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    );
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: app.secret_resolver.clone(),
        auths: Arc::new(auths),
        conns: connector.clone() as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let mut composed = crate::root::serve::compose_planes(
        &[(instance.to_owned(), plane)],
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        Some(&crate::root::serve::DoorEgress {
            reach: &reach,
            journal: post.clone(),
        }),
        Some(&stage),
        &app.serve_tables,
    )
    .expect("the actual root composes decisions egress and hooks");
    composed.post = Some(post);
    let doors = crate::root::serve::door_routes(composed, || CARD.pin(), &[], &[])
        .expect("actual decisions routes mount");
    let (router, _, handle) =
        busbar_kernel::build_split_routers_serving(app, doors, 1 << 20, 0, false);
    credential_handle.set(handle.clone());
    Served {
        router,
        token: token.expose(&busbar_kernel::seal::lend()).to_owned(),
        heard,
        _handle: handle,
        tasks: vec![provider_task, hook_task],
    }
}

impl Served {
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            self.heard.try_recv().ok(),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_global_gate_refuses_a_decisions_request_before_its_dial() {
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
    assert_eq!(body["error"]["message"], "no decisions today", "{body}");
    assert!(
        heard.is_none(),
        "the gated unit reached the provider: {heard:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_hooks_rewrite_alters_the_request_the_provider_receives() {
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gate_named_in_decisions_hooks_refuses_the_unit() {
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
    assert_eq!(body["error"]["message"], "decisions closed", "{body}");
    assert!(heard.is_none(), "{heard:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_hook_bound_the_provider_receives_the_callers_bytes() {
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
}
