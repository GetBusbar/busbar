// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use busbar_kernel::state::App;

use super::planes_tests::{bound, composed_services, PUBLISHING};
use super::{compose_planes, compose_served, data_routes, door_routes};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::plane_node::{Node, NodeEndPost};

#[path = "serve_datagram_open.rs"]
mod datagram_opening_tests;

pub(super) struct Governed {
    pub(super) router: axum::Router,
    served: super::Served,

    pub(super) driver: Arc<busbar_kernel::plane_driver::PlaneDriver>,
    post: Arc<NodeEndPost>,
    money: Arc<PlaneMoney>,
    gov: Arc<GovState>,
    key: VirtualKey,
    token: String,
    app: Arc<App>,
    book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,

    current: Arc<std::sync::Mutex<Arc<App>>>,
}

impl Governed {
    fn apply(&self, next: Arc<App>) {
        *self.current.lock().expect("unpoisoned") = next;
    }
}

pub(super) fn governed(instance: &'static str, keys_chain: bool) -> Governed {
    governed_with(instance, keys_chain, None)
}

const TEST_PLANE: &str = "plane-driver-test-plane";

fn governed_with(instance: &'static str, keys_chain: bool, budget: Option<u64>) -> Governed {
    governed_full(instance, keys_chain, budget, Screen::Nothing, None, None)
}

/// What a governed deployment's `hooks:` screen.
#[derive(Clone, Copy)]
enum Screen<'a> {
    /// No hook is configured.
    Nothing,
    /// A global gate rejects text carrying the token.
    Global(&'a str),
    /// A gate on the section's pool `p` (`pools: {p: {members: [m]}}`) rejects text carrying the
    /// token.
    Pool(&'a str),
}

fn screen_cfg(token: &str) -> busbar_kernel::config::HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "module": "test-hook",
        "timeout_ms": 10_000,
        "on_error": "weighted",
        "prompt": "ro",
        "priority": 0,
        "settings": { "reject_if_contains": token },
    }))
    .expect("an operator's gate definition")
}

fn screen_env() -> busbar_kernel::hooks::HookEnv {
    let needs = busbar_kernel_testkit::test_support::HookNeeds {
        prompt: busbar_contract::plugin_rows::NeedLevel::Ro,
        ..Default::default()
    };
    busbar_kernel_testkit::test_support::test_hook_env(&["test-hook"], needs)
}

fn screened(screen: Screen<'_>) -> busbar_kernel_testkit::test_support::TestApp {
    match screen {
        Screen::Nothing => busbar_kernel_testkit::test_support::TestApp::new(),
        Screen::Global(token) => screening_gate(token),
        Screen::Pool(token) => {
            let env = screen_env();
            let registry = [("screen".to_string(), screen_cfg(token))]
                .into_iter()
                .collect();
            let gates = busbar_kernel::hooks::resolve_gate_hooks(
                &registry,
                &["screen".to_string()],
                &env,
                0,
            );
            assert_eq!(gates.len(), 1, "the configured gate resolves");
            busbar_kernel_testkit::test_support::TestApp::new()
                .hook_env(env)
                .pool_gates_resolved("p", gates)
        }
    }
}

fn screening_gate(token: &str) -> busbar_kernel_testkit::test_support::TestApp {
    busbar_kernel_testkit::test_support::TestApp::new()
        .hook_env(screen_env())
        .hook("screen", screen_cfg(token))
        .global_hook("screen")
        .resolve_global_gates()
}

fn governed_hooked(
    instance: &'static str,
    keys_chain: bool,
    budget: Option<u64>,
    screen: Screen<'_>,
) -> Governed {
    governed_full(instance, keys_chain, budget, screen, None, None)
}

type BoundNode = (
    Arc<Node>,
    Arc<std::sync::Mutex<crate::root::durability::Durability>>,
);

fn governed_over(
    instance: &'static str,
    keys_chain: bool,
    budget: Option<u64>,
    on: Option<BoundNode>,
) -> Governed {
    governed_full(instance, keys_chain, budget, Screen::Nothing, on, None)
}

fn governed_full(
    instance: &'static str,
    keys_chain: bool,
    budget: Option<u64>,
    screen: Screen<'_>,
    on: Option<BoundNode>,
    flat_fee: Option<i64>,
) -> Governed {
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let plane = bound(instance, &dispatcher);
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(crate::root::real_store::records(), None, Some(signer))
            .expect("governance"),
    );
    let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = budget
        .map(|amount| {
            let limit = busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount,
                per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            };
            let cfg = busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![limit],
                ..Default::default()
            };
            (format!("{instance}-group"), cfg)
        })
        .into_iter()
        .collect();
    let cost = match budget {
        None => CostModel::flat(flat_fee.unwrap_or(1)),
        Some(_) => {
            let fees: busbar_kernel::config::PlaneFeesMap = [(
                TEST_PLANE.to_string(),
                busbar_kernel_ledger::cost::PlaneFees {
                    per_request: 1,
                    per_session: 0,
                },
            )]
            .into_iter()
            .collect();
            CostModel::resolve_parts(None, 0, &groups).with_plane_fees(&fees)
        }
    };
    let spec = NewKeySpec {
        name: "door".to_string(),
        group: groups.keys().next().cloned(),
        ..Default::default()
    };
    let (key, token) = gov
        .mint_signed(spec, 4_000_000_000, 1_700_000_000)
        .expect("mint");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");

    let (node, book) = on.unwrap_or_else(|| {
        let book = Arc::new(std::sync::Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_kernel_wal::NullShipper::new()),
            )
            .expect("a memory-buffered journal opens"),
        ));
        let node = Arc::new(Node::new());
        node.bind_book(Arc::clone(&book));
        (node, book)
    });
    let post = Arc::new(NodeEndPost::new(node));
    let money = Arc::new(PlaneMoney::new(
        Arc::clone(&gov),
        Arc::clone(&post) as Arc<dyn EndPost>,
    ));
    let one = Arc::clone(&money);
    let mut sections = BTreeMap::new();
    sections.insert(
        "test_plane",
        serde_yaml::from_str("m: {}\npools: {p: {members: [m]}}").expect("yaml"),
    );
    let app = screened(screen);
    let app = if keys_chain { app.keys_chain() } else { app };
    let app = groups
        .iter()
        .fold(app, |app, (name, cfg)| app.group(name, cfg.clone()));
    let app = app.governance(Arc::clone(&gov)).cost(cost).build();

    let current = Arc::new(std::sync::Mutex::new(Arc::clone(&app)));
    let reads = Arc::clone(&current);
    let hooks = super::HookStage {
        host: Arc::new(move || {
            busbar_kernel::plane_driver::engine_host(&reads.lock().expect("unpoisoned"))
        }),
        gov: Arc::clone(&gov),
        journal: None,
    };
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        None,
        &move || Arc::clone(&one),
        None,
        Some(&hooks),
        &app.serve_tables,
    )
    .expect("the door plane composes");
    served.post = Some(Arc::clone(&post));
    let driver = Arc::clone(&served.planes[0].driver);

    served.framers = Some(neutral_framers());
    let retained = served.clone();
    let routes = door_routes(served, || crate::root::kernel::ROOT_CARD.pin(), &[], &[])
        .expect("its claims mount");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), routes, 1 << 20, 0, false);
    Governed {
        router,
        served: retained,
        driver,
        post,
        money,
        gov,
        key,
        token: token.expose(&busbar_kernel::seal::lend()).clone(),
        app,
        book,
        current,
    }
}

impl Governed {
    async fn post(&self, path: &str, keyed: bool) -> (u16, String) {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder().method("POST").uri(path);
        if keyed {
            req = req.header("authorization", format!("Bearer {}", self.token));
        }
        let req = req.body(axum::body::Body::from("ping")).expect("a request");
        let resp = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = resp.status().as_u16();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn requests(&self) -> u64 {
        self.gov
            .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists")
            .requests
    }
}

#[tokio::test]
async fn a_keyed_unit_is_admitted_and_its_money_settles_at_its_end() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-keyed", true);
    assert_eq!(g.requests(), 0, "nothing admitted yet");
    let (status, body) = g.post("/call/direct:m", true).await;
    assert_eq!(
        (status, body.as_str()),
        (
            503,
            "refused:503:The service is temporarily overloaded. Please retry shortly."
        ),
        "admitted, then the walk is exhausted (the shed in 1.5.5's words)"
    );
    assert_eq!(g.requests(), 1, "its request was charged at admission");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
    assert_eq!(g.post.open_units(), 0, "its node facts closed at its end");
}

#[tokio::test]
async fn an_unknown_route_is_admitted_then_refused_and_settles() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-unknown", true);
    let (status, body) = g.post("/call/direct:nowhere", true).await;

    assert_eq!((status, body.as_str()), (404, "refused:404:no_destination"));
    assert_eq!(g.requests(), 1, "charged before its route was refused");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
}

#[tokio::test]
async fn an_unkeyed_unit_on_a_credential_claim_is_refused() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-unkeyed", false);
    let (status, body) = g.post("/call/direct:m", false).await;
    assert_eq!(
        (status, body.as_str()),
        (401, "refused:401:unauthenticated")
    );
    assert_eq!(g.requests(), 0, "nothing charged");
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn an_anonymous_unit_on_an_open_claim_routes_and_opens_no_money() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-open", false);
    let (status, body) = g.post("/open", false).await;
    assert_eq!(
        (status, body.as_str()),
        (
            503,
            "refused:503:The service is temporarily overloaded. Please retry shortly."
        ),
        "admitted, then the walk is exhausted"
    );
    assert_eq!(g.requests(), 0, "nothing charged");
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn a_counted_local_unit_is_charged_as_an_admitted_call() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-local-counted", true);
    let (status, body) = g.post("/call/local-counted", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "ping"),
        "answered by the plane"
    );
    assert_eq!(g.requests(), 1, "its request was counted at admission");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
    assert_eq!(g.post.open_units(), 0, "its node facts closed at its end");
}

#[tokio::test]
async fn an_uncounted_local_unit_is_charged_nothing() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-local-quiet", true);
    let (status, body) = g.post("/call/local-quiet", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "ping"),
        "answered by the plane"
    );
    assert_eq!(g.requests(), 0, "nothing charged");
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
}

#[tokio::test]
async fn an_estimated_local_unit_is_still_charged() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-local-estimated", true);
    let (status, body) = g.post("/call/local-estimated", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "ping"),
        "answered by the plane"
    );
    assert_eq!(g.requests(), 1, "its request was charged at admission");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
}

#[tokio::test]
async fn a_nested_unit_runs_under_its_parents_key_and_answers_it_whole() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-nest", true);
    let (status, body) = g.post("/call/nest:/call/local", true).await;
    assert_eq!((status, body.as_str()), (200, "nested:200:ping"));
    assert_eq!(
        g.requests(),
        2,
        "the parent and its child, both on the parent's key"
    );
    assert_eq!(g.money.open_units(), 0, "both units' money facts closed");
    assert_eq!(g.post.open_units(), 0, "both units' node facts closed");

    {
        let book = g.book.lock().expect("unpoisoned");
        let records = &book.audit_records;
        assert_eq!(records.len(), 2, "one record per unit: {records:?}");
        let parent = records
            .iter()
            .find(|r| r.what.parent.is_none())
            .expect("the parent's record");
        let child = records
            .iter()
            .find(|r| r.what.parent.is_some())
            .expect("the child's record");
        assert_eq!(child.what.parent, Some(parent.what.unit_key));
        assert_eq!(child.subject, parent.subject, "one principal");
        assert_eq!(child.origin_kind, "nested");
        assert_eq!(parent.origin_kind, "client");
    }

    let (status, body) = g.post("/call/nest:/nowhere", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "nest-refused:no plane serves the nested unit's claim")
    );
    assert_eq!(g.requests(), 3, "only the parent");
}

#[tokio::test]
async fn a_planes_unit_is_served_content_scan_hook_call_and_verify() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-services", true);
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=0 gate=0 rewrite=0 verify=2")
    );
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn a_configured_gate_blocks_in_session_content_through_a_dropped_in_plane() {
    let _one = PUBLISHING.lock().await;
    let g = governed_hooked("serve-money-gated", true, None, Screen::Global("ping"));
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=1 gate=403 rewrite=0 verify=2"),
        "the gate blocks the screened content and stops the gated sub-operation"
    );
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn a_gate_a_config_apply_adds_blocks_the_next_units_content_with_no_restart() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-live", true);
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=0 gate=0 rewrite=0 verify=2"),
        "the boot generation configures no hook"
    );

    let mut next = (*g.app).clone();
    let registry: std::collections::HashMap<_, _> = [("screen".to_string(), screen_cfg("ping"))]
        .into_iter()
        .collect();
    next.global_gates = busbar_kernel::hooks::resolve_gate_hooks(
        &registry,
        &["screen".to_string()],
        &screen_env(),
        1,
    );
    assert_eq!(next.global_gates.len(), 1, "the applied gate resolves");
    next.hook_registry = registry;
    next.global_hooks = vec!["screen".to_string()];
    let next = Arc::new(next);
    g.apply(next);
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=1 gate=403 rewrite=0 verify=1"),
        "the next unit binds the applied gate (and hits the verify entry the first one stored)"
    );
}

#[tokio::test]
async fn a_pool_gate_blocks_the_content_of_a_unit_routed_over_its_pool() {
    let _one = PUBLISHING.lock().await;
    let g = governed_hooked("serve-money-pool-gate", true, None, Screen::Pool("ping"));
    let (status, body) = g.post("/call/services-pool:p", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=1 gate=403 rewrite=0 verify=2"),
        "the pool's gate screens a unit routed over the pool"
    );
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=0 gate=0 rewrite=0 verify=1"),
        "a direct unit is not under the pool's gate"
    );
}

#[tokio::test]
async fn a_child_nested_after_the_budget_is_spent_is_refused_and_charged_nothing() {
    let _one = PUBLISHING.lock().await;
    let g = governed_with("serve-money-nest-budget", true, Some(1));
    let (status, body) = g.post("/call/nest:/call/local", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "nested:429:refused:429:over_budget"),
        "the parent ran; its child was refused on the parent's budget"
    );
    assert_eq!(g.requests(), 1, "the refused child charged nothing");
    assert_eq!(g.money.open_units(), 0);
    assert_eq!(g.post.open_units(), 0);
}

#[tokio::test]
async fn a_nest_past_the_depth_cap_is_refused() {
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-money-nest-deep", true);
    let deep = busbar_kernel::host_services::NEST_DEPTH_MAX as usize;
    let path = format!("{}/call/local", "/call/nest:".repeat(deep + 1));
    let (status, body) = g.post(&path, true).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        format!(
            "{}nest-refused:{}",
            "nested:200:".repeat(deep),
            busbar_kernel::host_services::NEST_TOO_DEEP
        )
    );
    assert_eq!(
        g.requests(),
        deep as u64 + 1,
        "every unit but the refused one"
    );
    assert_eq!(g.money.open_units(), 0);
}

const NODE_HOOKS_ARM: &str = "BUSBAR_TEST_NODE_HOOKS_ARM";

#[test]
fn the_nodes_boot_hooks_price_and_book_a_door_unit_in_every_build() {
    if std::env::var_os(NODE_HOOKS_ARM).is_some() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime")
            .block_on(node_boot_hooks_arm());
        return;
    }
    let run = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            "root::serve::money_tests::the_nodes_boot_hooks_price_and_book_a_door_unit_in_every_build",
        ])
        .args(["--test-threads", "1", "--nocapture"])
        .env(NODE_HOOKS_ARM, "1")
        .output()
        .expect("the test binary runs");
    let text =
        String::from_utf8_lossy(&run.stdout).into_owned() + &String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "the node-hooks arm failed:\n{text}");
    assert!(
        text.contains("1 passed"),
        "the node-hooks arm ran nothing:\n{text}"
    );
}

async fn node_boot_hooks_arm() {
    assert!(
        include_str!(concat!(env!("OUT_DIR"), "/linked.rs"))
            .contains("&crate::root::plane_node::ROOT_UNIT,"),
        "this build's generated ROOT_UNITS does not carry the node's root unit"
    );

    crate::root::linked::register_stores(&crate::LINKED);
    let rows = busbar_kernel::preflight::root_rows();
    assert!(
        rows.rate_apply.is_some() && rows.rate_epoch.is_some(),
        "the root's install record carries neither half (holder, dater) of the rate seam"
    );

    busbar_kernel_testkit::test_support::install_test_root(rows);
    busbar_kernel_testkit::test_support::metrics::init();

    let cfg = || {
        let deploy = busbar_kernel::config::deploy_from_yaml_str("providers: {}\nmodels: {}\n")
            .expect("a minimal deployment");
        let mut cfg =
            busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        cfg.store = Some(busbar_kernel_testkit::test_support::stand_in_store());
        cfg
    };
    let boot = cfg();
    for step in crate::ROOT_UNITS.iter().filter_map(|u| u.on_config) {
        step(&boot.limits);
    }
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(busbar_kernel::appbuild::AcceptAll);
    let (app, _rotate, limits) = busbar_kernel::build_app_from_config(
        boot,
        busbar_kernel::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the boot app builds");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, "test-store").expect("the boot book opens");
    limits.keep().expect("the boot card activates in its Store");
    assert!(
        crate::root::kernel::ROOT_CARD.pin().is_some(),
        "the boot build's rates never reached the card holder: its repricer is not installed"
    );
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|u| u.on_book) {
        step(&ctx);
    }

    let mut applied = cfg();
    applied.per_request_fee = 3;
    let _applied =
        busbar_kernel_testkit::app::build_once(applied, Some(&app)).expect("the apply builds");
    let pinned = crate::root::kernel::ROOT_CARD
        .pin()
        .expect("the card holder has entries")
        .seq()
        .get();
    assert_ne!(pinned, 0, "the apply appended no entry to the card history");

    let _one = PUBLISHING.lock().await;
    let g = governed_over(
        "serve-money-node-hooks",
        true,
        None,
        Some((
            crate::root::plane_node::node(),
            Arc::clone(&book.durability),
        )),
    );
    let lines = || {
        book.durability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies")
            .len()
    };
    let before = lines();
    let (status, body) = g.post("/call/direct:m", true).await;
    assert_eq!(
        (status, body.as_str()),
        (
            503,
            "refused:503:The service is temporarily overloaded. Please retry shortly."
        ),
        "admitted, then the walk is exhausted (the shed in 1.5.5's words, as every plane is handed \
         them: RefusalIn.text is the kernel's own message for the refusal)"
    );
    assert_eq!(g.requests(), 1, "its request was charged at admission");
    assert_eq!(g.post.open_units(), 0, "its node facts closed at its end");
    assert!(
        lines() > before,
        "the door unit settled nothing onto the durability book"
    );
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records
        .last()
        .expect("the door unit's audit record is on the book");
    assert_eq!(
        record.usage.rate_card_version, pinned,
        "the door unit was not pinned to the card in force at its door"
    );
}

#[tokio::test]
async fn the_boot_composition_serves_a_dropped_in_door_plane_in_every_build() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-money-boot-composition";
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let plane = bound(instance, &dispatcher);
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(crate::root::real_store::records(), None, Some(signer))
            .expect("governance"),
    );
    let cost = CostModel::flat(1);
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "door".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let providers = BTreeMap::new();
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
            Arc::clone(&dispatcher),
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::NoNeeds,
            busbar_kernel::diagnostics::Catalogue::NEUTRAL,
        )),
        conns: Arc::new(busbar_core_connector::Connector::new()),
        models: None,
        stream_ceiling_secs: 1,
        catalog: None,
        upgrades: Vec::new(),
    };
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::from_str("m: {}").expect("yaml"));
    let served = compose_served(
        Some(Arc::clone(&gov)),
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        None,
        &reach,
        None,
        &busbar_kernel::plane_driver::serve::ServeTables::default(),
    )
    .expect("every build composes a configured door plane");
    assert_eq!(served.planes.len(), 1, "the dropped-in door plane composed");
    let post = Arc::clone(served.post.as_ref().expect("its units post on the node"));
    let routes = data_routes(served, &[], &[]).expect("its claims mount on the data listener");
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), routes, 1 << 20, 0, false);
    let (status, body) = {
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/call/direct:m")
            .header(
                "authorization",
                format!("Bearer {}", token.expose(&busbar_kernel::seal::lend())),
            )
            .body(axum::body::Body::from("ping"))
            .expect("a request");
        let resp = router.oneshot(req).await.expect("the router answers");
        let status = resp.status().as_u16();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };
    assert!(
        status == 503 && body.starts_with("refused:503:"),
        "the dropped-in plane served the unit: admitted, then its walk exhausted; got {status} {body}"
    );
    let requests = gov
        .usage_for(&app.cost, &key.id, busbar_kernel::store::now())
        .expect("a read")
        .expect("the key exists")
        .requests;
    assert_eq!(requests, 1, "its request was charged at admission");
    assert_eq!(post.open_units(), 0, "its node facts closed at its end");
}

#[tokio::test]
async fn an_ungrouped_key_is_authed_but_unlimited_and_admission_never_blocks() {
    const ADMITS: u64 = 500;
    const FEE_CENTS: i64 = 30;
    let _one = PUBLISHING.lock().await;
    let deployment = governed_full(
        "serve-money-ungrouped",
        true,
        None,
        Screen::Nothing,
        None,
        Some(FEE_CENTS),
    );
    assert!(
        deployment.key.group.is_none(),
        "precondition: the key under test carries no group"
    );
    let at = busbar_kernel::store::now();
    for admitted in 0..ADMITS {
        deployment
            .gov
            .try_admit(&deployment.app.cost, &deployment.key, "", at)
            .unwrap_or_else(|blocked| {
                panic!(
                    "an ungrouped key is authed but UNLIMITED: admission #{admitted} must not \
                     block, got {blocked:?}"
                )
            });
    }
    let spend = || {
        deployment
            .gov
            .usage_for(&deployment.app.cost, &deployment.key.id, at)
            .expect("a read")
            .expect("the key exists")
            .spend_cents
    };
    assert_eq!(
        spend(),
        i64::try_from(ADMITS).expect("fits") * FEE_CENTS,
        "an ungrouped key accrues spend without any cap ever blocking its admission"
    );

    let (status, body) = deployment.post("/call/local-counted", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "ping"),
        "the door admits an ungrouped key whatever it has spent"
    );
    assert_eq!(
        deployment.requests(),
        ADMITS + 1,
        "the door's admission was counted"
    );
    assert_eq!(
        deployment.money.open_units(),
        0,
        "its money facts closed at its end"
    );
}

pub(super) fn neutral_framers() -> super::StreamFramers {
    use crate::root::test_plugins::{missing, neutral_frame_door, BUILD_LOADER_EXAMPLES};
    use busbar_core_connector::framer::FramerDoor;
    static DOOR: std::sync::OnceLock<Arc<dyn FramerDoor>> = std::sync::OnceLock::new();
    let door = DOOR
        .get_or_init(|| {
            let (plugin, _key) = neutral_frame_door()
                .unwrap_or_else(|| missing("neutral_frame_door", BUILD_LOADER_EXAMPLES));
            let door = crate::root::doors::Dispatched::open(
                plugin,
                &busbar_contract::transport::TransportSettings::default(),
            )
            .expect("the neutral frame door opens");
            Arc::new(door) as Arc<dyn FramerDoor>
        })
        .clone();
    super::StreamFramers(Arc::new(move |claim: &str| {
        Some(&door)
            .filter(|d| d.facts().claims.contains(&claim))
            .cloned()
    }))
}

type SpanSeen = (&'static str, Option<&'static str>, Vec<&'static str>);

/// THE SPANS A SERVED UNIT OPENS, as one capturing subscriber reads them.
#[derive(Clone, Default)]
struct SpanLog(Arc<std::sync::Mutex<Vec<SpanSeen>>>);

impl<S> tracing_subscriber::Layer<S> for SpanLog
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let parent = ctx
            .span(id)
            .and_then(|s| s.parent())
            .map(|p| p.metadata().name());
        let fields = attrs.metadata().fields().iter().map(|f| f.name()).collect();
        self.0
            .lock()
            .expect("unpoisoned")
            .push((attrs.metadata().name(), parent, fields));
    }
}

#[tokio::test]
async fn an_arrival_opens_its_claims_span_with_the_units_forward_span_beneath_it() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let _one = PUBLISHING.lock().await;
    let g = governed("serve-arrival-span", true);
    let log = SpanLog::default();
    let _subscribed =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
    let _called = g.post("/call/direct:m", true).await;
    let called = log.0.lock().expect("unpoisoned").clone();
    let arrivals: Vec<_> = called.iter().filter(|s| s.0 == "test_arrival").collect();
    assert_eq!(arrivals.len(), 1, "one arrival, one entry span: {called:?}");
    assert!(
        arrivals[0].2.is_empty(),
        "skip_all: the entry span carries no field"
    );
    let forward = called
        .iter()
        .find(|s| s.0 == "forward")
        .unwrap_or_else(|| panic!("the unit's request span: {called:?}"));
    assert_eq!(forward.1, Some("test_arrival"), "{called:?}");
    assert_eq!(forward.2, vec!["pool", "ingress", "op", "request_id"]);

    log.0.lock().expect("unpoisoned").clear();
    let _opened = g.post("/open", false).await;
    let opened = log.0.lock().expect("unpoisoned").clone();
    assert!(
        opened.iter().all(|s| s.0 != "test_arrival"),
        "RED: a claim that states no span opens none: {opened:?}"
    );
    let forward = opened
        .iter()
        .find(|s| s.0 == "forward")
        .unwrap_or_else(|| panic!("the unit's request span: {opened:?}"));
    assert_ne!(forward.1, Some("test_arrival"), "{opened:?}");
}

fn session_custody_routes(g: &mut Governed, pools_plane: bool) -> Arc<super::DataRoutes> {
    g.router = axum::Router::new();
    let mut served = std::mem::take(&mut g.served);
    if pools_plane {
        Arc::get_mut(&mut served.planes[0].live)
            .expect("the original router was released")
            .served_facts
            .section = busbar_contract::section::RESERVED_POOLS_KEY;
    }
    let mut lines = Vec::new();
    let mut of_line = std::collections::HashMap::new();
    for (plane, served) in served.planes.iter().enumerate() {
        for (claim, snapshot) in served.snapshot.claims.iter().enumerate() {
            let claim = u32::try_from(claim).expect("fixture claim");
            let (line, _) = super::claim_line(&served.instance, claim, snapshot, &[], &[], &[])
                .expect("the existing fixture claim mounts");
            of_line.insert((served.instance.clone(), claim), (plane, claim));
            lines.push(line);
        }
    }
    Arc::new(super::DataRoutes {
        served,
        claim_doors: None,
        post: Arc::clone(&g.post),
        pin: || crate::root::kernel::ROOT_CARD.pin(),
        guests: busbar_kernel::guest::GuestList::seal(lines).expect("fixture guest list"),
        of_line,
        frames: Default::default(),
    })
}

fn session_custody_request(g: &Governed, target: &str) -> super::DoorRequest {
    super::DoorRequest {
        method: axum::http::Method::POST,
        uri: target.parse().expect("fixture target"),
        headers: Default::default(),
        body: bytes::Bytes::from_static(b"ping"),
        gov: Default::default(),
        credential: None,
        ticket: None,
        app: Arc::clone(&g.app),
        scheme: 0,
        consumed_fields: Vec::new(),
    }
}

fn session_custody_caller() -> super::PipeCaller {
    let (_, from) = tokio::sync::mpsc::channel(1);
    let (to, _) = tokio::sync::mpsc::channel(1);
    super::PipeCaller {
        from: tokio::sync::Mutex::new(from),
        to,
    }
}

fn session_custody_nest(parent: u64, target: &str) -> busbar_kernel::host_services::Nest {
    busbar_kernel::host_services::Nest {
        parent,
        depth: 1,
        principal: None,
        ask: busbar_contract::services::NestAsk {
            verb: "POST".to_string(),
            target: target.to_string(),
            body: b"ping".to_vec(),
        },
    }
}

/// Capture the structured attachment diagnostic as tracing formats it for a subscriber.
#[derive(Clone, Default)]
struct AttachErrors(Arc<std::sync::Mutex<Vec<String>>>);

impl tracing::field::Visit for AttachErrors {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "error" {
            self.0
                .lock()
                .expect("unpoisoned")
                .push(format!("{value:?}"));
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AttachErrors {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        event.record(&mut self.clone());
    }
}

#[tokio::test]
async fn a_failed_session_attachment_records_its_fault_and_cleans_up_once() {
    use busbar_contract::caps::{Outcome, ReasonCode, StepName};
    use tracing_subscriber::layer::SubscriberExt as _;
    const ATTACH_FAILURE: &str = "the session book refused the unit: collision\nsecond line";
    let _one = PUBLISHING.lock().await;
    for fails in [true, false] {
        let mut g = governed("session-attach-outcome", false);
        let routes = session_custody_routes(&mut g, false);
        let admitted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ended = Arc::new(std::sync::Mutex::new(Vec::new()));
        let on_admit = Arc::clone(&admitted);
        let on_end = Arc::clone(&ended);
        let errors = AttachErrors::default();
        let _subscribed =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(errors.clone()));
        let attach = super::Attach {
            answered: super::SWITCHED,
            admitted: Some(Box::new(move |unit| {
                on_admit.lock().expect("unpoisoned").push(unit);
                if fails {
                    Err(ATTACH_FAILURE.to_string())
                } else {
                    Ok(())
                }
            })),
            ended: Some(Box::new(move |unit| {
                on_end.lock().expect("unpoisoned").push(unit);
            })),
        };
        let (door, arrival, _) = routes.arrived(0, 1, session_custody_request(&g, "/open"));
        let (verdict, said) = tokio::sync::oneshot::channel();
        Arc::clone(&routes)
            .session(door, session_custody_caller(), arrival, verdict, attach)
            .await;
        let verdict = said.await.expect("session verdict");
        if fails {
            assert!(
                matches!(verdict, Err(None)),
                "the carrier was never accepted"
            );
            let errors = errors.0.lock().expect("unpoisoned");
            assert!(
                errors.contains(&format!("{ATTACH_FAILURE:?}")),
                "{errors:?}"
            );
            assert!(errors.iter().all(|error| !error.contains('\n')));
        } else {
            assert!(verdict.is_ok(), "the successful carrier was accepted");
        }
        let admitted = admitted.lock().expect("unpoisoned");
        let ended = ended.lock().expect("unpoisoned");
        assert_eq!(admitted.len(), 1);
        assert_eq!(
            *ended, *admitted,
            "the carrier closes exactly once for its unit"
        );
        let book = g.book.lock().expect("unpoisoned");
        assert_eq!(book.audit_records.len(), 1, "one final session record");
        let record = &book.audit_records[0];
        assert_eq!(record.what.unit_key.get(), admitted[0]);
        assert_eq!(
            record.outcome.unit_end,
            if fails {
                Outcome::Refused(StepName::Route, ReasonCode::HandoffMismatch)
            } else {
                Outcome::Completed
            }
        );
        assert_eq!(g.post.open_units(), 0);
        assert_eq!(g.money.open_units(), 0);
        assert!(routes.frames_lock().is_empty());
    }
}

#[tokio::test]
async fn an_executed_nested_unit_with_an_oversized_reply_fails_instead_of_refusing() {
    let _one = PUBLISHING.lock().await;
    let g = governed("nested-unread-outcome", true);
    let target = format!(
        "/call/nest:/call/local-repeat:{}",
        super::NEST_REPLY_MAX + 1
    );
    let (status, body) = g.post(&target, true).await;
    assert_eq!(status, axum::http::StatusCode::OK.as_u16());
    assert_eq!(body, format!("nest-failed:{}", super::NEST_UNREAD));
    assert_eq!(g.requests(), 2, "the parent and exactly one admitted child");
    assert_eq!(g.post.open_units(), 0);
    assert_eq!(g.money.open_units(), 0);
    {
        let book = g.book.lock().expect("unpoisoned");
        assert_eq!(book.audit_records.len(), 2);
        assert_eq!(
            book.audit_records
                .iter()
                .filter(|r| r.what.parent.is_some())
                .count(),
            1,
            "the executed child is recorded once"
        );
    }
    let (status, body) = g.post("/call/nest:/nowhere", true).await;
    assert_eq!(status, axum::http::StatusCode::OK.as_u16());
    assert_eq!(body, format!("nest-refused:{}", super::NEST_UNSERVED));
    assert_eq!(g.requests(), 3, "an unserved claim starts no child");
}

#[tokio::test]
async fn a_nested_declared_length_reply_stops_its_producer_at_the_existing_bound() {
    let _one = PUBLISHING.lock().await;
    let g = governed("nested-declared-length-bound", true);
    let declared = super::NEST_REPLY_MAX * 4;
    let (status, body) = g
        .post(
            &format!("/call/nest:/call/local-repeat-whole:{declared}"),
            true,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK.as_u16());
    assert_eq!(body, format!("nest-failed:{}", super::NEST_UNREAD));

    tokio::time::timeout(super::OPEN_HEAD_WAIT, async {
        loop {
            g.post.node().sweep(g.post.node().arrived());
            if g.post.open_units() == 0
                && g.money.open_units() == 0
                && g.book.lock().expect("unpoisoned").audit_records.len() == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual child retires");
    assert_eq!(g.requests(), 2, "the parent and one child admission");
    let (status, produced) = g.post("/call/local-produced", true).await;
    assert_eq!(status, axum::http::StatusCode::OK.as_u16());
    let produced: usize = produced
        .parse()
        .expect("the fixture's produced-byte counter");

    const RETAINED_WINDOWS: usize = 3;
    assert!(produced > super::NEST_REPLY_MAX);
    assert!(
        produced <= super::NEST_REPLY_MAX + RETAINED_WINDOWS * super::BufferCaps::default().reply,
        "the producer ran beyond the bounded ingress windows: {produced}"
    );
    assert!(
        produced < declared,
        "the whole reply was never precollected"
    );
    let (_, stable) = g.post("/call/local-produced", true).await;
    assert_eq!(
        stable.parse::<usize>().expect("counter"),
        produced,
        "the child stopped producing"
    );
}

#[tokio::test]
async fn in_bound_nested_whole_and_streamed_replies_keep_their_bytes_and_head_fields() {
    use busbar_kernel::plane_driver::CallerEnd as _;
    const PAYLOAD: &[u8] = b"the child's complete body";
    const FIELD_NAME: &str = "x-child-fixture";
    const FIELD_VALUE: &[u8] = b"  same bytes  ";
    for whole in [true, false] {
        let (caller, reply) = super::IngressCaller::new();
        let unit = async move {
            let mut fields = vec![(FIELD_NAME.as_bytes().to_vec(), FIELD_VALUE.to_vec())];
            if whole {
                fields.push((
                    axum::http::header::CONTENT_LENGTH
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                    PAYLOAD.len().to_string().into_bytes(),
                ));
            }
            caller.head(u32::from(axum::http::StatusCode::OK.as_u16()), fields);
            assert!(caller.write(PAYLOAD).await);
            None
        };
        let response = reply.answer_nested(Box::pin(unit)).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(FIELD_NAME)
                .expect("child field")
                .as_bytes(),
            FIELD_VALUE
        );
        assert!(
            !response
                .headers()
                .contains_key(axum::http::header::CONTENT_LENGTH),
            "whole nested replies retain their previous unlengthened head"
        );
        let body = axum::body::to_bytes(response.into_body(), super::NEST_REPLY_MAX)
            .await
            .expect("in-bound child reply");
        assert_eq!(body.as_ref(), PAYLOAD);
    }
}

#[tokio::test]
async fn a_catalog_never_lends_never_kept_fields_and_preserves_permitted_field_bytes() {
    use axum::http::{HeaderName, HeaderValue, StatusCode};
    const PERMITTED_FIELD: &str = "x-catalog-fixture";
    const PERMITTED_VALUE: &[u8] = b"  permitted\tbytes  ";
    let _one = PUBLISHING.lock().await;
    let mut g = governed("catalog-head-custody", false);
    let routes = session_custody_routes(&mut g, false);
    let mut request = session_custody_request(&g, "/catalog");
    for field in busbar_contract::abi::host::conn::connector::NEVER_KEPT {
        request.headers.insert(
            HeaderName::from_bytes(field.as_bytes()).expect("a forbidden field name"),
            HeaderValue::from_static("credential-fixture"),
        );
    }
    request.headers.append(
        PERMITTED_FIELD,
        HeaderValue::from_bytes(PERMITTED_VALUE).expect("field bytes"),
    );
    request
        .headers
        .append(PERMITTED_FIELD, HeaderValue::from_static("second value"));
    let answer = routes.catalog(0, &request);
    assert_eq!(answer.status(), StatusCode::OK);
    for field in busbar_contract::abi::host::conn::connector::NEVER_KEPT {
        assert!(
            !answer.headers().contains_key(*field),
            "catalog received {field}"
        );
    }
    let values: Vec<_> = answer
        .headers()
        .get_all(PERMITTED_FIELD)
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    assert_eq!(values, [PERMITTED_VALUE, b"second value".as_slice()]);
    assert!(g.book.lock().expect("unpoisoned").audit_records.is_empty());
    assert_eq!(g.requests(), 0);
    assert_eq!(g.post.open_units(), 0);
    assert_eq!(g.money.open_units(), 0);
}

#[tokio::test]
async fn a_session_decode_refusal_uses_the_bound_live_facts() {
    let _one = PUBLISHING.lock().await;
    let mut g = governed("session-live-facts", false);
    let routes = session_custody_routes(&mut g, false);
    let live_kind = busbar_contract::OpClassId::new("session_live_generation");
    {
        let mut current = routes.served.planes[0]
            .live
            .live
            .write()
            .expect("unpoisoned");
        Arc::get_mut(&mut current)
            .expect("no unit has borrowed the generation")
            .facts
            .audit_kind = live_kind;
    }
    assert_ne!(routes.served.planes[0].facts.audit_kind, live_kind);
    let (door, arrival, _) = routes.arrived(0, 2, session_custody_request(&g, "/framed/refuse"));
    let (verdict, said) = tokio::sync::oneshot::channel();
    Arc::clone(&routes)
        .session(
            door,
            session_custody_caller(),
            arrival,
            verdict,
            super::Attach::switched(),
        )
        .await;
    let Err(Some(refused)) = said.await.expect("session verdict") else {
        panic!("decode refused")
    };
    assert_eq!(refused.status, 404);
    let book = g.book.lock().expect("unpoisoned");
    assert_eq!(
        book.audit_records
            .last()
            .expect("session audit")
            .what
            .op_class
            .as_str(),
        live_kind.as_str()
    );
    assert_eq!(g.post.open_units(), 0);
    assert_eq!(g.money.open_units(), 0);
    assert!(routes.frames_lock().is_empty());
}

#[tokio::test]
async fn an_admitted_session_exposes_its_parent_frame_until_cleanup() {
    let _one = PUBLISHING.lock().await;
    let mut g = governed("session-parent-frame", false);
    let routes = session_custody_routes(&mut g, false);
    let observed = Arc::new(std::sync::Mutex::new(None));
    let capture = Arc::clone(&observed);
    let reads = Arc::clone(&routes);
    let expected_app = Arc::clone(&g.app);
    let attach = super::Attach {
        answered: 101,
        admitted: Some(Box::new(move |unit| {
            let nest = session_custody_nest(unit, "/call/local");
            let node_live = reads
                .post
                .node()
                .parent(busbar_contract::UnitKey::new(unit))
                .is_some();
            let same_app = reads.parent_of(&nest).is_some_and(|(app, parent)| {
                parent.key().get() == unit && Arc::ptr_eq(&app, &expected_app)
            });
            *capture.lock().expect("unpoisoned") = Some((unit, node_live, same_app));
            Err("finish after inspecting the admitted session".to_string())
        })),
        ended: None,
    };
    let (door, arrival, _) = routes.arrived(0, 1, session_custody_request(&g, "/open"));
    let (verdict, _said) = tokio::sync::oneshot::channel();
    Arc::clone(&routes)
        .session(door, session_custody_caller(), arrival, verdict, attach)
        .await;
    let (unit, node_live, same_app) = observed
        .lock()
        .expect("unpoisoned")
        .take()
        .expect("admitted callback");
    assert!(
        routes.frames_lock().is_empty(),
        "the frame ended with the session"
    );
    assert!(routes
        .post
        .node()
        .parent(busbar_contract::UnitKey::new(unit))
        .is_none());
    assert_eq!(g.post.open_units(), 0);
    assert_eq!(g.money.open_units(), 0);
    assert!(node_live, "the node slot was live at admission");
    assert!(
        same_app,
        "parent_of must return that live session's exact App and slot"
    );
}

#[tokio::test]
async fn nested_anonymous_admission_matches_the_arrival_rule() {
    let _one = PUBLISHING.lock().await;
    for (instance, pools, keys, target, expected) in [
        ("nested-open-pools", true, false, "/call/local", 200),
        ("nested-closed-pools", true, true, "/call/local", 401),
        ("nested-other-plane", false, false, "/call/local", 401),
        ("nested-explicit-open", false, true, "/open", 503),
    ] {
        let mut g = governed(instance, keys);
        let routes = session_custody_routes(&mut g, pools);
        let bound = Arc::new(std::sync::Mutex::new(None));
        let capture = Arc::clone(&bound);
        let node = Arc::clone(g.post.node());
        let app = Arc::clone(&g.app);
        let attach = super::Attach {
            answered: 101,
            admitted: Some(Box::new(move |unit| {
                let parent = node
                    .parent(busbar_contract::UnitKey::new(unit))
                    .expect("live parent");
                *capture.lock().expect("unpoisoned") = Some((app, parent));
                Err("finish the parent after binding its continuation".to_string())
            })),
            ended: None,
        };
        let (door, arrival, _) = routes.arrived(0, 1, session_custody_request(&g, "/open"));
        let (verdict, _said) = tokio::sync::oneshot::channel();
        Arc::clone(&routes)
            .session(door, session_custody_caller(), arrival, verdict, attach)
            .await;
        let bound = bound
            .lock()
            .expect("unpoisoned")
            .take()
            .expect("parent bound while live");
        let nest = session_custody_nest(bound.1.key().get(), target);
        let reply = Arc::clone(&routes).nested(nest, bound).await;
        let busbar_kernel::host_services::NestReply::Answered { status, body, .. } = reply else {
            panic!("fixture claim is served");
        };
        assert_eq!(
            status,
            expected,
            "{instance}: {}",
            String::from_utf8_lossy(&body)
        );
        if expected == 200 {
            assert_eq!(body, b"ping");
        }
        assert_eq!(
            g.requests(),
            0,
            "no anonymous unit charges the governance book"
        );
        assert_eq!(g.post.open_units(), 0);
        assert_eq!(g.money.open_units(), 0);
        assert!(routes.frames_lock().is_empty());
    }
}
