// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MONEY STEPS OF A UNIT SERVED THROUGH A PLANE'S DOOR (SERVE-WIRE step 33, `$`; ARCHITECT
//! P3 (a), 2026-10-02), over the test plane dropped in: a keyed unit is admitted and charged, and
//! its money settles at its end; a route its section does not hold is admitted then refused (1.5.5's
//! order) and settles; an unkeyed unit on a claim that takes a credential is never admitted; an
//! anonymous unit on an open claim routes and never reaches a billed path. No egress is composed
//! here, so every admitted unit's walk is exhausted at once and nothing is dialled.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::records::VirtualKey;
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use busbar_kernel::state::App;

use super::planes_tests::{bound, composed_services, Published, PUBLISHING};
use super::{compose_planes, door_routes};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::plane_node::{Node, NodeEndPost};

/// A governed composition of the test plane: a signing book with one minted key, the plane's
/// section one entry `m`, its data routes on a data router built with them, over a node of its own.
struct Governed {
    _published: Published,
    router: axum::Router,
    post: Arc<NodeEndPost>,
    money: Arc<PlaneMoney>,
    gov: Arc<GovState>,
    key: VirtualKey,
    token: String,
    app: Arc<App>,
    book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
}

/// `keys_chain`: the deployment's data chain verifies a key (a claim that takes a credential is
/// then refused by the gate when none is presented).
fn governed(instance: &'static str, keys_chain: bool) -> Option<Governed> {
    governed_with(instance, keys_chain, None)
}

/// The test plane's key, the card its fee is charged on: its Statement name.
const TEST_PLANE: &str = "plane-driver-test-plane";

/// [`governed`], the key bound to a group whose all-time budget is `budget` cents, the test plane
/// charging one cent per request (`None`: no group, no fee).
fn governed_with(
    instance: &'static str,
    keys_chain: bool,
    budget: Option<u64>,
) -> Option<Governed> {
    // The dispatcher serves its instances the composition's host services (`unit.nest` among
    // them), as the boot's does.
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
    ));
    let plane = bound(instance, &dispatcher)?;
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
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
        None => CostModel::flat(1),
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
    // The node's one book, as the boot binds it: every unit's one line and its audit record.
    let book = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal opens"),
    ));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let post = Arc::new(NodeEndPost::new(node));
    let money = Arc::new(PlaneMoney::new(
        Arc::clone(&gov),
        Arc::clone(&post) as Arc<dyn EndPost>,
    ));
    let one = Arc::clone(&money);
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::from_str("m: {}").expect("yaml"));
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        &move || Arc::clone(&one),
        None,
    )
    .expect("the door plane composes");
    served.post = Some(Arc::clone(&post));
    let routes = door_routes(served, || crate::root::kernel::ROOT_CARD.pin(), &[], &[])
        .expect("its claims mount");
    let app = busbar_kernel::test_support::TestApp::new();
    let app = if keys_chain { app.keys_chain() } else { app };
    let app = groups
        .iter()
        .fold(app, |app, (name, cfg)| app.group(name, cfg.clone()));
    let app = app.governance(Arc::clone(&gov)).cost(cost).build();
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), routes, 1 << 20, 0, false);
    Some(Governed {
        _published: Published(instance),
        router,
        post,
        money,
        gov,
        key,
        token: token.expose_secret().clone(),
        app,
        book,
    })
}

impl Governed {
    /// A POST of `ping` to `path` on the data router, with the minted key's token or with none: the
    /// status and the body.
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

    /// The requests the governance book admitted for the key, this window.
    fn requests(&self) -> u64 {
        self.gov
            .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists")
            .requests
    }
}

/// A KEYED UNIT IS ADMITTED, AND ITS MONEY SETTLES: the governance book charges its request at
/// admission, it routes (every walk is exhausted: no egress is composed), and its money facts close
/// at its end.
#[tokio::test]
async fn a_keyed_unit_is_admitted_and_its_money_settles_at_its_end() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-keyed", true) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    assert_eq!(g.requests(), 0, "nothing admitted yet");
    let (status, body) = g.post("/call/direct:m", true).await;
    assert_eq!(
        (status, body.as_str()),
        (503, "refused:503:breaker_open"),
        "admitted, then the walk is exhausted"
    );
    assert_eq!(g.requests(), 1, "its request was charged at admission");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
    assert_eq!(g.post.open_units(), 0, "its node facts closed at its end");
}

/// 1.5.5'S ORDER FOR A ROUTE ITS SECTION DOES NOT HOLD: the keyed unit is admitted (charged) first
/// and refused for its route after, and its money settles at its end.
#[tokio::test]
async fn an_unknown_route_is_admitted_then_refused_and_settles() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-unknown", true) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let (status, body) = g.post("/call/direct:nowhere", true).await;
    assert_eq!((status, body.as_str()), (503, "refused:503:no_destination"));
    assert_eq!(g.requests(), 1, "charged before its route was refused");
    assert_eq!(g.money.open_units(), 0, "its money facts closed at its end");
}

/// A UNIT WITH NO KEY ON A CLAIM THAT TAKES A CREDENTIAL IS NEVER ADMITTED: fail closed, nothing
/// charged, nothing opened (ARCHITECT P3 (a)).
#[tokio::test]
async fn an_unkeyed_unit_on_a_credential_claim_is_refused() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-unkeyed", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let (status, body) = g.post("/call/direct:m", false).await;
    assert_eq!(
        (status, body.as_str()),
        (401, "refused:401:unauthenticated")
    );
    assert_eq!(g.requests(), 0, "nothing charged");
    assert_eq!(g.money.open_units(), 0);
}

/// AN ANONYMOUS UNIT ON AN OPEN CLAIM (`CLAIM_OPEN`) is admitted with nothing held and opens no
/// money (ARCHITECT P3 (a)): it routes, and nothing of it is ever on the governance book.
#[tokio::test]
async fn an_anonymous_unit_on_an_open_claim_routes_and_opens_no_money() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-open", false) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let (status, body) = g.post("/open", false).await;
    assert_eq!(
        (status, body.as_str()),
        (503, "refused:503:breaker_open"),
        "admitted, then the walk is exhausted"
    );
    assert_eq!(g.requests(), 0, "nothing charged");
    assert_eq!(g.money.open_units(), 0);
}

/// A NESTED UNIT (`unit.nest`, ARCHITECT round 4 (c)): the parent's plane runs a child on the claim
/// it names, under the parent's key (the child is admitted and charged on the same key's chain: one
/// admission chain), and hands the parent the child's whole reply; both units' money and node facts
/// close at their ends.
#[tokio::test]
async fn a_nested_unit_runs_under_its_parents_key_and_answers_it_whole() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-nest", true) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let (status, body) = g.post("/call/nest:/call/local", true).await;
    assert_eq!((status, body.as_str()), (200, "nested:200:ping"));
    assert_eq!(
        g.requests(),
        2,
        "the parent and its child, both on the parent's key"
    );
    assert_eq!(g.money.open_units(), 0, "both units' money facts closed");
    assert_eq!(g.post.open_units(), 0, "both units' node facts closed");
    // Each unit's one audit record: the child's names its parent and its nested origin, under the
    // parent's principal.
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
    // A claim no plane serves is refused, and nothing more is charged.
    let (status, body) = g.post("/call/nest:/nowhere", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "nest-refused:no plane serves the nested unit's claim")
    );
    assert_eq!(g.requests(), 3, "only the parent");
}

/// THE IN-SESSION SERVICES THROUGH THE ONE TABLE (U22): a dropped-in plane's unit calls
/// `content.scan`, `hook.call` (a gate, then a rewrite) and `verify.lookup` on its own ticket. The
/// unit's route leg stated its hook stage, so each is served (none refused as unbound): with no hook
/// bound the content passes, the gate passes and the chain is unchanged; the verify cache, empty,
/// makes the caller its leader.
#[tokio::test]
async fn a_planes_unit_is_served_content_scan_hook_call_and_verify() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-services", true) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let (status, body) = g.post("/call/services", true).await;
    assert_eq!(
        (status, body.as_str()),
        (200, "scan=0 gate=0 rewrite=0 verify=2")
    );
    assert_eq!(g.money.open_units(), 0);
}

/// BUDGET EXHAUSTION MID-NEST: the parent is admitted while its key's budget holds one more fee;
/// that fee spends it, so the child the parent then nests is refused over budget at its own
/// admission (one admission chain), charged nothing, and the parent is handed the refusal.
#[tokio::test]
async fn a_child_nested_after_the_budget_is_spent_is_refused_and_charged_nothing() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed_with("serve-money-nest-budget", true, Some(1)) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
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

/// THE DEPTH CAP: a chain of nests is cut at the deepest a nested unit may be; every unit above it
/// answers, each charged on the one key.
#[tokio::test]
async fn a_nest_past_the_depth_cap_is_refused() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-nest-deep", true) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
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
