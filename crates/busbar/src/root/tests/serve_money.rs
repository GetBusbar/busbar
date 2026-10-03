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

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, Uri};
use busbar_contract::records::{PlaneRequestCtx, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane_driver::serve::DataRequest;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use busbar_kernel::state::App;

use super::planes_tests::{bound, composed_services, Published, PUBLISHING};
use super::{compose_planes, DataRoutes};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::plane_node::{Node, NodeEndPost};

/// A governed composition of the test plane: a signing book with one minted key, the plane's
/// section one entry `m`, its data routes over a node of its own.
struct Governed {
    _published: Published,
    routes: Arc<DataRoutes>,
    money: Arc<PlaneMoney>,
    gov: Arc<GovState>,
    key: Arc<VirtualKey>,
    app: Arc<App>,
}

fn governed(instance: &'static str) -> Option<Governed> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plane = bound(instance, &dispatcher)?;
    let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let spec = NewKeySpec {
        name: "door".to_string(),
        ..Default::default()
    };
    let (key, _token) = gov
        .mint_signed(spec, 4_000_000_000, 1_700_000_000)
        .expect("mint");
    gov.hydrate_budgets(&CostModel::flat(1), 0)
        .expect("hydrate");
    let post = Arc::new(NodeEndPost::new(Arc::new(Node::new())));
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
        &composed_services(),
        &sections,
        &move || Arc::clone(&one),
    )
    .expect("the door plane composes");
    served.post = Some(Arc::clone(&post));
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(CostModel::flat(1))
        .build();
    Some(Governed {
        _published: Published(instance),
        routes: Arc::new(DataRoutes {
            served,
            post,
            pin: || crate::root::kernel::ROOT_CARD.pin(),
        }),
        money,
        gov,
        key: Arc::new(key),
        app,
    })
}

impl Governed {
    /// A POST of `ping` to `path`, as the keyed caller or as nobody: the status and the body.
    async fn post(&self, path: &str, keyed: bool) -> (u16, String) {
        let req = DataRequest {
            method: Method::POST,
            uri: path.parse::<Uri>().expect("a target"),
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"ping"),
            gov: PlaneRequestCtx {
                key: keyed.then(|| Arc::clone(&self.key)),
            },
            consumed: None,
            app: Arc::clone(&self.app),
        };
        let answer = self.routes.claimed(req).ok().expect("the plane claims it");
        let response = answer.await;
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, String::from_utf8_lossy(&body).into_owned())
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
    let Some(g) = governed("serve-money-keyed") else {
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
    assert_eq!(
        g.routes.post.open_units(),
        0,
        "its node facts closed at its end"
    );
}

/// 1.5.5'S ORDER FOR A ROUTE ITS SECTION DOES NOT HOLD: the keyed unit is admitted (charged) first
/// and refused for its route after, and its money settles at its end.
#[tokio::test]
async fn an_unknown_route_is_admitted_then_refused_and_settles() {
    let _one = PUBLISHING.lock().await;
    let Some(g) = governed("serve-money-unknown") else {
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
    let Some(g) = governed("serve-money-unkeyed") else {
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
    let Some(g) = governed("serve-money-open") else {
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
