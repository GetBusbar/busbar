// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA ROUTE, SERVED END TO END (SERVE-WIRE step 33, TODO U6-U7): a request the decisions
//! plane's door claims reaches that plane's driver through the kernel's data door, is admitted and
//! charged by the money steps, crosses the plane's door (`arrive`, the ATTEMPT, the far end's
//! pieces), leaves through the host chokepoint (the plane's egress walk over the process's
//! connector: the destination guard's judgement and pin, the breaker, the dispatch record) to a
//! real far end, and comes back a served 200 whose money record is posted: the governance ledger
//! holds the admitted request and the node's book the unit's one line with the decision the far end
//! reported. The plane is the jev plane's own door, linked (compiled in) and bound through the
//! loader's one load, its need declared on the connector, as its door row binds it. The dropped-in
//! fold of the same door is the plane crate's own conformance suite (`tests/conformance.rs`, one
//! transcript through both loads); this harness builds no cdylib of it.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use busbar_contract::caps::ReasonCode;
use busbar_contract::conn::{DeclaredConns, NeedId, PollConns};
use busbar_contract::records::{PlaneRequestCtx, VirtualKey};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, PLANE_LANE_SEP};
use busbar_kernel::plane_driver::serve::{claimed, DataRequest};
use busbar_kernel::plane_driver::{refusal_status, EndPost, MemberRoute, PlaneMoney};
use busbar_kernel::state::App;
use busbar_plane_decisions::plane_door::door as jev_door;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::{composed_services, money, Published, PUBLISHING};
use super::{compose_planes, mount, DataRoutes};
use crate::root::door_steps::compose_egress;
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::root::plane_node::{Node, NodeEndPost};

/// The deployment's dated card history the served unit is pinned to at its door: one entry, no
/// price (billing off: the counts are the unit's fact and price at nothing).
static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
    std::sync::LazyLock::new(|| {
        let holder = crate::root::kernel::RootHistory::default();
        holder.apply(
            crate::root::kernel::card_from_config(
                std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                0,
                true,
            ),
            1_000,
        );
        holder
    });

/// The jev plane's one claim, with one model configured.
const CLAIMED: &str = "/v1/systemone";

/// The far end's answer: a decision, and the one unit it reports using.
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

fn request(path: &str, key: Option<Arc<VirtualKey>>, app: Arc<App>) -> DataRequest {
    DataRequest {
        method: Method::POST,
        uri: path.parse::<Uri>().expect("a target"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(br#"{"state":{"amount":7}}"#),
        gov: PlaneRequestCtx { key },
        consumed: None,
        app,
    }
}

/// A far end on loopback answering every request with [`ANSWER`]; what it was sent comes back on
/// the channel, one request head per connection.
async fn far_end() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let sent = sent.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                // The head, then the body its content-length states.
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let length = text[..at]
                            .lines()
                            .find_map(|l| {
                                let (name, value) = l.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            let _ = sent.send(text);
                            break;
                        }
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{ANSWER}",
                    ANSWER.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, heard)
}

/// THE EXIT TEST: a keyed caller's claimed request is SERVED through the decisions door, 200, the
/// far end's answer relayed as it came, and the unit's money posted on both books.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claimed_request_is_served_through_the_door_and_its_money_posted() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-jev-served";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;

    // THE CONNECTOR, over every linked transport door and the http framer's door (the linked
    // `busbar-transport-http` crate's own memory-ABI door: the root's linked tables do not yet put
    // it on the transport-door axis), its dials judged by a destination guard that admits loopback
    // (a far end on this host).
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build(
        || {
            let mut doors = crate::LINKED_TRANSPORT_DOORS.to_vec();
            doors.push(("http", busbar_transport_http::door::door));
            crate::root::connector::entries(&doors)
        },
        judge,
        &[],
        Arc::new(|_| {}),
    )
    .expect("the connector builds");

    // THE DECISIONS DOOR, linked, bound through the loader's one load, its need declared on the
    // connector.
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(jev_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
        },
    )
    .expect("the linked door binds");
    let caller = plane.instance();
    let section_key = plane.served().section;

    // THE MONEY: a signing governance book with one minted key, the node's book bound.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (key, _token) = gov
        .mint_signed(
            NewKeySpec {
                name: "decider".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    let key = Arc::new(key);
    gov.hydrate_budgets(&CostModel::flat(1), 0)
        .expect("hydrate");
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
    node.bind_book(Arc::clone(&book.durability));
    let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
    let site = Arc::clone(&post);
    let book_money = Arc::clone(&gov);
    let plane_money = move || {
        Arc::new(PlaneMoney::new(
            Arc::clone(&book_money),
            Arc::clone(&site) as Arc<dyn EndPost>,
        ))
    };

    // THE COMPOSITION: the door opened with its section (one model), driven, its egress sealed:
    // the one entry's route is the far end on loopback over the door's one declared need. (Which
    // need a member dials is resolved from its auth key at config load, `resolve_member_needs`;
    // the decisions door's one outbound need is need 0.)
    let mut sections = BTreeMap::new();
    sections.insert(
        section_key,
        serde_yaml::from_str("models: {jev: {provider: typesafe}}").expect("a section"),
    );
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        &plane_money,
    )
    .expect("the door plane composes");
    let routes = BTreeMap::from([(
        "jev".to_string(),
        MemberRoute {
            need: NeedId(0),
            base_url: format!("http://127.0.0.1:{port}"),
            auth: None,
            provider: "typesafe".to_string(),
            keep: busbar_kernel::plane_driver::ResponseKeep::default(),
        },
    )]);
    let composed = &mut served.planes[0];
    let egress = compose_egress(
        &composed.facts,
        &composed.pools,
        caller,
        Arc::clone(&connector) as Arc<dyn PollConns>,
        &routes,
        Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        600,
    )
    .expect("the egress seals");
    composed.egress = Some(Arc::new(egress));
    let money_steps = Arc::clone(&composed.money);
    let plane_key = composed.facts.plane.clone();
    served.post = Some(Arc::clone(&post));
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(CostModel::flat(1))
        .build();
    let doors = Arc::new(DataRoutes {
        served,
        post: Arc::clone(&post),
        pin: || CARD.pin(),
    });

    // THE SERVED REQUEST.
    let answer = doors
        .claimed(request(CLAIMED, Some(Arc::clone(&key)), Arc::clone(&app)))
        .ok()
        .expect("the plane claims it");
    let response = answer.await;
    assert_eq!(response.status(), StatusCode::OK, "served through the door");
    let kind = response.headers()["content-type"].to_str().expect("a type");
    assert!(kind.starts_with("application/json"), "{kind}");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    assert_eq!(
        &body[..],
        ANSWER.as_bytes(),
        "the far end's answer, relayed as it came"
    );

    // THE FAR END HEARD THE PLANE'S REQUEST, through the connector.
    let head = heard.recv().await.expect("the far end was dialled");
    assert!(head.starts_with("POST /v1/systemone "), "{head}");
    assert!(
        head.ends_with(r#"{"state":{"amount":7}}"#),
        "the caller's body: {head}"
    );

    // THE MONEY RECORD: the request admitted on the governance ledger, the unit's facts closed on
    // the money steps and the node, and its one line on the node's book carrying the decision the
    // far end reported, under the (plane key, entry) it was served by.
    let usage = gov
        .usage_for(&app.cost, &key.id, busbar_kernel::store::now())
        .expect("a read")
        .expect("the key exists");
    assert_eq!(usage.requests, 1, "one admitted request");
    assert_eq!(
        money_steps.open_units(),
        0,
        "its money facts closed at its end"
    );
    assert_eq!(post.open_units(), 0, "its node facts closed at its end");
    let rows = book.durability.lock().expect("unpoisoned").read_back();
    let lane = format!("{plane_key}{PLANE_LANE_SEP}jev");
    let line = rows
        .iter()
        .find(|p| p.counts.as_ref().is_some_and(|c| c.lane == lane))
        .unwrap_or_else(|| panic!("the unit's one line on the node's book: {rows:?}"));
    let counts = line.counts.as_ref().expect("its counts");
    assert_eq!(line.refusal, None, "its classes resolve: {line:?}");
    assert_eq!(
        counts.classes.get("decision").copied(),
        Some(1),
        "the decision the far end reported: {counts:?}"
    );
}

/// THE MOUNT: a request the composed door does not claim comes back whole for the fallback's own
/// dispatch; a claimed one is the door's. An unkeyed caller on the door's claim (it takes a
/// credential) is refused before anything is charged, rendered by the plane.
#[tokio::test]
async fn the_mounted_data_door_claims_only_the_planes_routes() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-jev";
    let _published = Published(instance);
    let app = busbar_kernel::test_support::TestApp::new().build();
    // RED ARM, before the mount: the kernel's data door claims nothing.
    let back = claimed(request(CLAIMED, None, Arc::clone(&app)))
        .err()
        .expect("no data door is mounted yet");
    assert_eq!(back.uri.path(), CLAIMED);

    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(jev_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the linked door binds");
    let section = plane.served().section;
    let mut sections = BTreeMap::new();
    sections.insert(
        section,
        serde_yaml::from_str("models: {jev: {provider: typesafe}}").expect("a section"),
    );
    let served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        &money,
    )
    .expect("the door plane composes");
    mount(served).expect("the data routes mount");

    let back = claimed(request("/v1/unclaimed", None, Arc::clone(&app)))
        .err()
        .expect("unclaimed");
    assert_eq!(back.uri.path(), "/v1/unclaimed");

    let answer = claimed(request(CLAIMED, None, app))
        .ok()
        .expect("the plane claims it");
    let response = answer.await;
    assert_eq!(
        u32::from(response.status().as_u16()),
        refusal_status(ReasonCode::Unauthenticated)
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON");
    assert_eq!(
        body["error"]["message"],
        ReasonCode::Unauthenticated.as_str(),
        "the kernel wrote the text, the plane rendered it: {body}"
    );
    assert!(
        mount(super::Served::default()).is_ok(),
        "a composition that claims nothing mounts nothing"
    );
}
