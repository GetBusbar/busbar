// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA ROUTE, SERVED END TO END (SERVE-WIRE step 33, TODO U6-U7): a request the decisions
//! plane's door claims reaches that plane's driver through its route on the data router (mounted at
//! the router's construction, ARCHITECT Q-SW1), behind the deployment's auth gate, is admitted and
//! charged by the money steps, crosses the plane's door (`arrive`, the ATTEMPT, the far end's
//! pieces), leaves through the host chokepoint (the plane's egress walk over the process's
//! connector: the destination guard's judgement and pin, the breaker, the dispatch record) to a
//! real far end, and comes back a served 200 whose money record is posted: the governance ledger
//! holds the admitted request and the node's book the unit's one line with the decision the far end
//! reported. The plane is the decisions plane's own door, linked (compiled in) and bound through the
//! loader's one load, its need declared on the connector, as its door row binds it. The dropped-in
//! fold of the same door is the plane crate's own conformance suite (`tests/conformance.rs`, one
//! transcript through both loads); this harness builds no cdylib of it.

#[cfg(feature = "plane-decisions")]
use std::collections::BTreeMap;
#[cfg(feature = "plane-decisions")]
use std::sync::Arc;

#[cfg(feature = "plane-decisions")]
use axum::http::StatusCode;
#[cfg(feature = "plane-decisions")]
use busbar_contract::caps::ReasonCode;
#[cfg(feature = "plane-decisions")]
use busbar_contract::conn::{DeclaredConns, PollConns};
#[cfg(feature = "plane-decisions")]
use busbar_kernel::cost::CostModel;
#[cfg(feature = "plane-decisions")]
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
#[cfg(feature = "plane-decisions")]
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, PLANE_LANE_SEP};
#[cfg(feature = "plane-decisions")]
use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
#[cfg(feature = "plane-decisions")]
use busbar_plane_decisions::plane_door::door as decisions_door;
#[cfg(feature = "plane-decisions")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "plane-decisions")]
use super::planes_tests::{composed_services, money, Published, PUBLISHING};
#[cfg(feature = "plane-decisions")]
use super::{compose_planes, compose_planes_over, door_routes, DoorEgress};
#[cfg(feature = "plane-decisions")]
use crate::root::door_steps::{provider_routes, DoorReach, OutboundAuths};
#[cfg(feature = "plane-decisions")]
use crate::root::loader::dispatch::kinds::plane::Plane;
#[cfg(feature = "plane-decisions")]
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
#[cfg(feature = "plane-decisions")]
use crate::root::plane_node::{Node, NodeEndPost};

/// The deployment's dated card history the served unit is pinned to at its door: one entry, no
/// price (billing off: the counts are the unit's fact and price at nothing).
#[cfg(feature = "plane-decisions")]
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

/// The decisions plane's one claim, with one model configured.
#[cfg(feature = "plane-decisions")]
const CLAIMED: &str = "/v1/systemone";

/// The provider's credential, as its file holds it.
#[cfg(feature = "plane-decisions")]
const CREDENTIAL: &str = "sk-door-test";

/// The far end's answer: a decision, and the one unit it reports using.
#[cfg(feature = "plane-decisions")]
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

/// A far end's transient failure, as [`far_end_failing_first`] answers it.
#[cfg(feature = "plane-decisions")]
const UNAVAILABLE: &str = r#"{"error":"unavailable"}"#;

/// A POST of the caller's decision state to `path` on `router`, with `token` as its bearer or with
/// none: the response.
#[cfg(feature = "plane-decisions")]
async fn send(router: &axum::Router, path: &str, token: Option<&str>) -> axum::response::Response {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method("POST").uri(path);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req
        .body(axum::body::Body::from(r#"{"state":{"amount":7}}"#))
        .expect("a request");
    router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers")
}

/// A far end on loopback answering every request with [`ANSWER`]; what it was sent comes back on
/// the channel, one request head per connection.
#[cfg(feature = "plane-decisions")]
async fn far_end() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_failing_first(0).await
}

/// [`far_end`], but its first `failures` connections are answered with a bare transient failure
/// (503, no `Retry-After`) instead of [`ANSWER`].
#[cfg(feature = "plane-decisions")]
async fn far_end_failing_first(
    failures: usize,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut accepted = 0usize;
        while let Ok((mut socket, _)) = listener.accept().await {
            let failing = accepted < failures;
            accepted += 1;
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
                let (line, body) = if failing {
                    ("503 Service Unavailable", UNAVAILABLE)
                } else {
                    ("200 OK", ANSWER)
                };
                let reply = format!(
                    "HTTP/1.1 {line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{body}",
                    body.len()
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
#[cfg(feature = "plane-decisions")]
async fn a_claimed_request_is_served_through_the_door_and_its_money_posted() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-served";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;

    // THE CONNECTOR, over every linked transport door (the default distribution links the http
    // framer's door: the `connector-door` row), its dials judged by a destination guard that admits
    // loopback (a far end on this host).
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
    )
    .expect("the connector builds");

    // THE DECISIONS DOOR, linked, bound through the loader's one load, its need declared on the
    // connector.
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::root::loader::dispatch::ConnTable::Host(
                Arc::clone(&connector) as Arc<dyn DeclaredConns>
            ),
        },
    )
    .expect("the linked door binds");
    let section_key = plane.served().section;

    // THE MONEY: a signing governance book with one minted key, the node's book bound.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (key, token) = gov
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

    // THE PROVIDER the one model names, as the deployment configures it: the far end on loopback,
    // its credential a file reference, no `auth:` (so the decisions dialect's default style).
    let key_file = std::env::temp_dir().join(format!("busbar-serve-door-{}", std::process::id()));
    std::fs::write(&key_file, CREDENTIAL).expect("the credential file");
    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(&format!(
        "{{protocol: {}, base_url: 'http://127.0.0.1:{port}', api_key: {{file: '{}'}}, error_map: {{}}}}",
        busbar_plane_decisions::config::PROTOCOL,
        key_file.display()
    ))
    .expect("a provider entry");
    let providers = provider_routes(&std::collections::HashMap::from([(
        "typesafe".to_string(),
        provider,
    )]));
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let auths = OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::Host(
            Arc::clone(&connector) as Arc<dyn DeclaredConns>
        ),
    );
    let reach = DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: Arc::new(auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        models: None,
        upgrades: Vec::new(),
    };

    // THE COMPOSITION, AS PRODUCTION SEALS IT: the door opened with its section (one model),
    // driven, and its egress sealed by the composition itself — the member's provider resolved,
    // its style the dialect's default, its need the one that style names, its credential bound by
    // the linked auth plugin serving that style. Nothing is sealed by hand.
    let mut sections = BTreeMap::new();
    sections.insert(
        section_key,
        serde_yaml::from_str("models: {m: {provider: typesafe}}").expect("a section"),
    );
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        None,
    )
    .expect("the door plane composes, its egress sealed");
    let _ = std::fs::remove_file(&key_file);
    let composed = &mut served.planes[0];
    assert!(
        composed.live.current().egress.is_some(),
        "the composition sealed its egress"
    );
    let money_steps = Arc::clone(&composed.money);
    let plane_key = composed.facts.plane.clone();
    served.post = Some(Arc::clone(&post));
    let app = busbar_kernel::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov))
        .cost(CostModel::flat(1))
        .build();
    // THE DATA ROUTER, BUILT WITH THE DOOR'S ROUTES (Q-SW1: its construction, no static).
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);

    // THE SERVED REQUEST, as the keyed caller.
    let response = send(&router, CLAIMED, Some(token.expose_secret())).await;
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
        head.lines()
            .any(|l| l.eq_ignore_ascii_case(&format!("authorization: Bearer {CREDENTIAL}"))),
        "the member's credential, presented by the auth plugin serving its style: {head}"
    );
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
    let lane = format!("{plane_key}{PLANE_LANE_SEP}m");
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

/// THE MOUNT: the door's claim is a route on the data router only when the router is built with
/// it; a path the door does not claim is the router's own. An unkeyed caller on the door's claim (it
/// takes a credential) is refused before anything is charged, rendered by the plane.
#[tokio::test]
#[cfg(feature = "plane-decisions")]
async fn the_data_router_built_with_the_door_serves_only_its_claims() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door";
    let _published = Published(instance);
    let app = busbar_kernel::test_support::TestApp::new().build();
    // RED ARM: a data router built without the door's routes does not hand the claim to the plane.
    let (bare, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), Vec::new(), 1 << 20, 0, false);
    let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
    assert_ne!(send(&bare, CLAIMED, None).await.status().as_u16(), refused);

    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            // This row only routes (no request reaches the provider): the plane's need is not
            // declared, bound as a probe.
            conns: crate::root::loader::dispatch::ConnTable::Probe,
        },
    )
    .expect("the linked door binds");
    let section = plane.served().section;
    let mut sections = BTreeMap::new();
    sections.insert(
        section,
        serde_yaml::from_str("models: {m: {provider: typesafe}}").expect("a section"),
    );
    let served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the door plane composes");
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    assert!(!doors.is_empty(), "the claim is a route");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(app, doors, 1 << 20, 0, false);

    let unclaimed = send(&router, "/v1/unclaimed", None).await;
    assert_ne!(
        unclaimed.status().as_u16(),
        refused,
        "a path the door does not claim"
    );

    let response = send(&router, CLAIMED, None).await;
    assert_eq!(response.status().as_u16(), refused);
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
        door_routes(super::Served::default(), || CARD.pin(), &[], &[])
            .expect("nothing to mount")
            .is_empty(),
        "a composition that claims nothing mounts nothing"
    );
}

/// ONE MOUNT PER (PATH, METHOD) (SEAM-L(l), ported from 5ad225bc89): a door claiming one verb and
/// path over two carriers (an endpoint answered as a document or as an event stream) is one route
/// on the data listener, the first in its claim order; the data router builds with it. RED: each
/// claim mounted its own route, and the router refused the second as an overlapping method route.
#[tokio::test]
#[cfg(feature = "plane-decisions")]
async fn a_door_claiming_one_path_over_two_carriers_mounts_it_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-carriers";
    let _published = Published(instance);
    let app = busbar_kernel::test_support::TestApp::new().build();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            // This row only routes (no request reaches the provider): the plane's need is not
            // declared, bound as a probe.
            conns: crate::root::loader::dispatch::ConnTable::Probe,
        },
    )
    .expect("the linked door binds");
    let section = plane.served().section;
    let mut sections = BTreeMap::new();
    sections.insert(
        section,
        serde_yaml::from_str("models: {m: {provider: typesafe}}").expect("a section"),
    );
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the door plane composes");
    // The same verb and path again, over a second carrier.
    let claims = &mut served.planes[0].snapshot.claims;
    let mut twin = claims[0].clone();
    twin.carrier = format!("{}-stream", twin.carrier);
    claims.push(twin);
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    let mut seen = std::collections::BTreeSet::new();
    for door in &doors {
        assert!(
            seen.insert((door.path.clone(), door.method.as_str())),
            "{} {} is mounted once",
            door.method.as_str(),
            door.path
        );
    }
    assert!(
        seen.contains(&(CLAIMED.to_string(), "POST")),
        "the claim is a route: {seen:?}"
    );
    // The data router builds with them (an overlapping method route would panic here).
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(app, doors, 1 << 20, 0, false);
    let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
    assert_eq!(
        send(&router, CLAIMED, None).await.status().as_u16(),
        refused
    );
}

#[cfg(feature = "plane-decisions")]
/// What a served door's data router needs kept alive beside it.
struct Serving {
    router: axum::Router,
    token: String,
    _handle: Arc<busbar_kernel::state::AppHandle>,
}

#[cfg(feature = "plane-decisions")]
/// THE DECISIONS DOOR SERVED OVER `linked`, composed as the exit test above composes it (the
/// connector over the linked transport doors, the door bound through the loader's one load, one
/// model whose provider is the far end on `port`, a keyed caller): the composition reads the door
/// plane's declared facts off `linked`.
async fn serve_over(linked: &crate::root::linked::Linked, instance: &str, port: u16) -> Serving {
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
    )
    .expect("the connector builds");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: crate::root::loader::dispatch::ConnTable::Host(
                Arc::clone(&connector) as Arc<dyn DeclaredConns>
            ),
        },
    )
    .expect("the linked door binds");
    let section_key = plane.served().section;

    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (_key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "decider".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
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

    let key_file = std::env::temp_dir().join(format!(
        "busbar-serve-door-{instance}-{}",
        std::process::id()
    ));
    std::fs::write(&key_file, CREDENTIAL).expect("the credential file");
    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(&format!(
        "{{protocol: {}, base_url: 'http://127.0.0.1:{port}', api_key: {{file: '{}'}}, error_map: {{}}}}",
        busbar_plane_decisions::config::PROTOCOL,
        key_file.display()
    ))
    .expect("a provider entry");
    let providers = provider_routes(&std::collections::HashMap::from([(
        "typesafe".to_string(),
        provider,
    )]));
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let auths = OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::Host(
            Arc::clone(&connector) as Arc<dyn DeclaredConns>
        ),
    );
    let reach = DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: Arc::new(auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        models: None,
        upgrades: Vec::new(),
    };
    let mut sections = BTreeMap::new();
    sections.insert(
        section_key,
        serde_yaml::from_str("models: {m: {provider: typesafe}}").expect("a section"),
    );
    let mut served = compose_planes_over(
        linked,
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        None,
    )
    .expect("the door plane composes, its egress sealed");
    let _ = std::fs::remove_file(&key_file);
    served.post = Some(Arc::clone(&post));
    let app = busbar_kernel::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov))
        .cost(CostModel::flat(1))
        .build();
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    let (router, _admin, handle) =
        busbar_kernel::build_split_routers_serving(app, doors, 1 << 20, 0, false);
    Serving {
        router,
        token: token.expose_secret().to_string(),
        _handle: handle,
    }
}

#[cfg(feature = "plane-decisions")]
/// The decisions door's `declares` section stating the breaker fact false (ARCHITECT Q4).
const STATES_NO_BENCH: &str = r#"{"breaker":{"bench_below_trip_threshold":false}}"#;

#[cfg(feature = "plane-decisions")]
/// The linked table with the decisions door's row stating `declares` (the
/// `[package.metadata.busbar.linked-declares]` row a plane's door crate names).
fn declaring(declares: &'static str) -> crate::root::linked::Linked {
    crate::root::linked::Linked {
        plane_door_declares: vec![(
            "busbar-plane-decisions",
            decisions_door as busbar_contract::abi::mechanism::door::DoorFn,
            declares,
        )]
        .leak(),
        ..crate::LINKED
    }
}

#[cfg(feature = "plane-decisions")]
/// The decisions door's Statement name: the name the root finds its declared facts by.
fn decisions_name() -> String {
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name
}

#[cfg(feature = "plane-decisions")]
/// One call, then the far end's next request head when it reached the far end.
async fn call_once(
    serving: &Serving,
    heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> (StatusCode, Option<String>) {
    let status = send(&serving.router, CLAIMED, Some(&serving.token))
        .await
        .status();
    (status, heard.try_recv().ok())
}

#[cfg(feature = "plane-decisions")]
/// THE PLANE'S BREAKER FACT, READ BY THE ROOT (ARCHITECT Q4): a door plane whose `declares`
/// states `bench_below_trip_threshold: false` keeps its sole member in service through one
/// transient failure below the trip threshold — the 503 reaches the caller, and the NEXT call
/// reaches the far end and is served. The root names no plane: it finds the fact by the door's
/// Statement name. RED with the fact absent (the arm below).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plane_stating_no_bench_below_the_trip_keeps_its_sole_member_through_one_503() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-breaker-stated";
    let _published = Published(instance);
    let linked = declaring(STATES_NO_BENCH);
    assert_eq!(
        crate::root::linked::door_breaker(&linked, None, &decisions_name())
            .expect("the fact reads"),
        Some(crate::root::loader::sign::BreakerDecl {
            bench_below_trip_threshold: false
        }),
        "the root reads the fact off the door's declares, by its Statement name"
    );
    let (port, mut heard) = far_end_failing_first(1).await;
    let serving = serve_over(&linked, instance, port).await;

    let (status, reached) = call_once(&serving, &mut heard).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the far end's one transient failure"
    );
    assert!(reached.is_some(), "the failing call reached the far end");

    let (status, reached) = call_once(&serving, &mut heard).await;
    assert!(
        reached.is_some(),
        "one 503 below the trip benches nothing: the next call reaches the far end"
    );
    assert_eq!(status, StatusCode::OK, "and is served");
}

#[cfg(feature = "plane-decisions")]
/// ABSENT, THE DEFAULT HOLDS: a door plane whose `declares` states no breaker fact (or that has no
/// `declares` row at all, as no door in the shipped table has) keeps the host's default cell: one
/// transient failure benches the sole member for its cooldown, so the next call is refused without
/// reaching the far end, exactly as before the fact existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plane_stating_no_breaker_fact_keeps_the_default_bench() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-breaker-absent";
    let _published = Published(instance);
    // The door's row states a `declares` section without the fact; the shipped table has no row.
    let silent = declaring("{}");
    assert_eq!(
        crate::root::linked::door_breaker(&silent, None, &decisions_name()).expect("it reads"),
        None
    );
    assert_eq!(
        crate::root::linked::door_breaker(&crate::LINKED, None, &decisions_name())
            .expect("nothing to read"),
        None,
        "no linked door states the fact in this build"
    );

    let (port, mut heard) = far_end_failing_first(1).await;
    let serving = serve_over(&silent, instance, port).await;
    let (status, reached) = call_once(&serving, &mut heard).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the far end's one transient failure"
    );
    assert!(reached.is_some(), "the failing call reached the far end");

    let (status, reached) = call_once(&serving, &mut heard).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the benched member's call is refused"
    );
    assert_eq!(
        reached, None,
        "under the default one 503 benches the sole member: the next call never reaches the far end"
    );
}

// ── THE DOOR SERVING THE `pools` MAP: ITS CAPABILITY CELLS (Q128 U14) ───────────────────────────
//
// The capability-equality matrix's root column for this plane, witnessed on its door path: each
// cell below drives a keyed caller through the data router built with the door's claims, the
// kernel's hook stage, the model-serving walk over the kernel's lane cells and the node's book
// (`super::hook_seat_tests::rig`), and reads the capability where the kernel keeps it.
#[cfg(linked_fold_on_driver)]
use super::hook_seat_tests::{
    chunk, far_end_answering, far_end_scripted, rig, webhook_secret, RigOpts, Script, REWRITTEN,
    WEBHOOK_KEY,
};
#[cfg(linked_fold_on_driver)]
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// A served chat completion, marked by the member that answered it.
#[cfg(linked_fold_on_driver)]
const SERVED_BY_TWIN: &str = r#"{"id":"chatcmpl-2","object":"chat.completion","created":0,"model":"m1","choices":[{"index":0,"message":{"role":"assistant","content":"served-by-the-twin"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A far end that cannot serve now.
#[cfg(linked_fold_on_driver)]
const OVERLOADED: &str = r#"{"error":{"message":"overloaded","type":"server_error"}}"#;

/// A far end refusing the request itself.
#[cfg(linked_fold_on_driver)]
const MALFORMED: &str = r#"{"error":{"message":"bad request","type":"invalid_request_error"}}"#;

/// BREAKER-TRIP: a member whose far end fails records into the kernel's ONE breaker cell for its
/// (pool, lane), and the cell opens: the walk's failure benched it.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_trips_a_failing_members_breaker_cell() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-breaker-trip";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        far_end_answering(503, OVERLOADED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(down.port, 100), (twin.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let ready = || rig.app.store.ready_in("p", 0, busbar_kernel::store::now());
    assert!(ready(), "the member's cell admits before any failure");
    let (status, _, _) = rig.chat().await;
    assert_eq!(status, 200, "the twin serves");
    assert_eq!(down.served(), 1, "the failing member was dialled once");
    assert!(
        !ready(),
        "the failure recorded into the member's (pool, lane) cell and opened it"
    );
}

/// BREAKER-FASTFAIL: a tripped member is refused before dispatch, at once: the next unit never
/// dials it, and its twin serves.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refuses_a_tripped_member_before_dispatch() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-breaker-fastfail";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        far_end_answering(503, OVERLOADED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(down.port, 100), (twin.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    assert_eq!(down.served(), 1);
    let started = std::time::Instant::now();
    assert_eq!(rig.chat().await.0, 200, "the twin serves the next unit");
    assert_eq!(
        down.served(),
        1,
        "the tripped member is refused before dispatch: never dialled again"
    );
    assert_eq!(twin.served(), 2);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "refused at once, not after a timeout"
    );
}

/// FAILOVER-REROUTE: a second interchangeable candidate is tried before the first byte, through
/// the one walk: the first member fails, the twin's answer is the caller's.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_reroutes_to_the_twin_before_the_first_byte() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-failover";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        far_end_answering(503, OVERLOADED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(down.port, 100), (twin.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("served-by-the-twin"),
        "the twin's answer reached the caller: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!((down.served(), twin.served()), (1, 1));
}

/// DISPOSITION: the far end's answer is classified before it is relayed: a refusal of the request
/// itself is the caller's own fault, relayed with its status, never failed over and never charged
/// to the member's breaker cell.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_classifies_a_refused_request_as_the_callers_fault() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-disposition";
    let _published = Withdrawn(instance);
    let (refusing, twin) = (
        far_end_answering(400, MALFORMED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(refusing.port, 100), (twin.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, _) = rig.chat().await;
    assert_eq!(status, 400, "the far end's refusal is relayed");
    assert_eq!(
        (refusing.served(), twin.served()),
        (1, 0),
        "a caller's fault is not failed over"
    );
    assert!(
        rig.app.store.ready_in("p", 0, busbar_kernel::store::now()),
        "nor charged to the member's cell"
    );
}

/// EGRESS-AUTH: the member's credential is the one the egress mechanism binds and injects; the
/// caller's own token never crosses.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_injects_the_members_credential_not_the_callers() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-egress-auth";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let seen = far.authorizations.lock().unwrap().clone();
    assert_eq!(seen, vec!["Bearer sk-seats".to_string()]);
    assert!(
        !seen[0].contains(&rig.token),
        "the caller's token never crosses"
    );
}

/// METRICS: the door's traffic appears on the scrape, under the pool and lane it was served on.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_traffic_appears_on_the_metrics_scrape() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-metrics";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let scrape = busbar_kernel::metrics::render();
    assert!(
        scrape
            .lines()
            .any(|l| l.starts_with("busbar_upstream_attempts_total{")
                && l.contains("pool=\"p\"")
                && l.contains("lane=\"m0\"")),
        "the attempt is on the scrape under its pool and lane:\n{scrape}"
    );
}

/// GOVERNANCE-BUDGET: the unit's spend is attributed to the presenting key, and a key whose budget
/// is spent is refused before any far end is dialled.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_attributes_spend_and_a_spent_budget_refuses() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-budget";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            budget_cents: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let (requests, spend, _, billable) = rig.ledger_after(1).await;
    assert_eq!(
        (requests, spend, billable),
        (1, 1, 1),
        "the one fee on the key"
    );
    let (status, head, _) = rig.chat().await;
    assert_eq!(status, 429, "the spent budget refuses");
    assert!(
        head.contains_key("retry-after"),
        "with a Retry-After: {head:?}"
    );
    assert_eq!(far.served(), 1, "the refused unit dialled nothing");
}

/// AUDIT-CHAIN: every unit the door serves seals exactly one record on the node's chain.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_seals_one_audit_record_per_unit() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-audit";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let _ = rig.ledger_after(1).await;
    assert_eq!(rig.audit_records(), 1, "one record for the one unit");
}

/// HOOKS-GATE: a decision gate refuses the door's traffic before dispatch.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_gate_hook_refuses_before_dispatch() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-gate";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            reject_at_gate: true,
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 451, "the gate's own status");
    assert_eq!(far.served(), 0, "nothing was dispatched");
}

/// HOOKS-TAP: the rewrite and observe hooks run over the door's payloads: the request-stage tap
/// sees the request as the global rewrite left it.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_tap_hooks_observe_the_rewritten_request() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-tap";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let payload = rig
        .request_tap_payload(2_000)
        .await
        .expect("the request-stage tap is delivered");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.contains(REWRITTEN), "{text}");
    assert!(!text.contains("the original prompt"), "{text}");
}

/// CATALOGUE: what a restricted key may SEE is the one catalogue walk's answer: the pool it may
/// reach and that pool's members, never a model it cannot reach.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_catalogue_shows_a_restricted_key_only_what_it_reaches() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-catalogue";
    let _published = Withdrawn(instance);
    let (a, b) = (
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(a.port, 1), (b.port, 1)],
            pooled: Some(1),
            allowed_pools: Some(&["p"]),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.send("GET", "/v1/models", None).await;
    assert_eq!(status, 200);
    let listed: serde_json::Value = serde_json::from_slice(&body).expect("a JSON list");
    let ids: Vec<&str> = listed["data"]
        .as_array()
        .expect("the list")
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        ["p", "m0"],
        "the reachable pool and its member, nothing else"
    );
}

/// An anthropic message whose usage carries a member the openai caller's dialect has no form for.
#[cfg(linked_fold_on_driver)]
const ANTHROPIC_ANSWER: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"m0","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1,"output_tokens_details":{"reasoning_tokens":0}}}"#;

/// THE DROPPED-CONTROLS AUDIT ROW ON THE DOOR (ARCHITECT, Q128 gap): a TRANSLATE attempt that
/// cannot carry a control the caller set writes 1.5.5's `egress.control_unrepresentable` row,
/// outcome `degraded`, `<control> on <dialect>`; an answer member the caller's dialect has no form
/// for writes `<path> from <dialect>`. Both reach the kernel's audit chain through the plane's
/// `RECORD_AUDIT` write. RED arm: a request that sets nothing the far dialect drops writes no row.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_audits_a_control_the_far_dialect_cannot_carry() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-dropped-controls";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, ANTHROPIC_ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let rows = |resource: &str| {
        busbar_kernel::audit::auditlog::AUDIT_LOG
            .list_filtered(
                0,
                1000,
                Some("egress.control_unrepresentable"),
                Some(resource),
            )
            .into_iter()
            .filter(|e| e.principal == rig.key_id && e.outcome == "degraded")
            .count()
    };
    let (status, _, _) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        rows("logit_bias on anthropic"),
        0,
        "nothing set, nothing dropped"
    );
    let (status, _, _) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "logit_bias": {"50256": -100},
                "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        rows("logit_bias on anthropic"),
        1,
        "the dropped control, one row"
    );
    assert!(
        rows("usage.output_tokens_details from anthropic") >= 1,
        "the answer member the caller's dialect cannot carry"
    );
}

/// THE RANKING SIGNALS ON THE DOOR (ARCHITECT, Q128 gap): the hooks see each candidate as 1.5.5's
/// projection fed it: the pool member's tier and tags, the lane's latency signal once a sample is
/// recorded, its free concurrency, its remaining budget, and, where the generation declares them,
/// its breaker state, error rate and p95 latency in the routing pool. RED before: every one of them
/// was empty on the door path.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_hooks_see_each_candidates_standing() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-signals";
    let _published = Withdrawn(instance);
    let (a, b) = (
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(a.port, 1), (b.port, 1)],
            described: true,
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let first = rig.gate_saw();
    assert_eq!(first.len(), 2, "{first:?}");
    assert!(
        first[0].starts_with("m0 tier=Some(\"t0\") tags=[\"g0\"] latency=false avail=true"),
        "{first:?}"
    );
    assert!(
        first[0].contains("CandidateBreakerState=closed"),
        "the declared breaker state: {first:?}"
    );
    assert!(
        !first[0].contains("CandidateLatencyP95Ms"),
        "no p95 before a sample: {first:?}"
    );
    assert_eq!(rig.chat().await.0, 200);
    let second = rig.gate_saw();
    let second: Vec<String> = second
        .into_iter()
        .filter(|c| c.contains("latency=true"))
        .collect();
    assert!(
        !second.is_empty(),
        "the served attempt's latency sample: {second:?}"
    );
    assert!(
        second[0].contains("CandidateLatencyP95Ms=true")
            && second[0].contains("CandidateErrorRate=true"),
        "the p95 reservoir and the error rate, once fed: {second:?}"
    );
}

// ── what only the plane reads, the kernel routes on (ARCHITECT Q1 ArriveOut, 2026-10-05) ────────

/// A streamed far end's head: chunked, so a far end that closes before its last chunk CUT it.
#[cfg(linked_fold_on_driver)]
const STREAM_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                           transfer-encoding: chunked\r\nconnection: close\r\n\r\n";

/// The streamed answer's frames, in order: a delta, the stop, the usage, the end.
#[cfg(linked_fold_on_driver)]
const FRAMES: [&str; 4] = [
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#,
    "[DONE]",
];

/// One event-stream frame, as a chunk.
#[cfg(linked_fold_on_driver)]
fn frame(data: &str) -> Vec<u8> {
    chunk(format!("data: {data}\n\n").as_bytes())
}

/// A stream that pauses `pause_ms` after its first frame, then ends cleanly.
#[cfg(linked_fold_on_driver)]
fn stream_pausing(pause_ms: u64) -> Script {
    Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![
            (0, frame(FRAMES[0])),
            (pause_ms, frame(FRAMES[1])),
            (0, frame(FRAMES[2])),
            (0, frame(FRAMES[3])),
        ],
        finish: Some(b"0\r\n\r\n".to_vec()),
    }
}

/// A caller's chat on pool `p` asking for its answer streamed.
#[cfg(linked_fold_on_driver)]
fn streamed_chat() -> serde_json::Value {
    serde_json::json!({"model": "p", "stream": true, "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]})
}

/// THE STREAM CEILING, NOT THE POOL'S TIMEOUT, bounds a streamed answer (the plane states
/// `ROUTE_STREAM`; v1.5.5 bounded a stream's whole send by the stream ceiling): a stream that
/// outlives its pool's one-second failover timeout is delivered whole. Before the plane stated the
/// stream, the door cut it at the pool's timeout.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bounds_a_stream_by_the_stream_ceiling_not_the_pools_timeout() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-outlives-timeout";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(stream_pausing(2_000)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            failover_timeout_secs: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    let body = String::from_utf8_lossy(&body);
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("[DONE]") && body.contains("\"hi\""),
        "the stream outlived the pool's timeout whole: {body}"
    );
}

/// THE STREAM CEILING CUTS a streamed answer that outlives it, however long its pool's timeout
/// (RED before the plane stated `ROUTE_STREAM`: the door read the stream as buffered and waited the
/// pool's timeout out).
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_cuts_a_stream_at_the_stream_ceiling() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-ceiling";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(stream_pausing(4_000)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            failover_timeout_secs: Some(60),
            stream_ceiling_secs: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    let started = std::time::Instant::now();
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    let body = String::from_utf8_lossy(&body);
    assert_eq!(status, 200, "the stream had begun: {body}");
    assert!(
        body.contains("\"hi\""),
        "the first frame reached the caller: {body}"
    );
    assert!(!body.contains("[DONE]"), "the ceiling cut it: {body}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(3_500),
        "cut at the one-second ceiling, not when the far end ended: {:?}",
        started.elapsed()
    );
}

/// A MID-STREAM CUT IS NOT A REFUND (Part 2 #62): a streamed answer the far end cuts after its
/// first byte reached the caller keeps the member's lifetime budget unit it spent (RED before the
/// plane stated `ROUTE_STREAM`: the door refunded it as a buffered answer's).
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_the_budget_unit_of_a_stream_cut_after_its_first_byte() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-cut";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(0, frame(FRAMES[0])), (50, frame(FRAMES[1]))],
        finish: None,
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            lane_budget: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        rig.app.store.lane_budget_remaining(0),
        Some(4),
        "the streamed bytes were delivered: the unit is spent, not refunded"
    );
}

/// THE CONTROL: a buffered answer the far end cuts reaches the caller whole or not at all, so its
/// budget unit is given back (v1.5.5 `engine/mod.rs:329-353`).
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refunds_the_budget_unit_of_a_buffered_answer_cut() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-buffered-cut";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(Script {
        head: format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n",
            WHOLE.len()
        ),
        pieces: vec![(0, WHOLE.as_bytes()[..40].to_vec())],
        finish: None,
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            lane_budget: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    let _ = rig.chat().await;
    assert_eq!(rig.app.store.lane_budget_remaining(0), Some(5));
}

/// A whole same-dialect answer that reports 1500 + 90 tokens.
#[cfg(linked_fold_on_driver)]
const WHOLE: &str = r#"{"id":"chatcmpl-9","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hello there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1500,"completion_tokens":90,"total_tokens":1590}}"#;

/// A far end that answers [`WHOLE`] under its full length but writes only `prefix` of it, then
/// holds the connection `hold_ms` and closes (a cut).
#[cfg(linked_fold_on_driver)]
fn whole_cut_after(prefix: usize, hold_ms: u64) -> Script {
    Script {
        head: format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n",
            WHOLE.len()
        ),
        pieces: vec![
            (0, WHOLE.as_bytes()[..prefix].to_vec()),
            (hold_ms, Vec::new()),
        ],
        finish: None,
    }
}

/// OWNER RULING Q31, oracle cell `route.failover|fo|primary-cut-body` (legacy
/// `nonstream_drop_billing_tests`, rows 338/342): a same-dialect non-stream answer the far end cuts
/// AFTER its `usage` bills exactly what the far end reported; one cut BEFORE its `usage` reported
/// nothing and bills nothing, never a floor over the relayed bytes.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_a_cut_non_stream_answer_only_what_its_far_end_reported() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-nonstream-cut";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(whole_cut_after(WHOLE.len() - 1, 0)).await;
    let late = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let _ = late.chat().await;
    assert_eq!(late.tokens_after().await, 1590, "the far end's own report");
    drop(late);
    drop(_published);

    let instance = "serve-door-nonstream-cut-early";
    let _published = Withdrawn(instance);
    let usage_at = WHOLE.find(r#","usage""#).expect("the usage member");
    let far = far_end_scripted(whole_cut_after(usage_at, 0)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let _ = rig.chat().await;
    assert_eq!(rig.tokens_after().await, 0, "no report, no charge");
}

/// ITEM 367 (Q33 (a), told), legacy row 338: a same-dialect non-stream answer the CALLER drops
/// mid-relay was generated whole before its first byte, so it bills what it relayed: never 0.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_a_non_stream_answer_the_caller_dropped_mid_relay() {
    use http_body_util::BodyExt as _;
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-nonstream-drop";
    let _published = Withdrawn(instance);
    let usage_at = WHOLE.find(r#","usage""#).expect("the usage member");
    let far = far_end_scripted(whole_cut_after(usage_at, 5_000)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let response = rig
        .open(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]})),
            &[],
        )
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let mut body = response.into_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .expect("the first bytes arrive before the far end's hold")
        .expect("a frame")
        .expect("relayed");
    assert!(first.data_ref().is_some_and(|b| !b.is_empty()));
    // THE DISCONNECT: the caller goes before the answer's end.
    drop(body);
    // The driver finishes a buried unit at the start of its next one.
    let rig = std::sync::Arc::new(rig);
    let next = {
        let rig = std::sync::Arc::clone(&rig);
        tokio::spawn(async move { rig.chat().await })
    };
    assert_ne!(
        rig.tokens_after().await,
        0,
        "a non-stream answer dropped mid-relay never bills 0"
    );
    next.abort();
}

/// SESSION AFFINITY (legacy rows 2-4; v1.5.5 `affinity_header_for` and the sticky position): the
/// plane states the session key it reads (the pool's header, `x-session-id` by default, else chat's
/// body `system`) and the kernel pins every unit with that key to one member; a unit without one
/// is spread by the weighted floor.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_pins_a_session_to_one_member() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-affinity";
    let _published = Withdrawn(instance);
    let fars = [
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    ];
    let rig = rig(
        instance,
        RigOpts {
            members: &[(fars[0].port, 1), (fars[1].port, 1), (fars[2].port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let served = || fars.iter().map(|f| f.served()).collect::<Vec<_>>();
    let chat = serde_json::json!({"model": "p", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]});
    for _ in 0..6 {
        let r = rig
            .open(
                "POST",
                "/v1/chat/completions",
                Some(chat.clone()),
                &[("x-session-id", "session-42")],
            )
            .await;
        assert_eq!(r.status().as_u16(), 200);
        let _ = axum::body::to_bytes(r.into_body(), 1 << 20).await;
    }
    let pinned = served();
    assert_eq!(
        pinned.iter().filter(|n| **n == 6).count(),
        1,
        "one member served the whole session: {pinned:?}"
    );
    // The body's `system` is the key when no header names one.
    let system = serde_json::json!({"model": "p", "max_tokens": 16, "system": "be brief",
        "messages": [{"role": "user", "content": "hi"}]});
    let before = served();
    for _ in 0..3 {
        assert_eq!(
            rig.send("POST", "/v1/chat/completions", Some(system.clone()))
                .await
                .0,
            200
        );
    }
    let after = served();
    let moved: Vec<usize> = after.iter().zip(&before).map(|(a, b)| a - b).collect();
    assert_eq!(
        moved.iter().filter(|n| **n == 3).count(),
        1,
        "one member served the system-keyed session: {moved:?}"
    );
    // No key: the weighted floor spreads the units.
    let before = served();
    for _ in 0..3 {
        assert_eq!(rig.chat().await.0, 200);
    }
    let after = served();
    let moved = after.iter().zip(&before).filter(|(a, b)| a > b).count();
    assert!(moved >= 2, "unkeyed units spread: {before:?} -> {after:?}");
}

/// A POOL'S OWN AFFINITY HEADER (`affinity.header_name`) is the one its sessions are read from; the
/// default header is then no key.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_reads_a_session_from_the_pools_own_affinity_header() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-affinity-header";
    let _published = Withdrawn(instance);
    let fars = [
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    ];
    let rig = rig(
        instance,
        RigOpts {
            members: &[(fars[0].port, 1), (fars[1].port, 1), (fars[2].port, 1)],
            affinity_header: Some("x-user-id"),
            ..RigOpts::default()
        },
    )
    .await;
    let served = || fars.iter().map(|f| f.served()).collect::<Vec<_>>();
    let chat = serde_json::json!({"model": "p", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]});
    let send = |name: &'static str, value: &'static str| {
        let (rig, chat) = (&rig, chat.clone());
        async move {
            let r = rig
                .open("POST", "/v1/chat/completions", Some(chat), &[(name, value)])
                .await;
            assert_eq!(r.status().as_u16(), 200);
            let _ = axum::body::to_bytes(r.into_body(), 1 << 20).await;
        }
    };
    for _ in 0..4 {
        send("x-user-id", "user-7").await;
    }
    assert_eq!(
        served().iter().filter(|n| **n == 4).count(),
        1,
        "the pool's header pins: {:?}",
        served()
    );
    let before = served();
    for _ in 0..3 {
        send("x-session-id", "session-42").await;
    }
    let after = served();
    let moved = after.iter().zip(&before).filter(|(a, b)| a > b).count();
    assert!(
        moved >= 2,
        "the default header is not this pool's key: {before:?} -> {after:?}"
    );
}

// ── THE INBOUND RESPONSES WEBHOOK RECEIVER (new in 1.6.0; ARCHITECT Q2, 2026-10-06) ─────────────

/// A completed background turn's webhook body.
#[cfg(linked_fold_on_driver)]
const COMPLETED: &str = r#"{"id":"evt_abc123","type":"response.completed","created_at":1700000900,"data":{"id":"resp_xyz789"}}"#;

/// HMAC-SHA256 of `data` under `key` (RFC 2104 over the RustCrypto digest: an independent witness
/// of the plugin's own `ring` HMAC).
#[cfg(linked_fold_on_driver)]
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| block.iter().map(|k| k ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(data)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .to_vec()
}

/// The Standard Webhooks head for `body` sent as message `id` now, signed under `key`.
#[cfg(linked_fold_on_driver)]
fn signed_head(id: &str, key: &[u8], body: &str) -> Vec<(String, String)> {
    use base64::Engine as _;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock")
        .as_secs()
        .to_string();
    let signed = format!("{id}.{ts}.{body}");
    let sig = base64::engine::general_purpose::STANDARD.encode(hmac_sha256(key, signed.as_bytes()));
    vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("webhook-id".to_string(), id.to_string()),
        ("webhook-timestamp".to_string(), ts),
        ("webhook-signature".to_string(), format!("v1,{sig}")),
    ]
}

/// One unauthenticated POST of `body` to `path` with `head`: its status and body.
#[cfg(linked_fold_on_driver)]
async fn deliver(
    router: &axum::Router,
    path: &str,
    head: &[(String, String)],
    body: &str,
) -> (u16, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method("POST").uri(path);
    for (n, v) in head {
        req = req.header(n.as_str(), v.as_str());
    }
    let response = router
        .clone()
        .oneshot(
            req.body(axum::body::Body::from(body.to_string()))
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body")
        .to_vec();
    (status, bytes)
}

/// The receiver a configured rig's plane states: its one public route's target.
#[cfg(linked_fold_on_driver)]
fn receiver(rig: &super::hook_seat_tests::DoorRig) -> String {
    match rig.public_routes.as_slice() {
        [(verb, target)] if verb == "POST" => target.clone(),
        other => panic!("one public POST route: {other:?}"),
    }
}

/// CONFIGURED (the plane's owned webhook section, `openai.style: webhook-signature`): a delivery
/// signed under the scheme instance's secret is served by the plane's `serve` (the event
/// acknowledged with its correlation id); a missing signature, a wrong one and a replayed message
/// id are each 401, alike, and never reach the plane. RED without the kernel's verify: every
/// delivery would be served.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_webhook_receiver_serves_a_signed_delivery_once() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-webhook";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            webhook: true,
            ..RigOpts::default()
        },
    )
    .await;
    assert!(webhook_secret().starts_with("whsec_"));
    let path = receiver(&rig);
    let signed = signed_head("msg_1", WEBHOOK_KEY, COMPLETED);
    let (status, body) = deliver(&rig.router, &path, &signed, COMPLETED).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let ack: serde_json::Value = serde_json::from_slice(&body).expect("a JSON acknowledgement");
    assert_eq!(
        ack,
        serde_json::json!({"received": true, "response_id": "resp_xyz789", "type": "response.completed"})
    );
    // Missing: no signature header at all.
    let unsigned = vec![("content-type".to_string(), "application/json".to_string())];
    assert_eq!(
        deliver(&rig.router, &path, &unsigned, COMPLETED).await,
        (401, Vec::new())
    );
    // Wrong: signed under another key.
    let forged = signed_head("msg_2", b"another-key", COMPLETED);
    assert_eq!(
        deliver(&rig.router, &path, &forged, COMPLETED).await,
        (401, Vec::new())
    );
    // Replayed: the first message id again, freshly and correctly signed.
    let replay = signed_head("msg_1", WEBHOOK_KEY, COMPLETED);
    assert_eq!(
        deliver(&rig.router, &path, &replay, COMPLETED).await,
        (401, Vec::new())
    );
    assert_eq!(far.served(), 0, "a webhook reaches no member");
    // ANTI-ENUMERATION (Q88): the answer is a pure function of the delivery, never of what busbar
    // holds. A response id busbar never saw and one from another caller are answered exactly as any
    // other: the same status, and the same body but for the id the sender itself sent back.
    let mut answers = Vec::new();
    for (n, id) in ["resp_xyz789", "resp_never_issued", "resp_another_tenants"]
        .into_iter()
        .enumerate()
    {
        let body = COMPLETED.replace("resp_xyz789", id);
        let head = signed_head(&format!("msg_anti_{n}"), WEBHOOK_KEY, &body);
        let (status, ack) = deliver(&rig.router, &path, &head, &body).await;
        answers.push((status, String::from_utf8_lossy(&ack).replace(id, "<id>")));
    }
    assert!(
        answers.windows(2).all(|w| w[0] == w[1]),
        "known, unknown and foreign ids answer alike: {answers:?}"
    );
    assert_eq!(answers[0].0, 200);
    assert_eq!(far.served(), 0, "no lookup reached a far end");
}

/// UNCONFIGURED: with no owned webhook section the plane states no public route, so the path
/// answers as 1.5.5's did (an unkeyed caller the data auth gate's 401, a keyed caller the fallback's
/// not-found), and a signed delivery is never served. 1.5.5 refuses the section's key at boot, so
/// every configuration 1.5.5 accepts is this one.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfigured_webhook_receiver_states_no_route() {
    let _one = ONE_PUBLISHER.lock().await;
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let path = {
        let instance = "serve-door-webhook-path";
        let _published = Withdrawn(instance);
        let configured = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                webhook: true,
                ..RigOpts::default()
            },
        )
        .await;
        receiver(&configured)
    };
    let instance = "serve-door-webhook-absent";
    let _published = Withdrawn(instance);
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert!(rig.public_routes.is_empty(), "no route stated");
    let signed = signed_head("msg_1", WEBHOOK_KEY, COMPLETED);
    let (status, _) = deliver(&rig.router, &path, &signed, COMPLETED).await;
    assert_eq!(
        status, 401,
        "no receiver answers: an unkeyed caller meets the data auth gate, as 1.5.5's did"
    );
    let keyed = rig
        .send(
            "POST",
            &path,
            Some(serde_json::from_str(COMPLETED).expect("json")),
        )
        .await;
    assert_eq!(
        keyed.0,
        404,
        "the fallback's not-found: {}",
        String::from_utf8_lossy(&keyed.2)
    );
}

/// A ROUTE WHOSE SCHEME NO INSTANCE SERVES refuses the boot, naming the route and the scheme; one
/// `identity-providers:` entry whose module serves the scheme admits it; an unconfigured receiver
/// names no scheme to check.
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_webhook_scheme_no_identity_provider_serves_refuses_the_boot() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-webhook-unserved";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_BY_TWIN).await;
    let configured = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            webhook: true,
            ..RigOpts::default()
        },
    )
    .await;
    let refused = configured
        .scheme_check
        .0
        .clone()
        .expect_err("no instance serves the scheme");
    let route = format!("POST {}", receiver(&configured));
    assert!(
        refused.contains(&route) && refused.contains("'webhook-signature'"),
        "{refused}"
    );
    assert_eq!(
        configured.scheme_check.1,
        Ok(()),
        "an entry serving it admits it"
    );
    drop(configured);
    drop(_published);
    let instance = "serve-door-webhook-unserved-absent";
    let _published = Withdrawn(instance);
    let absent = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(
        absent.scheme_check.0,
        Ok(()),
        "no receiver, no scheme to serve"
    );
}

/// A STREAM THE CALLER LEAVES MID-RELAY BILLS WHAT ITS READERS COUNTED (1.5.5's drop arm: "only the
/// streaming reader's usage is consulted"): a same-dialect stream whose far end reported its input
/// usage in its opening frame bills it when the caller goes after the first bytes, never 0 (the
/// plane's cancel answers OK_PARTIAL and the reader's running counts are its checkpoint).
#[cfg(linked_fold_on_driver)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_a_stream_the_caller_dropped_what_its_readers_counted() {
    use http_body_util::BodyExt as _;
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-drop";
    let _published = Withdrawn(instance);
    let start = r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"m0","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"output_tokens":1}}}"#;
    let block =
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#;
    let delta =
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}"#;
    let event =
        |name: &str, data: &str| chunk(format!("event: {name}\ndata: {data}\n\n").as_bytes());
    let far = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![
            (0, event("message_start", start)),
            (0, event("content_block_start", block)),
            (0, event("content_block_delta", delta)),
            (5_000, Vec::new()),
        ],
        finish: None,
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let response = rig
        .open(
            "POST",
            "/v1/messages",
            Some(
                serde_json::json!({"model": "p", "max_tokens": 16, "stream": true,
                "messages": [{"role": "user", "content": "hi"}]}),
            ),
            &[("anthropic-version", "2023-06-01")],
        )
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let mut body = response.into_body();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .expect("the first frames arrive before the far end's hold")
        .expect("a frame")
        .expect("relayed");
    assert!(first.data_ref().is_some_and(|b| !b.is_empty()));
    drop(body);
    let rig = std::sync::Arc::new(rig);
    let next = {
        let rig = std::sync::Arc::clone(&rig);
        tokio::spawn(async move { rig.chat().await })
    };
    assert_ne!(
        rig.tokens_after().await,
        0,
        "the reader counted the far end's input usage before the caller left"
    );
    next.abort();
}
