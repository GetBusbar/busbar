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
use super::{compose_planes, door_routes, DoorEgress};
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
            conns: Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
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
        Some(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
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
            conns: None,
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
            conns: None,
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

// ── THE DOOR SERVING THE `pools` MAP: ITS CAPABILITY CELLS (Q128 U14) ───────────────────────────
//
// The capability-equality matrix's root column for this plane, witnessed on its door path: each
// cell below drives a keyed caller through the data router built with the door's claims, the
// kernel's hook stage, the model-serving walk over the kernel's lane cells and the node's book
// (`super::hook_seat_tests::rig`), and reads the capability where the kernel keeps it.

#[cfg(linked_fold_on_driver)]
use super::hook_seat_tests::{far_end_answering, rig, RigOpts, REWRITTEN};
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
