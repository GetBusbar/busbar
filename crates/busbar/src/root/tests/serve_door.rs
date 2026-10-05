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
//!
//! THE STREAMING DOOR, the same way (the `root-voice` leg of qa/capability-equality.json, ARCHITECT
//! 2026-10-05 Q1): the browser's ephemeral-secret mint, claimed by the streaming plane's door, served
//! end to end — a keyed caller, the door's DIRECT route to the top-level catalog model
//! `streams.session.model` names, the provider's own credential presented by the auth plugin, the
//! caller's spend posted against the key that presented it.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_contract::caps::ReasonCode;
use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
#[cfg(feature = "plane-decisions")]
use busbar_kernel::governance::PLANE_LANE_SEP;
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
#[cfg(feature = "plane-decisions")]
use busbar_plane_decisions::plane_door::door as decisions_door;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::{composed_services, money, Published, PUBLISHING};
use super::{compose_planes, door_routes, DoorEgress};
use crate::root::door_steps::{provider_routes, DoorReach, OutboundAuths};
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

/// The decisions plane's one claim, with one model configured.
#[cfg(feature = "plane-decisions")]
const CLAIMED: &str = "/v1/systemone";

/// The provider's credential, as its file holds it.
const CREDENTIAL: &str = "sk-door-test";

/// The far end's answer: a decision, and the one unit it reports using.
#[cfg(feature = "plane-decisions")]
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

/// A POST of the caller's decision state to `path` on `router`, with `token` as its bearer or with
/// none: the response.
#[cfg(feature = "plane-decisions")]
async fn send(router: &axum::Router, path: &str, token: Option<&str>) -> axum::response::Response {
    send_body(router, path, token, r#"{"state":{"amount":7}}"#).await
}

/// A POST of `body` (JSON) to `path` on `router`, with `token` as its bearer or with none.
async fn send_body(
    router: &axum::Router,
    path: &str,
    token: Option<&str>,
    body: &'static str,
) -> axum::response::Response {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req.body(axum::body::Body::from(body)).expect("a request");
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
    far_end_answering(ANSWER).await
}

/// A far end on loopback answering every request 200 with `answer` (JSON); what it was sent comes
/// back on the channel, one request (head and body) per connection.
async fn far_end_answering(
    answer: &'static str,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
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
                     connection: close\r\n\r\n{answer}",
                    answer.len()
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
#[cfg(feature = "plane-decisions")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        catalog: None,
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
#[cfg(feature = "plane-decisions")]
#[tokio::test]
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
#[cfg(feature = "plane-decisions")]
#[tokio::test]
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

/// The streaming door's mint claim.
#[cfg(feature = "plane-streaming")]
const MINT: &str = "/v1/realtime/client_secrets";

/// The provider's answer to the mint: an ephemeral secret and its expiry.
#[cfg(feature = "plane-streaming")]
const MINTED: &str = r#"{"value":"ek_door_0001","expires_at":1767225600}"#;

/// The deployment's public base URL the streaming door fronts.
#[cfg(feature = "plane-streaming")]
const PUBLIC: &str = "http://gw.test";

/// The streaming door, served as production composes it, and what each `root-voice` cell reads.
#[cfg(feature = "plane-streaming")]
struct Streaming {
    _published: Published,
    router: axum::Router,
    heard: tokio::sync::mpsc::UnboundedReceiver<String>,
    gov: Arc<GovState>,
    app: Arc<busbar_kernel::state::App>,
    key: busbar_contract::records::VirtualKey,
    /// The key's data-plane token.
    plain: String,
    money: Arc<PlaneMoney>,
    post: Arc<NodeEndPost>,
    book: crate::root::durability::NodeBook,
}

/// [`Streaming`]: the linked streaming door bound through the loader's one load, its needs declared
/// on the connector over every linked transport door; a signing governance book with one key (in a
/// group whose all-time budget is `budget`, the door's per-request fee one, or no group and no fee);
/// an OpenAI-protocol provider on a loopback far end answering the mint, reached through the catalog
/// model `streams.session.model` names; the door composed under [`PUBLIC`] with its egress sealed by
/// the composition itself, and its claims mounted on the data router.
#[cfg(feature = "plane-streaming")]
async fn streaming(instance: &'static str, budget: Option<u64>) -> Streaming {
    use busbar_plane_streaming::door::{door as streaming_door, NAME as PLANE};

    let published = Published(instance);
    let (port, heard) = far_end_answering(MINTED).await;
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
    let row = LinkedRow::of(streaming_door).expect("the door states its Statement");
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
                PLANE.to_string(),
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
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (key, plain) = gov
        .mint_signed(
            NewKeySpec {
                name: "browser".to_string(),
                group: groups.keys().next().cloned(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    let node = Arc::new(Node::new());
    let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
    node.bind_book(Arc::clone(&book.durability));
    let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
    let money = Arc::new(PlaneMoney::new(
        Arc::clone(&gov),
        Arc::clone(&post) as Arc<dyn EndPost>,
    ));
    let one = Arc::clone(&money);

    let key_file = std::env::temp_dir().join(format!(
        "busbar-serve-door-{instance}-{}",
        std::process::id()
    ));
    std::fs::write(&key_file, CREDENTIAL).expect("the credential file");
    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(&format!(
        "{{protocol: openai, base_url: 'http://127.0.0.1:{port}', api_key: {{file: '{}'}}, error_map: {{}}}}",
        key_file.display()
    ))
    .expect("a provider entry");
    let providers = provider_routes(&std::collections::HashMap::from([(
        "p".to_string(),
        provider,
    )]));
    let catalog: std::collections::HashMap<String, busbar_contract::config::ModelCfg> =
        serde_yaml::from_str("{m-cap: {provider: p}}").expect("the models catalog");
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
        catalog: Some(&catalog),
        upgrades: Vec::new(),
    };
    let mut sections = BTreeMap::new();
    sections.insert(
        section_key,
        serde_yaml::from_str("session: {model: m-cap}").expect("a section"),
    );
    let mut served = compose_planes(
        &[(instance.to_string(), plane)],
        &dispatcher,
        &composed_services(),
        &sections,
        Some(PUBLIC),
        &move || Arc::clone(&one),
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        None,
    )
    .expect("the streaming door composes, its egress sealed");
    let _ = std::fs::remove_file(&key_file);
    assert!(
        served.planes[0].live.current().egress.is_some(),
        "the composition sealed its egress"
    );
    served.post = Some(Arc::clone(&post));
    let app = busbar_kernel::test_support::TestApp::new().keys_chain();
    let app = groups
        .iter()
        .fold(app, |app, (name, cfg)| app.group(name, cfg.clone()));
    let app = app.governance(Arc::clone(&gov)).cost(cost).build();
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
    Streaming {
        _published: published,
        router,
        heard,
        gov,
        app,
        key,
        plain: plain.expose_secret().clone(),
        money,
        post,
        book,
    }
}

#[cfg(feature = "plane-streaming")]
impl Streaming {
    /// The requests the governance book admitted for the key, this window.
    fn requests(&self) -> u64 {
        self.gov
            .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists")
            .requests
    }

    /// The node book's lines for the streaming door's catalog route.
    fn lines(&self) -> usize {
        let rows = self.book.durability.lock().expect("unpoisoned").read_back();
        rows.iter()
            .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane.ends_with("m-cap")))
            .count()
    }
}

/// THE STREAMING DOOR'S MINT, SERVED (the `root-voice` leg, ARCHITECT 2026-10-05 Q1): a keyed
/// caller's `POST /v1/realtime/client_secrets` is one unit the door carries (ARRIVAL), admitted for
/// the key its token resolves (AUTHENTICATE), dialled to the destination the guard judged (VERIFY) on
/// the DIRECT route to the catalog model `streams.session.model` names (ROUTE), sent WITH THE
/// PROVIDER'S OWN CREDENTIAL and never the caller's token (EGRESS-AUTH), charged to the key that
/// presented it (METER, GOVERNANCE-BUDGET), and closed once with its one line on the node's book
/// (AUDIT, EXIT). (The door's audience binding is the deployment's mount table's, judged end to end
/// by the `streams|mint|wrong-audience` oracle cell.)
///
/// RED ARM: the same request with no credential is refused before anything is dialled or charged.
#[cfg(feature = "plane-streaming")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streaming_mint_is_served_through_the_door_under_the_providers_credential() {
    let _one = PUBLISHING.lock().await;
    let mut s = streaming("serve-door-streaming", None).await;

    let refused = send_body(&s.router, MINT, None, "{}").await;
    assert_eq!(
        refused.status().as_u16(),
        u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status"),
        "an unkeyed caller is refused at the streaming door"
    );
    assert!(s.heard.try_recv().is_err(), "nothing was dialled for it");
    assert_eq!(s.requests(), 0, "nor charged");

    let response = send_body(&s.router, MINT, Some(&s.plain), "{}").await;
    assert_eq!(response.status(), StatusCode::OK, "served through the door");
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("the door's JSON");
    assert_eq!(
        body,
        serde_json::json!({"value": "ek_door_0001", "expires_at_unix": 1_767_225_600_u64}),
        "the minted secret and its expiry"
    );

    let head = s.heard.recv().await.expect("the provider was dialled");
    assert!(head.starts_with(&format!("POST {MINT} ")), "{head}");
    assert!(
        head.lines()
            .any(|l| l.eq_ignore_ascii_case(&format!("authorization: Bearer {CREDENTIAL}"))),
        "the provider's own credential: {head}"
    );
    assert!(
        !head.contains(&s.plain),
        "the caller's token never reaches the provider: {head}"
    );
    assert!(
        head.contains(r#""model":"m-cap""#),
        "the locked session on the catalog model: {head}"
    );

    assert_eq!(
        s.requests(),
        1,
        "one admitted request, on the presenting key"
    );
    assert_eq!(s.money.open_units(), 0, "its money facts closed");
    assert_eq!(s.post.open_units(), 0, "its node facts closed");
    assert_eq!(s.lines(), 1, "its one line on the node's book");
}

/// ADMIT, at the streaming door (`root-voice`): a key whose group budget is already spent is refused
/// at admission — over budget, before the provider is dialled, charged nothing, no line written —
/// while a key with room is served (the mint cell above). RED: a door that dialled before admission
/// would have reached the far end.
#[cfg(feature = "plane-streaming")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_key_is_refused_at_the_streaming_door_before_any_dial() {
    let _one = PUBLISHING.lock().await;
    let mut s = streaming("serve-door-streaming-spent", Some(0)).await;
    let response = send_body(&s.router, MINT, Some(&s.plain), "{}").await;
    assert_eq!(
        response.status().as_u16(),
        429,
        "an over-budget caller is refused at admission"
    );
    assert!(
        s.heard.try_recv().is_err(),
        "the provider was never dialled"
    );
    assert_eq!(s.requests(), 0, "the refusal charged nothing");
    assert_eq!(s.money.open_units(), 0);
    assert_eq!(s.post.open_units(), 0);
    assert_eq!(s.lines(), 0, "no line on the node's book");
}
