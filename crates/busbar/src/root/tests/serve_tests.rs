// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA ROUTE, SERVED END TO END (SERVE-WIRE step 33): a request the decisions
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
//! The `mcp` module below is the `root-mcp` leg's loop cells (`qa/capability-equality.json`, U14):
//! the MCP plane's door, composed here the same way, each core capability driven through the data
//! router and asserted where it lands.
//!
//! The `session_door` module below is the session door's root-leg cells (ARCHITECT 2026-10-05 Q1):
//! the linked plane door that meters audio, served end to end the same way.

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

#[cfg(feature = "plane-decisions")]
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

#[cfg(feature = "plane-decisions")]
/// The decisions plane's one claim, with one model configured.
pub(super) const CLAIMED: &str = "/v1/systemone";

#[cfg(feature = "plane-decisions")]
/// The provider's credential, as its file holds it.
const CREDENTIAL: &str = "sk-door-test";

#[cfg(feature = "plane-decisions")]
/// The far end's answer: a decision, and the one unit it reports using.
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

#[cfg(feature = "plane-decisions")]
/// A far end's transient failure, as [`far_end_failing_first`] answers it.
const UNAVAILABLE: &str = r#"{"error":"unavailable"}"#;

#[cfg(feature = "plane-decisions")]
/// A POST of the caller's decision state to `path` on `router`, with `token` as its bearer or with
/// none: the response.
pub(super) async fn send(
    router: &axum::Router,
    path: &str,
    token: Option<&str>,
) -> axum::response::Response {
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

#[cfg(feature = "plane-decisions")]
/// A far end on loopback answering every request with [`ANSWER`]; what it was sent comes back on
/// the channel, one request head per connection.
pub(super) async fn far_end() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_failing_first(0).await
}

#[cfg(feature = "plane-decisions")]
/// [`far_end`], but its first `failures` connections are answered with a bare transient failure
/// (503, no `Retry-After`) instead of [`ANSWER`].
async fn far_end_failing_first(
    failures: usize,
) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_answering(Arc::new(move |n| {
        if n < failures {
            Answer::Says("503 Service Unavailable", UNAVAILABLE)
        } else {
            Answer::Says("200 OK", ANSWER)
        }
    }))
    .await
}

#[cfg(feature = "plane-decisions")]
/// How the far end answers one connection.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// A status line and a JSON body.
    Says(&'static str, &'static str),
    /// Nothing: the request is read and the connection held open, unanswered.
    Holds,
}

#[cfg(feature = "plane-decisions")]
/// How the far end answers its `n`th connection (from zero).
type Script = Arc<dyn Fn(usize) -> Answer + Send + Sync>;

#[cfg(feature = "plane-decisions")]
/// A far end on loopback answering its `n`th connection as `script` says; what it was sent comes
/// back on the channel, one request head per connection, before it answers.
async fn far_end_answering(script: Script) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut accepted = 0usize;
        while let Ok((mut socket, _)) = listener.accept().await {
            let answer = script(accepted);
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
                let (line, body) = match answer {
                    Answer::Says(line, body) => (line, body),
                    Answer::Holds => {
                        // Held past any bound a test waits for; the socket closes with the task.
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                        return;
                    }
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

#[cfg(feature = "plane-decisions")]
/// THE EXIT TEST: a keyed caller's claimed request is SERVED through the decisions door, 200, the
/// far end's answer relayed as it came, and the unit's money posted on both books.
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
    let connector = busbar_core_connector::process::build_with_secrets(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_kernel::config::secret::resolve_linked_string_at_config,
    )
    .expect("the connector builds");

    // THE DECISIONS DOOR, linked, bound through the loader's one load, its need declared on the
    // connector.
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = Arc::new(
        load_linked::<Plane>(
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
        .expect("the linked door binds"),
    );
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
        plane.served().dialects[0],
        key_file.display()
    ))
    .expect("a provider entry");
    let providers = provider_routes(
        &std::collections::HashMap::from([(
            "typesafe".to_string(),
            busbar_kernel::config::ResolvedProvider::from(provider),
        )]),
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
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
        secrets: Arc::clone(&secrets),
        auths: Arc::new(auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        catalog: None,
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
    let response = send(
        &router,
        CLAIMED,
        Some(token.expose(&busbar_kernel::seal::lend())),
    )
    .await;
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
        !head.contains(token.expose(&busbar_kernel::seal::lend())),
        "the caller's own credential never reaches the far end: {head}"
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

#[cfg(feature = "plane-decisions")]
/// THE MOUNT: the door's claim is a route on the data router only when the router is built with
/// it; a path the door does not claim is the router's own. An unkeyed caller on the door's claim (it
/// takes a credential) is refused before anything is charged, rendered by the plane.
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
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = Arc::new(
        load_linked::<Plane>(
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
        .expect("the linked door binds"),
    );
    let section = plane.served().section;
    let mut sections = BTreeMap::new();
    // Composed with no egress, the host states no provider's protocol at open, so the model states
    // its own (`protocol:` override, #51): the plane refuses a model whose dialect nothing states.
    sections.insert(
        section,
        serde_yaml::from_str(&format!(
            "models: {{m: {{provider: typesafe, protocol: {}}}}}",
            plane.served().dialects[0]
        ))
        .expect("a section"),
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

#[cfg(feature = "plane-decisions")]
/// ONE MOUNT PER (PATH, METHOD) (SEAM-L(l), ported from 5ad225bc89): a door claiming one verb and
/// path over two carriers (an endpoint answered as a document or as an event stream) is one route
/// on the data listener, the first in its claim order; the data router builds with it. RED: each
/// claim mounted its own route, and the router refused the second as an overlapping method route.
#[tokio::test]
async fn a_door_claiming_one_path_over_two_carriers_mounts_it_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-carriers";
    let _published = Published(instance);
    let app = busbar_kernel::test_support::TestApp::new().build();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = Arc::new(
        load_linked::<Plane>(
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
        .expect("the linked door binds"),
    );
    let section = plane.served().section;
    let mut sections = BTreeMap::new();
    // Composed with no egress, the host states no provider's protocol at open, so the model states
    // its own (`protocol:` override, #51): the plane refuses a model whose dialect nothing states.
    sections.insert(
        section,
        serde_yaml::from_str(&format!(
            "models: {{m: {{provider: typesafe, protocol: {}}}}}",
            plane.served().dialects[0]
        ))
        .expect("a section"),
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

/// THE SESSION DOOR'S ROOT-LEG CELLS (ARCHITECT 2026-10-05 Q1): the session door, served as
/// production composes it — the browser's ephemeral-secret mint, a keyed caller, the door's DIRECT
/// route to the top-level catalog model its section's `session.model` names, the provider's own
/// credential presented by the auth plugin, the caller's spend posted against the key that
/// presented it. The door is found among the linked plane doors by the audio class it meters; the
/// module is compiled where the build links that door, and there a door not found is a failure,
/// never a skip. The secret-source scan (`secret_source.rs`) drives the same door.
#[cfg(linked_section_streams)]
pub(super) mod session_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
    use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::root::door_steps::{provider_routes, DoorReach, OutboundAuths};
    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::root::plane_node::{Node, NodeEndPost};
    use crate::root::serve::planes_tests::{composed_services, Published, PUBLISHING};
    use crate::root::serve::{compose_planes, DoorEgress};

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

    /// The provider's credential, as its file holds it.
    const CREDENTIAL: &str = "sk-door-test";

    /// The session door's mint claim.
    const MINT: &str = "/v1/realtime/client_secrets";

    /// The session door's sideband claim: an upgrade line that attaches to a call the SDP door
    /// placed for the same caller, and to no other (ARCHITECT ruling 2026-10-23 on Part 2 #45).
    const SIDEBAND: &str = "/v1/realtime/sideband/{call_id}";

    /// The session door's plain OpenAI Realtime socket, as a caller opens it: a WS upgrade on
    /// `GET /v1/realtime`, its `?model=` on the query, a session attached to no call (ARCHITECT
    /// ruling 2026-10-23 on Part 2 #45: plain server-to-server OpenAI Realtime over WS is its own
    /// door, not the sideband).
    const REALTIME: &str = "/v1/realtime?model=m-cap";

    /// The provider's answer to the mint: an ephemeral secret and its expiry.
    const MINTED: &str = r#"{"value":"ek_door_0001","expires_at":1767225600}"#;

    /// The deployment's public base URL the session door fronts.
    const PUBLIC: &str = "http://gw.test";

    /// The billable class the session door meters a caller's audio under: how the harness finds that
    /// door among the linked plane doors without spelling the plane.
    const AUDIO_CLASS: &str = "audio_seconds_in";

    /// A POST of `body` (JSON) to `path` on `router`, with `token` as its bearer or with none,
    /// answered within [`ANSWER_BOUND`]: a door that held a call at its provider fails the cell
    /// instead of holding the job.
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
        tokio::time::timeout(ANSWER_BOUND, router.clone().oneshot(req))
            .await
            .unwrap_or_else(|_| panic!("the door answers {path} within {ANSWER_BOUND:?}"))
            .expect("the router answers")
    }

    /// How long a cell waits on a door's answer, or on the bytes of its body, before it fails.
    const ANSWER_BOUND: std::time::Duration = std::time::Duration::from_secs(15);

    /// `response`'s body, read to its end within [`ANSWER_BOUND`].
    async fn body_of(response: axum::response::Response) -> axum::body::Bytes {
        tokio::time::timeout(
            ANSWER_BOUND,
            axum::body::to_bytes(response.into_body(), 1 << 16),
        )
        .await
        .expect("the body ends within the bound")
        .expect("the body")
    }

    /// How the far end answers one connection.
    #[derive(Debug, Clone, Copy)]
    enum Far {
        /// A status line and a JSON body.
        Says(&'static str, &'static str),
        /// Nothing: the request is read and the connection held open, unanswered.
        Holds,
    }

    /// How the far end answers its `n`th connection (from zero).
    type FarScript = Arc<dyn Fn(usize) -> Far + Send + Sync>;

    /// A far end on loopback answering every request 200 with `answer` (JSON); what it was sent comes
    /// back on the channel, one request (head and body) per connection.
    async fn far_end_answering(
        answer: &'static str,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end_scripted(Arc::new(move |_| Far::Says("200 OK", answer))).await
    }

    /// A far end on loopback answering its `n`th connection as `script` says; what it was sent comes
    /// back on the channel, one request (head and body) per connection, before it answers.
    async fn far_end_scripted(
        script: FarScript,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut accepted = 0usize;
            while let Ok((mut socket, _)) = listener.accept().await {
                let answer = script(accepted);
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
                    let (line, body) = match answer {
                        Far::Says(line, body) => (line, body),
                        Far::Holds => {
                            // Held past any bound a test waits for; the socket closes with the task.
                            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                            return;
                        }
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

    /// The env whose `test-hook` is the kernel's in-process hook double (`prompt: rw`, `user: ro`):
    /// its `settings:` choose its answer.
    fn hook_env() -> busbar_kernel::hooks::HookEnv {
        busbar_kernel::test_support::test_hook_env(
            &["test-hook"],
            busbar_kernel::test_support::HookNeeds {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro,
            },
        )
    }

    /// A deployment-wide `kind: gate` on the in-process hook double, answering `reply` to every
    /// decision it is asked for.
    fn global_gate(reply: serde_json::Value) -> busbar_kernel::config::HookCfg {
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": "test-hook",
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": "ro",
            "user": "ro",
            "priority": 0,
            "settings": { "raw_decide_reply": reply },
            "global": true,
            "default": false,
            "signals": [],
            "groups": [],
            "phase": [],
        }))
        .expect("a hook document")
    }

    /// The session door, served as production composes it, and what each root-leg cell reads.
    pub(in crate::root::serve) struct SessionDoor {
        _published: Published,
        router: axum::Router,
        heard: tokio::sync::mpsc::UnboundedReceiver<String>,
        gov: Arc<GovState>,
        pub(in crate::root::serve) app: Arc<busbar_kernel::state::App>,
        key: busbar_contract::records::VirtualKey,
        /// The key's data-plane token.
        plain: String,
        /// What a config apply refreshes the served door onto (`DoorApply::apply`).
        pub(in crate::root::serve) live: Arc<crate::root::serve::DoorApply>,
        money: Arc<PlaneMoney>,
        post: Arc<NodeEndPost>,
        book: crate::root::durability::NodeBook,
    }

    /// How a cell composes the session door beyond the defaults ([`session_with`]).
    #[derive(Default)]
    struct Opts {
        /// The caller's group's all-time budget, with the door's per-request fee one; `None` = no
        /// budget and no fee.
        budget: Option<u64>,
        /// Further limits on the caller's group (a group is made for them when there is none).
        limits: Vec<busbar_kernel::config::groups::LimitCfg>,
        /// The pools the caller's key is minted with; `None` = every pool.
        allowed_pools: Option<Vec<String>>,
        /// How the provider answers; `None` = every mint answered 200 with [`MINTED`].
        far: Option<FarScript>,
        /// Hooks the deployment defines, each `global` (run on every plane's units), with the hook
        /// stage composed over the generation; empty = no hook stage.
        hooks: Vec<(&'static str, busbar_kernel::config::HookCfg)>,
        /// A provider the cell started itself (its port, and what it reports hearing), in place of
        /// the scripted one.
        far_end: Option<(u16, tokio::sync::mpsc::UnboundedReceiver<String>)>,
        /// The provider's wire name for the catalog model the section's `session.model` names
        /// (`upstream_model`, Part 2 #51), written in the deployment's `models:` as production
        /// writes it; `None` = the catalog name is the wire name.
        upstream_model: Option<&'static str>,
    }

    /// The linked plane door that meters audio (the session door), bound under `instance`; `None` in
    /// a build that links none.
    fn session_door(
        instance: &'static str,
        dispatcher: &Arc<Dispatcher>,
        conns: Arc<dyn DeclaredConns>,
    ) -> Option<crate::root::loader::dispatch::Plugin<Plane>> {
        crate::LINKED.plane_doors.iter().find_map(|door| {
            let row = LinkedRow::of(*door).expect("the door states its Statement");
            let plane = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: crate::root::loader::dispatch::ConnTable::Host(Arc::clone(&conns)),
                },
            )
            .expect("the linked door binds");
            plane
                .served()
                .billable_classes
                .contains(&AUDIO_CLASS)
                .then_some(plane)
        })
    }

    /// The process's connector over every linked transport door, its destination guard letting
    /// the loopback far end through.
    fn connector() -> Arc<busbar_core_connector::Connector> {
        let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
            block_private_addresses: false,
            ..Default::default()
        })
        .expect("the guard");
        busbar_core_connector::process::build_with_secrets(
            || {
                crate::root::connector::entries(
                    crate::LINKED_TRANSPORT_DOORS,
                    &busbar_contract::transport::TransportSettings::default(),
                )
            },
            judge,
            &[],
            Arc::new(|_, _| {}),
            busbar_core_connector::pool::PoolPosture::NONE,
            busbar_kernel::config::secret::resolve_linked_string_at_config,
        )
        .expect("the connector builds")
    }

    /// The linked session door's Statement name (the plane door that meters audio, bound only to
    /// read it); `None` in a build that links none. It holds the publishing lock, so it is called
    /// outside a runtime.
    pub(in crate::root::serve) fn name() -> Option<String> {
        let _one = PUBLISHING.blocking_lock();
        let instance = "session-door-name";
        let _published = Published(instance);
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        session_door(instance, &dispatcher, connector() as Arc<dyn DeclaredConns>)
            .map(|plane| plane.name().to_owned())
    }

    /// [`session_keyed`] over a provider credential its file holds; the composition must succeed.
    async fn session_served(instance: &'static str, budget: Option<u64>) -> Option<SessionDoor> {
        session_with(
            instance,
            Opts {
                budget,
                ..Opts::default()
            },
        )
        .await
    }

    /// [`session_composed`] under `opts`, over a provider credential its file holds; the composition
    /// must succeed.
    async fn session_with(instance: &'static str, opts: Opts) -> Option<SessionDoor> {
        let key_file = std::env::temp_dir().join(format!(
            "busbar-serve-door-{instance}-{}",
            std::process::id()
        ));
        std::fs::write(&key_file, CREDENTIAL).expect("the credential file");
        let api_key = format!("{{file: '{}'}}", key_file.display());
        let served = session_composed(instance, opts, &api_key).await;
        let _ = std::fs::remove_file(&key_file);
        served.map(|s| {
            s.unwrap_or_else(|e| panic!("the session door composes, its egress sealed: {e}"))
        })
    }

    /// [`session_composed`] with the defaults but `budget`.
    pub(in crate::root::serve) async fn session_keyed(
        instance: &'static str,
        budget: Option<u64>,
        api_key: &str,
    ) -> Option<Result<SessionDoor, String>> {
        session_composed(
            instance,
            Opts {
                budget,
                ..Opts::default()
            },
            api_key,
        )
        .await
    }

    /// [`SessionDoor`]: the linked session door (the plane door that meters audio) bound through
    /// the loader's one load, its needs declared on the connector over every linked transport door;
    /// a signing governance book with one key (in a group whose all-time budget is `budget`, the
    /// door's per-request fee one, or no group and no fee); a provider on the protocol the door
    /// states a bearer default for, its credential the secret reference `api_key` (YAML), on a
    /// loopback far end answering the mint, reached through the catalog model its section's
    /// `session.model` names; the door composed under [`PUBLIC`] with its egress sealed by the
    /// composition itself, and its claims mounted on the data router. `None` in a build that links
    /// no session door; the composition's refusal is answered rather than panicked on: what the
    /// root's boot dies on.
    async fn session_composed(
        instance: &'static str,
        opts: Opts,
        api_key: &str,
    ) -> Option<Result<SessionDoor, String>> {
        // The scrape's `/metrics` is mounted on a test app built with the recorder installed.
        busbar_kernel::snapshot::init();
        let budget = opts.budget;
        let published = Published(instance);
        let (port, heard) = match (opts.far_end, opts.far) {
            (Some(far_end), _) => far_end,
            (None, Some(script)) => far_end_scripted(script).await,
            (None, None) => far_end_answering(MINTED).await,
        };
        let connector = connector();
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plane = session_door(
            instance,
            &dispatcher,
            Arc::clone(&connector) as Arc<dyn DeclaredConns>,
        )?;
        let plane_name = plane.name().to_owned();
        let section_key = plane.served().section;
        // THE PROVIDER'S PROTOCOL, read off the door's Statement rather than spelled here: the last
        // dialect it states a `bearer` default outbound style for (its far-end spellings follow its
        // arrival dialects), so this harness names no dialect.
        let protocol = {
            let served = plane.served();
            served
                .dialect_auth
                .iter()
                .rev()
                .filter(|(_, style, _)| *style == "bearer")
                .find_map(|(d, _, _)| {
                    usize::try_from(*d)
                        .ok()
                        .and_then(|i| served.dialects.get(i).copied())
                })
                .expect("the session door states a bearer-style dialect")
        };

        let mut limits = opts.limits;
        if let Some(amount) = budget {
            limits.push(busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount,
                per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            });
        }
        let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = if limits.is_empty() {
            BTreeMap::new()
        } else {
            let cfg = busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits,
                ..Default::default()
            };
            BTreeMap::from([(format!("{instance}-group"), cfg)])
        };
        let cost = match budget {
            None if groups.is_empty() => CostModel::flat(1),
            None => CostModel::resolve_parts(None, 1, &groups),
            Some(_) => {
                let fees: busbar_kernel::config::PlaneFeesMap = [(
                    plane_name.clone(),
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
                    allowed_pools: opts.allowed_pools,
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

        let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(&format!(
            "{{protocol: {protocol}, base_url: 'http://127.0.0.1:{port}', api_key: {api_key}, error_map: {{}}}}",
        ))
        .expect("a provider entry");
        let providers = provider_routes(
            &std::collections::HashMap::from([(
                "p".to_string(),
                busbar_kernel::config::ResolvedProvider::from(provider),
            )]),
            &busbar_kernel::config_validate::MetadataPosture::default(),
        );
        let models_yaml = match opts.upstream_model {
            Some(wire) => format!("{{m-cap: {{provider: p, upstream_model: {wire}}}}}"),
            None => "{m-cap: {provider: p}}".to_string(),
        };
        let catalog: std::collections::HashMap<String, busbar_contract::config::ModelCfg> =
            serde_yaml::from_str(&models_yaml).expect("the models catalog");
        let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
            Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
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
            secrets: Arc::clone(&secrets),
            auths: Arc::new(auths),
            conns: Arc::clone(&connector) as Arc<dyn PollConns>,
            stream_ceiling_secs: 600,
            catalog: Some(&catalog),
            models: None,
            // The linked claims that open at an upgrade, as production composes them: a session
            // door's provider is dialled in its line's own scheme. This harness drops no transport
            // into a plugins directory, so the dropped-in rows are none.
            upgrades: crate::root::serve::upgrade_carriers(crate::LINKED.transports, &[]),
        };
        let mut sections = BTreeMap::new();
        sections.insert(
            section_key,
            serde_yaml::from_str("session: {model: m-cap}").expect("a section"),
        );
        // The deployment's `models:` beside it, as the root hands the kernel-owned sections a door
        // plane may read (`door_steps::kernel_sections`).
        sections.insert(
            busbar_contract::section::RESERVED_MODELS_KEY,
            serde_yaml::from_str(&models_yaml).expect("the models section"),
        );
        // THE KERNEL'S HOOK STAGE over this cell's generation (the App built below), when the cell
        // defines hooks: the door's tail states its hook order, and the stage binds the deployment's
        // hooks to each unit.
        let live_app: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
        let stage = (!opts.hooks.is_empty()).then(|| crate::root::serve::HookStage {
            host: {
                let live_app = Arc::clone(&live_app);
                Arc::new(move || {
                    busbar_kernel::plane_driver::engine_host(
                        live_app
                            .get()
                            .expect("the cell's App is built before any unit"),
                    )
                })
            },
            gov: Arc::clone(&gov),
            journal: None,
        });
        let mut served = match compose_planes(
            &[(instance.to_string(), Arc::new(plane))],
            &dispatcher,
            &composed_services(),
            &sections,
            Some(PUBLIC),
            &move || Arc::clone(&one),
            Some(&DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            }),
            stage.as_ref(),
        ) {
            Ok(served) => served,
            Err(refusal) => return Some(Err(refusal)),
        };
        assert!(
            served.planes[0].live.current().egress.is_some(),
            "the composition sealed its egress"
        );
        let live = Arc::clone(&served.planes[0].live);
        served.post = Some(Arc::clone(&post));
        let app = busbar_kernel::test_support::TestApp::new().keys_chain();
        let app = groups
            .iter()
            .fold(app, |app, (name, cfg)| app.group(name, cfg.clone()));
        // Each hook defined and attached deployment-wide (the runtime global list `pools.hooks:`
        // lowers to), its gates resolved into the generation as the production build resolves them.
        let app = if opts.hooks.is_empty() {
            app
        } else {
            opts.hooks
                .iter()
                .fold(app.hook_env(hook_env()), |app, (name, cfg)| {
                    app.hook(name, cfg.clone()).global_hook(name)
                })
                .resolve_global_gates()
        };
        let app = app.governance(Arc::clone(&gov)).cost(cost).build();
        let _ = live_app.set(Arc::clone(&app));
        // The door's claims as production mounts them: its request routes, and its session routes
        // (an upgrade line's claim, mounted as a GET session route).
        // No transport is dropped into a plugins directory here: the linked rows alone carry the
        // upgrade lines and the offered auth points, as production composes both.
        let upgrades = crate::root::serve::upgrade_carriers(crate::LINKED.transports, &[]);
        let offers = crate::root::serve::transport_offers(crate::LINKED.transports, &[]);
        let mounts = crate::root::serve::door_mounts(
            served,
            || CARD.pin(),
            &[],
            &[],
            &[],
            &upgrades,
            &offers,
        )
        .expect("its claims mount");
        let (router, _admin, _handle) = busbar_kernel::build_split_routers_serving_doors(
            Arc::clone(&app),
            mounts.routes,
            mounts.sessions,
            mounts.refusals,
            1 << 20,
            0,
            false,
        );
        Some(Ok(SessionDoor {
            _published: published,
            router,
            heard,
            gov,
            app,
            key,
            plain: plain.expose(&busbar_kernel::seal::lend()).clone(),
            live,
            money,
            post,
            book,
        }))
    }

    impl SessionDoor {
        /// The keyed caller's mint through the door: its response.
        pub(in crate::root::serve) async fn mint(&self) -> axum::response::Response {
            send_body(&self.router, MINT, Some(&self.plain), "{}").await
        }

        /// The requests the governance book admitted for the key, this window.
        fn requests(&self) -> u64 {
            self.gov
                .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
                .expect("a read")
                .expect("the key exists")
                .requests
        }

        /// The node book's lines for the session door's catalog route.
        fn lines(&self) -> usize {
            let rows = self.book.durability.lock().expect("unpoisoned").read_back();
            rows.iter()
                .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane.ends_with("m-cap")))
                .count()
        }

        /// The real `/metrics` scrape on the data router, as the keyed caller.
        async fn scrape(&self) -> String {
            use tower::ServiceExt as _;
            let req = axum::http::Request::builder()
                .method("GET")
                .uri("/metrics")
                .header("authorization", format!("Bearer {}", self.plain))
                .body(axum::body::Body::empty())
                .expect("a request");
            let response = self
                .router
                .clone()
                .oneshot(req)
                .await
                .expect("the router answers");
            assert_eq!(response.status(), StatusCode::OK, "the scrape is served");
            let body = axum::body::to_bytes(response.into_body(), 1 << 22)
                .await
                .expect("the exposition");
            String::from_utf8(body.to_vec()).expect("the exposition is UTF-8")
        }

        /// The audit records sealed on the node's book, oldest first.
        fn audit_records(&self) -> Vec<busbar_kernel_audit::AuditRecord> {
            self.book
                .durability
                .lock()
                .expect("unpoisoned")
                .audit_records
                .clone()
        }

        /// A keyed mint read to its end: its status, and whether the provider heard it.
        async fn mint_once(&mut self) -> (StatusCode, bool) {
            let response = self.mint().await;
            let status = response.status();
            let _ = body_of(response).await;
            // A dial the provider heard arrives before its answer was written back.
            (status, self.heard.try_recv().is_ok())
        }
    }

    /// The sum of `family`'s series on `exposition` whose `lane` label is the catalog route's (the
    /// lane the door's DIRECT route names, ending in its catalog model).
    fn counted(exposition: &str, family: &str) -> f64 {
        exposition
            .lines()
            .filter(|l| l.starts_with(&format!("{family}{{")))
            .filter(|l| {
                l.split("lane=\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .is_some_and(|lane| lane.ends_with("m-cap"))
            })
            .filter_map(|l| l.rsplit_once(' ')?.1.parse::<f64>().ok())
            .sum()
    }

    /// The provider's transient failure, as its far end words it.
    const UNAVAILABLE: &str = r#"{"error":{"message":"overloaded","type":"server_error"}}"#;

    /// How many failing mints the route's breaker cell is given to open before the run calls it
    /// stuck.
    const MAX_FAILURES: usize = 8;

    /// Mint until the route's breaker cell refuses a mint before its dial, the provider failing every
    /// dial it hears: the dials it heard first, each one refused to the caller. `None` if the cell
    /// never opened.
    async fn trip(s: &mut SessionDoor) -> Option<usize> {
        for n in 0..=MAX_FAILURES {
            let (status, heard) = s.mint_once().await;
            assert_ne!(status, StatusCode::OK, "mint {n} is not served");
            if !heard {
                return Some(n);
            }
        }
        None
    }

    /// One request an hour, for the caller's group.
    fn one_an_hour() -> busbar_kernel::config::groups::LimitCfg {
        busbar_kernel::config::groups::LimitCfg {
            metric: busbar_kernel::config::groups::LimitMetric::Requests,
            amount: 1,
            per: Some(busbar_kernel::config::groups::LimitWindow::Hour),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }
    }

    /// THE SESSION DOOR'S MINT, SERVED (its root leg, ARCHITECT 2026-10-05 Q1): a keyed caller's
    /// `POST /v1/realtime/client_secrets` is one unit the door carries (ARRIVAL), admitted for the
    /// key its token resolves (AUTHENTICATE), dialled to the destination the guard judged (VERIFY)
    /// on the DIRECT route to the catalog model its section's `session.model` names (ROUTE), sent
    /// WITH THE PROVIDER'S OWN CREDENTIAL and never the caller's token (EGRESS-AUTH), charged to
    /// the key that presented it (METER, GOVERNANCE-BUDGET), and closed once with its one line on
    /// the node's book (AUDIT, EXIT). (The door's audience binding is the deployment's mount
    /// table's, judged end to end by the oracle's wrong-audience mint cell.)
    ///
    /// RED ARM: the same request with no credential is refused before anything is dialled or charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_mint_is_served_under_the_providers_credential() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_served("serve-door-session", None)
            .await
            .expect("the build links the session door");

        let refused = send_body(&s.router, MINT, None, "{}").await;
        assert_eq!(
            refused.status().as_u16(),
            u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status"),
            "an unkeyed caller is refused at the session door"
        );
        assert!(s.heard.try_recv().is_err(), "nothing was dialled for it");
        assert_eq!(s.requests(), 0, "nor charged");

        let response = send_body(&s.router, MINT, Some(&s.plain), "{}").await;
        assert_eq!(response.status(), StatusCode::OK, "served through the door");
        let body = body_of(response).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("the door's JSON");
        assert_eq!(
            body,
            serde_json::json!({"value": "ek_door_0001", "expires_at_unix": 1_767_225_600_u64}),
            "the minted secret and its expiry"
        );

        let head = tokio::time::timeout(ANSWER_BOUND, s.heard.recv())
            .await
            .expect("the provider's dial is heard within the bound")
            .expect("the provider was dialled");
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

    /// ADMIT, at the session door (its root leg): a key whose group budget is already spent is
    /// refused at admission — over budget, before the provider is dialled, charged nothing, no line
    /// written — while a key with room is served (the mint cell above). RED: a door that dialled
    /// before admission would have reached the far end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spent_key_is_refused_at_the_session_door_before_any_dial() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_served("serve-door-session-spent", Some(0))
            .await
            .expect("the build links the session door");
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

    /// BREAKER-TRIP, at the session door: a provider failing every mint records each failure into
    /// the ONE breaker cell of the door's route, and the cell OPENS: the next mint is refused before
    /// it is dialled, and the provider's failures are counted under the route's lane on the scrape.
    /// RED: a breaker port that records no failure leaves the cell closed, and every mint is dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_provider_opens_the_breaker_cell_of_the_doors_route() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_with(
            "serve-door-session-trip",
            Opts {
                far: Some(Arc::new(|_| {
                    Far::Says("503 Service Unavailable", UNAVAILABLE)
                })),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let failures = counted(
            &s.scrape().await,
            busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
        );

        let dialled = trip(&mut s)
            .await
            .unwrap_or_else(|| panic!("{MAX_FAILURES} failing mints never opened the cell"));
        assert!(dialled >= 1, "the cell opened on a failure it recorded");
        assert!(
            counted(
                &s.scrape().await,
                busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
            ) >= failures + 1.0,
            "the provider's failures are counted under the route's lane"
        );
        assert_eq!(s.money.open_units(), 0, "every unit's money facts closed");
        assert_eq!(s.post.open_units(), 0, "every unit's node facts closed");
    }

    /// BREAKER-FASTFAIL, at the session door: once the route's breaker cell has opened, the next
    /// mint is refused BEFORE its dial and at once: the provider, which now holds every connection
    /// open unanswered, is never dialled, and the refusal comes back in well under a second. RED: a
    /// breaker port that admits an open cell dials the provider, which holds the mint past the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_provider_is_refused_at_the_session_door_before_the_dial_at_once() {
        let _one = PUBLISHING.lock().await;
        let holding = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = Arc::clone(&holding);
        let mut s = session_with(
            "serve-door-session-fastfail",
            Opts {
                far: Some(Arc::new(move |_| {
                    if held.load(std::sync::atomic::Ordering::SeqCst) {
                        Far::Holds
                    } else {
                        Far::Says("503 Service Unavailable", UNAVAILABLE)
                    }
                })),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        trip(&mut s)
            .await
            .unwrap_or_else(|| panic!("{MAX_FAILURES} failing mints never opened the cell"));

        // From here a dialled provider never answers: only the breaker can answer the next mint.
        holding.store(true, std::sync::atomic::Ordering::SeqCst);
        let started = std::time::Instant::now();
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), s.mint())
            .await
            .expect("the tripped route's mint is answered, not held at its provider");
        let took = started.elapsed();
        assert_ne!(response.status(), StatusCode::OK, "the mint is refused");
        assert!(
            s.heard.try_recv().is_err(),
            "the refused mint never reached the provider"
        );
        assert!(
            took < std::time::Duration::from_secs(1),
            "refused before the dial, in milliseconds: {took:?}"
        );
    }

    /// HOOKS-GATE, at the session door: a deployment-wide decision gate that rejects is asked about
    /// the mint after admission and before the route's dial, and its veto is the caller's answer —
    /// the hook's own status — with the provider never dialled and the unit closed. RED: a door
    /// whose units the hook stage never reaches dials the provider and serves the mint (the
    /// ungated mint cell above is the control).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gate_hook_refuses_the_mint_before_the_provider_is_dialled() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_with(
            "serve-door-session-gated",
            Opts {
                hooks: vec![(
                    "closed",
                    global_gate(serde_json::json!({
                        "reject": {"status": 409, "message": "no new sessions"}
                    })),
                )],
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (status, heard) = s.mint_once().await;
        assert_eq!(status.as_u16(), 409, "the hook's own status");
        assert!(!heard, "the gated mint never reached the provider");
        assert_eq!(
            s.money.open_units(),
            0,
            "the refused unit's money facts closed"
        );
        assert_eq!(
            s.post.open_units(),
            0,
            "the refused unit's node facts closed"
        );
        assert_eq!(s.lines(), 0, "no line on the node's book");
    }

    /// AUDIT-CHAIN, at the session door: every mint, served or refused, seals ONE record on the
    /// node's tamper-evident audit chain under the door's one operation class, the second linked to
    /// the first, and the chain walks clean; a record altered after its seal breaks the walk. The
    /// refusal is the kernel's own, inside the loop: the caller's group allows one request an hour.
    /// RED: a loop whose audit pass is never handed back to the node seals nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_session_door_mint_served_or_refused_seals_one_record_on_one_chain() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_with(
            "serve-door-session-audit",
            Opts {
                limits: vec![one_an_hour()],
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (status, heard) = s.mint_once().await;
        assert_eq!(status, StatusCode::OK, "the first mint is served");
        assert!(heard, "and dialled");
        let (status, heard) = s.mint_once().await;
        assert_ne!(status, StatusCode::OK, "the second is refused by the limit");
        assert!(!heard, "before its dial");

        let records = s.audit_records();
        assert_eq!(records.len(), 2, "one record per unit: {records:?}");
        let (served, refused) = (&records[0], &records[1]);
        assert_eq!(
            served.what.op_class.as_str(),
            refused.what.op_class.as_str(),
            "both sealed under the door's one operation class"
        );
        assert_eq!(
            served.outcome.unit_end,
            busbar_contract::caps::Outcome::Completed
        );
        assert!(
            matches!(
                refused.outcome.unit_end,
                busbar_contract::caps::Outcome::Refused(_, ReasonCode::RateLimited)
            ),
            "the refusal is chained as one: {:?}",
            refused.outcome
        );
        assert_eq!(refused.seq, served.seq + 1, "contiguous");
        assert_eq!(
            refused.prev_hash, served.hash,
            "linked to the record before"
        );
        assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
        assert!(
            s.book
                .durability
                .lock()
                .expect("unpoisoned")
                .retained_audit_findings()
                .is_empty(),
            "the node's own verify finds nothing"
        );
        let mut forged = records.clone();
        forged[0].outcome.unit_end = refused.outcome.unit_end;
        assert!(
            busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
            "a record altered after its seal breaks the chain"
        );
    }

    /// METRICS, at the session door: a served mint's dial to the provider appears on the real
    /// `/metrics` scrape, once, under the door's route lane. RED: an egress whose telemetry counts no
    /// attempt leaves the scrape where it was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_served_mint_counts_its_upstream_attempt_under_the_doors_route() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_served("serve-door-session-metrics", None)
            .await
            .expect("the build links the session door");
        let before = counted(
            &s.scrape().await,
            busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
        );
        let (status, heard) = s.mint_once().await;
        assert_eq!(status, StatusCode::OK, "served");
        assert!(heard, "dialled");
        let exposition = s.scrape().await;
        assert_eq!(
            counted(
                &exposition,
                busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL
            ),
            before + 1.0,
            "one attempt, counted under the route's lane:\n{exposition}"
        );
    }

    /// APPROVE, at the session door: a key whose grant does not reach the door's pool is refused at
    /// approval — before the provider is dialled, charged nothing, no line written — while a key with
    /// the grant is served (the mint cell above). RED: a door that skipped approval would dial.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_short_of_the_doors_grant_is_refused_before_any_dial() {
        let _one = PUBLISHING.lock().await;
        let mut s = session_with(
            "serve-door-session-ungranted",
            Opts {
                allowed_pools: Some(Vec::new()),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (status, heard) = s.mint_once().await;
        assert!(
            status.is_client_error(),
            "a key outside the door's grant is refused: {status}"
        );
        assert!(!heard, "the provider was never dialled");
        assert_eq!(s.requests(), 0, "the refusal charged nothing");
        assert_eq!(s.money.open_units(), 0);
        assert_eq!(s.post.open_units(), 0);
        assert_eq!(s.lines(), 0, "no line on the node's book");
    }

    // ── a live session through the door's session route, on a real listener ──────────────────────

    /// SHA-1 of `data` (RFC 3174), for the one place RFC 6455 asks for it: the far end's
    /// `Sec-WebSocket-Accept`.
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ];
        let mut msg = data.to_vec();
        let bits = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bits.to_be_bytes());
        for block in msg.chunks(64) {
            let mut w: Vec<u32> = block
                .chunks(4)
                .map(|word| u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
                .collect();
            while w.len() < 80 {
                let n = w.len();
                w.push((w[n - 3] ^ w[n - 8] ^ w[n - 14] ^ w[n - 16]).rotate_left(1));
            }
            let [mut a, mut b, mut c, mut d, mut e] = h;
            for (i, wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(*wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
                *slot = slot.wrapping_add(v);
            }
        }
        let mut out = [0u8; 20];
        for (i, v) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// The `Sec-WebSocket-Accept` answering `key` (RFC 6455 section 4.2.2).
    fn ws_accept(key: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(sha1(
            format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
        ))
    }

    /// Read an HTTP head (through its blank line) off `socket`; `None` at end of stream.
    async fn read_head(socket: &mut tokio::net::TcpStream) -> Option<String> {
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            match socket.read(&mut byte).await {
                Ok(1) => got.push(byte[0]),
                _ => return None,
            }
        }
        Some(String::from_utf8_lossy(&got).into_owned())
    }

    /// Read one WebSocket frame off `socket`, unmasking it: its opcode and payload; `None` at end of
    /// stream.
    async fn read_frame(socket: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        socket.read_exact(&mut head).await.ok()?;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let len = match head[1] & 0x7F {
            126 => {
                let mut n = [0u8; 2];
                socket.read_exact(&mut n).await.ok()?;
                u64::from(u16::from_be_bytes(n))
            }
            127 => {
                let mut n = [0u8; 8];
                socket.read_exact(&mut n).await.ok()?;
                u64::from_be_bytes(n)
            }
            n => u64::from(n),
        };
        let mut mask = [0u8; 4];
        if masked {
            socket.read_exact(&mut mask).await.ok()?;
        }
        let mut payload = vec![0u8; usize::try_from(len).ok()?];
        socket.read_exact(&mut payload).await.ok()?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Some((opcode, payload))
    }

    /// One text frame as a client sends it (masked, RFC 6455 section 5.3).
    fn client_text(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mask = [0x37u8, 0xFA, 0x21, 0x3D];
        let mut frame = vec![0x81u8];
        match bytes.len() {
            n if n < 126 => frame.push(0x80 | u8::try_from(n).expect("short")),
            n => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&u16::try_from(n).expect("a short frame").to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    /// One text frame as a server sends it (unmasked, RFC 6455 section 5.1).
    fn server_text(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut frame = vec![0x81u8, u8::try_from(bytes.len()).expect("a short frame")];
        frame.extend_from_slice(bytes);
        frame
    }

    /// The provider's opening event: the session it created, sent the moment its upgrade is
    /// answered and before it reads anything, as the provider's protocol has it speak first.
    const FAR_OPENING: &str = r#"{"type":"session.created","session":{"id":"sess_door_0001"}}"#;

    /// A provider on loopback speaking WebSocket: it accepts each dial's upgrade, speaks first
    /// ([`FAR_OPENING`]), as the provider does, and reports every TEXT frame it is sent on the
    /// channel, in order. A far end is held for a session's next turns once it has answered
    /// (`plane_driver::session`); its switching response is that answer (HEAD-FIELDS: the ws
    /// transport hands it up as the stream's head), its opening event the first message after it.
    async fn far_socket() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_socket_opening(Some(FAR_OPENING)).await
    }

    /// [`far_socket`], but a provider that answers the upgrade and does NOT speak first: it sends
    /// nothing until it is spoken to.
    async fn far_socket_silent() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_socket_opening(None).await
    }

    /// The provider [`far_socket`] and [`far_socket_silent`] start: `opening`, where it names one,
    /// is the event it sends the moment its upgrade is answered.
    async fn far_socket_opening(
        opening: Option<&'static str>,
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
                    let Some(head) = read_head(&mut socket).await else {
                        return;
                    };
                    let Some(key) = head.lines().find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    }) else {
                        return;
                    };
                    let reply = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\
                         connection: Upgrade\r\nsec-websocket-accept: {}\r\n\r\n",
                        ws_accept(&key)
                    );
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                    let spoke = match opening {
                        Some(opening) => socket.write_all(&server_text(opening)).await.is_ok(),
                        None => true,
                    };
                    if !spoke {
                        return;
                    }
                    while let Some((opcode, payload)) = read_frame(&mut socket).await {
                        match opcode {
                            0x1 => {
                                let _ = sent.send(String::from_utf8_lossy(&payload).into_owned());
                            }
                            0x8 => return,
                            _ => {}
                        }
                    }
                });
            }
        });
        (port, heard)
    }

    /// The next text the provider heard that is not the session's own configuration, within a few
    /// seconds; `None` when nothing more arrives.
    async fn next_heard(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Option<String> {
        loop {
            let text = tokio::time::timeout(std::time::Duration::from_secs(5), heard.recv())
                .await
                .ok()??;
            if !text.contains("session.update") {
                return Some(text);
            }
        }
    }

    /// DECODE, at the session door (its root leg): a live session opened through the door's session
    /// route, on a real listener, carries each client event the plane reads to the provider, and a
    /// frame the plane cannot read reaches the provider on no wire — the session stays open, and the
    /// next readable event is carried after it, in order. RED ARM: the readable events either side
    /// of the unreadable frame must arrive, so a door that dropped every frame, or one that closed
    /// the session on a bad one, fails here; a door that relayed the unreadable frame fails on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_carries_what_the_plane_reads_and_no_frame_it_cannot() {
        let _one = PUBLISHING.lock().await;
        let far_end = far_socket().await;
        let mut s = session_with(
            "serve-door-session-decode",
            Opts {
                far_end: Some(far_end),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (router, plain) = (s.router.clone(), s.plain.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });

        // The session door's plain realtime socket, as a keyed caller opens it.
        let route = REALTIME;
        let mut caller = tokio::net::TcpStream::connect(addr).await.expect("a dial");
        let open = format!(
            "GET {route} HTTP/1.1\r\nhost: {addr}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\
             authorization: Bearer {plain}\r\n\r\n"
        );
        caller.write_all(open.as_bytes()).await.expect("the open");
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), read_head(&mut caller))
            .await
            .expect("the door answers the open")
            .expect("a head");
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "the session opens: {head}"
        );

        let read = r#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#;
        caller
            .write_all(&client_text(read))
            .await
            .expect("a readable event");
        let carried = next_heard(&mut s.heard)
            .await
            .expect("a client event the plane reads is carried to the provider");
        assert!(
            carried.contains("input_audio_buffer.append"),
            "the readable event, carried: {carried}"
        );

        caller
            .write_all(&client_text("not a frame {"))
            .await
            .expect("an unreadable frame");
        let after = r#"{"type":"input_audio_buffer.commit"}"#;
        caller
            .write_all(&client_text(after))
            .await
            .expect("a second readable event");
        let next = next_heard(&mut s.heard)
            .await
            .expect("the session stays open and carries the next readable event");
        assert!(
            !next.contains("not a frame"),
            "a frame the plane cannot read reaches the provider on no wire: {next}"
        );
        assert!(
            next.contains("input_audio_buffer.commit"),
            "the next event carried is the readable one after it: {next}"
        );
    }

    /// HEAD-FIELDS (`BUSBAR-1.6.0.md` l.736: a transport always hands the response head up as the
    /// first `Fields` piece), at the session door's root leg: a provider that answers the upgrade
    /// (`101`) and does NOT speak first has ANSWERED, so the session's far end is held from its
    /// switching response and every turn the caller sends reaches it, in order, though the
    /// provider never says a word. RED ARM: on the ws transport that discarded the switching
    /// response the far end counted as answered only once it spoke, so every turn after the first
    /// waited on a provider that never would, and the second event never arrived.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_carries_turns_to_a_provider_that_does_not_speak_first() {
        let _one = PUBLISHING.lock().await;
        let far_end = far_socket_silent().await;
        let mut s = session_with(
            "serve-door-session-silent",
            Opts {
                far_end: Some(far_end),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (router, plain) = (s.router.clone(), s.plain.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });

        let route = REALTIME;
        let mut caller = tokio::net::TcpStream::connect(addr).await.expect("a dial");
        let open = format!(
            "GET {route} HTTP/1.1\r\nhost: {addr}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\
             authorization: Bearer {plain}\r\n\r\n"
        );
        caller.write_all(open.as_bytes()).await.expect("the open");
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), read_head(&mut caller))
            .await
            .expect("the door answers the open")
            .expect("a head");
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "the session opens: {head}"
        );

        for (event, kind) in [
            (
                r#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#,
                "input_audio_buffer.append",
            ),
            (
                r#"{"type":"input_audio_buffer.commit"}"#,
                "input_audio_buffer.commit",
            ),
        ] {
            caller
                .write_all(&client_text(event))
                .await
                .expect("a readable event");
            let carried = next_heard(&mut s.heard).await.unwrap_or_else(|| {
                panic!("{kind} reaches a provider that answered the upgrade and never spoke")
            });
            assert!(
                carried.contains(kind),
                "the turns arrive in order: {kind}, carried: {carried}"
            );
        }
    }

    /// MONEY (Q128 arch u64; THE DESIGN section 7, "the plane reports the units it did"), at the
    /// session door's root leg: a caller's GA `session.update` sets the uplink to µ-law through
    /// `session.audio.input.format`, the provider reads 8 bytes a millisecond from then on, and the
    /// session's one sealed line bills what it read: six seconds of µ-law (48 000 bytes) are 6
    /// `audio_seconds_in`. A session holds nothing on the book's chain (no hold, no settlement:
    /// `Node::open_borrowed`), so its one line is the record its end seals with the counts the
    /// plane reported (`Node::seal_session`, THE DESIGN section 7: "the session's end writes ONE
    /// sealed line"), and that record is what this cell reads. RED ARM: the plane read only the
    /// legacy `input_audio_format`, counted the 48 000 bytes at PCM16's 48 a millisecond, and the
    /// line billed 1 second of the 6 served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_bills_a_ga_mulaw_uplink_at_mulaw() {
        use base64::Engine as _;
        let _one = PUBLISHING.lock().await;
        let far_end = far_socket().await;
        let mut s = session_with(
            "serve-door-session-ga-format",
            Opts {
                far_end: Some(far_end),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (router, plain) = (s.router.clone(), s.plain.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });

        let route = REALTIME;
        let mut caller = tokio::net::TcpStream::connect(addr).await.expect("a dial");
        let open = format!(
            "GET {route} HTTP/1.1\r\nhost: {addr}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\
             authorization: Bearer {plain}\r\n\r\n"
        );
        caller.write_all(open.as_bytes()).await.expect("the open");
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), read_head(&mut caller))
            .await
            .expect("the door answers the open")
            .expect("a head");
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "the session opens: {head}"
        );

        let update = r#"{"type":"session.update","session":{"type":"realtime","audio":{"input":{"format":{"type":"audio/pcmu"}}}}}"#;
        caller
            .write_all(&client_text(update))
            .await
            .expect("the caller's GA update");
        // One second of µ-law (8 000 bytes) a frame, six frames.
        let second = base64::engine::general_purpose::STANDARD.encode(vec![0x7f_u8; 8_000]);
        let append = format!(r#"{{"type":"input_audio_buffer.append","audio":"{second}"}}"#);
        for n in 0..6 {
            caller
                .write_all(&client_text(&append))
                .await
                .expect("a second of audio");
            let carried = next_heard(&mut s.heard)
                .await
                .unwrap_or_else(|| panic!("second {n} reaches the provider"));
            assert!(carried.contains("input_audio_buffer.append"), "{carried}");
        }
        // The caller closes: the session ends and its one line is sealed.
        caller
            .write_all(&[0x88, 0x80, 0x37, 0xFA, 0x21, 0x3D])
            .await
            .expect("the caller's close");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (billed, sealed) = loop {
            let records = s.audit_records();
            let seconds = records.iter().find_map(|r| {
                r.usage
                    .lines
                    .iter()
                    .find(|l| l.class.as_str() == AUDIO_CLASS)
                    .map(|l| l.quantity)
            });
            if seconds.is_some() || std::time::Instant::now() > deadline {
                // What the session's end sealed, so a red names whether its line was never sealed
                // or was sealed without the audio the provider read.
                let sealed: Vec<String> = records
                    .iter()
                    .map(|r| format!("{:?} {:?}", r.outcome.unit_end, r.usage.lines))
                    .collect();
                break (seconds, sealed);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        assert_eq!(
            billed,
            Some(6),
            "six seconds of µ-law the provider read are six billed seconds; sealed: {sealed:?}"
        );
    }

    /// The call the far end's SDP answer places, where its `Location` says it lives.
    const PLACED_CALL: &str = "rtc_root0001";

    /// A provider on loopback that places calls and serves its realtime socket: a `POST` (the SDP
    /// offer) is answered `201` with an SDP answer and a `Location` naming [`PLACED_CALL`]; a
    /// WebSocket upgrade is answered `101`. It reports `OFFER <head>` for each offer, `DIAL <request
    /// line>` for each upgrade, and `TEXT <payload>` for every text frame a socket is sent.
    async fn far_calls_and_socket() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        const ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=root-answer\r\nt=0 0\r\n";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sent = sent.clone();
                tokio::spawn(async move {
                    let Some(head) = read_head(&mut socket).await else {
                        return;
                    };
                    let line = head.lines().next().unwrap_or_default().to_string();
                    let key = head.lines().find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    });
                    let Some(key) = key else {
                        // The SDP offer: its body, then the placed call.
                        let length = head
                            .lines()
                            .find_map(|l| {
                                let (name, value) = l.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        let mut body = vec![0u8; length];
                        if socket.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let _ = sent.send(format!("OFFER {head}"));
                        let reply = format!(
                            "HTTP/1.1 201 Created\r\ncontent-type: application/sdp\r\n\
                             location: /v1/realtime/calls/{PLACED_CALL}\r\ncontent-length: {}\r\n\
                             connection: close\r\n\r\n{ANSWER}",
                            ANSWER.len()
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                        let _ = socket.shutdown().await;
                        return;
                    };
                    let _ = sent.send(format!("DIAL {line}"));
                    let reply = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\
                         connection: Upgrade\r\nsec-websocket-accept: {}\r\n\r\n",
                        ws_accept(&key)
                    );
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                    if socket.write_all(&server_text(FAR_OPENING)).await.is_err() {
                        return;
                    }
                    while let Some((opcode, payload)) = read_frame(&mut socket).await {
                        match opcode {
                            0x1 => {
                                let _ = sent
                                    .send(format!("TEXT {}", String::from_utf8_lossy(&payload)));
                            }
                            0x8 => return,
                            _ => {}
                        }
                    }
                });
            }
        });
        (port, heard)
    }

    /// The next report from [`far_calls_and_socket`] that is not a session's own configuration,
    /// within a few seconds; `None` when nothing more arrives.
    async fn next_report(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Option<String> {
        loop {
            let text = tokio::time::timeout(std::time::Duration::from_secs(5), heard.recv())
                .await
                .ok()??;
            if !text.contains("session.update") {
                return Some(text);
            }
        }
    }

    /// A keyed caller's WebSocket open of `route` on the listener at `addr`: the socket, and the
    /// head the door answered with (`None` when the door closed without one).
    async fn open_socket(
        addr: std::net::SocketAddr,
        route: &str,
        plain: &str,
    ) -> (tokio::net::TcpStream, Option<String>) {
        let mut caller = tokio::net::TcpStream::connect(addr).await.expect("a dial");
        let open = format!(
            "GET {route} HTTP/1.1\r\nhost: {addr}\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\
             authorization: Bearer {plain}\r\n\r\n"
        );
        caller.write_all(open.as_bytes()).await.expect("the open");
        let head = tokio::time::timeout(std::time::Duration::from_secs(10), read_head(&mut caller))
            .await
            .expect("the door answers the open");
        (caller, head)
    }

    /// THE SIDEBAND ATTACHES ONLY TO A PLACED CALL (busbar row 159, the session door's audit round
    /// 2: "The sideband door attaches to no call"; ARCHITECT ruling 2026-10-23 on
    /// `BUSBAR-1.6.0.md` Part 2 #45), at the session door's root leg: a sideband naming a call the
    /// SDP door never placed reaches the provider on no dial; once the caller's own offer has placed
    /// a call through `POST /v1/realtime/calls` (the provider's answer naming it in `Location`), a
    /// sideband naming that call dials the provider's socket ATTACHED to it
    /// (`/v1/realtime?call_id=<id>`) and carries the caller's events there. RED ARM: the sideband
    /// that dialled a bare `/v1/realtime` for any call id opened a new provider session for the
    /// unplaced call, and attached to nothing for the placed one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_sideband_attaches_only_to_a_placed_call() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let far_end = far_calls_and_socket().await;
        let mut s = session_with(
            "serve-door-session-sideband",
            Opts {
                far_end: Some(far_end),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (router, plain) = (s.router.clone(), s.plain.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        let served = router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, served.into_make_service()).await;
        });
        let append = r#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#;

        // A call no offer placed: refused, and the provider is never dialled for it.
        let unplaced = SIDEBAND.replace("{call_id}", "rtc_unplaced0001");
        let (mut caller, head) = open_socket(addr, &unplaced, &plain).await;
        if head
            .as_deref()
            .is_some_and(|h| h.starts_with("HTTP/1.1 101"))
        {
            let _ = caller.write_all(&client_text(append)).await;
        }
        let stray = next_report(&mut s.heard).await;
        assert!(
            stray.is_none(),
            "a sideband naming a call no offer placed reaches the provider on no wire: \
             open {head:?}, provider heard {stray:?}"
        );
        drop(caller);

        // The caller's own offer places the call.
        let offer = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=root-offer\r\nt=0 0\r\n";
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/realtime/calls")
            .header("content-type", "application/sdp")
            .header("authorization", format!("Bearer {plain}"))
            .body(axum::body::Body::from(offer))
            .expect("a request");
        let placed = tokio::time::timeout(ANSWER_BOUND, router.clone().oneshot(req))
            .await
            .expect("the SDP door answers within the bound")
            .expect("the router answers");
        assert_eq!(placed.status().as_u16(), 201, "the offer placed a call");
        let location = placed
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert_eq!(
            location.as_deref(),
            Some(format!("/v1/realtime/calls/{PLACED_CALL}").as_str()),
            "the caller is told where the call lives"
        );
        let posted = next_report(&mut s.heard)
            .await
            .expect("the offer reached the provider");
        assert!(
            posted.starts_with("OFFER POST /v1/realtime/calls "),
            "{posted}"
        );

        // The sideband naming the placed call dials the provider's socket attached to it.
        let attached = SIDEBAND.replace("{call_id}", PLACED_CALL);
        let (mut caller, head) = open_socket(addr, &attached, &plain).await;
        assert!(
            head.as_deref()
                .is_some_and(|h| h.starts_with("HTTP/1.1 101")),
            "the sideband to the caller's own call opens: {head:?}"
        );
        caller
            .write_all(&client_text(append))
            .await
            .expect("a readable event");
        let dial = next_report(&mut s.heard)
            .await
            .expect("the sideband dials the provider");
        assert!(
            dial.starts_with(&format!("DIAL GET /v1/realtime?call_id={PLACED_CALL} ")),
            "the sideband attaches to the call it names: {dial}"
        );
        let carried = next_report(&mut s.heard)
            .await
            .expect("the caller's event reaches the call");
        assert!(
            carried.starts_with("TEXT ") && carried.contains("input_audio_buffer.append"),
            "{carried}"
        );
    }

    /// THE PROVIDER IS TOLD THE UPSTREAM MODEL (`BUSBAR-1.6.0.md` Part 2 #51: a model entry's
    /// `upstream_model` overrides its name on the wire; ARCHITECT rulings 2026-10-23, R-6: a plane
    /// that reads sections beside its own is handed them keyed), at the session door's root leg: a
    /// deployment whose catalog entry for the session model names an `upstream_model` has a plain
    /// session dial the provider's realtime socket with that wire name, never the catalog alias.
    /// RED ARM: the door was handed its section bare, never read the `models:` beside it, and
    /// dialled `?model=m-cap`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_door_dials_the_session_models_upstream_name() {
        let _one = PUBLISHING.lock().await;
        let far_end = far_calls_and_socket().await;
        let mut s = session_with(
            "serve-door-session-upstream",
            Opts {
                far_end: Some(far_end),
                upstream_model: Some("gpt-realtime-wire"),
                ..Opts::default()
            },
        )
        .await
        .expect("the build links the session door");
        let (router, plain) = (s.router.clone(), s.plain.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service()).await;
        });
        let (mut caller, head) = open_socket(addr, REALTIME, &plain).await;
        assert!(
            head.as_deref()
                .is_some_and(|h| h.starts_with("HTTP/1.1 101")),
            "the plain session opens: {head:?}"
        );
        caller
            .write_all(&client_text(
                r#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#,
            ))
            .await
            .expect("a readable event");
        let dial = next_report(&mut s.heard)
            .await
            .expect("the session dials the provider");
        assert!(
            dial.starts_with("DIAL GET /v1/realtime?model=gpt-realtime-wire "),
            "the dial names the upstream model, never the catalog alias: {dial}"
        );
    }
}

/// THE ROOT-MCP LEG'S LOOP CELLS (U14): the MCP plane served through its memory-ABI door, composed by
/// this file's composition (`compose_planes`, `door_routes`) on the kernel's plane driver, each core
/// capability of the capability-equality matrix (`qa/capability-equality.json`, the `mcp-client` and
/// `mcp-server` columns) driven through the data router the door's claims mount on and asserted
/// where the capability lands: the breaker cell and its walk, the hook stage, the call log's chain
/// and the kernel's audit chain, the governance book, the `/metrics` exposition, the trust state,
/// the connector's destination guard and the plane's argument guard, the member's auth binding, and
/// the caller's catalogue. The door rig is `door_steps`' own (`tool_door::Rig`), one composition
/// per case.
#[cfg(linked_axis_plane_door)]
mod tools_door {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::http::StatusCode;
    use busbar_kernel::governance::PLANE_LANE_SEP;

    use crate::root::door_steps::tests::hook_parity;
    use crate::root::door_steps::tests::tool_door::{
        protocol_version, rig_tools, send_as, send_headed, sentence, surface, three_tools,
        tool_digest, tool_listing, tool_server, tool_server_listing, tool_server_replying, Footing,
        Rig, STALL, TOOL_DESCRIPTION,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    type Heard = tokio::sync::mpsc::UnboundedReceiver<String>;

    /// The pin every test registration carries (the door requires one).
    const PIN: &str = "pin: { mechanism: pinned_pubkey, key: \"sha256/K=\" }";

    /// A `tools:` section of one registration `server` on loopback `port`, `extra` (indented YAML
    /// lines) beside its pin, the one approved tool.
    fn registration(server: &str, port: u16, extra: &str) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "{server}:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  {PIN}\n{extra}  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// A `tools/call` of `tool` (its published name) with `arguments`.
    fn call_of(tool: &str, arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 41, "method": "tools/call",
            "params": {
                "name": tool, "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string()
    }

    /// A `tools/list`, as a caller sends it.
    fn listing() -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 42, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": protocol_version(),
                "io.modelcontextprotocol/clientCapabilities": {},
            } },
        })
        .to_string()
    }

    /// `tool` called on `rig` as `token`: the status and the JSON-RPC answer.
    async fn call(
        rig: &Rig,
        token: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, body) = send_as(
            &rig.router,
            Some(token),
            &call_of(tool, arguments),
            "tools/call",
            Some(tool),
        )
        .await;
        let answer = serde_json::from_slice(&body)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
        (status, answer)
    }

    /// What the server heard since the last drain, as `list` / `call` / `other`.
    fn drain(heard: &mut Heard) -> Vec<&'static str> {
        std::iter::from_fn(|| heard.try_recv().ok())
            .map(|r| {
                if r.contains("\"tools/list\"") {
                    "list"
                } else if r.contains("\"tools/call\"") {
                    "call"
                } else {
                    "other"
                }
            })
            .collect()
    }

    /// The raw requests the server heard since the last drain.
    fn wire(heard: &mut Heard) -> Vec<String> {
        std::iter::from_fn(|| heard.try_recv().ok()).collect()
    }

    /// A tool server answering its tool list as approved and every `tools/call` with `status`.
    async fn answering_calls_with(status: u16) -> (u16, Heard) {
        tool_server_replying(Arc::new(move |r: &str| {
            if r.contains("\"tools/list\"") {
                let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}});
                (200, list.to_string())
            } else {
                (status, r#"{"error":"no"}"#.to_string())
            }
        }))
        .await
    }

    /// The registration `server`'s lane on `rig`'s plane: the breaker cell, the metrics label.
    fn lane(rig: &Rig, server: &str) -> String {
        format!("{}{PLANE_LANE_SEP}{server}", rig.plane_key)
    }

    /// The sum of every `/metrics` sample of `family` whose labels carry every `(key, value)`.
    fn scraped(family: &str, labels: &[(&str, &str)]) -> f64 {
        busbar_kernel::snapshot::render()
            .lines()
            .filter(|l| !l.starts_with('#') && l.starts_with(&format!("{family}{{")))
            .filter(|l| {
                labels
                    .iter()
                    .all(|(k, v)| l.contains(&format!("{k}=\"{v}\"")))
            })
            .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .sum()
    }

    /// THE CALLS THAT TRIP A MEMBER'S CELL under the door's breaker ladder: the trip's minimum
    /// outcome count, every one a failure. Below it a transient failure benches nothing: the plane
    /// declares it (`declares.breaker`, ARCHITECT Q4), the 1.5.5 MCP client leg's posture — a cell
    /// refuses on a TRIP (error rate at its threshold over at least this many outcomes) and nothing
    /// less.
    fn trip_calls() -> usize {
        busbar_kernel::store::pool_breaker_cfg(None)
            .trip
            .min_requests
    }

    /// `tool` called on `rig` against a server failing every call, calls `from..trip_calls()`:
    /// each one fails, and each one REACHES THE SERVER — below the trip threshold the member's cell
    /// stays closed — the last of them being the one that trips it.
    async fn fail_to_the_trip(rig: &Rig, tool: &str, heard: &mut Heard, from: usize) {
        for n in from..trip_calls() {
            let (status, answer) = call(rig, &rig.token, tool, serde_json::json!({})).await;
            assert_ne!(status, StatusCode::OK, "call {n}: {answer}");
            assert!(
                drain(heard).contains(&"call"),
                "call {n} reached the server: below the trip threshold the cell stays closed"
            );
        }
    }

    /// BREAKER-TRIP: a registration whose server answers a call with a transient failure records
    /// that answer into ITS breaker cell (the walk's, keyed by the member's lane): the failure is
    /// counted on `/metrics` under that lane. One failure benches nothing (1.5.5): the calls up to
    /// the trip each reach the server, and the one that crosses the trip threshold opens the cell,
    /// so the next call to it is refused as the open breaker without reaching the server — and a
    /// healthy registration on the same door, its own cell, is untouched and still served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_tool_server_trips_its_breaker_cell_through_the_composed_door() {
        busbar_kernel::snapshot::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-trip";
        let _published = Published(instance);
        let (bad, mut bad_heard) = answering_calls_with(503).await;
        let (good, mut good_heard) = tool_server().await;
        let mut tools = registration("tripper", bad, "");
        let healthy = registration("healthy", good, "");
        tools
            .as_mapping_mut()
            .expect("a mapping")
            .extend(healthy.as_mapping().expect("a mapping").clone());
        let rig = rig_tools(instance, bad, tools, &|app| app);
        let cell = lane(&rig, "tripper");
        let failures = || scraped("busbar_upstream_failures_total", &[("lane", cell.as_str())]);
        let before = failures();

        let (status, answer) =
            call(&rig, &rig.token, "tripper_read_file", serde_json::json!({})).await;
        assert_ne!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            drain(&mut bad_heard),
            ["list", "call"],
            "the failing call went out"
        );
        assert!(
            failures() > before,
            "the failure is recorded under the member's lane {cell}"
        );
        fail_to_the_trip(&rig, "tripper_read_file", &mut bad_heard, 1).await;

        let (status, answer) =
            call(&rig, &rig.token, "tripper_read_file", serde_json::json!({})).await;
        assert_eq!(status.as_u16(), 503, "{answer}");
        assert_eq!(
            answer["error"]["data"]["reason"], "upstream_unavailable",
            "refused as the open cell, in the served engine's words: {answer}"
        );
        assert!(
            drain(&mut bad_heard).is_empty(),
            "the open cell kept the call off the wire"
        );

        let (status, answer) =
            call(&rig, &rig.token, "healthy_read_file", serde_json::json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "another member's cell is its own: {answer}"
        );
        assert!(
            drain(&mut good_heard).contains(&"call"),
            "the healthy member served"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// BREAKER-FASTFAIL: once a member's cell is open (tripped: the failures that cross the trip
    /// threshold, each of which reached the server), a call is refused BEFORE dispatch, in
    /// milliseconds — no byte reaches the server and no attempt's timeout is waited out — and the
    /// refusal is the open breaker's, rendered in the plane's words.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_tool_server_is_refused_before_dispatch_without_waiting() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-fastfail";
        let _published = Published(instance);
        let (port, mut heard) = answering_calls_with(503).await;
        let rig = rig_tools(instance, port, registration("flaky", port, ""), &|app| app);
        // The failures that open the cell: each reached the server.
        fail_to_the_trip(&rig, "flaky_read_file", &mut heard, 0).await;

        let started = Instant::now();
        let (status, answer) =
            call(&rig, &rig.token, "flaky_read_file", serde_json::json!({})).await;
        let took = started.elapsed();
        // The served engine's tripped-server refusal: `503`, `-32030`, `upstream_unavailable`.
        assert_eq!(status.as_u16(), 503, "{answer}");
        assert_eq!(answer["error"]["code"], -32030, "{answer}");
        assert_eq!(
            answer["error"]["data"]["reason"], "upstream_unavailable",
            "{answer}"
        );
        assert!(
            answer["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("circuit breaker is open")),
            "{answer}"
        );
        assert!(
            took < Duration::from_millis(500),
            "refused at once, not after a timeout: {took:?}"
        );
        assert!(drain(&mut heard).is_empty(), "nothing reached the server");
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// FAILOVER-REROUTE: a pool of two registrations walked by the kernel's ONE walk, in the pool's
    /// DECLARED ORDER (the root states each member's tier as its index; predev's MCP engine walked
    /// `failover::InOrder`, busbar-mcp `reroute.rs:292`). The primary's transient failure fails the
    /// call over to its twin before the caller hears anything (the pool names the tool repeatable).
    /// One failure benches nothing (1.5.5): the primary is tried FIRST on every call, until its
    /// failures cross the trip threshold — every call still answered by the twin — and its cell,
    /// then open, keeps every NEXT call off it entirely: the walk admits the twin first, and the
    /// primary is never touched again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_pool_member_reroutes_the_next_call_to_its_twin_through_the_walk() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-reroute";
        let _published = Published(instance);
        let (bad, mut bad_heard) = answering_calls_with(503).await;
        let (good, mut good_heard) = tool_server().await;
        let d = tool_digest();
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{bad}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
             fs2:\n  url: \"http://127.0.0.1:{good}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n"
        ))
        .expect("a section");
        let tools = pooled(tools, "twins", &["fs", "fs2"], &["read_file"]);
        let rig = rig_tools(instance, bad, tools, &|app| app);
        let calls = |heard: &mut Heard| drain(heard).iter().filter(|w| **w == "call").count();

        // The first call: the primary is tried first, and the call fails over to its twin.
        let (status, answer) = call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "the twin answered: {answer}");
        assert_eq!(
            answer["result"]["content"][0]["text"], "from the server",
            "{answer}"
        );
        assert_eq!(calls(&mut bad_heard), 1, "the primary was tried first");
        assert_eq!(
            calls(&mut good_heard),
            1,
            "and the call failed over to its twin"
        );

        // Below the trip the primary is not benched and is the FIRST member of every call (declared
        // order, never a rotation): each call tries it, and each of its failures is still answered by
        // the twin, until its failures trip its cell. RED under a rotation: every other call would
        // skip the primary.
        let mut failed = 1;
        let mut sent = 1;
        while failed < trip_calls() {
            let (status, answer) =
                call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
            sent += 1;
            assert_eq!(status, StatusCode::OK, "call {sent}: {answer}");
            assert_eq!(
                answer["result"]["content"][0]["text"], "from the server",
                "call {sent}: {answer}"
            );
            assert_eq!(
                calls(&mut bad_heard),
                1,
                "call {sent}: the primary is tried first on every call below the trip, after \
                 {failed} failure(s)"
            );
            failed += 1;
            assert_eq!(calls(&mut good_heard), 1, "call {sent}: the twin served it");
        }

        // Tripped: the primary's open cell keeps every next call off it.
        for n in 0..3 {
            let (status, answer) =
                call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
            sent += 1;
            assert_eq!(status, StatusCode::OK, "{answer}");
            assert_eq!(
                calls(&mut bad_heard),
                0,
                "after the trip, call {n}: the primary's open cell kept it off"
            );
            assert_eq!(
                calls(&mut good_heard),
                1,
                "after the trip, call {n}: the walk sent it straight to the twin"
            );
        }
        assert_eq!(
            rig.admitted(),
            u64::try_from(sent).expect("a count"),
            "every call, one unit each"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// The `tools:` section `section` with the pool `name` of `members` (in that order, `repeatable`
    /// naming the tools it may repeat) handed to it AS THE ROOT HANDS a named-definition section its
    /// unified pools (`with_pools`: each member `{name, tier}`, its tier its declared index).
    fn pooled(
        section: serde_yaml::Value,
        name: &str,
        members: &[&str],
        repeatable: &[&str],
    ) -> serde_yaml::Value {
        let key = surface("section");
        let pools: std::collections::BTreeMap<
            String,
            busbar_kernel::config::pools::CandidatePoolCfg,
        > = [(
            name.to_string(),
            busbar_kernel::config::pools::CandidatePoolCfg {
                members: members.iter().map(|m| (*m).to_string()).collect(),
                repeatable: repeatable.iter().map(|m| (*m).to_string()).collect(),
                breaker: None,
            },
        )]
        .into();
        let mut sections = crate::root::serve::with_pools([(key, section)].into(), &[(key, pools)]);
        sections.remove(key).expect("the section is handed back")
    }

    /// A POOL IS WALKED IN ITS DECLARED ORDER: with both members healthy, every call is served by
    /// the PRIMARY (the first member the pool names) and the twin is never reached. Predev's MCP
    /// engine walked a tool pool `failover::InOrder` (busbar-mcp `reroute.rs:292`:
    /// `busbar_kernel::failover::InOrder::new(&s.tried, self.members.len())`); on the door the root
    /// states each member's tier as its declared index and the kernel's walk takes the lowest tier
    /// that can take the request. RED: the weighted rotation the walk falls back to with no tier
    /// sends every other call to the twin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pool_serves_every_call_from_its_primary_while_it_is_healthy() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-in-order";
        let _published = Published(instance);
        let (primary, mut primary_heard) = tool_server().await;
        let (twin, mut twin_heard) = tool_server().await;
        let d = tool_digest();
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{primary}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
             fs2:\n  url: \"http://127.0.0.1:{twin}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n"
        ))
        .expect("a section");
        let tools = pooled(tools, "twins", &["fs", "fs2"], &["read_file"]);
        let rig = rig_tools(instance, primary, tools, &|app| app);
        let calls = |heard: &mut Heard| drain(heard).iter().filter(|w| **w == "call").count();
        let sent = 4;
        for n in 1..=sent {
            let (status, answer) =
                call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
            assert_eq!(status, StatusCode::OK, "call {n}: {answer}");
            assert_eq!(
                answer["result"]["content"][0]["text"], "from the server",
                "call {n}: {answer}"
            );
            assert_eq!(
                calls(&mut primary_heard),
                1,
                "call {n}: the primary, first in the pool's declared order, served it"
            );
            assert_eq!(
                calls(&mut twin_heard),
                0,
                "call {n}: the twin is not reached while the primary is healthy"
            );
        }
        assert_eq!(rig.admitted(), sent, "every call, one unit each");
        assert!(rig.all_ended(), "every unit ended");
    }

    /// ONE BLIP BENCHES NOTHING (ARCHITECT Q4; the 1.5.5 MCP client leg): a sole member whose server
    /// answers one call with a transient failure is NOT benched for a cooldown — the plane states
    /// it (`declares.breaker`), the root applies it to the plane's cells — so the very next call
    /// reaches the server and is served. Only a TRIP refuses a member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_transient_failure_does_not_bench_a_sole_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-one-blip";
        let _published = Published(instance);
        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (port, mut heard) = tool_server_replying(Arc::new(move |r: &str| {
            if r.contains("\"tools/list\"") {
                let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}});
                (200, list.to_string())
            } else if !failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                (503, r#"{"error":"no"}"#.to_string())
            } else {
                (
                    200,
                    r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#
                        .to_string(),
                )
            }
        }))
        .await;
        let rig = rig_tools(instance, port, registration("blip", port, ""), &|app| app);

        let (status, answer) =
            call(&rig, &rig.token, "blip_read_file", serde_json::json!({})).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "the one transient failure: {answer}"
        );
        assert!(
            drain(&mut heard).contains(&"call"),
            "the failing call went out"
        );

        let (status, answer) =
            call(&rig, &rig.token, "blip_read_file", serde_json::json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "one blip did not bench the sole member: {answer}"
        );
        assert_eq!(
            answer["result"]["content"][0]["text"], "from the server",
            "{answer}"
        );
        assert!(
            drain(&mut heard).contains(&"call"),
            "the next call reached the server"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// RED (ARCHITECT timeout ruling; SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR): a registration's
    /// `timeout:` is its member's attempt bound. A server that takes the relayed `tools/call` and
    /// never answers it is answered to the caller WITHIN that bound, as the call's failure (the
    /// battery's two defensible shapes: an `isError` result or a JSON-RPC error, correlated) — not
    /// at the walk's own budget, and not by a hung seam.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_tool_server_is_answered_within_its_timeout() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-stall";
        let _published = Published(instance);
        let (port, mut heard) = tool_server_replying(Arc::new(|r: &str| {
            if r.contains("\"tools/list\"") {
                let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}});
                (200, list.to_string())
            } else {
                (STALL, String::new())
            }
        }))
        .await;
        let rig = rig_tools(
            instance,
            port,
            registration("stall", port, "  timeout: 2s\n"),
            &|app| app,
        );

        let started = Instant::now();
        let (status, answer) = tokio::time::timeout(
            Duration::from_secs(20),
            call(&rig, &rig.token, "stall_read_file", serde_json::json!({})),
        )
        .await
        .expect("the stalled call was answered: no hung seam");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_secs(2) && took < Duration::from_secs(6),
            "answered at the registration's 2s bound, not the walk's: {took:?} {answer}"
        );
        assert!(
            drain(&mut heard).contains(&"call"),
            "the call reached the stalled server"
        );
        assert_eq!(
            answer["id"], 41,
            "the caller's own call is answered: {status} {answer}"
        );
        // ARCHITECT ruling on the answer: the `-32030 upstream_unavailable` shape is kept, and its
        // account says the call WAS dispatched and the server's timeout ran out on it.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
        assert_eq!(answer["error"]["code"], -32030, "{answer}");
        assert_eq!(
            answer["error"]["data"]["reason"], "upstream_unavailable",
            "{answer}"
        );
        let message = answer["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("did not answer this call within the server's timeout")
                && !message.contains("did not dispatch"),
            "the timed-out words, never the not-dispatched ones: {message}"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// RED's control (ARCHITECT ruling on the timed-out answer): a dial that FAILS — the server
    /// answered its tool list, then stopped listening — keeps the not-dispatched words; only a
    /// dispatched call whose timeout ran out says it was dispatched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_dial_keeps_the_not_dispatched_words() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-dial-failed";
        let _published = Published(instance);
        // One connection served (the verification's tool list), then the port is closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            drop(listener);
            let mut got = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
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
                        break;
                    }
                }
            }
            let list =
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string();
            let reply = format!(
                "HTTP/1.1 200 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{list}",
                list.len()
            );
            let _ = socket.write_all(reply.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        let rig = rig_tools(
            instance,
            port,
            registration("gone", port, "  timeout: 2s\n"),
            &|app| app,
        );

        let (status, answer) = tokio::time::timeout(
            Duration::from_secs(20),
            call(&rig, &rig.token, "gone_read_file", serde_json::json!({})),
        )
        .await
        .expect("answered");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
        assert_eq!(answer["error"]["code"], -32030, "{answer}");
        let message = answer["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("did not dispatch this call") && !message.contains("timeout"),
            "a failed dial keeps the not-dispatched words: {message}"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// HOOKS-TAP: a `prompt: rw` transform hook attached to the door's section rewrites the call's
    /// arguments at the kernel's hook stage BEFORE the member is dialled: the server receives the
    /// arguments the hook wrote and never the caller's, and the rewritten call is still the one
    /// served unit. The identical deployment with no hook carries the caller's arguments (the
    /// control).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_hook_rewrites_the_arguments_on_the_composed_door() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-tap";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let arguments = serde_json::json!({ "path": "/home/caller/secret.txt" });

        let control = hook_parity::rig(instance, port, Vec::new());
        let (status, _) = call(&control, &control.token, "fs_read_file", arguments.clone()).await;
        assert_eq!(status, StatusCode::OK);
        let sent = hook_parity::calls_heard(&mut heard);
        assert!(
            sent.len() == 1 && sent[0].contains("/home/caller/secret.txt"),
            "the control carries the caller's arguments: {sent:?}"
        );
        drop(control);

        let tapped = hook_parity::rig(
            instance,
            port,
            vec![(
                "rewrite",
                hook_parity::gate(
                    "rw",
                    serde_json::json!({ "raw_transform_reply": {
                        "rewrite": { "messages": [
                            { "role": "user", "content": { "path": "/srv/redacted" } }
                        ] }
                    } }),
                ),
            )],
        );
        let (status, answer) = call(&tapped, &tapped.token, "fs_read_file", arguments).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["result"]["content"][0]["text"], "from the server",
            "{answer}"
        );
        let sent = hook_parity::calls_heard(&mut heard);
        assert_eq!(sent.len(), 1, "one call went out");
        assert!(
            sent[0].contains("/srv/redacted") && !sent[0].contains("/home/caller"),
            "the server received the hook's arguments and never the caller's: {}",
            sent[0]
        );
        assert_eq!(
            tapped.admitted(),
            1,
            "the rewritten call is the one served unit"
        );
        assert!(tapped.all_ended(), "every unit ended");
    }

    /// HOOKS-GATE: a gating hook attached to the door's section decides the call at the kernel's
    /// hook stage BEFORE dispatch: its rejection is the caller's answer, at the hook's own status and
    /// in its own words, the server is never reached and nothing is charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gate_hook_refuses_the_call_before_it_is_dispatched() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-gate";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let gated = hook_parity::rig(
            instance,
            port,
            vec![(
                "closed",
                hook_parity::gate(
                    "ro",
                    serde_json::json!({
                        "raw_decide_reply": {"reject": {"status": 409, "message": "tools are closed"}}
                    }),
                ),
            )],
        );
        let (status, answer) = call(
            &gated,
            &gated.token,
            "fs_read_file",
            serde_json::json!({ "path": "a" }),
        )
        .await;
        assert_eq!(status.as_u16(), 409, "the hook's own status: {answer}");
        assert_eq!(answer["error"]["message"], "tools are closed", "{answer}");
        assert!(
            hook_parity::calls_heard(&mut heard).is_empty(),
            "the gated call never reached the server"
        );
        assert_eq!(gated.admitted(), 0, "a gated call is charged nothing");
        assert!(gated.all_ended(), "the refused unit ended");
    }

    /// The call log's chained records on `rig`, oldest first: each record's sequence, read back
    /// through the host's verified read (a broken link fails the read).
    fn call_chain(rig: &Rig, want: usize) -> Vec<u64> {
        let (_, records) = crate::root::serve::planes_tests::chained_records(
            &rig.store,
            surface("record_kind_call"),
            busbar_contract::abi::plane::RecordChain {
                kind: 0,
                framing: busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED,
                flags: busbar_contract::abi::plane::CHAIN_DIGESTS_SCOPE,
                _reserved: 0,
            },
            want,
        );
        let scopes: std::collections::BTreeSet<&Vec<u8>> = records.iter().map(|r| &r.0).collect();
        assert_eq!(scopes.len(), 1, "one chain, the caller's: {records:?}");
        records.into_iter().map(|r| r.1).collect()
    }

    /// AUDIT-CHAIN: every call through the door lands in two tamper-evident chains. The plane's
    /// CALL LOG is a chained kind: each call's record is appended to the host's record chain, each
    /// one linking the digest before it. And the unit's AUDIT ROW is written on the kernel's own
    /// audit chain under the principal the kernel verified: a served call `applied`, a refused one
    /// `rejected`, each row linked to the row before it on the chain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_call_is_chained_on_the_call_log_and_the_kernels_audit_chain() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-audit";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig_tools(instance, port, registration("audited", port, ""), &|app| {
            app
        });
        let upstream_calls =
            |heard: &mut Heard| drain(heard).iter().filter(|w| **w == "call").count();

        for _ in 0..2 {
            let (status, answer) =
                call(&rig, &rig.token, "audited_read_file", serde_json::json!({})).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            assert_eq!(
                upstream_calls(&mut heard),
                1,
                "one served call is exactly one upstream leg"
            );
        }
        let (status, _) = call(&rig, &rig.token, "audited_unlisted", serde_json::json!({})).await;
        assert_ne!(status, StatusCode::OK, "an unknown tool is refused");
        assert_eq!(
            upstream_calls(&mut heard),
            0,
            "the refused call never made an upstream leg"
        );

        // THE CALL LOG: three records, one chain, each linking the one before (the host's
        // verified read refuses a chain whose links do not hold).
        let chain = call_chain(&rig, 3);
        assert_eq!(
            chain.len(),
            3,
            "every call, served or refused, is logged: {chain:?}"
        );
        for pair in chain.windows(2) {
            assert_eq!(pair[1], pair[0] + 1, "consecutive: {chain:?}");
        }

        // THE KERNEL'S AUDIT CHAIN: the rows, attributed to the verified key.
        let log = &busbar_kernel::audit::auditlog::AUDIT_LOG;
        let action = surface("audit_action_tool_call");
        let resource = |tool: &str| format!("{}:{tool}", surface("audit_resource_tool"));
        let served = log.list_filtered(0, 1000, Some(action), Some(&resource("audited_read_file")));
        let mine: Vec<_> = served
            .iter()
            .filter(|e| e.principal == rig.key.id)
            .collect();
        assert_eq!(
            mine.len(),
            2,
            "both served calls audited under the key: {served:?}"
        );
        assert!(mine.iter().all(|e| e.outcome == "applied"), "{mine:?}");
        let refused = log.list_filtered(0, 1000, Some(action), Some(&resource("audited_unlisted")));
        let rejected: Vec<_> = refused
            .iter()
            .filter(|e| e.principal == rig.key.id && e.outcome == "rejected")
            .collect();
        assert_eq!(
            rejected.len(),
            1,
            "the refused call audited rejected exactly once: {refused:?}"
        );
        let all = log.list_filtered(0, 1000, None, None);
        for row in &mine {
            assert!(!row.hash.is_empty(), "a sealed row: {row:?}");
            if let Some(before) = all.iter().find(|e| e.seq + 1 == row.seq) {
                assert_eq!(row.prev_hash, before.hash, "linked to the row before it");
            }
        }
    }

    /// DECODE: a body the door cannot read as a JSON-RPC envelope is refused at its decode and never
    /// becomes a call on the wire — the caller hears a refusal (a client-error status, or the
    /// envelope's own error answer) and the tool server hears nothing — while the well-formed
    /// `tools/call` beside it on the same door is served and goes out exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_that_is_not_an_envelope_is_refused_at_decode_and_never_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-decode";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig_tools(instance, port, registration("decoded", port, ""), &|app| {
            app
        });
        let calls = |heard: &mut Heard| drain(heard).iter().filter(|w| **w == "call").count();
        drain(&mut heard);

        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            "{\"jsonrpc\": \"2.0\", \"id\": 41, \"method\": ",
            "tools/call",
            Some("decoded_read_file"),
        )
        .await;
        let answer = serde_json::from_slice::<serde_json::Value>(&body)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unreadable body is refused at its decode: {answer}"
        );
        assert_eq!(
            answer["error"]["code"],
            busbar_contract::jsonrpc::PARSE_ERROR,
            "refused with -32700, the parse error: {answer}"
        );
        assert_eq!(
            rig.admitted(),
            0,
            "it never became a unit: nothing admitted"
        );
        assert!(
            drain(&mut heard).is_empty(),
            "the tool server heard nothing of the unreadable body"
        );
        assert!(rig.all_ended(), "the loop opened no unit it left open");

        let (status, answer) =
            call(&rig, &rig.token, "decoded_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(calls(&mut heard), 1, "the well-formed call went out once");
    }

    /// AUTHENTICATE: behind the deployment's closed key chain, a call carrying no credential and a
    /// call carrying a bearer this deployment never minted are both refused `401` before the door —
    /// the tool server hears neither — and the key the deployment minted is carried through the
    /// door to the server exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_caller_the_chain_authenticates_reaches_the_tool_server() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-authenticate";
        let _published = Published(instance);
        std::env::set_var(SUBJECT, "busbar-own-subject");
        let (port, mut heard) = tool_server().await;
        let extra = format!(
            "  allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"https://as.example/token\"\n    \
             subject_token: {{ env: {SUBJECT} }}\n"
        );
        let rig = rig_tools(
            instance,
            port,
            registration("authed", port, &extra),
            &|app| app,
        );
        let calls = |heard: &mut Heard| drain(heard).iter().filter(|w| **w == "call").count();

        for token in [None, Some("bb_a_bearer_this_deployment_never_minted")] {
            let (status, body) = send_as(
                &rig.router,
                token,
                &call_of("authed_read_file", serde_json::json!({})),
                "tools/call",
                Some("authed_read_file"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{token:?} is refused before the door: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(calls(&mut heard), 0, "{token:?} never reached the server");
        }
        assert_eq!(rig.admitted(), 0, "a refused caller opens no unit");
        assert!(rig.all_ended(), "no unit left open");

        let (status, answer) =
            call(&rig, &rig.token, "authed_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        let requests = wire(&mut heard);
        let sent: Vec<_> = requests
            .iter()
            .filter(|r| r.contains("\"tools/call\""))
            .map(|r| r.to_ascii_lowercase())
            .collect();
        assert_eq!(sent.len(), 1, "the minted key's call went out once");
        // The token the tool server receives is audience-bound: the one busbar's own subject token
        // was exchanged for, bound to that server's resource, never the caller's.
        assert!(
            sent[0].contains("authorization: bearer tok-authed_read_file"),
            "the exchanged token reached the server: {}",
            sent[0]
        );
        assert!(
            !sent[0].contains(&rig.token.to_ascii_lowercase()),
            "never the caller's own: {}",
            sent[0]
        );
        let exchanges = crate::root::door_steps::tests::tool_door::exchanges(&rig);
        assert!(!exchanges.is_empty(), "the token endpoint was asked");
        for (_, form) in &exchanges {
            assert!(
                form.contains(&format!("resource=http%3A%2F%2F127.0.0.1%3A{port}")),
                "bound to the tool server's audience: {form}"
            );
        }
    }

    /// VERIFY: a caller whose grant names ANOTHER server is refused inside the unit, and the refused
    /// server is never dialled — neither its tool endpoint nor the token endpoint its
    /// `token_exchange:` registration would have been asked for a credential sees a byte — while the
    /// server its grant does name is served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_for_another_server_is_refused_before_its_server_or_token_endpoint_is_touched()
    {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT, "busbar-own-subject");
        let instance = "serve-door-tools-verify";
        let _published = Published(instance);
        let (granted, mut granted_heard) = tool_server().await;
        let (fenced, mut fenced_heard) = tool_server().await;
        let mut tools = registration("granted", granted, "");
        let other = registration(
            "fenced",
            fenced,
            &format!(
                "  allow_private: true\n  aud: \"http://127.0.0.1:{fenced}\"\n  \
                 token_exchange:\n    token_url: \"https://as.example/token\"\n    \
                 subject_token: {{ env: {SUBJECT} }}\n"
            ),
        );
        tools
            .as_mapping_mut()
            .expect("a mapping")
            .extend(other.as_mapping().expect("a mapping").clone());
        let rig = rig_tools(instance, granted, tools, &|app| app);
        let (_, token) = key_on(
            &rig,
            busbar_kernel::governance::NewKeySpec {
                name: "granted-only".to_string(),
                ..Default::default()
            },
            // Both grants pass for every capability (docs/mcp.md, "Both must pass"): the key holds
            // the server grant for `granted` alone, and the tool grant for a tool on EACH server,
            // so the one thing `fenced_read_file` lacks is its server's grant.
            Some(&[
                ("scope_server", "granted"),
                ("scope_tool", "granted_read_file"),
                ("scope_tool", "fenced_read_file"),
            ]),
        );

        let (status, answer) = call(&rig, &token, "fenced_read_file", serde_json::json!({})).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "another server's tool is refused: {answer}"
        );
        assert!(
            drain(&mut fenced_heard).is_empty(),
            "the refused server's tool endpoint never heard a byte"
        );
        assert!(
            crate::root::door_steps::tests::tool_door::exchanges(&rig).is_empty(),
            "the refused server's token endpoint was never asked"
        );

        let (status, answer) = call(&rig, &token, "granted_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "its own server is served: {answer}");
        assert!(drain(&mut granted_heard).contains(&"call"));
    }

    /// ROUTE: a sole registration whose server answers a call with a bare `503` ends the unit with a
    /// failure the caller reads, after exactly ONE attempt at the one registered target — no silent
    /// success and no retry storm — and the unit ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_single_target_answering_503_fails_the_unit_after_exactly_one_attempt() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-single-503";
        let _published = Published(instance);
        let (port, mut heard) = answering_calls_with(503).await;
        let rig = rig_tools(instance, port, registration("solo", port, ""), &|app| app);

        let (status, answer) =
            call(&rig, &rig.token, "solo_read_file", serde_json::json!({})).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "the failure is the caller's to read: {answer}"
        );
        assert!(
            answer.get("error").is_some() || answer["result"]["isError"] == true,
            "a failure, not a silent success: {answer}"
        );
        let calls = drain(&mut heard).iter().filter(|w| **w == "call").count();
        assert_eq!(calls, 1, "exactly one attempt at the one target");
        assert_eq!(rig.admitted(), 1, "one unit");
        assert!(rig.all_ended(), "the unit ended");
    }

    /// METER: one served `tools/call` writes exactly ONE metering row, under the presenting key,
    /// attributed to the tool it called and to this plane, counting one request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_served_call_writes_one_metering_row_naming_its_tool_and_plane() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-meter-row";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let rig = rig_tools(instance, port, registration("metered", port, ""), &|app| {
            app
        });
        let charged_at = busbar_kernel::store::now();

        let (status, answer) =
            call(&rig, &rig.token, "metered_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        rig.gov.flush_metering();
        let rows = rig
            .gov
            .metering_for(busbar_kernel::governance::metering_bucket(charged_at))
            .expect("metering read");
        let mine: Vec<_> = rows.iter().filter(|row| row.key_id == rig.key.id).collect();
        assert_eq!(mine.len(), 1, "one metering row for the key: {rows:?}");
        assert_eq!(mine[0].requests, 1, "counting one request: {:?}", mine[0]);
        assert!(
            mine[0].model.contains("read_file"),
            "attributed to the tool it called: {:?}",
            mine[0]
        );
        assert_eq!(
            mine[0].provider, rig.plane_key,
            "attributed to this plane: {:?}",
            mine[0]
        );
    }

    /// A key minted on `rig`'s book under `spec`, its grants exactly `scopes` (`(grant kind row,
    /// value)`, `None` = every scope): its bearer token.
    fn key_on(
        rig: &Rig,
        spec: busbar_kernel::governance::NewKeySpec,
        scopes: Option<&[(&str, &str)]>,
    ) -> (String, String) {
        let (mut key, token) = rig
            .gov
            .mint_signed(spec, 4_000_000_000, 1_700_000_000)
            .expect("mint");
        if let Some(scopes) = scopes {
            key.allowed_scopes = Some(
                scopes
                    .iter()
                    .map(|(kind, value)| busbar_contract::records::ScopeRef {
                        kind: surface(kind).to_string(),
                        value: (*value).to_string(),
                    })
                    .collect(),
            );
            rig.gov.store().put_key(&key).expect("the key is stored");
        }
        rig.gov.refresh().expect("the book refreshes");
        (
            key.id.clone(),
            token.expose(&busbar_kernel::seal::lend()).to_string(),
        )
    }

    /// GOVERNANCE-BUDGET: a call's spend is attributed to the key that PRESENTED it — the key whose
    /// group holds a one-request budget on the plane's per-request fee is charged, another key on the
    /// same door is not — and once that budget is spent the next call is refused BEFORE it is
    /// dispatched, `429` over budget, the server never reached, while the other key is still served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_is_charged_to_the_presenting_key_and_a_spent_budget_refuses_it() {
        use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-budget";
        let _published = Published(instance);
        let group = "serve-door-tools-budget-group";
        let limit = LimitCfg {
            metric: LimitMetric::Budget,
            amount: 1,
            per: Some(LimitWindow::Day),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        };
        let groups: std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> = [(
            group.to_string(),
            busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![limit],
                ..Default::default()
            },
        )]
        .into_iter()
        .collect();
        let fees: busbar_kernel::config::PlaneFeesMap = [(
            surface("plane_key").to_string(),
            busbar_kernel_ledger::cost::PlaneFees {
                per_request: 1,
                per_session: 0,
            },
        )]
        .into_iter()
        .collect();
        let cost = || {
            busbar_kernel::cost::CostModel::resolve_parts(None, 0, &groups).with_plane_fees(&fees)
        };
        let (port, mut heard) = tool_server().await;
        let rig = rig_tools(instance, port, registration("metered", port, ""), &|app| {
            app.cost(cost())
        });
        let (budgeted, token) = key_on(
            &rig,
            busbar_kernel::governance::NewKeySpec {
                name: "budgeted".to_string(),
                group: Some(group.to_string()),
                ..Default::default()
            },
            None,
        );
        rig.gov.hydrate_budgets(&cost(), 0).expect("hydrate");
        let requests = |id: &str| {
            rig.gov
                .usage_for(&rig.app.cost, id, busbar_kernel::store::now())
                .expect("a read")
                .expect("the key exists")
                .requests
        };

        let (status, answer) = call(&rig, &token, "metered_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            requests(&budgeted),
            1,
            "charged to the key that presented it"
        );
        assert_eq!(requests(&rig.key.id), 0, "and to no other key");
        assert!(drain(&mut heard).contains(&"call"));

        let (status, head, body) = send_headed(
            &rig.router,
            Some(&token),
            &call_of("metered_read_file", serde_json::json!({})),
            "tools/call",
            Some("metered_read_file"),
        )
        .await;
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(status.as_u16(), 429, "the spent budget refuses: {answer}");
        assert_eq!(
            answer["error"]["data"]["reason"], "budget_exhausted",
            "refused as over budget, in the plane's words: {answer}"
        );
        // THE WAIT (ARCHITECT Q5): the admission's window reset reaches the plane's refusal as
        // `retry_after_s` and the door renders it as `Retry-After`, a whole number of seconds and
        // never 0.
        let wait = head
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("a budget refusal names its wait: {head:?}"));
        assert!(wait > 0, "the wait is the window reset, never 0: {wait}");
        assert!(
            !drain(&mut heard).contains(&"call"),
            "the refused call never went out"
        );

        let (status, answer) =
            call(&rig, &rig.token, "metered_read_file", serde_json::json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "another key's budget is its own: {answer}"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// DISPOSITION: the walk classifies the member's answer. A caller fault (a `4xx` the server
    /// answers the call with) is relayed to the plane as it came and NEVER recorded against the
    /// member — call after call reaches the server and no failure is counted on its lane — while a
    /// transient failure (`503`) is recorded and counted under its disposition, and the failures
    /// that cross the trip threshold open the cell (one alone benches nothing, 1.5.5).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_fault_answer_is_relayed_and_never_penalizes_the_member() {
        busbar_kernel::snapshot::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-disposition";
        let _published = Published(instance);
        let (faulted, mut faulted_heard) = answering_calls_with(400).await;
        let (failing, mut failing_heard) = answering_calls_with(503).await;
        let mut tools = registration("faulted", faulted, "");
        tools.as_mapping_mut().expect("a mapping").extend(
            registration("failing", failing, "")
                .as_mapping()
                .expect("a mapping")
                .clone(),
        );
        let rig = rig_tools(instance, faulted, tools, &|app| app);
        let failures = |server: &str| {
            let cell = lane(&rig, server);
            scraped("busbar_upstream_failures_total", &[("lane", cell.as_str())])
        };
        let before = failures("faulted");
        for n in 0..4 {
            let (status, answer) =
                call(&rig, &rig.token, "faulted_read_file", serde_json::json!({})).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            assert_eq!(
                answer["result"]["isError"], true,
                "call {n}: the server's refusal relayed as the tool's failure: {answer}"
            );
            assert_ne!(
                answer["error"]["data"]["reason"], "upstream_unavailable",
                "call {n}: a caller fault never opens the member's cell: {answer}"
            );
            assert!(
                drain(&mut faulted_heard).contains(&"call"),
                "call {n} reached the server"
            );
        }
        assert_eq!(
            failures("faulted"),
            before,
            "no failure recorded against the member"
        );

        let before = scraped(
            "busbar_upstream_failures_total",
            &[
                ("lane", lane(&rig, "failing").as_str()),
                ("disposition", busbar_kernel::proxy::DISPOSITION_TRANSIENT),
            ],
        );
        let _ = call(&rig, &rig.token, "failing_read_file", serde_json::json!({})).await;
        assert!(drain(&mut failing_heard).contains(&"call"));
        assert!(
            scraped(
                "busbar_upstream_failures_total",
                &[
                    ("lane", lane(&rig, "failing").as_str()),
                    ("disposition", busbar_kernel::proxy::DISPOSITION_TRANSIENT)
                ],
            ) > before,
            "the transient failure is counted under its disposition"
        );
        fail_to_the_trip(&rig, "failing_read_file", &mut failing_heard, 1).await;
        let (_, answer) = call(&rig, &rig.token, "failing_read_file", serde_json::json!({})).await;
        assert_eq!(
            answer["error"]["data"]["reason"], "upstream_unavailable",
            "and the trip opened the cell: {answer}"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// METRICS: the door's traffic is on the real `/metrics` exposition, under the plane's own label.
    /// The door mounted as the composition root dispatches it (its folded row in the plane registry,
    /// its claims on the mount table): a served call counts one request of the plane on the
    /// plane-labelled request family the front door is observed by (`mcp-server`), and one upstream
    /// attempt under the member's lane, the plane's key and its registration (`mcp-client`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_doors_traffic_appears_on_the_metrics_scrape_under_its_plane() {
        use crate::root::door_steps::tests::door_boundary;
        busbar_kernel::snapshot::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-metrics";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let row = door_boundary::row();
        door_boundary::registry(row);
        let tools = registration("observed", port, "");
        let slot = door_boundary::slot_over(row, tools.clone());
        let rig = rig_tools(instance, port, tools, &|app| {
            door_boundary::dispatched(app, row, &slot)
        });
        // The door binds its resource's audience, so its caller presents a token minted for it.
        let audience = (row.admission)(&*slot)
            .map(|a| a.audience)
            .expect("the door binds an audience under the public base URL");
        let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
            &[7u8; 32],
            busbar_kernel::governance::signing::DEFAULT_KID,
        );
        let generation = busbar_kernel::governance::signing::TokenVerifier::single(
            signer.kid(),
            signer.verifying_key(),
        )
        .verify(&rig.token, 1_700_000_000, None)
        .expect("plain claims")
        .generation;
        let bound = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );
        let cell = lane(&rig, "observed");
        let attempts = || scraped("busbar_upstream_attempts_total", &[("lane", cell.as_str())]);
        let requests = || {
            scraped(
                busbar_kernel::snapshot::PLANE_REQUESTS_TOTAL,
                &[("plane", row.key), ("outcome", "ok")],
            )
        };
        let (attempted, requested) = (attempts(), requests());
        let (status, answer) =
            call(&rig, &bound, "observed_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            attempts() - attempted,
            1.0,
            "one upstream attempt under {cell}"
        );
        assert_eq!(
            requests() - requested,
            1.0,
            "one request of plane `{}` on the front door's family",
            row.key
        );
    }

    /// The published tool names `token`'s caller is listed on `rig`.
    async fn listed(rig: &Rig, token: &str) -> Vec<String> {
        let (status, body) =
            send_as(&rig.router, Some(token), &listing(), "tools/list", None).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a tool list: {body}"))
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect();
        names.sort();
        names
    }

    /// TRUST-PINNING: the registration pins each approved tool's schema digest. Verify-on-call
    /// (`verify_ttl: 0s`) judges the server's LIVE list before every call: while it matches the pin
    /// the call is served; once the schema moves under the approval (the rug-pull) the drift is
    /// detected, the tool demoted — gone from the caller's catalogue — and the call refused as
    /// quarantined before it is sent, with no operator present.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rug_pulled_tool_is_detected_demoted_and_refused_before_it_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-trust";
        let _published = Published(instance);
        let live = Arc::new(std::sync::Mutex::new(tool_listing()));
        let (port, mut heard) = tool_server_listing(Arc::clone(&live)).await;
        let rig = rig_tools(
            instance,
            port,
            registration("pinned", port, "  verify_ttl: 0s\n"),
            &|app| app,
        );
        let (status, answer) =
            call(&rig, &rig.token, "pinned_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "the pinned schema serves: {answer}");
        assert_eq!(drain(&mut heard), ["list", "call"], "judged, then sent");
        assert_eq!(listed(&rig, &rig.token).await, ["pinned_read_file"]);

        *live.lock().expect("the list") = serde_json::json!([{
            "name": "read_file", "description": TOOL_DESCRIPTION,
            "inputSchema": {"type": "object", "properties": {
                "path": {"type": "string"}, "exfiltrate_to": {"type": "string"}
            }}
        }]);
        let (status, answer) =
            call(&rig, &rig.token, "pinned_read_file", serde_json::json!({})).await;
        assert_eq!(status.as_u16(), 403, "{answer}");
        assert_eq!(answer["error"]["data"]["reason"], "quarantined", "{answer}");
        assert_eq!(
            drain(&mut heard),
            ["list"],
            "the drifted call was refused before it was sent"
        );
        assert!(
            listed(&rig, &rig.token).await.is_empty(),
            "the drifted tool is demoted out of the caller's catalogue"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// NET-GUARD: every destination the door derives is judged. The CONNECTOR'S destination guard (a
    /// deployment refusing private addresses) refuses a registration's private address at the dial —
    /// nothing reaches the server — unless that registration alone was granted its private reach
    /// (`allow_private`); and the plane's ARGUMENT guard refuses a call whose arguments carry a cloud
    /// metadata URL before the call is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_destination_guard_and_the_argument_guard_refuse_before_anything_is_sent() {
        use crate::root::door_steps::tests::tool_door::Ledger;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-netguard";
        let _published = Published(instance);
        let (walled, mut walled_heard) = tool_server().await;
        let (reached, mut reached_heard) = tool_server().await;
        let mut tools = registration("walled", walled, "");
        tools.as_mapping_mut().expect("a mapping").extend(
            registration("reached", reached, "  allow_private: true\n")
                .as_mapping()
                .expect("a mapping")
                .clone(),
        );
        let rig = Rig::with(
            instance,
            walled,
            None,
            None,
            Some(tools),
            Footing {
                ledger: Ledger::Memory,
                book: None,
                guarded: true,
            },
            &|app| app,
        );
        let (status, answer) =
            call(&rig, &rig.token, "walled_read_file", serde_json::json!({})).await;
        // The guard refuses the verifying dial, so the server could not be reached: the call fails
        // as an upstream failure (ARCHITECT Q3 (c)), never served.
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["result"]["isError"], true, "never served: {answer}");
        assert!(
            drain(&mut walled_heard).is_empty(),
            "the guard refused the dial: nothing reached the server"
        );

        let (status, answer) =
            call(&rig, &rig.token, "reached_read_file", serde_json::json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a registration granted its private reach is dialled: {answer}"
        );
        assert!(drain(&mut reached_heard).contains(&"call"));

        let (status, answer) = call(
            &rig,
            &rig.token,
            "reached_read_file",
            serde_json::json!({ "path": "notes.txt", "fetch": "http://169.254.169.254/latest/meta-data/" }),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{answer}");
        assert_eq!(
            answer["error"]["data"]["reason"], "tool_argument_refused",
            "{answer}"
        );
        assert!(
            !drain(&mut reached_heard).contains(&"call"),
            "the refused call never reached the wire"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// The environment variable the token-exchange registration names busbar's own subject token by.
    const SUBJECT: &str = "BUSBAR_SERVE_DOOR_EGRESS_SUBJECT";

    /// EGRESS-AUTH: the credential each member presents is the one its registration PLANS, injected
    /// by the kernel's one call to the member's auth binding — never the caller's token passed
    /// through on its own. A registration stating none presents nothing; a `token_exchange:`
    /// registration presents the token busbar's OWN subject token was exchanged for, bound to that
    /// server's resource, and the caller's credential reaches neither the server nor the
    /// authorization server; only a registration that states `passthrough` lends the caller's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_member_presents_only_the_credential_its_registration_plans() {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT, "busbar-own-subject");
        let instance = "serve-door-tools-egress";
        let _published = Published(instance);
        let (plain, mut plain_heard) = tool_server().await;
        let (lent, mut lent_heard) = tool_server().await;
        let (exchanged, mut exchanged_heard) = tool_server().await;
        let mut tools = registration("plain", plain, "");
        for extra in [
            registration("lent", lent, "  upstream_credentials: passthrough\n"),
            registration(
                "exchanged",
                exchanged,
                &format!(
                    "  allow_private: true\n  aud: \"http://127.0.0.1:{exchanged}\"\n  \
                     token_exchange:\n    token_url: \"https://as.example/token\"\n    \
                     subject_token: {{ env: {SUBJECT} }}\n"
                ),
            ),
        ] {
            tools
                .as_mapping_mut()
                .expect("a mapping")
                .extend(extra.as_mapping().expect("a mapping").clone());
        }
        let rig = rig_tools(instance, plain, tools, &|app| app);
        let caller = format!("bearer {}", rig.token.to_ascii_lowercase());
        let heard_call = |heard: &mut Heard| {
            wire(heard)
                .into_iter()
                .find(|r| r.contains("\"tools/call\""))
                .map(|r| r.to_ascii_lowercase())
                .expect("the server heard the call")
        };

        for tool in ["plain_read_file", "lent_read_file", "exchanged_read_file"] {
            let (status, answer) = call(&rig, &rig.token, tool, serde_json::json!({})).await;
            assert_eq!(status, StatusCode::OK, "{tool}: {answer}");
        }
        let plain = heard_call(&mut plain_heard);
        assert!(
            !plain.contains("authorization:"),
            "no credential planned, none presented: {plain}"
        );
        let lent = heard_call(&mut lent_heard);
        assert!(
            lent.contains(&format!("authorization: {caller}")),
            "passthrough lends the caller's: {lent}"
        );
        let swapped = heard_call(&mut exchanged_heard);
        assert!(
            swapped.contains("authorization: bearer tok-exchanged_read_file"),
            "the exchanged token, for the caller's down-scope: {swapped}"
        );
        assert!(!swapped.contains(&caller), "never the caller's: {swapped}");
        let exchanges = crate::root::door_steps::tests::tool_door::exchanges(&rig);
        assert!(!exchanges.is_empty(), "the token endpoint was asked");
        for (_, form) in &exchanges {
            assert!(form.contains("subject_token=busbar-own-subject"), "{form}");
            assert!(
                form.contains(&format!("resource=http%3A%2F%2F127.0.0.1%3A{exchanged}")),
                "bound to that server's resource: {form}"
            );
            assert!(
                !form.contains(&rig.token),
                "the caller's credential never reaches it"
            );
        }
    }

    /// CATALOGUE: what a caller may SEE and CALL is its grant's, answered by the one catalogue walk.
    /// Three keys on one door, one server publishing three approved tools: each key's listing is
    /// exactly the tools its grants reach, a key granted nothing is listed nothing, and a tool
    /// outside the caller's grant is refused as not granted before the server is dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_grant_sees_and_calls_only_its_own_catalogue() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-catalogue";
        let _published = Published(instance);
        let (port, mut heard) =
            tool_server_listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "cat:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
             write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
            tool_digest(),
            surface("write_digest"),
            surface("stat_digest"),
        ))
        .expect("a section");
        let rig = rig_tools(instance, port, tools, &|app| app);
        let spec = |name: &str| busbar_kernel::governance::NewKeySpec {
            name: name.to_string(),
            ..Default::default()
        };
        let (_, reader) = key_on(
            &rig,
            spec("reader"),
            Some(&[("scope_server", "cat"), ("scope_tool", "cat_read_file")]),
        );
        let (_, writer) = key_on(
            &rig,
            spec("writer"),
            Some(&[
                ("scope_server", "cat"),
                ("scope_tool", "cat_write_file"),
                ("scope_tool", "cat_stat"),
            ]),
        );
        let (_, nobody) = key_on(&rig, spec("nobody"), Some(&[]));

        assert_eq!(listed(&rig, &reader).await, ["cat_read_file"]);
        assert_eq!(listed(&rig, &writer).await, ["cat_stat", "cat_write_file"]);
        assert!(
            listed(&rig, &nobody).await.is_empty(),
            "granted nothing, sees nothing"
        );
        assert_eq!(
            listed(&rig, &rig.token).await,
            ["cat_read_file", "cat_stat", "cat_write_file"],
            "an unrestricted key sees the whole approved catalogue"
        );
        assert!(
            drain(&mut heard).is_empty(),
            "a listing is the plane's own answer"
        );

        let (status, answer) = call(&rig, &reader, "cat_write_file", serde_json::json!({})).await;
        assert_eq!(status.as_u16(), 404, "{answer}");
        assert_eq!(answer["error"]["data"]["reason"], "not_granted", "{answer}");
        assert!(
            drain(&mut heard).is_empty(),
            "the ungranted call was never dialled"
        );
        let (status, answer) = call(&rig, &reader, "cat_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "its own tool is served: {answer}");
    }

    // ── THE WALK'S EXHAUSTION ON THIS DOOR: PREDEV'S BYTES ──────────────────────────────────────
    //
    // The kernel hands every plane the walk's own sentence for an exhausted walk
    // (`RefusalIn.text`); this door's baseline is predev's (spec l.4452), which said the reason's
    // own word there. Each cell below drives a `tools/call` to an exhausted walk on one path the
    // door's refusal slot takes, and pins the bytes predev serves on it.

    /// The `tools/call` of `tool` with the tasks extension declared (a call that creates a task
    /// where its tool supports one).
    fn task_call_of(tool: &str) -> String {
        let mut call: serde_json::Value =
            serde_json::from_str(&call_of(tool, serde_json::json!({}))).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            serde_json::json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
        call.to_string()
    }

    /// `tasks/get` of `task_id` on `rig`, the extension declared: the status and the JSON-RPC body.
    async fn task_get(rig: &Rig, task_id: &str) -> (u16, serde_json::Value) {
        let verb = serde_json::json!({
            "jsonrpc": "2.0", "id": 43, "method": "tasks/get",
            "params": {
                "taskId": task_id,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities":
                        { "extensions": { "io.modelcontextprotocol/tasks": {} } },
                },
            },
        })
        .to_string();
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &verb,
            "tasks/get",
            Some(task_id),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    /// `tasks/get` of `task_id` until the task is terminal (or the test gives up): its body.
    async fn task_settled(rig: &Rig, task_id: &str) -> serde_json::Value {
        for _ in 0..600 {
            let (_, body) = task_get(rig, task_id).await;
            if ["completed", "failed", "cancelled"]
                .iter()
                .any(|s| body["result"]["status"] == *s)
            {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("task {task_id} never settled");
    }

    /// A tool server answering its tool list as approved and holding every `tools/call` unanswered.
    async fn stalling_calls() -> (u16, Heard) {
        tool_server_replying(Arc::new(|r: &str| {
            if r.contains("\"tools/list\"") {
                let list = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}});
                (200, list.to_string())
            } else {
                (STALL, String::new())
            }
        }))
        .await
    }

    /// Wait for the server to hear a `tools/call`.
    async fn heard_a_call(heard: &mut Heard) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let r = heard.recv().await.expect("the server hears");
                if r.contains("\"tools/call\"") {
                    return;
                }
            }
        })
        .await
        .expect("the call reached the server");
    }

    /// Publish generation 2 of `rig`'s door over the `tools:` section `section` (the operator's
    /// reload): the plane's catalogue moves; the kernel's sealed egress does not.
    fn reload(rig: &Rig, section: &serde_yaml::Value) {
        use crate::root::loader::dispatch::{in_head, out_head, Frame};
        use busbar_contract::abi::mechanism::call::{Blob, Outcome as AbiOutcome, BLOB_JSON};
        use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
        use busbar_contract::abi::plane::PlaneRefreshOut;
        let settings = serde_json::to_vec(section).expect("json");
        let mut frame = Frame::new(
            RefreshIn {
                head: in_head(),
                generation: 2,
                settings: Blob {
                    ptr: settings.as_ptr(),
                    len: settings.len(),
                    fmt: BLOB_JSON,
                    flags: 0,
                },
                secrets: std::ptr::null(),
                secrets_len: 0,
            },
            PlaneRefreshOut {
                head: out_head(),
                snapshot: std::ptr::null(),
            },
        );
        let (called, snapshot) = rig.plane.refresh(&mut frame);
        assert_eq!(called.outcome, AbiOutcome::Ready, "the refresh is taken");
        assert!(snapshot.is_some(), "generation 2 is published");
    }

    /// EXHAUSTED, THE SERVER RESOLVED (the control the two cells after it stand beside): a tripped
    /// server's call is refused as the served engine refused it, `503` / `-32030` /
    /// `upstream_unavailable` with its sentence and the wait, byte for byte as predev serves it; the
    /// walk's own sentence never reaches the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_servers_exhausted_walk_is_refused_in_predevs_bytes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-exhausted-bytes";
        let _published = Published(instance);
        let (port, mut heard) = answering_calls_with(503).await;
        let rig = rig_tools(instance, port, registration("flaky", port, ""), &|app| app);
        fail_to_the_trip(&rig, "flaky_read_file", &mut heard, 0).await;

        let (status, headers, body) = send_headed(
            &rig.router,
            Some(&rig.token),
            &call_of("flaky_read_file", serde_json::json!({})),
            "tools/call",
            Some("flaky_read_file"),
        )
        .await;
        let body = String::from_utf8_lossy(&body).to_string();
        let wait: u64 = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("a Retry-After: {headers:?} {body}"));
        assert!(wait > 0, "the open cell's wait: {headers:?}");
        assert_eq!(status.as_u16(), 503, "{headers:?} {body}");
        assert_eq!(
            body,
            format!(
                "{{\"error\":{{\"code\":-32030,\"data\":{{\"reason\":\"upstream_unavailable\",\
                 \"retry_after_ms\":{},\"server\":\"flaky\"}},\"message\":\"{}\"}},\"id\":41,\
                 \"jsonrpc\":\"2.0\"}}",
                wait * 1000,
                sentence("tripped_server_message")
                    .replace("{server}", "flaky")
                    .replace("{wait}", &wait.to_string())
            ),
            "{headers:?}"
        );
        assert!(drain(&mut heard).is_empty(), "nothing reached the server");
        assert!(rig.all_ended(), "every unit ended");
    }

    /// EXHAUSTED, THE SERVER NO LONGER RESOLVED (the generic arm of the door's refusal slot): a call
    /// dispatched to a server that never answers, whose tool leaves the catalogue (an operator's
    /// reload) while the call waits out the server's `timeout:`, is refused when the walk is
    /// exhausted as predev refused it: the walk's status, `-32000`, and the reason's own word, no
    /// data and no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_exhausted_walk_whose_tool_left_the_catalogue_is_refused_in_predevs_bytes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-exhausted-unlisted";
        let _published = Published(instance);
        let (port, mut heard) = stalling_calls().await;
        let rig = rig_tools(
            instance,
            port,
            registration("stall", port, "  timeout: 2s\n"),
            &|app| app,
        );
        let (router, token) = (rig.router.clone(), rig.token.clone());
        let pending = tokio::spawn(async move {
            send_headed(
                &router,
                Some(&token),
                &call_of("stall_read_file", serde_json::json!({})),
                "tools/call",
                Some("stall_read_file"),
            )
            .await
        });
        heard_a_call(&mut heard).await;
        // The reload: the server is registered under another name, so the stalled call's tool is no
        // longer one the catalogue publishes.
        reload(&rig, &registration("other", port, ""));

        let (status, headers, body) = tokio::time::timeout(Duration::from_secs(20), pending)
            .await
            .expect("the stalled call was answered")
            .expect("the call ran");
        let body = String::from_utf8_lossy(&body).to_string();
        assert_eq!(status.as_u16(), 503, "{headers:?} {body}");
        assert_eq!(
            body, r#"{"error":{"code":-32000,"message":"breaker_open"},"id":41,"jsonrpc":"2.0"}"#,
            "{headers:?}"
        );
        assert!(
            headers.get("retry-after").is_none(),
            "no wait on this arm: {headers:?}"
        );
        assert!(rig.all_ended(), "every unit ended");
    }

    /// EXHAUSTED UNDER A TASK (the continuation's refusal): a task whose call is dispatched to a
    /// server that never answers fails when its continuation's walk is exhausted, and `tasks/get`
    /// states the failure as predev stated it: `-32603`, the upstream call failed, and the reason's
    /// own word.
    #[cfg(linked_section_pools)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tasks_exhausted_walk_fails_the_task_in_predevs_bytes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-exhausted-task";
        let _published = Published(instance);
        let (port, mut heard) = stalling_calls().await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "stall:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  {PIN}\n  timeout: 2s\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = rig_tools(instance, port, tools, &|app| app);

        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &task_call_of("stall_read_file"),
            "tools/call",
            Some("stall_read_file"),
        )
        .await;
        let created: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{created}");
        let task_id = created["result"]["taskId"]
            .as_str()
            .unwrap_or_else(|| panic!("a task: {created}"))
            .to_string();
        heard_a_call(&mut heard).await;

        let settled = task_settled(&rig, &task_id).await;
        assert_eq!(settled["result"]["status"], "failed", "{settled}");
        assert_eq!(
            settled["result"]["error"].to_string(),
            sentence("continuation_refused_error"),
            "{settled}"
        );
    }

    /// EXHAUSTED UNDER A TASK, THE SERVER TRIPPED: a task created on a tool whose server's cell is
    /// open fails as predev failed it, its `tasks/get` stating `-32603`, the upstream call failed,
    /// and the reason's own word.
    #[cfg(linked_section_pools)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_on_a_tripped_server_fails_in_predevs_bytes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-exhausted-task-tripped";
        let _published = Published(instance);
        let (port, mut heard) = answering_calls_with(503).await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "flaky:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = rig_tools(instance, port, tools, &|app| app);
        fail_to_the_trip(&rig, "flaky_read_file", &mut heard, 0).await;

        let (status, headers, body) = send_headed(
            &rig.router,
            Some(&rig.token),
            &task_call_of("flaky_read_file"),
            "tools/call",
            Some("flaky_read_file"),
        )
        .await;
        let created: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{headers:?} {created}");
        let task_id = created["result"]["taskId"]
            .as_str()
            .unwrap_or_else(|| panic!("a task: {created}"))
            .to_string();

        let settled = task_settled(&rig, &task_id).await;
        assert_eq!(settled["result"]["status"], "failed", "{settled}");
        assert_eq!(
            settled["result"]["error"].to_string(),
            sentence("continuation_refused_error"),
            "{settled}"
        );
        assert!(drain(&mut heard).is_empty(), "nothing reached the server");
    }
}

#[cfg(feature = "plane-decisions")]
/// What a served door's data router needs kept alive beside it, and what a test reads back off
/// the composition it served through.
pub(super) struct Serving {
    pub(super) router: axum::Router,
    pub(super) token: String,
    /// The kernel's swap handle: the generation a config apply refreshes the door onto.
    pub(super) handle: Arc<busbar_kernel::state::AppHandle>,
    /// What a config apply refreshes the served door onto (`DoorApply::apply`).
    pub(super) live: Arc<super::DoorApply>,
    /// The door plane's egress as the composition sealed it: its members' breaker cells.
    egress: Arc<busbar_kernel::plane_driver::Egress>,
    /// The plane's key, which its lanes are named under.
    plane: String,
    /// The node's book: the journal, the ledger and the audit chain its units seal onto.
    book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    /// The governance book the caller's key is charged on, and that key.
    gov: Arc<GovState>,
    key: String,
    /// The app the data router serves (its cost model prices the key's usage).
    app: Arc<busbar_kernel::state::App>,
    /// The operation classes the door's plane tail states, in its order.
    op_classes: Vec<&'static str>,
}

#[cfg(feature = "plane-decisions")]
impl Serving {
    /// The one model's lane, `(plane key, m)`: its member's name, and on a direct route the pool
    /// its breaker cell is keyed under.
    fn lane(&self) -> String {
        format!("{}{PLANE_LANE_SEP}m", self.plane)
    }

    /// Whether the model's member's breaker cell would take a request now (the walk's own filter).
    fn ready(&self) -> bool {
        self.egress.breaker.ready(
            &self.lane(),
            MEMBER,
            self.egress.clock.now_secs(),
            &busbar_kernel::test_support::tokens::pass(),
        )
    }

    /// The seconds of cooldown the member's breaker cell has left; zero for a closed cell.
    fn cooldown(&self) -> u64 {
        self.egress.breaker.cooldown_remaining(
            &self.lane(),
            MEMBER,
            self.egress.clock.now_secs(),
            &busbar_kernel::test_support::tokens::pass(),
        )
    }

    /// The real `/metrics` scrape on the data router, as the keyed caller.
    async fn scrape(&self) -> String {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/metrics")
            .header("authorization", format!("Bearer {}", self.token))
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = self
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::OK, "the scrape is served");
        let body = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .expect("the exposition");
        String::from_utf8(body.to_vec()).expect("the exposition is UTF-8")
    }

    /// The audit records sealed on the node's book, oldest first.
    fn audit_records(&self) -> Vec<busbar_kernel_audit::AuditRecord> {
        self.book.lock().expect("unpoisoned").audit_records.clone()
    }
}

#[cfg(feature = "plane-decisions")]
/// The model's one member: the first (and only) entry its egress seals.
const MEMBER: busbar_contract::DestinationId = busbar_contract::DestinationId::new(0);

#[cfg(feature = "plane-decisions")]
/// The sum of `family`'s series on `exposition` whose `lane` label is `lane`.
fn counted(exposition: &str, family: &str, lane: &str) -> f64 {
    let lane = format!("lane=\"{lane}\"");
    exposition
        .lines()
        .filter(|l| l.starts_with(&format!("{family}{{")) && l.contains(&lane))
        .filter_map(|l| l.rsplit_once(' ')?.1.parse::<f64>().ok())
        .sum()
}

#[cfg(feature = "plane-decisions")]
/// THE DECISIONS DOOR SERVED OVER `linked`, composed as the exit test above composes it (the
/// connector over the linked transport doors, the door bound through the loader's one load, one
/// model whose provider is the far end on `port`, a keyed caller): the composition reads the door
/// plane's declared facts off `linked`.
async fn serve_over(linked: &crate::root::linked::Linked, instance: &str, port: u16) -> Serving {
    serve_limited(linked, instance, port, Vec::new()).await
}

#[cfg(feature = "plane-decisions")]
/// [`serve_over`], its caller's key bound to a group that states `limits`.
async fn serve_limited(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
) -> Serving {
    serve_governed(linked, instance, port, limits, 0, None).await
}

#[cfg(feature = "plane-decisions")]
/// [`serve_limited`], the plane stating its own per-request fee (its section's reserved
/// `fees.per_request`, #47), in minor units, and the caller's key minted with `allowed_pools`
/// (`None` = every pool).
async fn serve_governed(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    fee: i64,
    allowed_pools: Option<Vec<String>>,
) -> Serving {
    let key_file = std::env::temp_dir().join(format!(
        "busbar-serve-door-{instance}-{}",
        std::process::id()
    ));
    std::fs::write(&key_file, CREDENTIAL).expect("the credential file");
    let api_key = format!("{{file: '{}'}}", key_file.display());
    let serving = serve_configured(linked, instance, port, limits, fee, allowed_pools, &api_key)
        .await
        .unwrap_or_else(|e| panic!("the door plane composes, its egress sealed: {e}"));
    let _ = std::fs::remove_file(&key_file);
    serving
}

#[cfg(linked_section_decisions)]
/// [`serve_over`], the one provider's credential the secret reference `api_key` (YAML), the
/// composition's refusal answered rather than panicked on: what the root's boot dies on.
pub(super) async fn serve_keyed(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    api_key: &str,
) -> Result<Serving, String> {
    serve_configured(linked, instance, port, Vec::new(), 0, None, api_key).await
}

#[cfg(linked_section_decisions)]
/// [`serve_governed`] over the provider credential `api_key`, the composition's refusal answered.
async fn serve_configured(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    fee: i64,
    allowed_pools: Option<Vec<String>>,
    api_key: &str,
) -> Result<Serving, String> {
    // The scrape sink's `/metrics` is mounted on a test app built with the recorder installed.
    busbar_kernel::snapshot::init();
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..Default::default()
    })
    .expect("the guard");
    let connector = busbar_core_connector::process::build_with_secrets(
        || {
            crate::root::connector::entries(
                crate::LINKED_TRANSPORT_DOORS,
                &busbar_contract::transport::TransportSettings::default(),
            )
        },
        judge,
        &[],
        Arc::new(|_, _| {}),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_kernel::config::secret::resolve_linked_string_at_config,
    )
    .expect("the connector builds");
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    let plane = Arc::new(
        load_linked::<Plane>(
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
        .expect("the linked door binds"),
    );
    let section_key = plane.served().section;
    // The plane's dialect word and its operation classes, as its door's plane tail states them
    // (BUSBAR-1.6.0.md l.247): the door is the crate's one public item (l.3567).
    let dialect = plane.served().dialects[0];
    let op_classes = plane.served().op_classes;

    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let group = format!("decider-{instance}");
    let groups = if limits.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([(
            group.clone(),
            busbar_kernel::config::GroupCfg {
                limits,
                ..Default::default()
            },
        )])
    };
    let cost = if groups.is_empty() {
        CostModel::flat(1)
    } else {
        CostModel::resolve_parts(None, 1, &groups)
    };
    let cost = if fee == 0 {
        cost
    } else {
        cost.with_plane_fees(&busbar_kernel::config::PlaneFeesMap::from([(
            plane.name().to_string(),
            busbar_kernel_ledger::cost::PlaneFees {
                per_request: fee,
                per_session: 0,
            },
        )]))
    };
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "decider".to_string(),
                allowed_pools,
                group: (!groups.is_empty()).then(|| group.clone()),
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
    let site = Arc::clone(&post);
    let book_money = Arc::clone(&gov);
    let plane_money = move || {
        Arc::new(PlaneMoney::new(
            Arc::clone(&book_money),
            Arc::clone(&site) as Arc<dyn EndPost>,
        ))
    };

    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(&format!(
        "{{protocol: {dialect}, base_url: 'http://127.0.0.1:{port}', api_key: {api_key}, error_map: {{}}}}",
    ))
    .expect("a provider entry");
    let providers = provider_routes(
        &std::collections::HashMap::from([(
            "typesafe".to_string(),
            busbar_kernel::config::ResolvedProvider::from(provider),
        )]),
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
        Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
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
        secrets: Arc::clone(&secrets),
        auths: Arc::new(auths),
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        catalog: None,
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
        &(Arc::new(crate::root::egress_ports::NodeClock::new())
            as Arc<dyn busbar_kernel_egress::ports::Clock>),
        &busbar_contract::config_time::ConfigScope::config_time(),
    )?;
    let live = Arc::clone(&served.planes[0].live);
    served.post = Some(Arc::clone(&post));
    let composed = &served.planes[0];
    let egress = composed
        .live
        .current()
        .egress
        .clone()
        .expect("the composition sealed its egress");
    let plane = composed.facts.plane.clone();
    let app = busbar_kernel::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov))
        .groups_tree(groups)
        .cost(cost)
        .build();
    let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
    let (router, _admin, handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
    Ok(Serving {
        router,
        token: token.expose(&busbar_kernel::seal::lend()).to_string(),
        handle,
        live,
        egress,
        plane,
        book: Arc::clone(&book.durability),
        gov,
        key: key.id.to_string(),
        app,
        op_classes,
    })
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
pub(super) fn decisions_name() -> String {
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
///
/// A row that also states `needs` (the conformance suite's and the fleet render's) reads the same
/// fact: the root reads the row through the one reader of a declares document, which checks and
/// drops `needs` (ARCHITECT ruling (b)). RED ARM: a malformed `needs` is refused, naming the row.
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
    let with_needs =
        declaring(r#"{"needs":["scheme-a"],"breaker":{"bench_below_trip_threshold":false}}"#);
    assert_eq!(
        crate::root::linked::door_breaker(&with_needs, None, &decisions_name())
            .expect("the fact reads beside `needs`"),
        Some(crate::root::loader::sign::BreakerDecl {
            bench_below_trip_threshold: false
        })
    );
    let malformed = declaring(r#"{"needs":"scheme-a"}"#);
    let refused = crate::root::linked::door_breaker(&malformed, None, &decisions_name())
        .expect_err("a `needs` that is not a list");
    let row = malformed.plane_door_declares[0].0;
    assert!(refused.contains(row), "{refused}");
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
/// `declares` row at all, as the decisions door has none in the shipped table) keeps the host's
/// default cell: one transient failure benches the sole member for its cooldown, so the next call
/// is refused without reaching the far end, exactly as before the fact existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plane_stating_no_breaker_fact_keeps_the_default_bench() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-breaker-absent";
    let _published = Published(instance);
    // The door's row states a `declares` section without the fact; the shipped table has no row
    // for it (the MCP door's row states the fact for the MCP plane alone).
    let silent = declaring("{}");
    assert_eq!(
        crate::root::linked::door_breaker(&silent, None, &decisions_name()).expect("it reads"),
        None
    );
    assert_eq!(
        crate::root::linked::door_breaker(&crate::LINKED, None, &decisions_name())
            .expect("nothing to read"),
        None,
        "no linked door states the fact for this plane in this build"
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
#[cfg(linked_driver_proofs)]
use super::hook_seat_tests::{
    chunk, far_end_answering as seat_far_end, far_end_scripted, rig, word as door_word, RigOpts,
    Script as SeatScript, REWRITTEN,
};
#[cfg(linked_driver_proofs)]
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// A served chat completion, marked by the member that answered it.
#[cfg(linked_driver_proofs)]
const SERVED_BY_TWIN: &str = r#"{"id":"chatcmpl-2","object":"chat.completion","created":0,"model":"m1","choices":[{"index":0,"message":{"role":"assistant","content":"served-by-the-twin"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A far end that cannot serve now.
#[cfg(linked_driver_proofs)]
const OVERLOADED: &str = r#"{"error":{"message":"overloaded","type":"server_error"}}"#;

/// A far end refusing the request itself.
#[cfg(linked_driver_proofs)]
const MALFORMED: &str = r#"{"error":{"message":"bad request","type":"invalid_request_error"}}"#;

/// BREAKER-TRIP: a member whose far end fails records into the kernel's ONE breaker cell for its
/// (pool, lane), and the cell opens: the walk's failure benched it.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_trips_a_failing_members_breaker_cell() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-breaker-trip";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        seat_far_end(503, OVERLOADED).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refuses_a_tripped_member_before_dispatch() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-breaker-fastfail";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        seat_far_end(503, OVERLOADED).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_reroutes_to_the_twin_before_the_first_byte() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-failover";
    let _published = Withdrawn(instance);
    let (down, twin) = (
        seat_far_end(503, OVERLOADED).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_classifies_a_refused_request_as_the_callers_fault() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-disposition";
    let _published = Withdrawn(instance);
    let (refusing, twin) = (
        seat_far_end(400, MALFORMED).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_injects_the_members_credential_not_the_callers() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-egress-auth";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_traffic_appears_on_the_metrics_scrape() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-metrics";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let scrape = busbar_kernel::snapshot::render();
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_attributes_spend_and_a_spent_budget_refuses() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-budget";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
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

/// A FAILED UNIT'S FEE COMES BACK AND ITS ADMISSION SLOT DOES NOT (legacy
/// `chain::the_refund_is_the_terminal_doors_and_it_lands_on_the_ledger`, item 366): the key's group
/// charges a flat 1-cent fee per request; a unit whose far end answers 503 keeps its admitted
/// request on the ledger, while the fee base the admission charged is refunded (spend 0) and
/// nothing is billable.
/// RED: the fee kept for an answer that was never delivered, or the admission slot refunded too.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refunds_a_failed_units_fee_and_keeps_its_admission() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-failed-fee-refund";
    let _published = Withdrawn(instance);
    let down = seat_far_end(503, OVERLOADED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(down.port, 1)],
            budget_cents: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    assert_ne!(rig.chat().await.0, 200, "the far end fails");
    // The refund lands when the unit ends, after its admission is on the ledger.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut ledger = rig.ledger_after(0).await;
    while (ledger.0 == 0 || ledger.1 != 0) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        ledger = rig.ledger_after(0).await;
    }
    let (requests, spend, _, billable) = ledger;
    assert_eq!(requests, 1, "the admission slot is never refunded");
    assert_eq!(spend, 0, "the fee base the admission charged is refunded");
    assert_eq!(billable, 0, "nothing billable");
}

/// AUDIT-CHAIN: every unit the door serves seals exactly one record on the node's chain.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_seals_one_audit_record_per_unit() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-audit";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
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

/// AUDIT-CHAIN, ON ONE TAMPER-EVIDENT CHAIN (Law 10, status row 178): every unit the pools door
/// answers, served (a dispatched completion) or refused inside the loop (a key whose budget the
/// first unit spent), seals ONE record on the node's audit chain, the second the first's
/// successor; the chain walks clean, and a record altered after its seal (the served unit re-told
/// as the refused one) breaks the walk. This is the claim the node-axis cell made, on the door
/// path CI's test build runs.
/// RED: a door whose audit pass never reaches the node seals nothing; a refusal sealed off the
/// chain leaves one record, or two that are not linked.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_seals_every_unit_served_or_refused_on_one_tamper_evident_chain() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-pools-audit-chain";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            budget_cents: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200, "the first unit is served");
    let _ = rig.ledger_after(1).await;
    assert_eq!(
        rig.chat().await.0,
        429,
        "the second is refused: its budget is spent"
    );
    assert_eq!(far.served(), 1, "the refused unit dialled nothing");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while rig.audit_records() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let records = rig.records();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed,
        "the served unit: {served:?}"
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(..)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

/// A NODE WHOSE JOURNAL CANNOT REACH ITS STORE FAILS CLOSED, ON THE DOOR (ARCHITECT 2026-10-07 H3
/// ruling): the node's journal is kept by a configured store that refuses, and the lane to it is
/// full, so a new unit through the door is answered 503 with the reason, in the caller's dialect
/// (the plane's `refusal` renders it for the target, kind `overloaded`, the bytes the node's
/// handed path answered: `ingress_error(dialect, 503, overloaded, reason)`), before anything is
/// dispatched or charged, and nothing the journal holds is dropped. RED before the fix: the door
/// answered a bare 502 (`plane_panic`) with an empty body, because nothing asked the node's
/// `journal_refusal` before the borrowed drive declined the unit.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refuses_a_new_unit_503_with_the_reason_while_its_journal_is_full() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-full-journal";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            full_journal: true,
            ..RigOpts::default()
        },
    )
    .await;
    let (status, head, body) = rig.chat().await;
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, 503, "{text}");
    assert_eq!(
        head.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "the caller's dialect envelope: {text}"
    );
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON envelope");
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("journal is full") && message.contains("`test-store`"),
        "the reason names the full journal and the store: {answer}"
    );
    assert!(answer["error"]["type"].is_string(), "{answer}");
    assert_eq!(far.served(), 0, "nothing dispatched");
    let (requests, spend, _, billable) = rig.ledger_after(0).await;
    assert_eq!((requests, spend, billable), (0, 0, 0), "nothing charged");
    assert_eq!(
        rig.book.lock().unwrap().journal.dropped_total(),
        0,
        "no record is dropped"
    );
}

/// HOOKS-GATE: a rejecting gate refuses the door's traffic before dispatch.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_gate_hook_refuses_before_dispatch() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-gate";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
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

/// A GATE'S VETO KEEPS THE ADMISSION AND GIVES THE FEE BACK, AS 1.5.5 DID (legacy
/// `approve::a_veto_refuses_at_approve_which_is_before_the_door`): v1.5.5 admitted and charged a
/// unit before its gates ran (`ingress/dispatch.rs` `governance_guard` ahead of
/// `forward_with_pool_parsed`, whose gates fire at `proxy/engine/mod.rs:946`), and the vetoed
/// answer's non-2xx end refunded the flat fee (`finish_admitted`); the hook stages run at the head
/// of the route leg after admit (K5, BUSBAR-1.6.0.md). So a vetoed unit answers the gate's status,
/// dials nothing, keeps its admitted request and nets no spend.
/// RED: the vetoed unit's fee kept, its admission dropped, or a far end dialled.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_gate_veto_keeps_the_admission_and_refunds_the_fee() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-gate-money";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            reject_at_gate: true,
            budget_cents: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 451, "the gate's own status");
    assert_eq!(far.served(), 0, "nothing was dispatched");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut ledger = rig.ledger_after(0).await;
    while (ledger.0 == 0 || ledger.1 != 0) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        ledger = rig.ledger_after(0).await;
    }
    let (requests, spend, _, billable) = ledger;
    assert_eq!(requests, 1, "the admission stands");
    assert_eq!(spend, 0, "the vetoed unit's fee is refunded");
    assert_eq!(billable, 0, "nothing billable");
}

/// HOOKS-TAP: the rewrite and observe hooks run over the door's payloads: the request-stage tap
/// sees the request as the global rewrite left it.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_tap_hooks_observe_the_rewritten_request() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-tap";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_catalogue_shows_a_restricted_key_only_what_it_reaches() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-catalogue";
    let _published = Withdrawn(instance);
    let (a, b) = (
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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

/// THE DROPPED-CONTROLS AUDIT ROW ON THE DOOR (ARCHITECT, Q128 gap): a TRANSLATE attempt that
/// cannot carry a control the caller set writes 1.5.5's `egress.control_unrepresentable` row,
/// outcome `degraded`, `<control> on <dialect>`; an answer member the caller's dialect has no form
/// for writes `<path> from <dialect>`. Both reach the kernel's audit chain through the plane's
/// `RECORD_AUDIT` write. RED arm: a request that sets nothing the far dialect drops writes no row.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_audits_a_control_the_far_dialect_cannot_carry() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-dropped-controls";
    let _published = Withdrawn(instance);
    // The far dialect is the plane's own door word (`untranslatable_dialect`), and so is its answer:
    // a message whose usage carries a member the caller's dialect has no form for.
    let far_dialect = door_word("untranslatable_dialect");
    let far = seat_far_end(200, door_word("untranslatable_answer")).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some(far_dialect),
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
        rows(format!("logit_bias on {far_dialect}").as_str()),
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
        rows(format!("logit_bias on {far_dialect}").as_str()),
        1,
        "the dropped control, one row"
    );
    assert!(
        rows(format!("usage.output_tokens_details from {far_dialect}").as_str()) >= 1,
        "the answer member the caller's dialect cannot carry"
    );
}

/// THE RANKING SIGNALS ON THE DOOR (ARCHITECT, Q128 gap): the hooks see each candidate as 1.5.5's
/// projection fed it: the pool member's tier and tags, the lane's latency signal once a sample is
/// recorded, its free concurrency, its remaining budget, and, where the generation declares them,
/// its breaker state, error rate and p95 latency in the routing pool. RED before: every one of them
/// was empty on the door path.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_doors_hooks_see_each_candidates_standing() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-signals";
    let _published = Withdrawn(instance);
    let (a, b) = (
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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

/// A far end's clean event stream: each of `events` one frame, the stream ending with no abort. The
/// served pools door's rehomed cells (the walk's and the money's) share this one spelling of the
/// mock's stream answer rather than each naming the wire's variant.
#[cfg(linked_driver_proofs)]
fn event_stream(events: Vec<String>) -> busbar_kernel::test_support::MockResponse {
    busbar_kernel::test_support::MockResponse::Sse {
        events,
        abort_at_index: None,
    }
}

// ── F25 REHOME: THE WALK AND THE BREAKER ON THE SERVED POOLS DOOR ───────────────────────────────
//
// The previous release's engine tests of the walk (failover, exhaustion, the first-byte boundary)
// and of the far end's disposition (what a far answer records on the member's breaker cell), each
// driven here as a keyed caller's request through the composed door to real far ends on loopback,
// its figures read where the kernel keeps them: the lane store's snapshot and its pool cells.
#[cfg(linked_driver_proofs)]
mod pools_door_walk_and_breaker {
    use super::*;

    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_kernel::test_support::{MockResponse, MockServer, MockServerState};

    /// The store's clock.
    fn now() -> u64 {
        busbar_kernel::store::now()
    }

    /// A recording far end answering its requests with `replies`, in order.
    async fn mock(replies: Vec<MockResponse>) -> (Arc<MockServerState>, MockServer) {
        let state = Arc::new(MockServerState::new());
        for reply in replies.into_iter().rev() {
            state.push(reply);
        }
        let server = MockServer::new(Arc::clone(&state)).await;
        (state, server)
    }

    /// The port a mock listens on.
    fn port_of(server: &MockServer) -> u16 {
        server.address().port()
    }

    /// The messages dialect's answer, its text `text`.
    fn messages_answer_saying(text: &str) -> serde_json::Value {
        let mut answer: serde_json::Value =
            serde_json::from_str(door_word("messages_answer")).expect("the answer is JSON");
        answer["content"][0]["text"] = serde_json::Value::from(text);
        answer
    }

    /// A caller's request in the messages dialect on pool `p`, streamed when `stream`.
    fn messages_request(stream: bool) -> serde_json::Value {
        serde_json::json!({"model": "p", "max_tokens": 100, "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]})
    }

    /// One request in the messages dialect on pool `p`.
    async fn send_messages(rig: &DoorRig, stream: bool) -> (u16, axum::http::HeaderMap, String) {
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_request(stream)),
            )
            .await;
        (status, head, String::from_utf8_lossy(&body).to_string())
    }

    /// `n` raw event payloads `event-0` .. `event-<n-1>`.
    fn events(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("event-{i}")).collect()
    }

    /// The far-end error map the previous release's tests configured: a billing code and a rate
    /// limit code, as a provider states them.
    const ERROR_MAP: &str = "error_map:\n  '1113': billing\n  '1302': rate_limit";

    /// A port nothing listens on: every dial to it is refused.
    fn refusing_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    use super::super::hook_seat_tests::DoorRig;

    /// A NULL `stream_options` IS UPGRADED (F25 row 2; legacy
    /// `assemble::a_null_stream_options_is_upgraded_so_the_upstream_reports_usage`): a same-dialect
    /// streamed chat spelling `"stream_options": null` reaches the far end carrying
    /// `stream_options.include_usage: true` (1.5.5 upgraded it like an absent key, so the far end
    /// reports usage and the ledger reads it), and the caller, who did not opt in, is served the
    /// answer ("Hi", 200) without the usage chunk (`completion_tokens` never reaches it). RED: the
    /// null forwarded verbatim, or the usage chunk relayed to the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_upgrades_a_null_stream_options_and_keeps_the_usage_chunk_back() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-null-stream-options";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![event_stream(vec![
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"Hi"},"finish_reason":null}]}"#.to_string(),
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
            r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":17,"total_tokens":24}}"#.to_string(),
        ])])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": "p", "stream": true,
                    "stream_options": null,
                    "messages": [{"role": "user", "content": "hi"}]})),
            )
            .await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 200, "the stream is served: {text}");
        let egress: serde_json::Value = serde_json::from_slice(
            &state
                .get_last_request_body()
                .expect("the far end received the request"),
        )
        .expect("the far end's request is JSON");
        assert_eq!(
            egress.pointer("/stream_options/include_usage"),
            Some(&serde_json::Value::Bool(true)),
            "a null stream_options asks the far end for its usage: {egress}"
        );
        assert!(text.contains("Hi"), "the answer reaches the caller: {text}");
        assert!(
            !text.contains("completion_tokens"),
            "a caller that did not opt in is not sent the usage chunk: {text}"
        );
    }

    /// THE CALLER'S CREDENTIALS NEVER CROSS (F25 row 81; legacy
    /// `client_header_forwarding_tests::caller_credential_is_replaced_by_the_lane_credential`): a
    /// caller presenting `authorization: Bearer busbar-caller-key` and the same key in `x-api-key`,
    /// `x-goog-api-key` and `api-key` on a chat route is relayed to a far end that sees
    /// `authorization: Bearer sk-seats` (the member's own key) and none of the other three
    /// carriers. RED: any carrier of the caller's key reaching the far end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_replaces_every_caller_credential_with_the_members() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-caller-credentials";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::from_str(SERVED_BY_TWIN).expect("JSON"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                open_door: true,
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send_bare(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": "p", "max_tokens": 16,
                    "messages": [{"role": "user", "content": "hi"}]})),
                &[
                    ("authorization", "Bearer busbar-caller-key"),
                    ("x-api-key", "busbar-caller-key"),
                    ("x-goog-api-key", "busbar-caller-key"),
                    ("api-key", "busbar-caller-key"),
                ],
            )
            .await;
        let seen = |name: &str| state.get_last_request_header(name);
        assert_eq!(
            seen("authorization"),
            Some("Bearer sk-seats".to_string()),
            "the member's own credential ({status}: {})",
            String::from_utf8_lossy(&body)
        );
        for carrier in ["x-api-key", "x-goog-api-key", "api-key"] {
            assert_eq!(
                seen(carrier),
                None,
                "{carrier}: the caller's key never goes to the far end"
            );
        }
    }

    /// A POOL WHOSE DIALS ARE ALL REFUSED ANSWERS AS AN ALL-DOWN POOL (F25 row 97; legacy
    /// `dial_refusal_failover_tests::an_all_refused_pool_answers_as_an_all_down_pool`): a pool of
    /// two members whose dials the destination judge refuses answers the caller the SAME status
    /// (503) and the same body (its request id aside) as a pool of two members whose ports refuse
    /// the connection, and both members were tried in both (the same failures recorded), the
    /// refused far ends never reached. RED: a judged refusal answering anything the all-down pool
    /// does not, or stopping after one member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_answers_an_all_refused_pool_as_an_all_down_pool() {
        let _one = ONE_PUBLISHER.lock().await;
        let without_request_id = |body: &[u8]| {
            let mut answer: serde_json::Value =
                serde_json::from_slice(body).expect("a JSON error body");
            if let Some(id) = answer.get_mut("request_id") {
                *id = serde_json::Value::Null;
            }
            answer
        };
        let failures = |rig: &DoorRig| {
            (0..2)
                .map(|lane| rig.app.store.snapshot(lane, now()).err)
                .sum::<u64>()
        };

        let instance = "rehome-walk-all-down";
        let published = Withdrawn(instance);
        let down = rig(
            instance,
            RigOpts {
                members: &[(refusing_port(), 1), (refusing_port(), 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (down_status, _, down_body) = down.chat().await;
        let down_failures = failures(&down);
        drop(down);
        drop(published);

        let instance = "rehome-walk-all-refused";
        let _published = Withdrawn(instance);
        let (first, second) = (
            seat_far_end(200, SERVED_BY_TWIN).await,
            seat_far_end(200, SERVED_BY_TWIN).await,
        );
        let judged = rig(
            instance,
            RigOpts {
                members: &[(first.port, 1), (second.port, 1)],
                refuse_private: true,
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = judged.chat().await;
        assert_eq!(
            down_status, 503,
            "the all-down baseline is the 503 terminal"
        );
        assert_eq!(status, down_status, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            without_request_id(&body),
            without_request_id(&down_body),
            "the all-down body"
        );
        assert_eq!(
            (first.served(), second.served()),
            (0, 0),
            "a refused dial never leaves"
        );
        assert_eq!(
            failures(&judged),
            down_failures,
            "both members were tried, as both down members were"
        );
    }

    /// AN UNMAPPED MEMBER IS AUDITED BY ITS WIRE PATH (F25 row 113; legacy
    /// `egress_dropped_controls_audit_tests::openai_to_anthropic_unmapped_members_are_audited_by_wire_path`):
    /// a chat caller setting `logit_bias` and sending a content part of a type no dialect knows
    /// (`x_future_part`) onto a member of the messages dialect is forwarded with
    /// `messages[0].content` holding ONE part (the unknown part dropped, not replaced), and two
    /// `degraded` `egress.control_unrepresentable` rows are written for the caller:
    /// `logit_bias on <dialect>` and `messages[].content[].type=x_future_part on <dialect>`. RED:
    /// either row missing, or the request refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_audits_an_unmapped_content_part_by_its_wire_path() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-unmapped-part";
        let _published = Withdrawn(instance);
        let far_dialect = door_word("messages_dialect");
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer_saying("hi"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(far_dialect),
                // The caller's own parts reach the translation: no rewrite seat replaces them.
                no_rewrite: true,
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "logit_bias": {"50256": -100},
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "hi"},
                    {"type": "x_future_part", "x": 1}
                ]}]})),
            )
            .await;
        assert_eq!(
            status,
            200,
            "the dropped members do not refuse the request: {}",
            String::from_utf8_lossy(&body)
        );
        let rebuilt: serde_json::Value = serde_json::from_slice(
            &state
                .get_last_request_body()
                .expect("the far end received the request"),
        )
        .expect("JSON");
        assert_eq!(
            rebuilt
                .pointer("/messages/0/content")
                .and_then(|parts| parts.as_array())
                .map(Vec::len),
            Some(1),
            "the unknown part is dropped, not replaced: {rebuilt}"
        );
        for resource in [
            format!("logit_bias on {far_dialect}"),
            format!("messages[].content[].type=x_future_part on {far_dialect}"),
        ] {
            let rows = busbar_kernel::audit::auditlog::AUDIT_LOG
                .list_filtered(
                    0,
                    1000,
                    Some("egress.control_unrepresentable"),
                    Some(resource.as_str()),
                )
                .into_iter()
                .filter(|e| e.principal == rig.key_id && e.outcome == "degraded")
                .count();
            assert_eq!(rows, 1, "one degraded row names `{resource}`");
        }
    }

    /// EVERY PIECE OF AN EVENT-STREAM ARRIVES (F25 row 152; legacy
    /// `forward_pool_integration_tests::test_sse_incremental_arrival`): a member of the messages
    /// dialect sending ten events `event-0` .. `event-9` answers the caller 200, its
    /// content-type exactly `text/event-stream`, with exactly ten `data: event-` lines. RED: a
    /// piece lost, merged or rewritten on the relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_relays_every_event_of_a_streamed_answer() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-ten-events";
        let _published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Sse {
            events: events(10),
            abort_at_index: None,
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, head, text) = send_messages(&rig, true).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(
            head.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("data: event-"))
                .count(),
            10,
            "every event reached the caller: {text}"
        );
    }

    /// A FAULT BEFORE THE FIRST BYTE FAILS OVER (F25 row 156; legacy
    /// `forward_pool_integration_tests::test_pre_first_byte_failover`): member 0 answers HTTP 500
    /// `{"error":"lane 0 failed"}` before any byte, member 1 streams `event-0` .. `event-2`: the
    /// caller is served 200 and member 0's cell is in its transient cooldown (not ready). RED: the
    /// 500 relayed, or member 0 left ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_fails_over_a_fault_before_the_first_byte_and_cools_the_member() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-pre-first-byte";
        let _published = Withdrawn(instance);
        let (_failing, down) = mock(vec![MockResponse::ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: serde_json::json!({ "error": "lane 0 failed" }),
        }])
        .await;
        let (_serving, up) = mock(vec![MockResponse::Sse {
            events: events(3),
            abort_at_index: None,
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&down), 100), (port_of(&up), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, true).await;
        assert_eq!(status, 200, "{text}");
        assert!(
            !rig.app.store.ready_in("p", 0, now()),
            "member 0 is in its transient cooldown"
        );
    }

    /// A CUT AFTER THE FIRST BYTE IS NOT FAILED OVER (F25 row 157; legacy
    /// `forward_pool_integration_tests::test_midstream_abort_records_and_no_failover`): member 0
    /// streams `event-0` of five and the stream aborts; member 1 would answer. The caller has its
    /// 200 and an `event: error` frame, member 0's failure is recorded (err > 0, a cooldown), and
    /// member 1 was never dialled (err 0). RED: a second attempt on member 1, or no failure
    /// recorded on member 0.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_records_a_cut_after_the_first_byte_and_does_not_fail_over() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-midstream-abort";
        let _published = Withdrawn(instance);
        let (_cut, cutting) = mock(vec![MockResponse::Sse {
            events: events(5),
            abort_at_index: Some(1),
        }])
        .await;
        let (sibling_state, sibling) = mock(vec![MockResponse::Sse {
            events: vec!["lane1-ok".to_string()],
            abort_at_index: None,
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&cutting), 100), (port_of(&sibling), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, true).await;
        assert_eq!(status, 200, "{text}");
        assert!(
            text.contains("event: error"),
            "the cut ends on an error event: {text}"
        );
        let first = rig.app.store.snapshot(0, now());
        assert!(first.err > 0, "member 0's failure is recorded");
        assert!(first.cooldown_remaining_s > 0, "and cools it");
        assert_eq!(
            rig.app.store.snapshot(1, now()).err,
            0,
            "member 1 is untouched"
        );
        assert!(
            sibling_state.get_last_request_body().is_none(),
            "member 1 was never dialled: no failover after the first byte"
        );
    }

    /// A PASSTHROUGH 401 IS THE CALLER'S, AN OWN-CREDENTIAL 401 IS THE MEMBER'S (F25 row 158; legacy
    /// `forward_pool_integration_tests::test_section6_passthrough_401_no_trip_vs_token_mode`): a
    /// pool reaching its member with the caller's own credential relays the far end's 401 and
    /// leaves the member untouched (ready, err 0, streak 0, not dead); the same 401 to a member
    /// reached with its own credential is relayed as a 401 and takes the member down (not ready,
    /// recoverable: not dead). RED: a passthrough 401 tripping the member, or an own-credential 401
    /// leaving it ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_trips_on_an_own_credential_401_but_not_on_a_passthrough_one() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-passthrough-401";
        let published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        }])
        .await;
        let passthrough = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                pool_yaml: "upstream_credentials: passthrough",
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&passthrough, false).await;
        assert_eq!(status, 401, "the far end's 401 is relayed: {text}");
        assert!(
            passthrough.app.store.ready_in("p", 0, now()),
            "a passthrough 401 trips nothing"
        );
        let snap = passthrough.app.store.snapshot(0, now());
        assert_eq!((snap.err, snap.streak), (0, 0), "nothing recorded");
        assert!(!snap.dead);
        drop(passthrough);
        drop(published);

        let instance = "rehome-walk-own-401";
        let _published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Auth {
            status: StatusCode::UNAUTHORIZED,
        }])
        .await;
        let own = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&own, false).await;
        assert_eq!(status, 401, "{text}");
        assert!(
            !own.app.store.ready_in("p", 0, now()),
            "the member's own credential failed: it is down"
        );
        assert!(
            !own.app.store.snapshot(0, now()).dead,
            "recoverable hard-down (long cooldown and probe), never permanently dead"
        );
    }

    /// PASSTHROUGH FORWARDS THE CALLER'S TOKEN (F25 row 160; legacy
    /// `forward_pool_integration_tests::test_passthrough_forwards_caller_token`): a pool whose
    /// members are reached with the caller's own credential serves 200, and the far end's
    /// `authorization` is the caller's token as a bearer credential, never the member's configured
    /// key (`sk-seats`). RED: the configured key presented on a passthrough pool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_forwards_the_callers_token_on_a_passthrough_pool() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-passthrough-token";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                pool_yaml: "upstream_credentials: passthrough",
                ..RigOpts::default()
            },
        )
        .await;
        assert_eq!(rig.chat().await.0, 200);
        let seen = far.authorizations.lock().unwrap().clone();
        assert_eq!(seen, vec![format!("Bearer {}", rig.token)]);
        assert!(
            !seen[0].contains("sk-seats"),
            "the configured key never stands in"
        );
    }

    /// EACH MEMBER IS TRIED ONCE (F25 row 161; legacy
    /// `forward_pool_integration_tests::test_failover_exclusions`): a two-member pool whose far
    /// ends answer every request 500 answers the caller 503, and the members' error counts sum to
    /// exactly 2: each tried once, none retried within the request. RED: a tried member picked
    /// again (a sum above 2), or the walk stopping early.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_tries_each_member_once_before_its_terminal() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-exclusions";
        let _published = Withdrawn(instance);
        let fars = [
            seat_far_end(500, r#"{"error":"transient failure"}"#).await,
            seat_far_end(500, r#"{"error":"transient failure"}"#).await,
        ];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(fars[0].port, 1), (fars[1].port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        assert_eq!(rig.chat().await.0, 503);
        let errs: u64 = (0..2)
            .map(|lane| rig.app.store.snapshot(lane, now()).err)
            .sum();
        assert_eq!(errs, 2, "one attempt per distinct member, no retry");
        assert_eq!((fars[0].served(), fars[1].served()), (1, 1));
    }

    /// THE HOP CAP BOUNDS THE WALK (F25 row 162; legacy
    /// `forward_pool_integration_tests::test_failover_cap`): a three-member pool, every far answer
    /// 500, under the default failover settings, answers 503 after exactly three attempts (the
    /// members' error counts sum to 3, each member dialled once). RED: a walk past the cap or a
    /// member retried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_caps_the_walk_at_one_attempt_per_member() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-cap";
        let _published = Withdrawn(instance);
        let fars = [
            seat_far_end(500, r#"{"error":"transient failure"}"#).await,
            seat_far_end(500, r#"{"error":"transient failure"}"#).await,
            seat_far_end(500, r#"{"error":"transient failure"}"#).await,
        ];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(fars[0].port, 1), (fars[1].port, 1), (fars[2].port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        assert_eq!(rig.chat().await.0, 503);
        let errs: u64 = (0..3)
            .map(|lane| rig.app.store.snapshot(lane, now()).err)
            .sum();
        assert_eq!(errs, 3, "three members, three attempts");
        assert!(fars.iter().all(|far| far.served() == 1));
    }

    /// A CALLER'S FAULT IS NEVER RETRIED ON ANOTHER MEMBER: a two-member pool whose far ends both
    /// answer a 400 relays the first 400 to the caller, and exactly one member was dialled; the
    /// walk does not try the second for a fault that is the caller's own. Rehomes
    /// the retired engine crate's `src/engine/tests/forward_pool_integration_tests.rs::test_client_fault_no_failover_two_lanes`.
    /// RED: the second member dialled, or the 400 replaced by a terminal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_never_retries_a_callers_fault_on_another_member() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-client-fault-once";
        let _published = Withdrawn(instance);
        let fars = [
            seat_far_end(
                400,
                r#"{"error":{"message":"bad input","type":"invalid_request_error"}}"#,
            )
            .await,
            seat_far_end(
                400,
                r#"{"error":{"message":"bad input","type":"invalid_request_error"}}"#,
            )
            .await,
        ];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(fars[0].port, 1), (fars[1].port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        assert_eq!(rig.chat().await.0, 400, "the caller's fault is relayed");
        assert_eq!(
            fars[0].served() + fars[1].served(),
            1,
            "one member dialled: a caller's fault is not retried"
        );
    }

    /// One member of the messages dialect stating [`ERROR_MAP`], its far end answering `reply`.
    async fn mapped_member(
        instance: &'static str,
        reply: MockResponse,
    ) -> (DoorRig, (u16, axum::http::HeaderMap, String), MockServer) {
        let (_state, server) = mock(vec![reply]).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                provider_yaml: ERROR_MAP,
                ..RigOpts::default()
            },
        )
        .await;
        let answer = send_messages(&rig, false).await;
        (rig, answer, server)
    }

    /// A MAPPED BILLING CODE IS A RECOVERABLE HARD-DOWN (F25 row 169; legacy
    /// `forward_pool_integration_tests::test_disposition_hard_down_billing_code`): a provider
    /// mapping code `1113` to `billing` whose far end answers 402 `{"error":{"code":"1113",
    /// "message":"insufficient balance"}}` takes the member down (not ready), recoverable (not
    /// dead), its reason `billing / insufficient balance`. RED: the member left ready, marked dead,
    /// or its reason not the class and the far end's message.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_takes_a_member_down_on_a_mapped_billing_code() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-billing-code";
        let _published = Withdrawn(instance);
        let (rig, _, _server) = mapped_member(
            instance,
            MockResponse::Billing {
                status: StatusCode::PAYMENT_REQUIRED,
                code: "1113",
                message: "insufficient balance",
            },
        )
        .await;
        assert!(!rig.app.store.ready_in("p", 0, now()), "down after billing");
        let snap = rig.app.store.snapshot(0, now());
        assert!(
            !snap.dead,
            "billing is recoverable (long cooldown and probe)"
        );
        assert_eq!(snap.dead_reason, "billing / insufficient balance");
    }

    /// A MAPPED RATE-LIMIT CODE IS TRANSIENT (F25 row 170; legacy
    /// `forward_pool_integration_tests::test_disposition_transient_rate_limit_code`): a 429 whose
    /// body carries the mapped code `1302` cools the member (not ready), counts one failure
    /// (err > 0, streak exactly 1) and leaves it alive. RED: no failure recorded, a streak other
    /// than 1, or the member marked dead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_cools_a_member_on_a_mapped_rate_limit_code() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-rate-limit-code";
        let _published = Withdrawn(instance);
        let (rig, _, _server) = mapped_member(
            instance,
            MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: Some("1302"),
                retry_after: None,
            },
        )
        .await;
        assert!(!rig.app.store.ready_in("p", 0, now()), "cooling down");
        let snap = rig.app.store.snapshot(0, now());
        assert!(snap.err > 0, "the rate limit is counted");
        assert_eq!(snap.streak, 1, "the first rate limit");
        assert!(!snap.dead);
    }

    /// A BARE 429 IS TRANSIENT (F25 row 171; legacy
    /// `forward_pool_integration_tests::test_disposition_transient_rate_limit_no_code`): a 429
    /// with no provider code cools the member (not ready) and counts a failure (err > 0). RED: a
    /// 429 recording nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_cools_a_member_on_a_bare_rate_limit() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-rate-limit-bare";
        let _published = Withdrawn(instance);
        let (rig, _, _server) = mapped_member(
            instance,
            MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: None,
                retry_after: None,
            },
        )
        .await;
        assert!(!rig.app.store.ready_in("p", 0, now()), "cooling down");
        assert!(rig.app.store.snapshot(0, now()).err > 0);
    }

    /// A SERVER ERROR IS TRANSIENT (F25 row 172; legacy
    /// `forward_pool_integration_tests::test_disposition_transient_server_error`): a 500
    /// `{"error":"server error"}` cools the member (not ready), counts a failure (err > 0) and
    /// leaves it alive. RED: a 500 recording nothing or killing the member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_cools_a_member_on_a_server_error() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-server-error";
        let _published = Withdrawn(instance);
        let (rig, _, _server) = mapped_member(
            instance,
            MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: serde_json::json!({ "error": "server error" }),
            },
        )
        .await;
        assert!(!rig.app.store.ready_in("p", 0, now()), "cooling down");
        let snap = rig.app.store.snapshot(0, now());
        assert!(snap.err > 0);
        assert!(!snap.dead);
    }

    /// A REFUSED OWN CREDENTIAL IS A HARD-DOWN, ANSWERED IN THE CALLER'S OWN WORDS (F25 row 173;
    /// legacy `forward_pool_integration_tests::test_disposition_hard_down_auth`): a far end
    /// answering 401 to the member's own credential takes the member down (not ready),
    /// recoverable (not dead), its reason naming `auth`; the caller gets a 401 in its own
    /// dialect's envelope (`type: error`, `error.type: authentication_error`), the dialect's own
    /// auth-failure sentence, never the far end's body and never the word `lane`. RED: the far
    /// end's body relayed, internal vocabulary on the wire, or the member left ready.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_takes_a_member_down_on_a_refused_own_credential() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-auth-down";
        let _published = Withdrawn(instance);
        let (rig, (status, _, text), _server) = mapped_member(
            instance,
            MockResponse::Auth {
                status: StatusCode::UNAUTHORIZED,
            },
        )
        .await;
        assert!(!rig.app.store.ready_in("p", 0, now()), "down after auth");
        let snap = rig.app.store.snapshot(0, now());
        assert!(!snap.dead, "recoverable (long cooldown and probe)");
        assert!(
            snap.dead_reason.contains("auth"),
            "the reason names auth: {}",
            snap.dead_reason
        );
        assert_eq!(status, 401, "{text}");
        let answer: serde_json::Value = serde_json::from_str(&text).expect("a JSON envelope");
        assert_eq!(answer["type"], "error", "{answer}");
        assert_eq!(answer["error"]["type"], "authentication_error", "{answer}");
        let message = answer["error"]["message"].as_str().unwrap_or("");
        assert_eq!(
            message,
            busbar_kernel::proto::vendor_auth_failure_message(door_word("messages_dialect")),
            "the dialect's own sentence: {answer}"
        );
        assert!(!message.contains("lane"), "{answer}");
    }

    /// THE PROVIDER'S CODE, NOT THE STATUS, DRIVES THE CLASS (F25 row 174; legacy
    /// `forward_pool_integration_tests::test_disposition_code_drives_classification`): a member
    /// mapping `1113` to `billing` answered 402 with code `1113` is taken down (not ready); a
    /// member with no mapping answered 400 `{"error":"not a known error"}` relays the 400 and
    /// stays ready (the caller's fault). RED: both read by their status alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_classifies_by_the_mapped_code_not_the_status() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-code-drives-mapped";
        let published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Billing {
            status: StatusCode::PAYMENT_REQUIRED,
            code: "1113",
            message: "insufficient balance",
        }])
        .await;
        let mapped = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                provider_yaml: "error_map:\n  '1113': billing",
                ..RigOpts::default()
            },
        )
        .await;
        let _ = send_messages(&mapped, false).await;
        assert!(
            !mapped.app.store.ready_in("p", 0, now()),
            "the mapped billing code takes the member down"
        );
        drop(mapped);
        drop(published);

        let instance = "rehome-walk-code-drives-unmapped";
        let _published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({ "error": "not a known error" }),
        }])
        .await;
        let unmapped = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&unmapped, false).await;
        assert_eq!(status, 400, "the caller's fault is relayed: {text}");
        assert!(
            unmapped.app.store.ready_in("p", 0, now()),
            "and records nothing against the member"
        );
    }

    /// A CALLER'S FAULT IS RELAYED VERBATIM AND COUNTED APART (F25 row 177; legacy
    /// `forward_pool_integration_tests::test_client_fault_400_relayed_verbatim_no_penalty`): a far
    /// end of the caller's dialect answering 400 `{"error":"invalid_request","message":"bad
    /// input"}` reaches the caller as that 400 with those very bytes; the member's cell stays
    /// closed, err 0, streak 0, no cooldown, and its client-fault counter reads exactly 1. RED: a
    /// penalty on the member, a rewritten body, or the fault not counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_relays_a_callers_fault_verbatim_and_counts_it_apart() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-client-fault";
        let _published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({ "error": "invalid_request", "message": "bad input" }),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, false).await;
        assert_eq!(status, 400);
        assert_eq!(
            text, r#"{"error":"invalid_request","message":"bad input"}"#,
            "relayed verbatim"
        );
        assert!(matches!(
            rig.app.store.breaker_state_in("p", 0),
            busbar_kernel::store::BreakerState::Closed
        ));
        let snap = rig.app.store.snapshot(0, now());
        assert_eq!(
            (snap.err, snap.streak, snap.cooldown_remaining_s),
            (0, 0, 0)
        );
        assert_eq!(snap.client_fault, 1, "the caller's fault is counted apart");
    }

    /// EXHAUSTION IS A 503 NAMING ITS WAIT (F25 row 179; legacy
    /// `forward_pool_integration_tests::test_exhaustion_status_503_with_retry_after`): a
    /// two-member pool whose far ends both answer 429 (code `1302`) in one request answers 503
    /// with a `Retry-After` of whole seconds, at least 1. RED: a relayed 429, or no Retry-After.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_sheds_an_exhausted_pool_with_a_retry_after() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-exhaustion";
        let _published = Withdrawn(instance);
        let limited = || MockResponse::RateLimit {
            status: StatusCode::TOO_MANY_REQUESTS,
            provider_signal: Some("1302"),
            retry_after: None,
        };
        let (_first_state, first) = mock(vec![limited()]).await;
        let (_second_state, second) = mock(vec![limited()]).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&first), 1), (port_of(&second), 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, head, _) = rig.chat().await;
        assert_eq!(status, 503, "the exhausted terminal");
        let wait: u64 = head
            .get("retry-after")
            .expect("a Retry-After")
            .to_str()
            .expect("text")
            .parse()
            .expect("whole seconds");
        assert!(wait >= 1, "at least one second: {wait}");
    }

    /// A CLOCK THE TEST HOLDS: its whole seconds stay where the test put them, so every reading
    /// the walk takes (an admission, a cooldown it records, the wait a shed advertises) is the same
    /// instant; its sub-second readings and its sleeps are real, so a bounded wait still ends.
    struct HeldClock {
        secs: u64,
        origin: std::time::Instant,
    }

    impl HeldClock {
        /// The door egress's clock, held at `secs`.
        fn at(secs: u64) -> Arc<dyn busbar_kernel_egress::ports::Clock> {
            Arc::new(HeldClock {
                secs,
                origin: std::time::Instant::now(),
            })
        }
    }

    impl busbar_kernel_egress::ports::Clock for HeldClock {
        fn now_secs(&self) -> u64 {
            self.secs
        }

        fn now_millis(&self) -> u128 {
            self.origin.elapsed().as_millis()
        }

        fn now_micros(&self) -> u128 {
            self.origin.elapsed().as_micros()
        }

        fn sleep(&self, ms: u64) -> busbar_kernel_egress::ports::BoxFut<'_, ()> {
            Box::pin(tokio::time::sleep(std::time::Duration::from_millis(ms)))
        }
    }

    /// The instant the held clock reads: well before the wall clock, so a cooldown recorded on the
    /// wall clock instead of the walk's reads as years long at it.
    const HELD_AT: u64 = 1_700_000_000;

    /// ONE FAILURE BELOW THE TRIP AGAINST THE SOLE MEMBER OF POOL `p`, the walk's clock held at
    /// [`HELD_AT`]: the far end answers `reply` and then would serve. Asserts what 1.5.5 did: the
    /// cell stays Closed (the default breaker trips on an error rate over at least five outcomes),
    /// cooling for a cooldown in `band`; the next call is refused 503 without reaching the far end,
    /// its `Retry-After` the cooldown exactly.
    async fn benched_once(
        instance: &'static str,
        reply: MockResponse,
        band: std::ops::RangeInclusive<u64>,
    ) {
        let _one = ONE_PUBLISHER.lock().await;
        let _published = Withdrawn(instance);
        let clock = HeldClock::at(HELD_AT);
        let (state, server) = mock(vec![reply, MockResponse::default()]).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                clock: Some(&clock),
                ..RigOpts::default()
            },
        )
        .await;

        let (status, _, _) = rig.chat().await;
        assert_ne!(status, 200, "{instance}: the far end's one failure");
        assert!(
            matches!(
                rig.app.store.breaker_state_in("p", 0),
                busbar_kernel::store::BreakerState::Closed
            ),
            "{instance}: one failure is below the trip"
        );
        let cooling = rig.app.store.cooldown_remaining_in("p", 0, HELD_AT);
        assert!(
            band.contains(&cooling),
            "{instance}: the member is benched for 1.5.5's cooldown {band:?}, on the walk's clock: \
             {cooling}"
        );

        let (status, head, _) = rig.chat().await;
        assert_eq!(status, 503, "{instance}: the benched sole member sheds");
        let wait: u64 = head
            .get("retry-after")
            .expect("a Retry-After")
            .to_str()
            .expect("text")
            .parse()
            .expect("whole seconds");
        assert_eq!(
            wait, cooling,
            "{instance}: the Retry-After is the cooldown, read on the same clock"
        );
        assert!(
            state.next_response().is_some(),
            "{instance}: the refused call never reached the far end"
        );
    }

    /// A SINGLE-MEMBER POOL BENCHES ITS MEMBER ON ONE FAILURE BELOW THE TRIP, AS 1.5.5 DID: one 429
    /// against the sole member of pool `p` leaves the cell Closed but cooling, and the next call is
    /// refused 503 naming the cooldown as its `Retry-After` ([`benched_once`]).
    ///
    /// The wait, derived from v1.5.5:
    /// - `crates/busbar/src/store/in_memory/breaker.rs:714-724`: every Closed failure that does not
    ///   trip stores `now + compute_cooldown_with_retry_after(..)`; there is no single-member arm.
    /// - `breaker.rs:281-388`: the streak is bumped to 1 first, so the backoff is `15 * 2^1 = 30`,
    ///   jittered by `±(30 / 10) = ±3` and clamped to `[15, 120]`: 27..=33. A stated wait `W` is a
    ///   floor over it: `max(27..=33, W)`, so a stated 60 is exactly 60.
    /// - `crates/busbar/src/proxy/engine/walk.rs:49-64`: the shed advertises the soonest genuine
    ///   cooldown remaining among the admissible members, at least 1: here the sole member's.
    ///
    /// A REGRESSION GUARD of that parity, without and with a stated wait (60 s), on the held clock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_single_member_pool_benches_one_failure_below_the_trip_with_1_5_5s_wait() {
        benched_once(
            "rehome-walk-single-bench-unstated",
            MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: None,
                retry_after: None,
            },
            27..=33,
        )
        .await;
        benched_once(
            "rehome-walk-single-bench-stated",
            MockResponse::RateLimit {
                status: StatusCode::TOO_MANY_REQUESTS,
                provider_signal: None,
                retry_after: Some(60),
            },
            60..=60,
        )
        .await;
    }

    /// THE COOLDOWN A TRANSIENT FAILURE ARMS AND THE WAIT A SHED ADVERTISES READ ONE CLOCK, the
    /// walk's: one 500 against the sole member of pool `p` is recorded at the walk's `now`, as
    /// 1.5.5's store took the record's `now_time` (`availability.rs:500-513`), so at the walk's
    /// clock the member cools for 1.5.5's 27..=33 and the shed names that same wait. RED: the
    /// failure recorded on the store's own wall-clock read, which at the held clock reads as a
    /// cooldown years long.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transient_failure_is_benched_on_the_walks_clock() {
        benched_once(
            "rehome-walk-single-bench-walk-clock",
            MockResponse::ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: serde_json::json!({ "error": "server error" }),
            },
            27..=33,
        )
        .await;
    }

    /// A SESSION PINNED TO A TRIPPED MEMBER YIELDS (F25 row 187; legacy
    /// `forward_pool_integration_tests::test_sticky_yields_when_tripped`): with member 0's cell
    /// open (cooldown 600 s) before the requests, every session is served 200 by the healthy member
    /// 1, whichever member its key would pin, and member 0 receives nothing: affinity is a
    /// preference, never a pin past an open breaker. RED: a session routed to the tripped member.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_yields_a_session_pinned_to_a_tripped_member() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-sticky-yields";
        let _published = Withdrawn(instance);
        let (tripped, healthy) = (
            seat_far_end(200, SERVED_BY_TWIN).await,
            seat_far_end(200, SERVED_BY_TWIN).await,
        );
        let rig = rig(
            instance,
            RigOpts {
                members: &[(tripped.port, 1), (healthy.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        rig.app.store.force_open_in("p", 0, now() + 600);
        let chat = serde_json::json!({"model": "p", "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]});
        for session in [
            "session-abc",
            "session-1",
            "session-2",
            "session-3",
            "session-4",
            "session-5",
            "session-6",
            "session-7",
        ] {
            let response = rig
                .open(
                    "POST",
                    "/v1/chat/completions",
                    Some(chat.clone()),
                    &[("x-session-id", session)],
                )
                .await;
            assert_eq!(response.status().as_u16(), 200, "{session}");
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("the body");
            assert!(
                String::from_utf8_lossy(&body).contains("served-by-the-twin"),
                "{session} is served by the healthy member"
            );
        }
        assert_eq!(tripped.served(), 0, "the tripped member receives nothing");
        assert_eq!(healthy.served(), 8);
    }

    /// The messages dialect's context-length refusal naming a window of `window` tokens.
    fn too_long(window: u64) -> MockResponse {
        MockResponse::ServerError {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({"error": {"type": "invalid_request_error",
                "message": format!("prompt is too long: 250000 tokens > {window} maximum")}}),
        }
    }

    /// A CONTEXT-LENGTH REFUSAL FAILS OVER WITHOUT A PENALTY (F25 row 203; legacy
    /// `forward_pool_integration_tests::test_context_length_failover_no_penalty`): two members of
    /// the messages dialect with no stated window; member 0 answers 400 `prompt is too long:
    /// 250000 tokens > 200000 maximum`, member 1 answers 200: the caller is served 200 and neither
    /// member is in a cooldown. RED: the refusal relayed, or member 0 penalized for a request too
    /// big for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_fails_a_context_length_refusal_over_without_a_penalty() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-context-length";
        let _published = Withdrawn(instance);
        let (_refusing_state, refusing) = mock(vec![too_long(200_000)]).await;
        let (_serving_state, serving) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer_saying("ok"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&refusing), 100), (port_of(&serving), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, false).await;
        assert_eq!(status, 200, "the context-length refusal fails over: {text}");
        for lane in 0..2 {
            assert_eq!(
                rig.app.store.snapshot(lane, now()).cooldown_remaining_s,
                0,
                "member {lane} is not cooled for a request too big for it"
            );
        }
    }

    /// THE LARGER WINDOW SERVES (F25 row 204; legacy
    /// `forward_pool_integration_tests::test_prefers_larger_context_max`): member 0 states
    /// `context_max: 8000`, member 1 `context_max: 200000`; member 0 answers 400 `prompt is too
    /// long: 250000 tokens > 8000 maximum`: member 1 serves the 200 and member 0 stays ready. RED:
    /// no failover to the larger window, or the smaller member penalized.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_serves_a_too_long_request_from_the_larger_window() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-larger-window";
        let _published = Withdrawn(instance);
        let (_small_state, small) = mock(vec![too_long(8_000)]).await;
        let (large_state, large) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer_saying("ok"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&small), 100), (port_of(&large), 1)],
                dialect: Some(door_word("messages_dialect")),
                member_yaml: &["context_max: 8000", "context_max: 200000"],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, false).await;
        assert_eq!(status, 200, "{text}");
        assert!(
            large_state.get_last_request_body().is_some(),
            "the larger window served"
        );
        assert!(
            rig.app.store.ready_in("p", 0, now()),
            "the smaller member stays ready"
        );
    }

    /// NO LARGER WINDOW: THE TERMINAL, AND NO PENALTY (F25 row 205; legacy
    /// `forward_pool_integration_tests::test_same_size_pool_exhausts`): two members both stating
    /// `context_max: 8000`, both answering 400 `prompt is too long: 250000 tokens > 8000 maximum`:
    /// the caller gets 503 and neither member is in a cooldown. RED: a member penalized, or the
    /// walk answering anything but its terminal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_ends_a_too_long_request_at_its_terminal_without_a_penalty() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-same-window";
        let _published = Withdrawn(instance);
        let (_first_state, first) = mock(vec![too_long(8_000)]).await;
        let (_second_state, second) = mock(vec![too_long(8_000)]).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&first), 1), (port_of(&second), 1)],
                dialect: Some(door_word("messages_dialect")),
                member_yaml: &["context_max: 8000", "context_max: 8000"],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, text) = send_messages(&rig, false).await;
        assert_eq!(status, 503, "{text}");
        for lane in 0..2 {
            assert_eq!(
                rig.app.store.snapshot(lane, now()).cooldown_remaining_s,
                0,
                "member {lane} is not cooled"
            );
        }
    }

    /// A CLEAN STREAM END IS ONE SUCCESS (F25 row 206; legacy
    /// `forward_pool_integration_tests::test_clean_sse_end_records_success_not_failure`): eight
    /// clean streamed answers of the messages dialect (start, a `Hi` delta, usage 3/2, stop) on one
    /// member leave its snapshot at err 0 and ok exactly 8, the member ready. RED: a clean end
    /// recorded as a failure, or a success counted twice or not at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_records_one_success_per_clean_stream_end() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-clean-ends";
        let _published = Withdrawn(instance);
        const RUNS: usize = 8;
        let clean = || {
            MockResponse::Sse {
            events: vec![
                r#"{"type":"message_start"}"#.to_string(),
                r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#.to_string(),
                r#"{"type":"message_delta","usage":{"input_tokens":3,"output_tokens":2}}"#.to_string(),
                r#"{"type":"message_stop"}"#.to_string(),
            ],
            abort_at_index: None,
        }
        };
        let (_state, server) = mock((0..RUNS).map(|_| clean()).collect()).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        for _ in 0..RUNS {
            let (status, _, text) = send_messages(&rig, true).await;
            assert_eq!(status, 200, "{text}");
        }
        let snap = rig.app.store.snapshot(0, now());
        assert_eq!(snap.err, 0, "a clean end records no failure");
        assert_eq!(snap.ok, RUNS as u64, "one success per clean stream");
        assert!(rig.app.store.ready_in("p", 0, now()));
    }

    /// PASSTHROUGH WITH NO CALLER CREDENTIAL PRESENTS NONE (F25 row 342; legacy
    /// `ingress_indistinguishability_tests::test_passthrough_no_caller_token_selects_empty_not_lane_key`):
    /// on an open front door, a passthrough pool whose provider HAS an operator key, reached by a
    /// caller presenting no credential, serves 200 and the far end receives NO `authorization` at
    /// all, never the operator's key. RED: the operator's key (or a bare `Bearer`) presented.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_presents_no_credential_for_a_passthrough_caller_with_none() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-passthrough-none";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::from_str(SERVED_BY_TWIN).expect("JSON"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&server), 1)],
                pool_yaml: "upstream_credentials: passthrough",
                open_door: true,
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send_bare(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": "p", "max_tokens": 50,
                    "messages": [{"role": "user", "content": "hi"}]})),
                &[],
            )
            .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        if let Some(seen) = state.get_last_request_header("authorization") {
            let what = if seen.contains("sk-seats") {
                "the operator's key (LEAK)"
            } else {
                "an unexpected credential"
            };
            panic!("a passthrough caller with no credential is forwarded none; got {what}");
        }
    }

    /// A REAL MID-STREAM FAILURE STAYS WITH ITS MEMBER (F25 row 452; legacy
    /// `ingress_integration_tests::test_real_mid_stream_failure_does_not_fail_over_to_second_member`):
    /// member 1 of a streamed pool sends `MEMBER-1-REAL-FIRST-FRAME` and its connection then
    /// fails: the caller has its 200, member 1's frame, never `MEMBER-2-MUST-NEVER-APPEAR`, and a
    /// trailing frame that is the caller dialect's error envelope; member 1's error count rises by
    /// exactly one. RED: a fresh attempt on member 2 after the first byte, no in-band error, or a
    /// failure counted other than once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_keeps_a_real_mid_stream_failure_with_its_member() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-real-midstream";
        let _published = Withdrawn(instance);
        let (_bad_state, bad) = mock(vec![MockResponse::SseTransportError {
            ok_events: vec![
                r#"{"choices":[{"delta":{"content":"MEMBER-1-REAL-FIRST-FRAME"}}]}"#.to_string(),
            ],
        }])
        .await;
        let (_good_state, good) = mock(vec![MockResponse::Sse {
            events: vec![
                r#"{"choices":[{"delta":{"content":"MEMBER-2-MUST-NEVER-APPEAR"}}]}"#.to_string(),
            ],
            abort_at_index: None,
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&bad), 100), (port_of(&good), 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let err_before = rig.app.store.snapshot(0, now()).err;
        let (status, _, body) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": "p", "stream": true,
                    "messages": [{"role": "user", "content": "hi"}]})),
            )
            .await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 200, "member 1's first byte began the answer");
        assert!(text.contains("MEMBER-1-REAL-FIRST-FRAME"), "{text}");
        assert!(!text.contains("MEMBER-2-MUST-NEVER-APPEAR"), "{text}");
        let last_data = text
            .split("\n\n")
            .filter(|piece| !piece.trim().is_empty())
            .last()
            .and_then(|piece| piece.lines().find_map(|l| l.strip_prefix("data: ")))
            .expect("a trailing data frame");
        let terminal: serde_json::Value =
            serde_json::from_str(last_data).expect("the caller dialect's JSON envelope");
        assert!(
            terminal.get("error").is_some(),
            "the in-band terminal frame is an error envelope: {terminal}"
        );
        assert_eq!(
            rig.app.store.snapshot(0, now()).err,
            err_before + 1,
            "member 1's cell records exactly one mid-stream failure"
        );
    }

    /// A TRIPPED PRIMARY IS NEVER DIALLED; ITS TWIN SERVES (F25 row 586; legacy
    /// `reroute_pool_tests::a_tripped_pool_primary_reroutes_the_request_to_its_twin_and_stays_untouched`):
    /// a two-member pool whose primary's breaker is open before the request serves 200 `from the
    /// twin`; the primary's far end receives NO request, the twin's receives it. RED: the tripped
    /// primary dialled (even if it then fails over).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_reroutes_a_tripped_primary_to_its_twin_without_dialling_it() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-walk-tripped-primary";
        let _published = Withdrawn(instance);
        let (primary_state, primary) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer_saying("from the primary"),
        }])
        .await;
        let (twin_state, twin) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer_saying("from the twin"),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(port_of(&primary), 1), (port_of(&twin), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        rig.app.store.force_open_in("p", 0, now() + 1_000_000);
        let (status, _, text) = send_messages(&rig, false).await;
        assert_eq!(status, 200, "the twin is admissible: {text}");
        assert!(text.contains("from the twin"), "{text}");
        assert!(
            primary_state.get_last_request_body().is_none(),
            "the tripped primary is never dispatched to"
        );
        assert!(
            twin_state.get_last_request_body().is_some(),
            "the twin received the request"
        );
    }
}

// ── F25 REHOME: THE FRONT DOOR'S REFUSALS IN EVERY CALLER DIALECT ───────────────────────────────
//
// The previous release's engine tests of what a caller is told before any far end is dialled: a
// credential the door refuses, a spent budget, a rate limit, a pool the key may not reach, a
// misdirected ad-hoc route, each rendered in the caller's own dialect. Each is driven here through
// the composed door, the refusal real (the governance book enforcing a configured group), the
// dialects' paths and bodies the plane's own door words.
#[cfg(linked_driver_proofs)]
mod pools_door_refusals {
    use super::*;

    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};

    use super::super::hook_seat_tests::{DoorRig, FarEnd};

    /// One group limit of `amount` `metric` per `per`.
    fn limit(metric: LimitMetric, amount: u64, per: LimitWindow) -> LimitCfg {
        LimitCfg {
            metric,
            amount,
            per: Some(per),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }
    }

    /// A door word that is a JSON request body.
    fn body_word(key: &str) -> serde_json::Value {
        serde_json::from_str(door_word(key)).expect("a JSON request body")
    }

    /// A chat-shaped request on pool `p`.
    fn chat_on_p() -> serde_json::Value {
        serde_json::json!({"model": "p", "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]})
    }

    /// Every caller dialect's path onto pool `p` and a request in that dialect: chat, messages,
    /// the second chat surface, the respond surface, generate, converse.
    fn every_dialect() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("/v1/chat/completions", chat_on_p()),
            (door_word("messages_path"), chat_on_p()),
            (door_word("chat_v2_path"), body_word("chat_v2_body")),
            (door_word("respond_path"), body_word("respond_body")),
            (door_word("generate_path"), body_word("generate_body")),
            (door_word("converse_path"), body_word("converse_body")),
        ]
    }

    /// A body as JSON.
    fn json_of(body: &[u8]) -> serde_json::Value {
        serde_json::from_slice(body)
            .unwrap_or_else(|e| panic!("a JSON envelope ({e}): {}", String::from_utf8_lossy(body)))
    }

    /// A head field as text.
    fn field<'h>(head: &'h axum::http::HeaderMap, name: &str) -> Option<&'h str> {
        head.get(name).and_then(|v| v.to_str().ok())
    }

    /// A canonical UUID-v4: five dash-separated lowercase-hex groups 8-4-4-4-12, version nibble 4,
    /// variant nibble 8, 9, a or b.
    fn assert_uuid_v4_shaped(id: &str) {
        let groups: Vec<&str> = id.split('-').collect();
        assert_eq!(
            groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12],
            "UUID-v4 shaped (8-4-4-4-12), got '{id}'"
        );
        assert!(
            id.chars()
                .all(|ch| ch == '-' || (ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())),
            "lowercase hex with dashes only, got '{id}'"
        );
        assert_eq!(groups[2].chars().next(), Some('4'), "version 4: '{id}'");
        assert!(
            matches!(groups[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
            "variant nibble 8/9/a/b: '{id}'"
        );
    }

    /// One request carrying `x-api-key: wrong-token` and the previous release's body.
    async fn with_wrong_key(rig: &DoorRig, path: &str) -> (u16, axum::http::HeaderMap, Vec<u8>) {
        rig.send_bare(
            "POST",
            path,
            Some(serde_json::json!({"model": "p",
                "messages": [{"role": "user", "content": "hi"}]})),
            &[("x-api-key", "wrong-token")],
        )
        .await
    }

    /// A rig over one far end (which no refusal below may reach).
    async fn keyed(instance: &'static str) -> (DoorRig, FarEnd) {
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        (rig, far)
    }

    /// THE REFUSED CREDENTIAL IN EVERY DIALECT'S OWN ENVELOPE (F25 row 64; legacy
    /// `auth_native_envelope_tests::test_unauthorized_response_is_json_with_native_envelope`): a
    /// caller presenting a wrong key is refused before routing, in its path's dialect: generate on
    /// the beta and the stable path, 400 `application/json`, `error.code` 400, `error.status`
    /// `INVALID_ARGUMENT`; messages 401, `type: error`, `error.type: authentication_error`; chat 401,
    /// no top-level `type`, `error.type: authentication_error`, `error.code: invalid_api_key`; the
    /// respond surface `error.code: invalid_api_key` with an `error.param`; the second chat
    /// surface a bare top-level `message`, no `error`, no `type`; converse 403 with
    /// `x-amzn-errortype: AccessDeniedException`, a UUID-v4 `x-amzn-requestid` and
    /// `__type: AccessDeniedException`, no `error`. Nothing is dialled. RED: any dialect answered
    /// in another's envelope, or with another status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_wrong_key_in_every_dialects_own_envelope() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-wrong-key-envelopes";
        let _published = Withdrawn(instance);
        let (rig, far) = keyed(instance).await;

        for path in [door_word("generate_path"), door_word("generate_v1_path")] {
            let (status, head, body) = with_wrong_key(&rig, path).await;
            assert_eq!(status, 400, "{path}");
            assert_eq!(
                field(&head, "content-type"),
                Some("application/json"),
                "{path}"
            );
            let answer = json_of(&body);
            assert_eq!(answer["error"]["code"], 400, "{path}: {answer}");
            assert_eq!(
                answer["error"]["status"], "INVALID_ARGUMENT",
                "{path}: {answer}"
            );
        }

        let (status, _, body) = with_wrong_key(&rig, door_word("messages_path")).await;
        assert_eq!(status, 401);
        let answer = json_of(&body);
        assert_eq!(answer["type"], "error", "{answer}");
        assert_eq!(answer["error"]["type"], "authentication_error", "{answer}");

        let (status, _, body) = with_wrong_key(&rig, "/v1/chat/completions").await;
        assert_eq!(status, 401);
        let answer = json_of(&body);
        assert!(answer.get("type").is_none(), "no top-level type: {answer}");
        assert_eq!(answer["error"]["type"], "authentication_error", "{answer}");
        assert_eq!(answer["error"]["code"], "invalid_api_key", "{answer}");

        let (_, _, body) = with_wrong_key(&rig, door_word("respond_path")).await;
        let answer = json_of(&body);
        assert_eq!(answer["error"]["type"], "authentication_error", "{answer}");
        assert_eq!(answer["error"]["code"], "invalid_api_key", "{answer}");
        assert!(answer["error"].get("param").is_some(), "{answer}");

        let (_, _, body) = with_wrong_key(&rig, door_word("chat_v2_path")).await;
        let answer = json_of(&body);
        assert!(answer.get("message").is_some(), "a bare message: {answer}");
        assert!(
            answer.get("error").is_none() && answer.get("type").is_none(),
            "no error, no type: {answer}"
        );

        let (status, head, body) = with_wrong_key(&rig, door_word("converse_path")).await;
        assert_eq!(status, 403, "a signature-style auth failure is 403");
        assert_eq!(
            field(&head, "x-amzn-errortype"),
            Some("AccessDeniedException")
        );
        assert_uuid_v4_shaped(field(&head, "x-amzn-requestid").expect("a request id"));
        let answer = json_of(&body);
        assert_eq!(answer["__type"], "AccessDeniedException", "{answer}");
        assert!(answer.get("error").is_none(), "{answer}");
        assert_eq!(far.served(), 0, "no refusal is dialled");
    }

    /// THE SECOND CHAT SURFACE AND THE RESPOND SURFACE REFUSE A WRONG KEY NATIVELY (F25 row 68;
    /// legacy `auth_native_envelope_tests::test_cohere_and_responses_ingress_token_mode_native_401`):
    /// `x-api-key: wrong-token` on the second chat surface is 401 `application/json`, a bare
    /// top-level `message`, no `error` and no `type`; on the respond surface 401
    /// `application/json`, `error.type: authentication_error`, `error.code: invalid_api_key`. RED:
    /// either answered in another dialect's envelope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_wrong_key_on_the_second_chat_and_respond_surfaces() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-wrong-key-chat-v2";
        let _published = Withdrawn(instance);
        let (rig, _far) = keyed(instance).await;

        let (status, head, body) = with_wrong_key(&rig, door_word("chat_v2_path")).await;
        assert_eq!(status, 401);
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        let answer = json_of(&body);
        assert!(answer.get("message").is_some(), "{answer}");
        assert!(
            answer.get("error").is_none() && answer.get("type").is_none(),
            "{answer}"
        );

        let (status, head, body) = with_wrong_key(&rig, door_word("respond_path")).await;
        assert_eq!(status, 401);
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        let answer = json_of(&body);
        assert_eq!(answer["error"]["type"], "authentication_error", "{answer}");
        assert_eq!(answer["error"]["code"], "invalid_api_key", "{answer}");
    }

    /// CONVERSE REFUSES A WRONG BEARER WITH A 403 (F25 row 69; legacy
    /// `auth_native_envelope_tests::test_bedrock_ingress_wrong_token_is_403_native_envelope`):
    /// `Authorization: Bearer wrong-token` on the converse path is 403 (never 401),
    /// `x-amzn-errortype: AccessDeniedException`, a UUID-v4 `x-amzn-requestid`, content-type
    /// `application/json`, body `__type: AccessDeniedException`. RED: a 401, or either head field
    /// missing or another value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_wrong_bearer_on_converse_with_a_403() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-wrong-bearer-converse";
        let _published = Withdrawn(instance);
        let (rig, _far) = keyed(instance).await;
        let (status, head, body) = rig
            .send_bare(
                "POST",
                door_word("converse_path"),
                Some(body_word("converse_body")),
                &[("authorization", "Bearer wrong-token")],
            )
            .await;
        assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            field(&head, "x-amzn-errortype"),
            Some("AccessDeniedException")
        );
        assert_uuid_v4_shaped(field(&head, "x-amzn-requestid").expect("a request id"));
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        assert_eq!(json_of(&body)["__type"], "AccessDeniedException");
    }

    /// GENERATE REFUSES A WRONG KEY AS A BAD ARGUMENT, ON BOTH ITS PATHS (F25 row 70; legacy
    /// `auth_native_envelope_tests::test_gemini_ingress_wrong_token_is_native_bad_key_envelope`):
    /// `x-goog-api-key: wrong-token` on the beta and the stable generate path is 400
    /// `application/json`, `error.code` 400, `error.status: INVALID_ARGUMENT`. RED: either path
    /// answered 401 or in another envelope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_wrong_key_on_both_generate_paths_as_a_bad_argument() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-wrong-key-generate";
        let _published = Withdrawn(instance);
        let (rig, _far) = keyed(instance).await;
        for path in [door_word("generate_path"), door_word("generate_v1_path")] {
            let (status, head, body) = rig
                .send_bare(
                    "POST",
                    path,
                    Some(body_word("generate_body")),
                    &[("x-goog-api-key", "wrong-token")],
                )
                .await;
            assert_eq!(status, 400, "{path}: {}", String::from_utf8_lossy(&body));
            assert_eq!(
                field(&head, "content-type"),
                Some("application/json"),
                "{path}"
            );
            let answer = json_of(&body);
            assert_eq!(answer["error"]["code"], 400, "{path}: {answer}");
            assert_eq!(
                answer["error"]["status"], "INVALID_ARGUMENT",
                "{path}: {answer}"
            );
        }
    }

    /// A rig whose key's group `bgrp` caps its all-time budget at 100 cents with 250 cents (250
    /// requests at a one-cent fee) already spent and hydrated.
    async fn over_budget(instance: &'static str) -> (DoorRig, FarEnd) {
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let limits = [limit(LimitMetric::Budget, 100, LimitWindow::Total)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("bgrp", &limits)),
                seed: &[("group:bgrp@total", 250)],
                ..RigOpts::default()
            },
        )
        .await;
        (rig, far)
    }

    /// A rig whose key's group admits no request a minute.
    async fn over_rpm(instance: &'static str) -> (DoorRig, FarEnd) {
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let limits = [limit(LimitMetric::Requests, 0, LimitWindow::Minute)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("rl0", &limits)),
                ..RigOpts::default()
            },
        )
        .await;
        (rig, far)
    }

    /// A SPENT GROUP BUDGET IN THE MESSAGES DIALECT (F25 row 140; legacy
    /// `forward_pool_integration_tests::test_governance_budget_over_quota`): a key in group `bgrp`,
    /// its 100-cent all-time cap spent (250 cents seeded and hydrated), posting on the messages path
    /// is refused 429 before any far dial, `application/json`, body `type: error`, `error.type:
    /// billing_error` (the dialect's own billing word, never another dialect's quota token). RED:
    /// the request admitted, another status, or another error type.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_in_the_messages_dialect() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-messages";
        let _published = Withdrawn(instance);
        let (rig, far) = over_budget(instance).await;
        let (status, head, body) = rig
            .send("POST", door_word("messages_path"), Some(chat_on_p()))
            .await;
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        let answer = json_of(&body);
        assert_eq!(answer["type"], "error", "{answer}");
        assert_eq!(answer["error"]["type"], "billing_error", "{answer}");
        assert_eq!(far.served(), 0, "refused before any far dial");
    }

    /// A SPENT BUDGET ON CHAT (F25 row 141; legacy
    /// `forward_pool_integration_tests::test_budget_over_quota_openai_envelope`): 429,
    /// `application/json`, `error.type: insufficient_quota`. RED: another status or type.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_on_chat() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-chat";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_budget(instance).await;
        let (status, head, body) = rig.chat().await;
        assert_eq!(status, 429);
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        let answer = json_of(&body);
        assert_eq!(answer["error"]["type"], "insufficient_quota", "{answer}");
    }

    /// A SPENT BUDGET ON THE RESPOND SURFACE (F25 row 142; legacy
    /// `forward_pool_integration_tests::test_budget_over_quota_responses_envelope`): 429,
    /// `error.type` and `error.code` both `insufficient_quota` (the code never null). RED: a null
    /// code, another type or status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_on_the_respond_surface() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-respond";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_budget(instance).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("respond_path"),
                Some(body_word("respond_body")),
            )
            .await;
        assert_eq!(status, 429);
        let answer = json_of(&body);
        assert_eq!(answer["error"]["type"], "insufficient_quota", "{answer}");
        assert_eq!(answer["error"]["code"], "insufficient_quota", "{answer}");
    }

    /// A SPENT BUDGET ON THE SECOND CHAT SURFACE (F25 row 143; legacy
    /// `forward_pool_integration_tests::test_budget_over_quota_cohere_envelope`): 429, a string
    /// top-level `message`, no `error`, no `type`. RED: a wrapped envelope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_on_the_second_chat_surface() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-chat-v2";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_budget(instance).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("chat_v2_path"),
                Some(body_word("chat_v2_body")),
            )
            .await;
        assert_eq!(status, 429);
        let answer = json_of(&body);
        assert!(answer["message"].is_string(), "{answer}");
        assert!(
            answer.get("error").is_none() && answer.get("type").is_none(),
            "{answer}"
        );
    }

    /// A SPENT BUDGET ON GENERATE (F25 row 144; legacy
    /// `forward_pool_integration_tests::test_budget_over_quota_gemini_envelope`): 429,
    /// `error.code` 429, `error.status: RESOURCE_EXHAUSTED`. RED: another code or status word.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_on_generate() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-generate";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_budget(instance).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("generate_path"),
                Some(body_word("generate_body")),
            )
            .await;
        assert_eq!(status, 429);
        let answer = json_of(&body);
        assert_eq!(answer["error"]["code"], 429, "{answer}");
        assert_eq!(answer["error"]["status"], "RESOURCE_EXHAUSTED", "{answer}");
    }

    /// A SPENT BUDGET ON CONVERSE (F25 row 145; legacy
    /// `forward_pool_integration_tests::test_budget_over_quota_bedrock_envelope`): 429,
    /// `x-amzn-errortype: ThrottlingException`, an `x-amzn-requestid`, body `__type:
    /// ThrottlingException` (#958: an error Converse declares; 1.5.5's 400
    /// `ServiceQuotaExceededException` is one it does not). RED: a 400, or either field missing or
    /// another value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_on_converse() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-converse";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_budget(instance).await;
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("converse_path"),
                Some(body_word("converse_body")),
            )
            .await;
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            field(&head, "x-amzn-errortype"),
            Some("ThrottlingException")
        );
        assert!(head.contains_key("x-amzn-requestid"));
        assert_eq!(json_of(&body)["__type"], "ThrottlingException");
    }

    /// THE REQUESTS-A-MINUTE LIMIT (F25 row 146; legacy
    /// `forward_pool_integration_tests::test_governance_rate_limit_429`): a key in a group allowing
    /// 2 requests a minute is let through twice (each served), and its third request is refused 429
    /// with a `Retry-After`. RED: a third admission, or a refusal without its wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_the_request_past_its_groups_rate() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-two";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let limits = [limit(LimitMetric::Requests, 2, LimitWindow::Minute)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("rl2", &limits)),
                ..RigOpts::default()
            },
        )
        .await;
        // Not across a minute's roll: start the three requests well inside one window.
        let into_window = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
            % 60;
        if into_window >= 57 {
            tokio::time::sleep(std::time::Duration::from_secs(60 - into_window + 1)).await;
        }
        for n in 0..2 {
            assert_eq!(rig.chat().await.0, 200, "request {n} is under the rate");
        }
        let (status, head, _) = rig.chat().await;
        assert_eq!(status, 429, "the third request is over the rate");
        assert!(
            head.contains_key("retry-after"),
            "with a Retry-After: {head:?}"
        );
        assert_eq!(far.served(), 2);
    }

    /// AN EXHAUSTED RATE ON CHAT (F25 row 147; legacy
    /// `forward_pool_integration_tests::test_rate_limit_429_openai_native_envelope`): 429,
    /// `application/json`, a `Retry-After`, `error.type: rate_limit_error`. RED: another type, or
    /// no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_on_chat() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-chat";
        let _published = Withdrawn(instance);
        let (rig, far) = over_rpm(instance).await;
        let (status, head, body) = rig.chat().await;
        assert_eq!(status, 429);
        assert_eq!(field(&head, "content-type"), Some("application/json"));
        assert!(head.contains_key("retry-after"));
        assert_eq!(json_of(&body)["error"]["type"], "rate_limit_error");
        assert_eq!(far.served(), 0);
    }

    /// AN EXHAUSTED RATE ON THE RESPOND SURFACE (F25 row 148; legacy
    /// `forward_pool_integration_tests::test_rate_limit_429_responses_native_envelope`): 429, a
    /// `Retry-After`, `error.type: rate_limit_error`. RED: another type, or no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_on_the_respond_surface() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-respond";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_rpm(instance).await;
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("respond_path"),
                Some(body_word("respond_body")),
            )
            .await;
        assert_eq!(status, 429);
        assert!(head.contains_key("retry-after"));
        assert_eq!(json_of(&body)["error"]["type"], "rate_limit_error");
    }

    /// AN EXHAUSTED RATE ON THE SECOND CHAT SURFACE (F25 row 149; legacy
    /// `forward_pool_integration_tests::test_rate_limit_429_cohere_native_envelope`): 429, a
    /// `Retry-After`, a string top-level `message`, no `error`, no `type`. RED: a wrapped
    /// envelope, or no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_on_the_second_chat_surface() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-chat-v2";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_rpm(instance).await;
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("chat_v2_path"),
                Some(body_word("chat_v2_body")),
            )
            .await;
        assert_eq!(status, 429);
        assert!(head.contains_key("retry-after"));
        let answer = json_of(&body);
        assert!(answer["message"].is_string(), "{answer}");
        assert!(
            answer.get("error").is_none() && answer.get("type").is_none(),
            "{answer}"
        );
    }

    /// AN EXHAUSTED RATE ON GENERATE (F25 row 150; legacy
    /// `forward_pool_integration_tests::test_rate_limit_429_gemini_native_envelope`): 429, a
    /// `Retry-After`, `error.code` 429, `error.status: RESOURCE_EXHAUSTED`. RED: another code or
    /// status word, or no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_on_generate() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-generate";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_rpm(instance).await;
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("generate_path"),
                Some(body_word("generate_body")),
            )
            .await;
        assert_eq!(status, 429);
        assert!(head.contains_key("retry-after"));
        let answer = json_of(&body);
        assert_eq!(answer["error"]["code"], 429, "{answer}");
        assert_eq!(answer["error"]["status"], "RESOURCE_EXHAUSTED", "{answer}");
    }

    /// AN EXHAUSTED RATE ON CONVERSE (F25 row 151; legacy
    /// `forward_pool_integration_tests::test_rate_limit_429_bedrock_native_envelope`): 429, a
    /// `Retry-After`, `x-amzn-errortype: ThrottlingException`, an `x-amzn-requestid`, body
    /// `__type: ThrottlingException`. RED: either field missing or another value, or no wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_on_converse() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-converse";
        let _published = Withdrawn(instance);
        let (rig, _far) = over_rpm(instance).await;
        let (status, head, body) = rig
            .send(
                "POST",
                door_word("converse_path"),
                Some(body_word("converse_body")),
            )
            .await;
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        assert!(head.contains_key("retry-after"));
        assert_eq!(
            field(&head, "x-amzn-errortype"),
            Some("ThrottlingException")
        );
        assert!(head.contains_key("x-amzn-requestid"));
        assert_eq!(json_of(&body)["__type"], "ThrottlingException");
    }

    /// NO INTERNAL PREFIX ON A FORWARD-LAYER ERROR, IN ANY DIALECT (F25 row 354; legacy
    /// `ingress_indistinguishability_tests::test_forward_layer_errors_carry_no_router_prefix`): in
    /// every caller dialect, a pool whose members are all down, and (for the dialects naming their
    /// model in the body) a pool that does not exist, answer a body that never carries the
    /// internal `router:` prefix. RED: the prefix on any of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_puts_no_internal_prefix_on_a_forward_layer_error() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-no-router-prefix";
        let _published = Withdrawn(instance);
        let closed = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            listener.local_addr().expect("its address").port()
        };
        let rig = rig(
            instance,
            RigOpts {
                members: &[(closed, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        for (path, request) in every_dialect() {
            let (status, _, body) = rig.send("POST", path, Some(request.clone())).await;
            let text = String::from_utf8_lossy(&body);
            assert!(
                !text.contains("router:"),
                "all members down on {path} ({status}) leaked the prefix: {text}"
            );
            if request.get("model").is_some() {
                let mut missing = request;
                missing["model"] = serde_json::Value::from("missingpool");
                let (status, _, body) = rig.send("POST", path, Some(missing)).await;
                let text = String::from_utf8_lossy(&body);
                assert!(
                    !text.contains("router:"),
                    "a missing pool on {path} ({status}) leaked the prefix: {text}"
                );
            }
        }
    }

    /// The previous release's leak check: a governance refusal body never says `virtual key`, the
    /// key's id, the pool's name or the product's name.
    fn assert_leak_free(body: &str, key_id: &str, pool: &str) {
        assert!(!body.contains("virtual key"), "{body}");
        assert!(!body.contains(key_id), "the key id: {body}");
        assert!(!body.contains(pool), "the pool name: {body}");
        assert!(!body.to_lowercase().contains("busbar"), "{body}");
    }

    /// GOVERNANCE REFUSALS LEAK NO INTERNAL VOCABULARY (F25 row 427; legacy
    /// `ingress_integration_tests::test_governance_rejection_bodies_leak_no_internal_vocab`): a key
    /// restricted to another pool is refused 403; a key whose group has a zero all-time budget is
    /// refused 429 on chat and 429 `ThrottlingException` on converse (#958); a key whose group
    /// allows no request a minute is refused 429 with a `Retry-After`; and none of those bodies
    /// says `virtual key`, the key's id, the pool's name or the product's name. RED: a refusal of
    /// another status, or any of those words on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_doors_governance_refusals_leak_no_internal_vocabulary() {
        let _one = ONE_PUBLISHER.lock().await;
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let pool = "any-pool";
        let request = serde_json::json!({"model": pool, "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]});

        let instance = "rehome-gate-leak-restricted";
        let published = Withdrawn(instance);
        let restricted = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                more_pools: &[(pool, &[(0, 1)])],
                allowed_pools: Some(&["allowed-only"]),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = restricted
            .send("POST", "/v1/chat/completions", Some(request.clone()))
            .await;
        assert_eq!(status, 403, "a pool the key may not reach");
        assert_leak_free(&String::from_utf8_lossy(&body), &restricted.key_id, pool);
        drop(restricted);
        drop(published);

        let empty = [limit(LimitMetric::Budget, 0, LimitWindow::Total)];
        let instance = "rehome-gate-leak-broke";
        let published = Withdrawn(instance);
        let broke = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                more_pools: &[(pool, &[(0, 1)])],
                group: Some(("empty", &empty)),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = broke
            .send("POST", "/v1/chat/completions", Some(request.clone()))
            .await;
        assert_eq!(status, 429, "a zero budget");
        assert_leak_free(&String::from_utf8_lossy(&body), &broke.key_id, pool);
        let converse_on_pool = door_word("converse_path").replacen("/p/", &format!("/{pool}/"), 1);
        let (status, _, body) = broke
            .send("POST", &converse_on_pool, Some(body_word("converse_body")))
            .await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 429, "a zero budget on converse: {text}");
        assert!(text.contains("ThrottlingException"), "{text}");
        assert_leak_free(&text, &broke.key_id, pool);
        drop(broke);
        drop(published);

        let closed = [limit(LimitMetric::Requests, 0, LimitWindow::Minute)];
        let instance = "rehome-gate-leak-throttled";
        let _published = Withdrawn(instance);
        let throttled = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                more_pools: &[(pool, &[(0, 1)])],
                group: Some(("closed", &closed)),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, head, body) = throttled
            .send("POST", "/v1/chat/completions", Some(request))
            .await;
        assert_eq!(status, 429, "no request a minute");
        assert!(head.contains_key("retry-after"), "{head:?}");
        assert_leak_free(&String::from_utf8_lossy(&body), &throttled.key_id, pool);
        assert_eq!(far.served(), 0, "no refusal is dialled");
    }

    /// A PROVIDER SEGMENT THAT IS NOT THE MODEL'S IS A 400 IN THE CALLER'S ENVELOPE (F25 row 462;
    /// legacy `ingress_integration_tests::test_adhoc_provider_mismatch_400_anthropic_envelope_via_router`):
    /// an ad-hoc messages route `/<provider>/<model>/...` naming model `m0` under provider `oai1`
    /// (not the model's) is refused 400, content-type starting `application/json`, body `type:
    /// error`, `error.type: invalid_request_error`. RED: the model served anyway, or another
    /// status or envelope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_ad_hoc_route_naming_the_wrong_provider() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-adhoc-mismatch";
        let _published = Withdrawn(instance);
        let (first, second) = (
            seat_far_end(200, SERVED_BY_TWIN).await,
            seat_far_end(200, SERVED_BY_TWIN).await,
        );
        let rig = rig(
            instance,
            RigOpts {
                members: &[(first.port, 1), (second.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, head, body) = rig
            .send(
                "POST",
                &format!("/oai1/m0{}", door_word("messages_path")),
                Some(serde_json::json!({"model": "m0", "messages": [], "max_tokens": 16})),
            )
            .await;
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
        assert!(
            field(&head, "content-type").is_some_and(|ct| ct.starts_with("application/json")),
            "{head:?}"
        );
        let answer = json_of(&body);
        assert_eq!(answer["type"], "error", "{answer}");
        assert_eq!(answer["error"]["type"], "invalid_request_error", "{answer}");
        assert_eq!((first.served(), second.served()), (0, 0));
    }

    /// AN EXHAUSTED RATE ON EVERY CALLER DIALECT (F25 row 468; legacy
    /// `ingress_integration_tests::test_governance_rate_limit_429_native_envelope_all_ingress`): a
    /// key whose group allows no request a minute is refused 429 with a `Retry-After` on all six
    /// caller dialects; generate's `error.status` is `RESOURCE_EXHAUSTED`, converse carries
    /// `x-amzn-errortype` and `x-amzn-requestid`. RED: any dialect answered otherwise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_an_exhausted_rate_in_every_dialect() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-rate-every-dialect";
        let _published = Withdrawn(instance);
        let (rig, far) = over_rpm(instance).await;
        for (path, request) in every_dialect() {
            let (status, head, body) = rig.send("POST", path, Some(request)).await;
            assert_eq!(status, 429, "{path}: {}", String::from_utf8_lossy(&body));
            assert!(head.contains_key("retry-after"), "{path}: {head:?}");
            if path == door_word("generate_path") {
                assert_eq!(json_of(&body)["error"]["status"], "RESOURCE_EXHAUSTED");
            }
            if path == door_word("converse_path") {
                assert!(head.contains_key("x-amzn-errortype"), "{head:?}");
                assert!(head.contains_key("x-amzn-requestid"), "{head:?}");
            }
        }
        assert_eq!(far.served(), 0);
    }

    /// A SPENT BUDGET ON EVERY CALLER DIALECT (F25 row 469; legacy
    /// `ingress_integration_tests::test_governance_over_budget_native_envelope_all_ingress`): a key
    /// over its group's all-time budget is refused 429 on chat, messages, the second chat surface,
    /// the respond surface and generate, and 429 with body `__type: ThrottlingException` on
    /// converse (#958: an error Converse declares). RED: any dialect answered otherwise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_in_every_dialect() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-budget-every-dialect";
        let _published = Withdrawn(instance);
        let (rig, far) = over_budget(instance).await;
        for (path, request) in every_dialect() {
            let (status, _, body) = rig.send("POST", path, Some(request)).await;
            assert_eq!(status, 429, "{path}: {}", String::from_utf8_lossy(&body));
            if path == door_word("converse_path") {
                assert_eq!(json_of(&body)["__type"], "ThrottlingException");
            }
        }
        assert_eq!(far.served(), 0);
    }

    /// A KEY NAMING A GROUP NOBODY CONFIGURED FAILS CLOSED (F25 row 473; legacy
    /// `ingress_integration_tests::test_missing_group_fails_closed_at_ingress`): a governed key whose
    /// group `ghost` is not configured is refused 429 (never admitted uncapped), and the body names
    /// the fix: `group 'ghost' is not configured`. RED: the request served, or the missing group
    /// not named.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_fails_closed_on_a_key_naming_an_unconfigured_group() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-ghost-group";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let finance = [limit(LimitMetric::Budget, 0, LimitWindow::Total)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("finance", &finance)),
                key_group: Some("ghost"),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig.chat().await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 429, "{text}");
        assert!(text.contains("group 'ghost' is not configured"), "{text}");
        assert_eq!(far.served(), 0);
    }

    /// PB-19, THE RENDERED REFUSAL IS THE DIRECT ADMISSION'S, BYTE FOR BYTE: a key naming a group
    /// this node's config does not know is refused by the pools door with exactly the status, kind
    /// and message the kernel's one limit-refusal spelling renders for the direct admission's own
    /// `MissingGroup` block over the same book and card — nothing reworded on the door path — and
    /// the far end is never dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_doors_missing_group_refusal_is_the_direct_admissions_bytes() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-gate-ghost-group-bytes";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let finance = [limit(LimitMetric::Budget, 0, LimitWindow::Total)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("finance", &finance)),
                key_group: Some("ghost"),
                ..RigOpts::default()
            },
        )
        .await;
        let key = rig.gov.lookup_by_sub(&rig.key_id).expect("the rig's key");
        let Err(blocked) = rig
            .gov
            .try_admit(&rig.app.cost, &key, "p", busbar_kernel::store::now())
        else {
            panic!("the direct admission refuses a key naming an unconfigured group");
        };
        let (direct_status, direct_kind, direct_message, _) =
            busbar_kernel::ingress::limit_refusal("", &blocked);

        // The over-quota kind is OpenAI's own `insufficient_quota`, which the chat dialect's native
        // envelope carries as both its `type` and its `code` (1.5.5's pairing, never a null code).
        assert_eq!(direct_kind, "insufficient_quota");

        let (status, _, body) = rig.chat().await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, direct_status.as_u16(), "{text}");
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("the door's JSON");
        assert_eq!(
            answer,
            serde_json::json!({ "error": {
                "message": direct_message,
                "type": direct_kind,
                "param": null,
                "code": direct_kind,
            } }),
            "the whole refusal is the direct admission's, nothing reworded or added: {text}"
        );
        assert_eq!(far.served(), 0);
    }
}

// ── what only the plane reads, the kernel routes on (ARCHITECT Q1 ArriveOut, 2026-10-05) ────────

/// A streamed far end's head: chunked, so a far end that closes before its last chunk CUT it.
#[cfg(linked_driver_proofs)]
const STREAM_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                           transfer-encoding: chunked\r\nconnection: close\r\n\r\n";

/// The streamed answer's frames, in order: a delta, the stop, the usage, the end.
#[cfg(linked_driver_proofs)]
const FRAMES: [&str; 4] = [
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#,
    "[DONE]",
];

/// One event-stream frame, as a chunk.
#[cfg(linked_driver_proofs)]
fn frame(data: &str) -> Vec<u8> {
    chunk(format!("data: {data}\n\n").as_bytes())
}

/// A stream that pauses `pause_ms` after its first frame, then ends cleanly.
#[cfg(linked_driver_proofs)]
fn stream_pausing(pause_ms: u64) -> SeatScript {
    SeatScript {
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
#[cfg(linked_driver_proofs)]
fn streamed_chat() -> serde_json::Value {
    serde_json::json!({"model": "p", "stream": true, "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]})
}

/// THE STREAM CEILING, NOT THE POOL'S TIMEOUT, bounds a streamed answer (the plane states
/// `ROUTE_STREAM`; v1.5.5 bounded a stream's whole send by the stream ceiling): a stream that
/// outlives its pool's two-second failover timeout is delivered whole. Before the plane stated the
/// stream, the door cut it at the pool's timeout.
///
/// The pool's timeout is two seconds, not one, because the walk's deadline is whole wall-clock
/// seconds (`RequestCtx::expired`, as 1.5.5's): a one-second budget whose walk starts late in a
/// wall second is spent at the next second boundary, so the first pick could find it expired (a
/// 503 request-timeout shed before anything is dialled) whenever that boundary fell between the
/// walk's start and its pick. Two seconds leaves the pick at least one whole second; the far end's
/// three-second pause still outlives the whole budget, so a door that bounded the stream by it
/// would cut the answer.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bounds_a_stream_by_the_stream_ceiling_not_the_pools_timeout() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-outlives-timeout";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(stream_pausing(3_000)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            failover_timeout_secs: Some(2),
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
#[cfg(linked_driver_proofs)]
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_keeps_the_budget_unit_of_a_stream_cut_after_its_first_byte() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-stream-cut";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(SeatScript {
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refunds_the_budget_unit_of_a_buffered_answer_cut() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-buffered-cut";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(SeatScript {
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
#[cfg(linked_driver_proofs)]
const WHOLE: &str = r#"{"id":"chatcmpl-9","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hello there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1500,"completion_tokens":90,"total_tokens":1590}}"#;

/// A far end that answers [`WHOLE`] under its full length but writes only `prefix` of it, then
/// holds the connection `hold_ms` and closes (a cut).
#[cfg(linked_driver_proofs)]
fn whole_cut_after(prefix: usize, hold_ms: u64) -> SeatScript {
    SeatScript {
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
#[cfg(linked_driver_proofs)]
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

/// Legacy row 338: a same-dialect non-stream answer the CALLER drops mid-relay bills no tokens, as
/// 1.5.5 billed none (v1.5.5 `crates/busbar/src/proxy/response_body.rs:620-625`: a partially
/// buffered same-protocol body is not billed on a mid-buffer drop). ARCHITECT ruling 2026-10-15:
/// v1.5.5 wins over item 367's relayed floor (Q33 (a), told, never signed), and no floor is added
/// (#77(2)).
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_nothing_for_a_non_stream_answer_the_caller_dropped_mid_relay() {
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
    assert_eq!(
        rig.tokens_after().await,
        0,
        "a non-stream answer dropped mid-relay bills no tokens, as in 1.5.5"
    );
    next.abort();
}

// ── F25 REHOME: THE MONEY A SERVED UNIT LEAVES ──────────────────────────────────────────────────
//
// The previous release's engine tests of what a unit bills: the tokens a whole, cut or dropped
// answer reports, the fee a refused or failed unit keeps or never takes, the metering row a
// streamed unit writes, and the limits the ledger then enforces. Each is driven here through the
// composed door, its figures read off the key's ledger, the group's bucket, the metering series
// and the unit's sealed audit record.
#[cfg(linked_driver_proofs)]
mod pools_door_money {
    use super::*;

    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use busbar_kernel::test_support::{metric_sum, MockResponse, MockServer, MockServerState};

    use super::super::hook_seat_tests::DoorRig;

    /// The store's clock.
    fn now() -> u64 {
        busbar_kernel::store::now()
    }

    /// A recording far end answering its requests with `replies`, in order.
    async fn mock(replies: Vec<MockResponse>) -> (Arc<MockServerState>, MockServer) {
        let state = Arc::new(MockServerState::new());
        for reply in replies.into_iter().rev() {
            state.push(reply);
        }
        let server = MockServer::new(Arc::clone(&state)).await;
        (state, server)
    }

    /// One group limit of `amount` `metric` per `per`.
    fn limit(metric: LimitMetric, amount: u64, per: LimitWindow) -> LimitCfg {
        LimitCfg {
            metric,
            amount,
            per: Some(per),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }
    }

    /// The messages dialect's whole answer reporting 1500 + 90 tokens.
    fn answer_1590() -> &'static str {
        door_word("messages_answer_usage")
    }

    /// A far end that announces `body` whole but writes only its first `prefix` bytes, holds the
    /// connection `hold_ms`, and closes (a cut).
    fn cut_after(body: &str, prefix: usize, hold_ms: u64) -> SeatScript {
        SeatScript {
            head: format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                body.len()
            ),
            pieces: vec![
                (0, body.as_bytes()[..prefix].to_vec()),
                (hold_ms, Vec::new()),
            ],
            finish: None,
        }
    }

    /// A caller's request in the messages dialect on pool `p`.
    fn messages_on_p(stream: bool) -> serde_json::Value {
        serde_json::json!({"model": "p", "max_tokens": 50, "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]})
    }

    /// A rig over one member of the messages dialect at `port`.
    async fn messages_member(instance: &'static str, port: u16) -> DoorRig {
        rig(
            instance,
            RigOpts {
                members: &[(port, 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await
    }

    /// The unit's sealed record whose finish is `finish`, once sealed (bounded).
    async fn sealed_as(
        rig: &DoorRig,
        finish: busbar_kernel_audit::FinishClass,
    ) -> busbar_kernel_audit::AuditRecord {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Some(record) = rig
                .records()
                .into_iter()
                .find(|record| record.outcome.finish == finish)
            {
                return record;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "a record sealed {finish:?}: {:?}",
                rig.records()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// The token figures a sealed record reports: each token line's class and quantity. The token
    /// classes are the contract's four reserved units (`records::RESERVED_UNITS`: input, output,
    /// cache read, cache write), the names a record line carries them under.
    fn token_lines(record: &busbar_kernel_audit::AuditRecord) -> Vec<(String, u64)> {
        record
            .usage
            .lines
            .iter()
            .filter(|line| busbar_contract::records::RESERVED_UNITS.contains(&line.class.as_str()))
            .map(|line| (line.class.as_str().to_string(), line.quantity))
            .collect()
    }

    /// The tokens a sealed record reports, summed.
    fn reported(record: &busbar_kernel_audit::AuditRecord) -> u64 {
        token_lines(record)
            .iter()
            .map(|(_, quantity)| quantity)
            .sum()
    }

    /// Start three requests well inside one minute's window.
    async fn inside_one_minute() {
        let into_window = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
            % 60;
        if into_window >= 55 {
            tokio::time::sleep(std::time::Duration::from_secs(60 - into_window + 1)).await;
        }
    }

    /// A WHOLE ANSWER DROPPED BY ITS CALLER BILLS NO TOKENS (F25 row 28; legacy
    /// `nonstream_drop_billing_tests::a_same_protocol_nonstream_body_dropped_mid_relay_bills_no_tokens_as_in_1_5_5`):
    /// a same-dialect whole answer (usage 1500/90) whose caller goes after its first bytes, the
    /// prefix before `"stop_reason"` relayed verbatim, bills no tokens, as 1.5.5 billed none (v1.5.5
    /// `crates/busbar/src/proxy/response_body.rs:620-625`; ARCHITECT ruling 2026-10-15 retired item
    /// 367's relayed floor, #77(2)); the unit ends Partial, and its sealed record reports that same
    /// nothing. RED: any token billed, or the record disagreeing with the ledger.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_nothing_for_a_whole_answer_its_caller_dropped() {
        use http_body_util::BodyExt as _;
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-dropped-floor";
        let _published = Withdrawn(instance);
        let whole = answer_1590();
        let prefix = whole.find(r#""stop_reason""#).expect("a stop reason");
        let far = far_end_scripted(cut_after(whole, prefix, 5_000)).await;
        let rig = messages_member(instance, far.port).await;
        let response = rig
            .open(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
                &[],
            )
            .await;
        assert_eq!(response.status().as_u16(), 200);
        let mut body = response.into_body();
        let mut relayed: Vec<u8> = Vec::new();
        while relayed.len() < prefix {
            let piece = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
                .await
                .expect("the prefix arrives before the far end's hold")
                .expect("a frame")
                .expect("relayed");
            if let Some(bytes) = piece.data_ref() {
                relayed.extend_from_slice(bytes);
            }
        }
        assert_eq!(
            relayed,
            whole.as_bytes()[..prefix].to_vec(),
            "the prefix relays verbatim"
        );
        // THE DISCONNECT: the caller goes before the answer's end.
        drop(body);
        // The driver finishes a buried unit at the start of its next one.
        let rig = Arc::new(rig);
        let next = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.chat().await })
        };
        let billed = rig.tokens_after().await;
        next.abort();
        assert_eq!(
            billed, 0,
            "a whole answer dropped mid-relay bills no tokens"
        );
        let record = sealed_as(&rig, busbar_kernel_audit::FinishClass::Partial).await;
        assert_eq!(
            reported(&record),
            0,
            "the record reports what the ledger accrued: {:?}",
            token_lines(&record)
        );
    }

    /// A WHOLE ANSWER RELAYED WHOLE BILLS ITS OWN USAGE ONCE (F25 row 29; legacy
    /// `nonstream_drop_billing_tests::a_same_protocol_nonstream_body_relayed_whole_bills_its_own_usage_once`):
    /// a same-dialect whole answer reporting 1500 + 90 reaches the caller as those very bytes, the
    /// key's ledger holds exactly 1590 tokens (counted once), and the unit ends Complete. RED: a
    /// rewritten body, a figure other than 1590, or the end not Complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_a_whole_answer_its_own_usage_once() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-whole-once";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, answer_1590()).await;
        let rig = messages_member(instance, far.port).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            answer_1590().as_bytes(),
            "relayed whole, as one answer"
        );
        assert_eq!(
            rig.tokens_after().await,
            1590,
            "the far end's own figure, once"
        );
        let record = sealed_as(&rig, busbar_kernel_audit::FinishClass::Complete).await;
        assert_eq!(reported(&record), 1590);
    }

    /// A WHOLE ANSWER THE FAR END CUTS BEFORE ITS USAGE BILLS NOTHING (F25 row 31; legacy
    /// `nonstream_drop_billing_tests::a_nonstream_body_cut_by_the_upstream_before_its_usage_bills_nothing`):
    /// the far end closes before `"stop_reason"` (no usage reported): the ledger holds 0 tokens, the
    /// unit ends Partial, and its record reports no tokens. RED: a floor or any figure billed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_nothing_for_a_whole_answer_cut_before_its_usage() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-cut-before-usage";
        let _published = Withdrawn(instance);
        let whole = answer_1590();
        let prefix = whole.find(r#""stop_reason""#).expect("a stop reason");
        let far = far_end_scripted(cut_after(whole, prefix, 0)).await;
        let rig = messages_member(instance, far.port).await;
        let _ = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(rig.tokens_after().await, 0, "no reported usage, no charge");
        let record = sealed_as(&rig, busbar_kernel_audit::FinishClass::Partial).await;
        assert_eq!(
            reported(&record),
            0,
            "the record reports no usage either: {:?}",
            token_lines(&record)
        );
    }

    /// A WHOLE ANSWER THE FAR END CUTS AFTER ITS USAGE BILLS WHAT IT REPORTED (F25 row 32; legacy
    /// `nonstream_drop_billing_tests::a_nonstream_body_cut_by_the_upstream_after_its_usage_bills_what_it_reported`):
    /// the far end closes one byte short of the end, after its usage (1500/90): the ledger holds
    /// exactly 1590, and the unit ends Partial. RED: 0, a floor, or the end sealed Complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_what_a_cut_whole_answer_reported() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-cut-after-usage";
        let _published = Withdrawn(instance);
        let whole = answer_1590();
        let far = far_end_scripted(cut_after(whole, whole.len() - 1, 0)).await;
        let rig = messages_member(instance, far.port).await;
        let _ = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(rig.tokens_after().await, 1590, "the far end's own report");
        let _ = sealed_as(&rig, busbar_kernel_audit::FinishClass::Partial).await;
    }

    /// The far end's chat answer (usage 100 in, 60 out) the two token-limit cells are answered with.
    fn chat_160() -> serde_json::Value {
        serde_json::json!({
            "model": "glm-4.5",
            "choices": [{"index": 0, "message": {"role": "assistant",
                "content": "Hello there friend"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 60}
        })
    }

    /// A rig whose key's group allows 30 tokens a minute, its one member (the default dialect)
    /// answering `replies`.
    async fn thirty_tokens_a_minute(
        instance: &'static str,
        replies: Vec<MockResponse>,
    ) -> (DoorRig, MockServer) {
        let (_state, server) = mock(replies).await;
        let limits = [limit(LimitMetric::Tokens, 30, LimitWindow::Minute)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(server.address().port(), 1)],
                group: Some(("tpmgrp", &limits)),
                allowed_pools: Some(&["p"]),
                ..RigOpts::default()
            },
        )
        .await;
        (rig, server)
    }

    /// A TRANSLATED WHOLE ANSWER'S TOKENS ARE CHARGED, AND THE TOKEN LIMIT THEN REFUSES (F25 row
    /// 133; legacy `forward_pool_integration_tests::test_cross_protocol_nonstream_records_tokens_for_tpm`):
    /// a messages caller served by a member of another dialect reporting 160 tokens gets its 200,
    /// the far end's model name preserved, and its key's group (30 tokens a minute) refuses the
    /// next request 429. RED: the translated usage not charged, so the limit never refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_charges_a_translated_answers_tokens_against_the_token_limit() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-tpm-whole";
        let _published = Withdrawn(instance);
        inside_one_minute().await;
        let ok = || MockResponse::Ok {
            status: StatusCode::OK,
            body: chat_160(),
        };
        let (rig, _server) = thirty_tokens_a_minute(instance, vec![ok(), ok()]).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(
            status,
            200,
            "under the limit: {}",
            String::from_utf8_lossy(&body)
        );
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(answer["model"], "glm-4.5", "the far end's model preserved");
        let _ = rig.tokens_after().await;
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(status, 429, "the charged tokens make the limit refuse");
    }

    /// A TRANSLATED STREAM'S TOKENS ARE CHARGED AT ITS END, AND THE TOKEN LIMIT THEN REFUSES (F25
    /// row 134; legacy `forward_pool_integration_tests::test_cross_protocol_stream_records_tokens_for_tpm`):
    /// a streamed messages caller served by a member of another dialect whose last frame reports
    /// 160 tokens gets its 200 stream, and its key's group (30 tokens a minute) refuses the next
    /// request 429. RED: the stream-end usage not charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_charges_a_translated_stream_tokens_against_the_token_limit() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-tpm-stream";
        let _published = Withdrawn(instance);
        inside_one_minute().await;
        let streamed = || {
            event_stream(vec![
                r#"{"choices":[{"delta":{"role":"assistant"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{"content":"Hello there friend"}}]}"#.to_string(),
                r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":60}}"#.to_string(),
            ])
        };
        let (rig, _server) = thirty_tokens_a_minute(instance, vec![streamed(), streamed()]).await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(true)),
            )
            .await;
        assert_eq!(
            status,
            200,
            "under the limit: {}",
            String::from_utf8_lossy(&body)
        );
        let _ = rig.tokens_after().await;
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(true)),
            )
            .await;
        assert_eq!(
            status, 429,
            "the charged stream-end tokens make the limit refuse"
        );
    }

    /// AN OVER-CAP ANSWER KEEPS ITS BUDGET UNIT (F25 row 360; legacy
    /// `ingress_indistinguishability_tests::test_truncated_body_does_not_refund_budget`): with the
    /// translation cap at 4096 bytes, a member of another dialect (lifetime budget 1) answering a
    /// body over the cap is a 500 to the messages caller, and the member's budget unit stays spent
    /// (remaining 0): our cap, not the far end's fault, is never refunded. RED: the unit refunded
    /// (remaining 1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_keeps_the_budget_unit_of_an_over_cap_answer() {
        let _one = ONE_PUBLISHER.lock().await;
        let _limits = busbar_kernel::config::limits::LIMITS_TEST_LOCK.lock().await;
        const CAP: usize = 4096;
        let _cap = busbar_kernel::config::limits::InstallGuard::install(
            &busbar_kernel::config::limits::LimitsResolved::with_request_body_max_bytes(CAP),
        );
        let instance = "rehome-money-over-cap";
        let _published = Withdrawn(instance);
        let (_state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({
                "id": "chatcmpl-huge",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "m0",
                "choices": [{"index": 0, "message": {"role": "assistant",
                    "content": "x".repeat(CAP + 1024)}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 999999}
            }),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(server.address().port(), 1)],
                lane_budget: Some(1),
                // The cap reaches the door as the deployment's `limits` (its settings), not as
                // the process-wide install above, which only the kernel's own reads see.
                request_body_max_bytes: Some(CAP),
                ..RigOpts::default()
            },
        )
        .await;
        assert_eq!(rig.app.store.lane_budget_remaining(0), Some(1));
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_on_p(false)),
            )
            .await;
        assert_eq!(status, 500, "over the translation cap");
        assert_eq!(
            rig.app.store.lane_budget_remaining(0),
            Some(0),
            "an over-cap body is our cap, not the far end's fault: never refunded"
        );
    }

    /// A POOL-ACCESS REFUSAL IS COUNTED AND CHARGES NO FEE (F25 row 424; legacy
    /// `ingress_integration_tests::test_governance_rejection_is_counted_via_finish`): a key allowed
    /// only another pool is refused 403 on `p`; the refusal raises `busbar_requests_total` under
    /// `outcome="client_error"` and the request-duration count, and the key's ledger takes no fee
    /// (spend 0, nothing billable). RED: the refusal invisible to the scrape, or a fee charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_a_pool_refusal_and_charges_no_fee() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-pool-refusal";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                allowed_pools: Some(&["denied-elsewhere"]),
                ..RigOpts::default()
            },
        )
        .await;
        let duration_count = format!(
            "{}_count",
            busbar_kernel::snapshot::REQUEST_DURATION_SECONDS
        );
        let counted = || {
            (
                metric_sum(
                    busbar_kernel::snapshot::REQUESTS_TOTAL,
                    &[("outcome", "client_error")],
                ),
                metric_sum(&duration_count, &[]),
            )
        };
        let before = counted();
        assert_eq!(rig.chat().await.0, 403, "a pool the key may not reach");
        let after = counted();
        assert!(
            after.0 > before.0,
            "outcome=client_error: {before:?} -> {after:?}"
        );
        assert!(
            after.1 > before.1,
            "its duration observed: {before:?} -> {after:?}"
        );
        let (_, spend, _, billable) = rig.ledger_after(0).await;
        assert_eq!((spend, billable), (0, 0), "no fee for a refused request");
        assert_eq!(far.served(), 0);
    }

    /// A ZERO BUDGET NAMES ITS GROUP AND CHARGES NOTHING (F25 row 472; legacy
    /// `ingress_integration_tests::test_group_blocked_429_names_the_budget_group`): a key in group
    /// `finance`, whose all-time budget is 0, is refused 429; the body carries `insufficient_quota`
    /// and names the blocking bucket, `group 'finance' budget per total exhausted`, never the key's
    /// id; and the key's recorded requests stay 0. RED: the bucket unnamed, the key id on the wire,
    /// or the refused request recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_names_the_blocking_group_and_records_nothing() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-finance-blocked";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let finance = [limit(LimitMetric::Budget, 0, LimitWindow::Total)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("finance", &finance)),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig.chat().await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(status, 429, "{text}");
        assert!(text.contains("insufficient_quota"), "{text}");
        assert!(
            text.contains("group 'finance' budget per total exhausted"),
            "the blocking bucket is named: {text}"
        );
        assert!(!text.contains(&rig.key_id), "never the key id: {text}");
        let (requests, _, _, _) = rig.ledger_after(0).await;
        assert_eq!(requests, 0, "the refused request is not recorded");
    }

    /// A STREAM WITH NO USAGE FRAME BILLS ZERO TOKENS IN EVERY DIALECT (F25 row 618; legacy
    /// `stream_no_usage_bills_zero_tests::stream_without_usage_frame_bills_zero_on_every_dialect`):
    /// for each of the six caller dialects, a streamed answer whose far end sends no usage frame is
    /// served 200, the key's ledger holds 0 tokens and no token spend (its spend is the request fee
    /// alone), and exactly one metering row is written for the key: model `m0`, requests 1, every
    /// token tier (input, output, cache read, cache write) 0. RED: tokens invented, a second row,
    /// or no row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_zero_tokens_for_a_stream_with_no_usage_in_every_dialect() {
        let _one = ONE_PUBLISHER.lock().await;
        let streamed = |mut body: serde_json::Value| {
            body["stream"] = serde_json::Value::Bool(true);
            body
        };
        let chat = serde_json::json!({"model": "p", "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]});
        let word_body = |key: &str| -> serde_json::Value {
            serde_json::from_str(door_word(key)).expect("a JSON request body")
        };
        let dialects = [
            (
                "rehome-money-no-usage-chat",
                "/v1/chat/completions",
                streamed(chat.clone()),
            ),
            (
                "rehome-money-no-usage-messages",
                door_word("messages_path"),
                streamed(chat.clone()),
            ),
            (
                "rehome-money-no-usage-chat-v2",
                door_word("chat_v2_path"),
                streamed(word_body("chat_v2_body")),
            ),
            (
                "rehome-money-no-usage-respond",
                door_word("respond_path"),
                streamed(word_body("respond_body")),
            ),
            (
                "rehome-money-no-usage-generate",
                door_word("generate_stream_path"),
                word_body("generate_body"),
            ),
            (
                "rehome-money-no-usage-converse",
                door_word("converse_stream_path"),
                word_body("converse_body"),
            ),
        ];
        for (instance, path, request) in dialects {
            let _published = Withdrawn(instance);
            let (_state, server) = mock(vec![event_stream(vec![
                r#"{"id":"chatcmpl-nousage","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}"#.to_string(),
                r#"{"id":"chatcmpl-nousage","object":"chat.completion.chunk","created":0,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
            ])])
            .await;
            let rig = rig(
                instance,
                RigOpts {
                    members: &[(server.address().port(), 1)],
                    ..RigOpts::default()
                },
            )
            .await;
            let charged_at = now();
            let (status, _, body) = rig.send("POST", path, Some(request)).await;
            assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&body));
            let (requests, spend, _, billable) = rig.ledger_after(1).await;
            assert_eq!(requests, 1, "{path}");
            assert_eq!(
                rig.tokens_after().await,
                0,
                "{path}: no usage frame, no tokens"
            );
            assert_eq!(
                spend,
                i64::try_from(billable).expect("a count"),
                "{path}: the fee alone, no token spend"
            );
            rig.gov.flush_metering();
            let rows = rig
                .gov
                .metering_for(busbar_kernel::governance::metering_bucket(charged_at))
                .expect("metering read");
            let mine: Vec<_> = rows.iter().filter(|row| row.key_id == rig.key_id).collect();
            assert_eq!(mine.len(), 1, "{path}: one metering row: {rows:?}");
            assert_eq!(mine[0].model, "m0", "{path}");
            assert_eq!(mine[0].requests, 1, "{path}");
            assert_eq!(
                (
                    mine[0].tokens_input,
                    mine[0].tokens_output,
                    mine[0].tokens_cache_read,
                    mine[0].tokens_cache_write
                ),
                (0, 0, 0, 0),
                "{path}: every token tier is zero"
            );
        }
    }

    /// A SPENT BUDGET REFUSES AND CHARGES NOTHING, SO NOTHING IS REFUNDED (F25 row 657; legacy
    /// `admit::over_budget_refuses_with_no_charge_and_nothing_to_refund`): group `bgrp`'s all-time
    /// bucket seeded with 250 requests at a one-cent fee (250 cents, over its 100-cent cap); its key
    /// is refused 429, and afterwards the group's bucket still reads 250 requests, 250 cents, 250 on
    /// its durable row and 250 billable, the key's own ledger 0 throughout; the refusal is sealed as
    /// `OverBudget` at the Admit step. RED: any counter moved by the refusal, or the refusal stamped
    /// at another step or reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_refuses_a_spent_budget_without_charging_anything() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-over-budget-untouched";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let limits = [limit(LimitMetric::Budget, 100, LimitWindow::Total)];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                group: Some(("bgrp", &limits)),
                seed: &[("group:bgrp@total", 250)],
                ..RigOpts::default()
            },
        )
        .await;
        let group_before = rig.bucket("group:bgrp@total");
        assert_eq!(
            group_before,
            (250, 250, 250, 250),
            "250 seeded requests at a one-cent fee: 250 cents over a 100-cent cap"
        );
        let key_before = rig.ledger_after(0).await;
        assert_eq!(key_before, (0, 0, 0, 0), "the key has been charged nothing");
        let (status, _, _) = rig.chat().await;
        assert_eq!(status, 429, "an exhausted budget is a 429");
        assert_eq!(
            rig.bucket("group:bgrp@total"),
            group_before,
            "the refusal moved nothing on the blocking bucket"
        );
        assert_eq!(
            rig.ledger_after(0).await,
            key_before,
            "nor on the key's own"
        );
        assert_eq!(far.served(), 0);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while rig.audit_records() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let records = rig.records();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(
            records[0].outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Admit,
                busbar_contract::caps::ReasonCode::OverBudget
            ),
            "refused at the door, for the budget"
        );
    }

    /// THE STREAMED AND THE FAILED UNIT LEAVE THE MONEY WHERE 1.5.5 LEFT IT (F25 row 691; legacy
    /// `chain::the_chain_leaves_the_money_where_the_legacy_plane_leaves_it`): a streamed unit whose
    /// far end reports 11 in and 7 out accrues 18 tokens and one admitted request, and writes ONE
    /// metering row for the key (model `m0`, in 11, out 7, cache 0 and 0, requests 1, billable 1);
    /// a unit whose far end fails keeps its admitted request, accrues no tokens and writes no
    /// metering row. RED: the stream's tokens not accrued or accrued twice, a failed unit's slot
    /// refunded, or a row for a unit that delivered nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_leaves_a_streamed_and_a_failed_units_money_where_1_5_5_left_it() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-streamed-row";
        let published = Withdrawn(instance);
        let far = far_end_scripted(stream_pausing(0)).await;
        let streamed = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let charged_at = now();
        let (status, _, _) = streamed
            .send("POST", "/v1/chat/completions", Some(streamed_chat()))
            .await;
        assert_eq!(status, 200);
        let (requests, _, _, _) = streamed.ledger_after(1).await;
        assert_eq!(requests, 1, "one admitted request");
        assert_eq!(
            streamed.tokens_after().await,
            18,
            "the stream-end report, once"
        );
        streamed.gov.flush_metering();
        let rows = streamed
            .gov
            .metering_for(busbar_kernel::governance::metering_bucket(charged_at))
            .expect("metering read");
        let mine: Vec<String> = rows
            .iter()
            .filter(|row| row.key_id == streamed.key_id)
            .map(|row| {
                format!(
                    "{} in={} out={} cr={} cw={} req={} billable={}",
                    row.model,
                    row.tokens_input,
                    row.tokens_output,
                    row.tokens_cache_read,
                    row.tokens_cache_write,
                    row.requests,
                    row.billable_requests
                )
            })
            .collect();
        assert_eq!(
            mine,
            vec!["m0 in=11 out=7 cr=0 cw=0 req=1 billable=1".to_string()]
        );
        drop(streamed);
        drop(published);

        let instance = "rehome-money-failed-row";
        let _published = Withdrawn(instance);
        let down = seat_far_end(503, OVERLOADED).await;
        let failed = rig(
            instance,
            RigOpts {
                members: &[(down.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let charged_at = now();
        assert_ne!(failed.chat().await.0, 200, "the far end fails");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut ledger = failed.ledger_after(0).await;
        while ledger.0 == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            ledger = failed.ledger_after(0).await;
        }
        assert_eq!(ledger.0, 1, "the failed unit keeps its admitted request");
        assert_eq!(failed.tokens_after().await, 0, "and accrues no tokens");
        failed.gov.flush_metering();
        let rows = failed
            .gov
            .metering_for(busbar_kernel::governance::metering_bucket(charged_at))
            .expect("metering read");
        assert!(
            rows.iter().all(|row| row.key_id != failed.key_id),
            "no metering row for a unit that delivered nothing: {rows:?}"
        );
    }

    /// A STREAM THAT DIED BILLS WHAT IT STREAMED AND KEEPS ITS FEE (F25 row 720; legacy
    /// `meter::a_stream_that_died_bills_the_tokens_it_streamed_and_keeps_the_fee_it_earned`; owner
    /// ruling 2026-10-20: "spend is what it is. if spend occurred it occurred. null is not a fix."):
    /// a streamed answer whose far end reports its usage (11 in, 7 out) and is then cut before its
    /// end bills those 18 tokens, as its plane ledgered them; it keeps its one request and its one
    /// fee (billable 1, the 200 that went out is not reversed), and its sealed record reports one
    /// line per streamed tier: input 11, output 7. RED: the streamed tokens dropped, the fee
    /// reversed, or the tiers merged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bills_a_dead_stream_tokens_and_keeps_its_fee() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-money-dead-stream";
        let _published = Withdrawn(instance);
        let far = far_end_scripted(SeatScript {
            head: STREAM_HEAD.to_string(),
            pieces: vec![
                (0, frame(FRAMES[0])),
                (0, frame(FRAMES[2])),
                (50, Vec::new()),
            ],
            finish: None,
        })
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, _) = rig
            .send("POST", "/v1/chat/completions", Some(streamed_chat()))
            .await;
        assert_eq!(status, 200, "the stream had begun");
        let (requests, _, _, billable) = rig.ledger_after(1).await;
        assert_eq!(requests, 1, "the request unit still counts");
        assert_eq!(billable, 1, "the fee it earned is kept");
        assert_eq!(
            rig.tokens_after().await,
            18,
            "the streamed tokens are the charge"
        );
        let record = sealed_as(&rig, busbar_kernel_audit::FinishClass::Partial).await;
        let mut lines = token_lines(&record);
        lines.retain(|(_, quantity)| *quantity > 0);
        lines.sort();
        assert_eq!(
            lines,
            vec![
                (busbar_contract::records::UNIT_INPUT.to_string(), 11),
                (busbar_contract::records::UNIT_OUTPUT.to_string(), 7)
            ],
            "one line per streamed tier"
        );
    }

    /// A 2XX STREAM IS SEALED WITH THE END ITS TAP SAW, NOT THE END ITS STATUS LINE CLAIMS (legacy
    /// `chain::a_stream_audited_at_its_end_seals_the_class_the_tap_reported`): both answers go out
    /// under a 200 status line, yet a stream cut after its first frame is sealed `Partial` and a
    /// transfer that failed before its first byte is sealed `Error`; neither is sealed `Complete`.
    /// RED: a record sealed from the status line (`Complete`) for an answer that never completed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_seals_a_2xx_stream_with_the_end_its_tap_saw() {
        for (instance, pieces, finish) in [
            (
                "rehome-sealed-end-cut",
                vec![(0, frame(FRAMES[0])), (50, Vec::new())],
                busbar_kernel_audit::FinishClass::Partial,
            ),
            (
                "rehome-sealed-end-failed",
                vec![(50, Vec::new())],
                busbar_kernel_audit::FinishClass::Error,
            ),
        ] {
            let _one = ONE_PUBLISHER.lock().await;
            let _published = Withdrawn(instance);
            let far = far_end_scripted(SeatScript {
                head: STREAM_HEAD.to_string(),
                pieces,
                finish: None,
            })
            .await;
            let rig = rig(
                instance,
                RigOpts {
                    members: &[(far.port, 1)],
                    ..RigOpts::default()
                },
            )
            .await;
            let (status, _, _) = rig
                .send("POST", "/v1/chat/completions", Some(streamed_chat()))
                .await;
            assert_eq!(status, 200, "{instance}: served on 2xx headers");
            let record = sealed_as(&rig, finish).await;
            assert_ne!(
                record.outcome.finish,
                busbar_kernel_audit::FinishClass::Complete,
                "{instance}"
            );
        }
    }
}

/// SESSION AFFINITY (legacy rows 2-4; v1.5.5 `affinity_header_for` and the sticky position): the
/// plane states the session key it reads (the pool's header, `x-session-id` by default, else chat's
/// body `system`) and the kernel pins every unit with that key to one member; a unit without one
/// is spread by the weighted floor.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_pins_a_session_to_one_member() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-affinity";
    let _published = Withdrawn(instance);
    let fars = [
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_reads_a_session_from_the_pools_own_affinity_header() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-affinity-header";
    let _published = Withdrawn(instance);
    let fars = [
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
        seat_far_end(200, SERVED_BY_TWIN).await,
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

// ── F25 REHOME: WHAT THE SERVED POOLS DOOR COUNTS, ROUTES, PROBES AND SHOWS ─────────────────────
//
// The previous release's engine tests of the scrape a served unit leaves (its request count, its
// duration, its bounded pool label), of the routes a request may take (a fallback pool, an ad-hoc
// provider route, a model named directly), of the queue and the recovery probe, of the signals the
// ranking hooks are shown, and of the record an error end seals: each driven here through the
// composed door to real far ends on loopback.
#[cfg(linked_driver_proofs)]
mod pools_door_counts_and_routes {
    use super::*;

    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::Signal;
    use busbar_kernel::store::BreakerState;
    use busbar_kernel::test_support::{metric_sum, MockResponse, MockServer, MockServerState};

    use super::super::hook_seat_tests::DoorRig;

    /// The store's clock.
    fn now() -> u64 {
        busbar_kernel::store::now()
    }

    /// A recording far end answering its requests with `replies`, in order.
    async fn mock(replies: Vec<MockResponse>) -> (Arc<MockServerState>, MockServer) {
        let state = Arc::new(MockServerState::new());
        for reply in replies.into_iter().rev() {
            state.push(reply);
        }
        let server = MockServer::new(Arc::clone(&state)).await;
        (state, server)
    }

    /// The messages dialect's answer.
    fn messages_answer() -> serde_json::Value {
        serde_json::from_str(door_word("messages_answer")).expect("the answer is JSON")
    }

    /// A caller's request in the messages dialect naming `model`.
    fn messages_naming(model: &str) -> serde_json::Value {
        serde_json::json!({"model": model, "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]})
    }

    /// One request through the door as the keyed caller, its body sent as these very bytes.
    async fn send_bytes(rig: &DoorRig, path: &str, body: &str) -> u16 {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", format!("Bearer {}", rig.token))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = rig
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status().as_u16();
        let _ = axum::body::to_bytes(response.into_body(), 1 << 20).await;
        status
    }

    /// The pre-routing refusals counted so far: `busbar_requests_total` under the bounded
    /// `unresolved` pool label and the `client_error` outcome.
    fn unresolved_client_errors() -> f64 {
        metric_sum(
            busbar_kernel::snapshot::REQUESTS_TOTAL,
            &[("pool", "unresolved"), ("outcome", "client_error")],
        )
    }

    /// A port nothing listens on.
    fn refusing_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    /// A rig over one far end that answers every request.
    async fn serving(instance: &'static str) -> (DoorRig, super::super::hook_seat_tests::FarEnd) {
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        (rig, far)
    }

    /// A SERVED UNIT IS COUNTED, TIMED AND ITS ATTEMPT COUNTED (F25 rows 372 and 401; legacy
    /// `ingress_integration_tests::test_finish_emits_request_metrics` and
    /// `ingress_integration_tests::test_served_request_increments_hot_path_metrics`): a 200 chat on
    /// pool `p` raises `busbar_requests_total{pool="p",outcome="ok"}`, the request-duration
    /// histogram's count under `pool="p"`, and `busbar_upstream_attempts_total{pool="p",lane="m0"}`.
    /// RED: a served request missing from any of the three series.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_times_and_attributes_a_served_unit() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-served";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let duration_count = format!(
            "{}_count",
            busbar_kernel::snapshot::REQUEST_DURATION_SECONDS
        );
        let requests = || {
            metric_sum(
                busbar_kernel::snapshot::REQUESTS_TOTAL,
                &[("pool", "p"), ("outcome", "ok")],
            )
        };
        let timed = || metric_sum(&duration_count, &[("pool", "p")]);
        let attempts = || {
            metric_sum(
                busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
                &[("pool", "p"), ("lane", "m0")],
            )
        };
        let before = (requests(), timed(), attempts());
        assert_eq!(rig.chat().await.0, 200);
        let _ = rig.ledger_after(1).await;
        let after = (requests(), timed(), attempts());
        assert!(
            after.0 > before.0,
            "outcome=ok counted: {before:?} -> {after:?}"
        );
        assert!(
            after.1 > before.1,
            "its duration observed: {before:?} -> {after:?}"
        );
        assert!(
            after.2 > before.2,
            "its attempt counted: {before:?} -> {after:?}"
        );
    }

    /// AN UNKNOWN MODEL NEVER BECOMES A LABEL (F25 row 398; legacy
    /// `ingress_integration_tests::test_unresolved_model_uses_bounded_pool_label_not_raw_string`):
    /// a chat naming `zzz-unbounded-cardinality-probe-9f3a` is a 404, the scrape never carries that
    /// string, and the request is counted under `pool="unresolved"`. RED: the caller's raw model
    /// string on the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_an_unknown_model_under_the_bounded_label() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-unknown-model";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let probe = "zzz-unbounded-cardinality-probe-9f3a";
        let (status, _, _) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"model": probe,
                    "messages": [{"role": "user", "content": "hi"}]})),
            )
            .await;
        assert_eq!(status, 404, "an unknown model is a 404");
        let scrape = busbar_kernel::snapshot::render();
        assert!(
            !scrape.contains(probe),
            "the raw model is never a label:\n{scrape}"
        );
        assert!(
            scrape.contains("pool=\"unresolved\""),
            "the bounded sentinel:\n{scrape}"
        );
    }

    /// A MALFORMED BODY IS COUNTED (F25 row 399; legacy
    /// `ingress_integration_tests::test_body_model_parse_error_is_observable`): a chat whose body is
    /// `{ this is not json ` is a 400 and raises `busbar_requests_total{pool="unresolved",
    /// outcome="client_error"}`. RED: a pre-routing refusal invisible to the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_a_malformed_body() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-malformed";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let before = unresolved_client_errors();
        assert_eq!(
            send_bytes(&rig, "/v1/chat/completions", "{ this is not json ").await,
            400
        );
        let after = unresolved_client_errors();
        assert!(after > before, "{before} -> {after}");
    }

    /// AN UNRESOLVABLE INVOKE BODY IS COUNTED (F25 row 400; legacy
    /// `ingress_integration_tests::test_bedrock_invoke_unresolvable_body_is_observable`): an invoke
    /// on the converse dialect's model-scoped path whose body matches no known shape
    /// (`{"nonsense":1}`) is a 400 and raises the `unresolved` / `client_error` count. RED: the
    /// refusal invisible to the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_an_unresolvable_invoke_body() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-invoke";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let before = unresolved_client_errors();
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("invoke_path"),
                Some(serde_json::json!({"nonsense": 1})),
            )
            .await;
        assert_eq!(status, 400);
        let after = unresolved_client_errors();
        assert!(after > before, "{before} -> {after}");
    }

    /// A MISSING MODEL IS COUNTED (F25 row 404; legacy
    /// `ingress_integration_tests::test_body_model_missing_model_is_observable`): a chat with no
    /// `model` is a 400 and raises the `unresolved` / `client_error` count. RED: the refusal
    /// invisible to the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_a_missing_model() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-missing-model";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let before = unresolved_client_errors();
        let (status, _, _) = rig
            .send(
                "POST",
                "/v1/chat/completions",
                Some(serde_json::json!({"messages": [{"role": "user", "content": "hi"}]})),
            )
            .await;
        assert_eq!(status, 400);
        let after = unresolved_client_errors();
        assert!(after > before, "{before} -> {after}");
    }

    /// A NON-OBJECT BODY ON A PATH-MODEL DIALECT IS COUNTED (F25 row 405; legacy
    /// `ingress_integration_tests::test_path_model_non_object_body_is_observable`): a converse
    /// request whose body is `[1,2,3]` is a 400 and raises the `unresolved` / `client_error` count.
    /// RED: the refusal invisible to the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_a_non_object_body() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-non-object";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let before = unresolved_client_errors();
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("converse_path"),
                Some(serde_json::json!([1, 2, 3])),
            )
            .await;
        assert_eq!(status, 400);
        let after = unresolved_client_errors();
        assert!(after > before, "{before} -> {after}");
    }

    /// AN ACTION THE DOOR DOES NOT SERVE IS COUNTED (F25 row 406; legacy
    /// `ingress_integration_tests::test_gemini_unsupported_action_is_observable`): the generate
    /// dialect's token-count action is a 404 and raises the `unresolved` / `client_error` count.
    /// RED: the refusal invisible to the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_an_unsupported_action() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-unsupported";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let before = unresolved_client_errors();
        let (status, _, _) = rig
            .send(
                "POST",
                door_word("count_tokens_path"),
                Some(serde_json::json!({"contents": []})),
            )
            .await;
        assert_eq!(status, 404);
        let after = unresolved_client_errors();
        assert!(after > before, "{before} -> {after}");
    }

    /// THE POOL LABEL IS BOUNDED (F25 row 407; legacy
    /// `ingress_integration_tests::test_pool_label_bounds_cardinality`): a unit on configured pool
    /// `p` is counted under `pool="p"`, one naming configured model `m0` directly under
    /// `pool="m0"`, and one naming anything else, or nothing, under `pool="unresolved"`; neither
    /// unconfigured spelling ever becomes a label. RED: a configured name relabelled, or a caller's
    /// string on the scrape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_bounds_its_pool_label_to_what_is_configured() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-count-label-bounds";
        let _published = Withdrawn(instance);
        let (rig, _far) = serving(instance).await;
        let counted =
            |pool: &str| metric_sum(busbar_kernel::snapshot::REQUESTS_TOTAL, &[("pool", pool)]);
        for (model, label) in [
            ("p", "p"),
            ("m0", "m0"),
            ("anything-else", "unresolved"),
            ("", "unresolved"),
        ] {
            let before = counted(label);
            let _ = rig
                .send(
                    "POST",
                    "/v1/chat/completions",
                    Some(serde_json::json!({"model": model, "max_tokens": 16,
                        "messages": [{"role": "user", "content": "hi"}]})),
                )
                .await;
            let after = counted(label);
            assert!(
                after > before,
                "`{model}` counts under `{label}`: {before} -> {after}"
            );
        }
        let scrape = busbar_kernel::snapshot::render();
        assert!(!scrape.contains("pool=\"anything-else\""), "{scrape}");
        assert!(!scrape.contains("pool=\"\""), "{scrape}");
    }

    /// A FALLBACK POOL THE KEY MAY ALSO REACH SERVES (F25 row 460; legacy
    /// `ingress_integration_tests::test_fallback_pool_acl_allows_key_permitted_on_both_pools`): a
    /// key allowed pools `p` and `q`, pool `p` exhausted (its one member down) with `on_exhausted:
    /// { fallback_pool: q }`: the request on `p` is answered 200 by `q`'s member; the fallback's
    /// pool check does not refuse a key allowed on both. RED: a 403 on the fallback, or the
    /// exhausted terminal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_serves_a_fallback_pool_the_key_may_reach() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-route-fallback-acl";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer(),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(refusing_port(), 1), (server.address().port(), 1)],
                pooled: Some(1),
                more_pools: &[("q", &[(1, 1)])],
                pool_yaml: "on_exhausted: { fallback_pool: q }",
                allowed_pools: Some(&["p", "q"]),
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                door_word("messages_path"),
                Some(messages_naming("p")),
            )
            .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert!(
            state.get_last_request_body().is_some(),
            "the fallback's member served"
        );
    }

    /// AN AD-HOC PROVIDER ROUTE ROUND-TRIPS (F25 row 461; legacy
    /// `ingress_integration_tests::test_adhoc_success_round_trip_via_router`): a messages request on
    /// `/<provider>/<model>/...` naming model `m0` under its own provider `oai0` resolves and is
    /// served 2xx by that model's far end. RED: the ad-hoc route refused or unrouted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_serves_an_ad_hoc_provider_route() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-route-adhoc";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer(),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(server.address().port(), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                &format!("/oai0/m0{}", door_word("messages_path")),
                Some(serde_json::json!({"model": "m0", "messages": [], "max_tokens": 16})),
            )
            .await;
        assert!(
            (200..300).contains(&status),
            "{status}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            state.get_last_request_body().is_some(),
            "the model's far end served"
        );
    }

    /// A MODEL NAMED DIRECTLY ROUND-TRIPS (F25 row 470; legacy
    /// `ingress_integration_tests::test_named_by_model_fallback_round_trip_via_router`): a messages
    /// request on `/m0/...` naming `m0`, a configured model that is no pool, takes the model's
    /// direct route: its far end receives the forwarded request and the caller has its 200. RED:
    /// the direct route refused, or another member dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_serves_a_model_named_directly() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-route-direct-model";
        let _published = Withdrawn(instance);
        let (state, server) = mock(vec![MockResponse::Ok {
            status: StatusCode::OK,
            body: messages_answer(),
        }])
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(server.address().port(), 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig
            .send(
                "POST",
                &format!("/m0{}", door_word("messages_path")),
                Some(serde_json::json!({"model": "m0", "messages": [], "max_tokens": 16})),
            )
            .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert!(
            state.get_last_request_body().is_some(),
            "the model's far end received the forwarded request"
        );
    }

    /// A rig over one member of the messages dialect at `port`, concurrency 1, its pool waiting
    /// `max_ms` for a slot when the member is at capacity, under a long failover budget.
    async fn queued(instance: &'static str, port: u16, max_ms: u64) -> Arc<DoorRig> {
        let pool_yaml = format!("on_exhausted: {{ queue: {{ max_ms: {max_ms} }} }}");
        Arc::new(
            rig(
                instance,
                RigOpts {
                    members: &[(port, 1)],
                    dialect: Some(door_word("messages_dialect")),
                    model_yaml: &["max_concurrent: 1"],
                    pool_yaml: &pool_yaml,
                    failover_timeout_secs: Some(300),
                    ..RigOpts::default()
                },
            )
            .await,
        )
    }

    /// One messages request on pool `p`, in the background.
    fn spawn_request(
        rig: &Arc<DoorRig>,
    ) -> tokio::task::JoinHandle<(u16, axum::http::HeaderMap, Vec<u8>)> {
        let rig = Arc::clone(rig);
        tokio::spawn(async move {
            rig.send(
                "POST",
                door_word("messages_path"),
                Some(messages_naming("p")),
            )
            .await
        })
    }

    /// A far-end answer whose body is held until `release`, `started` told when it is read.
    fn gated(
        status: StatusCode,
        started: &Arc<tokio::sync::Notify>,
        release: &Arc<tokio::sync::Notify>,
    ) -> MockResponse {
        MockResponse::Gated {
            status,
            body: serde_json::json!({"error": {"message": "boom"}}),
            started: Arc::clone(started),
            release: Arc::clone(release),
        }
    }

    /// Wait (bounded) until the member's cell leaves HalfOpen.
    async fn left_half_open(rig: &DoorRig, what: &str) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while matches!(
            rig.app.store.breaker_state_in("p", 0),
            BreakerState::HalfOpen
        ) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what} left the cell stuck HalfOpen: the won probe leaked"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// A DROPPED QUEUED DISPATCH RELEASES ITS PROBE (F25 row 540; legacy
    /// `on_exhausted_tests::queue_dropped_dispatch_future_releases_probe`): a request queued for the
    /// member's only slot, the member's cell open with its cooldown spent, wins the recovery probe
    /// when the slot frees (cell HalfOpen, its far end reading); dropped there, the cell leaves
    /// HalfOpen within two seconds and is Open: the probe released, the member not benched. RED:
    /// the cell stuck HalfOpen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_releases_the_probe_of_a_dropped_queued_dispatch() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-probe-queued-drop";
        let _published = Withdrawn(instance);
        let (holding, holding_release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let (probing, probing_release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let (_state, server) = mock(vec![
            gated(
                StatusCode::INTERNAL_SERVER_ERROR,
                &holding,
                &holding_release,
            ),
            gated(
                StatusCode::INTERNAL_SERVER_ERROR,
                &probing,
                &probing_release,
            ),
        ])
        .await;
        let rig = queued(instance, server.address().port(), 30_000).await;
        // The slot's holder: dispatched on the closed cell, its far end reading.
        let holder = spawn_request(&rig);
        tokio::time::timeout(std::time::Duration::from_secs(5), holding.notified())
            .await
            .expect("the holder reaches its far end");
        rig.app.store.force_open_in("p", 0, 0);
        let waiter = spawn_request(&rig);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        holder.abort();
        let _ = holder.await;
        tokio::time::timeout(std::time::Duration::from_secs(5), probing.notified())
            .await
            .expect("the queued dispatch reaches its far end once the slot frees");
        assert!(
            matches!(
                rig.app.store.breaker_state_in("p", 0),
                BreakerState::HalfOpen
            ),
            "precondition: the queued dispatch won the recovery probe"
        );
        waiter.abort();
        let _ = waiter.await;
        left_half_open(&rig, "the dropped queued dispatch").await;
        assert!(
            matches!(
                rig.app.store.breaker_state_in("p", 0),
                BreakerState::Open { .. }
            ),
            "the probe released (HalfOpen to Open), the member not benched"
        );
        holding_release.notify_waiters();
        probing_release.notify_waiters();
    }

    /// A QUEUE THAT NEVER GETS A SLOT TIMES OUT AT ITS BOUND (F25 row 543; legacy
    /// `on_exhausted_tests::queue_times_out_to_503_when_capacity_never_frees`): a pool waiting at
    /// most 300 ms for its member's only slot, the slot held for the whole request by another, sheds
    /// the request 503 with a `Retry-After` after waiting at least 250 ms and under 2 s (the queue's
    /// bound, not the 300 s failover budget), and the pool's queued depth is back to 0. RED: no
    /// wait, an unbounded wait, no Retry-After, or a depth left raised.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_sheds_a_queued_request_at_the_queues_bound() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-queue-times-out";
        let _published = Withdrawn(instance);
        let answer = door_word("messages_answer");
        let slow = far_end_scripted(SeatScript {
            head: format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                answer.len()
            ),
            pieces: vec![(3_000, answer.as_bytes().to_vec())],
            finish: None,
        })
        .await;
        let rig = queued(instance, slow.port, 300).await;
        let holder = spawn_request(&rig);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while slow.served() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the holder dispatches"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let started = std::time::Instant::now();
        let (status, head, _) = tokio::time::timeout(
            std::time::Duration::from_secs(4),
            rig.send(
                "POST",
                door_word("messages_path"),
                Some(messages_naming("p")),
            ),
        )
        .await
        .expect("the queue's wait is bounded and never hangs");
        let waited = started.elapsed();
        assert_eq!(status, 503, "a queue that never gets its slot sheds");
        assert!(head.contains_key("retry-after"), "{head:?}");
        assert!(
            waited >= std::time::Duration::from_millis(250),
            "it waited for the slot: {waited:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(2),
            "bounded by the queue's 300 ms, not the failover budget: {waited:?}"
        );
        assert_eq!(
            rig.app.engine_tables_view().queued_depth("p"),
            0,
            "the depth is back to 0"
        );
        holder.abort();
    }

    /// A STALE RELEASE DOES NOT REVERT A NEWER PROBE (F25 row 571; legacy
    /// `probe_release_owner_tests::a_stale_resume_does_not_revert_a_newer_probe`): while a request's
    /// far end holds a 400 mid-read, the cell is closed, re-opened and a NEWER probe won (epoch
    /// bumped, cell HalfOpen); the stale request then ends with its 400 relayed, and the cell is
    /// STILL HalfOpen: the stale end's owner-checked release is a no-op against the newer epoch.
    /// RED: the stale request reverting the newer probe's cell.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_never_reverts_a_newer_probe_on_a_stale_end() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-probe-stale-end";
        let _published = Withdrawn(instance);
        let (started, release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let (_state, server) = mock(vec![MockResponse::Gated {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({"error": {"message": "malformed request"}}),
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }])
        .await;
        let rig = Arc::new(
            rig(
                instance,
                RigOpts {
                    members: &[(server.address().port(), 1)],
                    dialect: Some(door_word("messages_dialect")),
                    ..RigOpts::default()
                },
            )
            .await,
        );
        let stale = spawn_request(&rig);
        tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
            .await
            .expect("the request reaches its far end");
        let epoch_before = rig.app.store.probe_epoch_in("p", 0);
        rig.app
            .store
            .record_success_in("p", 0, busbar_kernel::store::now());
        rig.app.store.force_open_in("p", 0, 0);
        assert!(
            rig.app
                .store
                .acquire_for_dispatch_in("p", 0, now().saturating_add(86_400)),
            "a NEW probe is won on the re-opened cell"
        );
        assert_ne!(
            epoch_before,
            rig.app.store.probe_epoch_in("p", 0),
            "the second win bumps the epoch"
        );
        assert!(matches!(
            rig.app.store.breaker_state_in("p", 0),
            BreakerState::HalfOpen
        ));
        release.notify_one();
        let (status, _, _) = stale.await.expect("the stale request ends");
        assert_eq!(status, 400, "the held 400 relays through");
        assert!(
            matches!(
                rig.app.store.breaker_state_in("p", 0),
                BreakerState::HalfOpen
            ),
            "the stale end left the newer probe's cell HalfOpen"
        );
    }

    /// A DROPPED DISPATCH RELEASES ITS WON PROBE (F25 row 572; legacy
    /// `probe_release_owner_tests::a_dropped_main_path_future_releases_its_won_probe`): a request
    /// that won the recovery probe on the member's open cell (cell HalfOpen, its far end reading a
    /// 500) is dropped: within two seconds the cell is Open again, and a later dispatch can win the
    /// probe again. RED: the cell stuck HalfOpen, the probe leaked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_releases_the_probe_of_a_dropped_dispatch() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-probe-dropped";
        let _published = Withdrawn(instance);
        let (started, release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let (_state, server) = mock(vec![gated(
            StatusCode::INTERNAL_SERVER_ERROR,
            &started,
            &release,
        )])
        .await;
        let rig = Arc::new(
            rig(
                instance,
                RigOpts {
                    members: &[(server.address().port(), 1)],
                    dialect: Some(door_word("messages_dialect")),
                    ..RigOpts::default()
                },
            )
            .await,
        );
        rig.app.store.force_open_in("p", 0, 0);
        let request = spawn_request(&rig);
        tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
            .await
            .expect("the probing dispatch reaches its far end");
        assert!(
            matches!(
                rig.app.store.breaker_state_in("p", 0),
                BreakerState::HalfOpen
            ),
            "precondition: the dispatch won the recovery probe"
        );
        request.abort();
        let _ = request.await;
        left_half_open(&rig, "the dropped dispatch").await;
        assert!(matches!(
            rig.app.store.breaker_state_in("p", 0),
            BreakerState::Open { .. }
        ));
        assert!(
            rig.app
                .store
                .acquire_for_dispatch_in("p", 0, now().saturating_add(86_400)),
            "a later dispatch can win the probe again"
        );
        release.notify_waiters();
    }

    /// A rig whose pool's ranking policy is shown its two members, the generation declaring
    /// `declared` of the candidate catalog signals.
    async fn ranked(
        instance: &'static str,
        declared: &[Signal],
    ) -> (DoorRig, [super::super::hook_seat_tests::FarEnd; 2]) {
        let fars = [
            seat_far_end(200, SERVED_BY_TWIN).await,
            seat_far_end(200, SERVED_BY_TWIN).await,
        ];
        let rig = rig(
            instance,
            RigOpts {
                members: &[(fars[0].port, 1), (fars[1].port, 1)],
                described: true,
                declared: Some(declared),
                ..RigOpts::default()
            },
        )
        .await;
        (rig, fars)
    }

    /// Member `m<i>`'s signal bag as the ranking policy was last shown it.
    fn bag_of(rig: &DoorRig, member: &str) -> String {
        let bags = rig.gate_signals();
        bags.iter()
            .find(|line| line.split(' ').next() == Some(member))
            .cloned()
            .unwrap_or_else(|| panic!("the ranking policy was shown {member}: {bags:?}"))
    }

    /// AN UNDECLARED SIGNAL IS ABSENT (F25 row 606; legacy
    /// `signal_catalog_tests::undeclared_signal_is_absent`): with only the breaker state declared,
    /// the ranking policy's bag for a member holds that signal and no error rate. RED: an
    /// undeclared signal computed and shown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_shows_no_signal_nobody_declared() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-signal-undeclared";
        let _published = Withdrawn(instance);
        let (rig, _fars) = ranked(instance, &[Signal::CandidateBreakerState]).await;
        assert_eq!(rig.chat().await.0, 200);
        let bag = bag_of(&rig, "m0");
        assert!(bag.contains("CandidateBreakerState="), "{bag}");
        assert!(!bag.contains("CandidateErrorRate"), "never declared: {bag}");
    }

    /// AN OPEN BREAKER IS SHOWN OPEN (F25 row 608; legacy
    /// `signal_catalog_tests::breaker_state_projects_open_after_a_trip`): member 0's cell forced
    /// open for an hour, the breaker state declared: the ranking policy's bag for member 0 says
    /// `CandidateBreakerState = "open"`. RED: a tripped member shown closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_shows_a_tripped_members_breaker_open() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-signal-open";
        let _published = Withdrawn(instance);
        let (rig, _fars) = ranked(instance, &[Signal::CandidateBreakerState]).await;
        rig.app.store.force_open_in("p", 0, now() + 3600);
        let _ = rig.chat().await;
        let bag = bag_of(&rig, "m0");
        assert!(
            bag.contains(r#"CandidateBreakerState=Str("open")"#),
            "the tripped member's state: {bag}"
        );
    }

    /// THE ERROR RATE IS THE WINDOW'S FRACTION (F25 row 609; legacy
    /// `signal_catalog_tests::error_rate_projects_the_outcome_window_fraction`): one transient
    /// failure and three successes recorded on member 0's cell, the error rate declared: the
    /// ranking policy is shown exactly 0.25 for member 0. RED: any other figure, or none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_shows_the_error_rate_as_the_windows_fraction() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-signal-error-rate";
        let _published = Withdrawn(instance);
        let (rig, _fars) = ranked(instance, &[Signal::CandidateErrorRate]).await;
        let cfg = busbar_kernel::store::BreakerCfg::default();
        rig.app
            .store
            .record_transient_in("p", 0, "test", &cfg, None);
        for _ in 0..3 {
            rig.app
                .store
                .record_success_in("p", 0, busbar_kernel::store::now());
        }
        let _ = rig.chat().await;
        let bag = bag_of(&rig, "m0");
        assert!(
            bag.contains("CandidateErrorRate=F64(0.25)"),
            "one failure in four outcomes: {bag}"
        );
    }

    /// AN UNDECLARED P95 IS NEVER COLLECTED (F25 row 611; legacy
    /// `signal_catalog_tests::undeclared_latency_p95_is_never_collected`): with only the error rate
    /// declared, a served request records the lane's always-on latency figure, and the ranking
    /// policy is never shown a p95 for any member, on that request or the next. RED: a p95
    /// collected and shown though no hook declared it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_never_collects_an_undeclared_p95() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-signal-undeclared-p95";
        let _published = Withdrawn(instance);
        let (rig, _fars) = ranked(instance, &[Signal::CandidateErrorRate]).await;
        assert_eq!(rig.chat().await.0, 200);
        assert!(
            (0..2).any(|lane| rig.app.store.lane_latency_ms(lane).is_some()),
            "the latency figure is always on"
        );
        assert_eq!(rig.chat().await.0, 200);
        let bags = rig.gate_signals();
        assert!(
            bags.iter()
                .all(|bag| !bag.contains("CandidateLatencyP95Ms")),
            "never declared, never shown: {bags:?}"
        );
    }

    /// AN ERROR END SEALS ONE RECORD AS AN ERROR (F25 row 678; legacy
    /// `audit::audit_matches_the_live_admitted_terminal`): a member of the messages dialect whose
    /// far end cuts its whole answer becomes a client-facing 502 for a chat caller, in the caller's
    /// own error envelope, and the unit seals exactly ONE audit record, under its operation class,
    /// its finish `Error`. RED: no record, two, or the error end sealed as complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_seals_an_error_end_as_one_error_record() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-audit-error-end";
        let _published = Withdrawn(instance);
        let answer = door_word("messages_answer");
        let far = far_end_scripted(SeatScript {
            head: format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                answer.len()
            ),
            pieces: vec![(0, answer.as_bytes()[..answer.len() / 2].to_vec())],
            finish: None,
        })
        .await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                dialect: Some(door_word("messages_dialect")),
                ..RigOpts::default()
            },
        )
        .await;
        let (status, _, body) = rig.chat().await;
        assert_eq!(status, 502, "{}", String::from_utf8_lossy(&body));
        let envelope: serde_json::Value =
            serde_json::from_slice(&body).expect("the caller's JSON error envelope");
        assert!(envelope.get("error").is_some(), "{envelope}");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while rig.audit_records() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let records = rig.records();
        assert_eq!(records.len(), 1, "one record for the one unit: {records:?}");
        assert!(!records[0].what.op_class.as_str().is_empty());
        assert_eq!(
            records[0].outcome.finish,
            busbar_kernel_audit::FinishClass::Error,
            "a client-facing 502 is sealed as an error end"
        );
    }

    /// A PROBE BUMPS THE LANE'S OK ONCE, NOT ONCE PER POOL (F25 row 227; legacy
    /// `health_tests::test_probe_success_bumps_lane_ok_once_not_per_cell`): an actively probed
    /// member of three pools (`p`, `q`, `r`) answering every probe 200 counts exactly one `ok` per
    /// probe on its lane snapshot (two probes, ok 2), never one per pool cell. RED: the lane's ok
    /// running ahead of the probes its far end answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pools_door_counts_one_ok_per_probe_not_per_pool() {
        let _one = ONE_PUBLISHER.lock().await;
        let instance = "rehome-probe-ok-once";
        let _published = Withdrawn(instance);
        let far = seat_far_end(200, SERVED_BY_TWIN).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                more_pools: &[("q", &[(0, 1)]), ("r", &[(0, 1)])],
                provider_yaml: "health:\n  mode: active\n  interval_secs: 1",
                ..RigOpts::default()
            },
        )
        .await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            // The lane's ok first: a probe is answered before it is counted, so a read in this
            // order never sees ok ahead of the answered probes unless one probe counted twice.
            let ok = rig.app.store.snapshot(0, now()).ok;
            let probes = far.served() as u64;
            assert!(
                ok <= probes,
                "ok {ok} ran ahead of the {probes} probes answered: counted per pool"
            );
            if probes >= 2 && ok == probes {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "two probes answered and counted: {probes} probes, ok {ok}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

// ── the core capabilities on the decisions plane (qa/capability-equality.json) ─────────────────
//
// The decisions plane is served only through its door on the kernel's plane driver, so each cell
// below is the plane's proof and the `root-decisions` leg's at once: every unit is a keyed
// caller's request on the data router, crossing the composition production seals.

#[cfg(feature = "plane-decisions")]
/// How many failing calls a breaker cell is given to open before the run calls it stuck.
const MAX_FAILURES: usize = 8;

#[cfg(feature = "plane-decisions")]
/// A caller fault, as the far end words it.
const CALLER_FAULT: &str = r#"{"error":"the state names no amount"}"#;

#[cfg(feature = "plane-decisions")]
/// Call the door until the model's member's breaker cell opens, its far end failing every call:
/// the number of failures the cell recorded first. Every one reached the far end and was not
/// served.
async fn trip(
    serving: &Serving,
    heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> usize {
    for n in 1..=MAX_FAILURES {
        let (status, reached) = call_once(serving, heard).await;
        assert_ne!(status, StatusCode::OK, "failure {n} is not served");
        assert!(reached.is_some(), "failure {n} reached the far end");
        if serving.cooldown() > 0 {
            return n;
        }
    }
    panic!("{MAX_FAILURES} failures in a row never opened the member's breaker cell");
}

#[cfg(feature = "plane-decisions")]
/// BREAKER-TRIP: a decisions provider that keeps failing records each failure into its member's
/// ONE breaker cell (the egress walk's, keyed by the model's pool and member) until the cell OPENS:
/// it then takes no request and carries a cooldown, and the trip is counted once on the scrape
/// under the model's lane. The door states no bench below the trip threshold, so the failures below
/// it open nothing and the run reaches the threshold itself. RED: a breaker port that records no
/// failure leaves the cell closed through every failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_decisions_provider_records_into_its_breaker_cell_until_the_cell_opens() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-breaker-trip";
    let _published = Published(instance);
    let (port, mut heard) = far_end_failing_first(MAX_FAILURES).await;
    let serving = serve_over(&declaring(STATES_NO_BENCH), instance, port).await;
    assert!(serving.ready(), "the member's cell starts closed");
    let trips = counted(
        &serving.scrape().await,
        busbar_kernel::snapshot::BREAKER_TRIPS_TOTAL,
        &serving.lane(),
    );

    let failures = trip(&serving, &mut heard).await;
    assert!(
        failures > 1,
        "the cell recorded failures below its threshold before it opened, not one: {failures}"
    );
    assert!(!serving.ready(), "the opened cell takes no request");
    assert_eq!(
        counted(
            &serving.scrape().await,
            busbar_kernel::snapshot::BREAKER_TRIPS_TOTAL,
            &serving.lane(),
        ),
        trips + 1.0,
        "one fresh trip, counted under the model's lane"
    );
}

#[cfg(feature = "plane-decisions")]
/// BREAKER-FASTFAIL: once the member's breaker cell has opened, the next unit is refused BEFORE its
/// dial and at once: the far end, which now holds every connection open unanswered, is never
/// dialled, and the refusal comes back in well under a second rather than after the walk's
/// budget. RED: a breaker port that admits an open cell dials the far end, which holds the unit
/// past the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_decisions_provider_is_refused_before_the_dial_at_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-breaker-fastfail";
    let _published = Published(instance);
    let holding = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let held = Arc::clone(&holding);
    let (port, mut heard) = far_end_answering(Arc::new(move |_| {
        if held.load(std::sync::atomic::Ordering::SeqCst) {
            Answer::Holds
        } else {
            Answer::Says("503 Service Unavailable", UNAVAILABLE)
        }
    }))
    .await;
    let serving = serve_over(&declaring(STATES_NO_BENCH), instance, port).await;
    trip(&serving, &mut heard).await;

    // From here a dialled far end never answers: only the breaker can answer the next unit.
    holding.store(true, std::sync::atomic::Ordering::SeqCst);
    let started = std::time::Instant::now();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        send(&serving.router, CLAIMED, Some(&serving.token)),
    )
    .await
    .expect("the tripped member's unit is answered, not held at its far end");
    let took = started.elapsed();
    assert_ne!(response.status(), StatusCode::OK, "the unit is refused");
    assert!(
        heard.try_recv().is_err(),
        "the refused unit never reached the far end"
    );
    assert!(
        took < std::time::Duration::from_secs(1),
        "refused before the dial, in milliseconds: {took:?}"
    );
}

#[cfg(feature = "plane-decisions")]
/// DISPOSITION: the decisions provider's answers are normalized and classified before the plane
/// sees them. A caller fault (400) is relayed to the caller as the far end said it, records nothing
/// against the member and counts no upstream failure, so the next call reaches it again; a
/// transient failure (503) is the member's: it is counted under the model's lane, benches the
/// member, and is failed over rather than relayed, so the caller is answered by the walk's
/// terminal, never with the far end's own bytes. RED: a classifier that reads every status as
/// transient fails the caller fault over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_providers_answers_are_classified_before_the_plane_relays_them() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-disposition";
    let _published = Published(instance);
    let (port, mut heard) = far_end_answering(Arc::new(|n| match n {
        0 | 1 => Answer::Says("400 Bad Request", CALLER_FAULT),
        2 => Answer::Says("503 Service Unavailable", UNAVAILABLE),
        _ => Answer::Says("200 OK", ANSWER),
    }))
    .await;
    // The shipped table: the door states no breaker fact, so the default bench holds.
    let serving = serve_over(&crate::LINKED, instance, port).await;
    let failures = || async {
        counted(
            &serving.scrape().await,
            busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
            &serving.lane(),
        )
    };
    let before = failures().await;

    for n in 1..=2 {
        let response = send(&serving.router, CLAIMED, Some(&serving.token)).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "caller fault {n} is relayed with the far end's status"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        assert_eq!(
            &body[..],
            CALLER_FAULT.as_bytes(),
            "caller fault {n} is relayed as the far end said it"
        );
        assert!(
            heard.try_recv().is_ok(),
            "caller fault {n} reached the far end"
        );
        assert!(serving.ready(), "a caller fault benches nothing ({n})");
    }
    assert_eq!(
        failures().await,
        before,
        "a caller fault is not the destination's: no upstream failure is counted"
    );

    let response = send(&serving.router, CLAIMED, Some(&serving.token)).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    assert!(
        heard.try_recv().is_ok(),
        "the transient failure reached the far end"
    );
    assert!(
        status.is_server_error(),
        "the walk's terminal answers the transient failure: {status}"
    );
    assert_ne!(
        &body[..],
        UNAVAILABLE.as_bytes(),
        "a transient failure is failed over, never relayed"
    );
    assert!(!serving.ready(), "the transient failure benches the member");
    assert_eq!(
        failures().await,
        before + 1.0,
        "the transient failure is counted once under the model's lane"
    );
}

#[cfg(feature = "plane-decisions")]
/// AUDIT-CHAIN: every decisions unit, served or refused, seals ONE record on the node's audit
/// chain under the plane's operation class, the second linked to the first, and the chain walks clean;
/// a record altered after its seal (the served unit re-told as refused) breaks the walk. The
/// refusal is the kernel's own, inside the loop: the caller's group allows one request an hour.
/// RED: a loop whose audit door's pass is never handed back to the node seals nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_decisions_unit_served_or_refused_seals_one_record_on_one_tamper_evident_chain() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-audit-chain";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let one_an_hour = busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Requests,
        amount: 1,
        per: Some(busbar_kernel::config::groups::LimitWindow::Hour),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    };
    let serving = serve_limited(&crate::LINKED, instance, port, vec![one_an_hour]).await;
    // Each answer read to its end, as a caller that stays reads it: a caller gone before its last
    // byte is a unit that ended for that reason, and its record says so.
    let call = || async {
        let response = send(&serving.router, CLAIMED, Some(&serving.token)).await;
        let status = response.status();
        let _ = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        status
    };

    assert_eq!(call().await, StatusCode::OK, "the first unit is served");
    assert!(heard.try_recv().is_ok(), "and dispatched");
    assert_ne!(
        call().await,
        StatusCode::OK,
        "the second is refused by the limit"
    );
    assert!(heard.try_recv().is_err(), "before its dial");

    let records = serving.audit_records();
    assert_eq!(records.len(), 2, "one record per unit: {records:?}");
    let (served, refused) = (&records[0], &records[1]);
    for record in &records {
        assert_eq!(
            record.what.op_class.as_str(),
            serving.op_classes[0],
            "sealed under the plane's operation class: {record:?}"
        );
    }
    assert_eq!(
        served.outcome.unit_end,
        busbar_contract::caps::Outcome::Completed
    );
    assert!(
        matches!(
            refused.outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(_, ReasonCode::RateLimited)
        ),
        "the refusal is chained as one: {:?}",
        refused.outcome
    );
    assert_eq!(refused.seq, served.seq + 1, "contiguous");
    assert_eq!(
        refused.prev_hash, served.hash,
        "linked to the record before"
    );
    assert!(busbar_kernel_audit::AuditChain::verify_window(&records).is_ok());
    assert!(
        serving
            .book
            .lock()
            .expect("unpoisoned")
            .retained_audit_findings()
            .is_empty(),
        "the node's own verify finds nothing"
    );

    let mut forged = records.clone();
    forged[0].outcome.unit_end = refused.outcome.unit_end;
    assert!(
        busbar_kernel_audit::AuditChain::verify_window(&forged).is_err(),
        "a record altered after its seal breaks the chain"
    );
}

#[cfg(feature = "plane-decisions")]
/// METRICS: a served decisions unit's upstream leg appears on the real `/metrics` scrape under the
/// plane's own lane (`<plane key><sep><model>`), as its pool and its lane, once per attempt. RED: an
/// egress whose telemetry counts no attempt leaves the scrape where it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_decisions_unit_counts_its_upstream_attempt_under_the_planes_lane() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-metrics";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let serving = serve_over(&crate::LINKED, instance, port).await;
    let lane = serving.lane();
    assert!(lane.starts_with(&serving.plane), "{lane}");
    let before = counted(
        &serving.scrape().await,
        busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
        &lane,
    );

    let (status, reached) = call_once(&serving, &mut heard).await;
    assert_eq!(status, StatusCode::OK, "served");
    assert!(reached.is_some(), "dispatched");

    let exposition = serving.scrape().await;
    assert_eq!(
        counted(
            &exposition,
            busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
            &lane
        ),
        before + 1.0,
        "one attempt, counted under the plane's lane:\n{exposition}"
    );
    let pool = format!("pool=\"{lane}\"");
    assert!(
        exposition.lines().any(|l| l.starts_with(&format!(
            "{}{{",
            busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL
        )) && l.contains(&pool)),
        "its pool label is the plane's too:\n{exposition}"
    );
}

#[cfg(feature = "plane-decisions")]
/// EGRESS-AUTH: the decisions provider is handed the credential the egress mechanism planned for
/// its style (the dialect's default, `bearer`), presented once, and nothing the caller sent as a
/// credential: not its bearer, not a key it put in a header of its own. RED: an egress walk that
/// drops the auth binding's fields sends the provider no credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_provider_is_handed_the_planned_credential_and_never_the_callers() {
    use tower::ServiceExt as _;
    const CALLER_SECRET: &str = "caller-own-provider-key";
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-egress-auth";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let serving = serve_over(&crate::LINKED, instance, port).await;

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(CLAIMED)
        .header("authorization", format!("Bearer {}", serving.token))
        .header("api-key", CALLER_SECRET)
        .header("x-api-key", CALLER_SECRET)
        .body(axum::body::Body::from(r#"{"state":{"amount":7}}"#))
        .expect("a request");
    let response = serving
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK, "served");

    let head = heard.recv().await.expect("the far end was dialled");
    let presented: Vec<&str> = head
        .lines()
        .filter(|l| {
            l.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        })
        .collect();
    assert_eq!(presented.len(), 1, "one credential is presented: {head}");
    assert!(
        presented[0].eq_ignore_ascii_case(&format!("authorization: Bearer {CREDENTIAL}")),
        "the planned credential, in its style: {head}"
    );
    assert!(
        !head.contains(&serving.token),
        "the caller's bearer never reaches the provider: {head}"
    );
    assert!(
        !head.contains(CALLER_SECRET),
        "nor a key the caller sent: {head}"
    );
}

#[cfg(feature = "plane-decisions")]
/// A budget limit of `amount` minor units per `per`, on the caller's group.
fn budget_of(
    amount: u64,
    per: busbar_kernel::config::groups::LimitWindow,
) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount,
        per: Some(per),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

#[cfg(feature = "plane-decisions")]
/// One call to the door, its answer read to its end: the status, the `Retry-After` it named, and
/// whether the far end heard it.
async fn call_through(
    serving: &Serving,
    heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> (StatusCode, Option<String>, bool) {
    let response = send(&serving.router, CLAIMED, Some(&serving.token)).await;
    let status = response.status();
    let wait = response
        .headers()
        .get("retry-after")
        .map(|v| v.to_str().expect("a header value").to_string());
    let _ = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    (status, wait, heard.try_recv().is_ok())
}

#[cfg(feature = "plane-decisions")]
/// GOVERNANCE-BUDGET: a decisions unit's spend (the plane's own per-request fee, its section's
/// `fees.per_request`) is charged to the presenting key, and the key's group BUDGET refuses the unit
/// past it before its dial, 429, naming in `Retry-After` the seconds until the budget's window rolls,
/// as 1.5.5's governance refusal names them. A window that never rolls (`per:
/// total`) names no wait. RED: a driver that drops the governance refusal's wait, or a decisions
/// renderer that does not render it, answers the refusal with no `Retry-After`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_unit_past_its_budget_is_refused_with_a_retry_after() {
    use busbar_kernel::config::groups::LimitWindow;
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-budget";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let serving = serve_governed(
        &crate::LINKED,
        instance,
        port,
        vec![budget_of(1, LimitWindow::Hour)],
        1,
        None,
    )
    .await;

    let (status, wait, reached) = call_through(&serving, &mut heard).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "within its budget the unit is served"
    );
    assert!(reached, "and dispatched");
    assert_eq!(wait, None, "a served unit names no wait");
    let usage = serving
        .gov
        .usage_for(&serving.app.cost, &serving.key, busbar_kernel::store::now())
        .expect("a read")
        .expect("the key exists");
    assert_eq!(usage.requests, 1, "its spend is the presenting key's");

    let (status, wait, reached) = call_through(&serving, &mut heard).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "past its budget the unit is refused"
    );
    assert!(!reached, "before its dial");
    let secs: u64 = wait
        .expect("the refusal names its wait")
        .parse()
        .expect("whole seconds");
    assert!(
        (1..=3600).contains(&secs),
        "the seconds until the hour's window rolls: {secs}"
    );
    drop(serving);

    // A budget whose window never rolls names no wait, as 1.5.5 named none.
    let instance = "serve-door-budget-total";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let serving = serve_governed(
        &crate::LINKED,
        instance,
        port,
        vec![budget_of(1, LimitWindow::Total)],
        1,
        None,
    )
    .await;
    assert_eq!(call_through(&serving, &mut heard).await.0, StatusCode::OK);
    let (status, wait, reached) = call_through(&serving, &mut heard).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!reached);
    assert_eq!(wait, None, "a total never rolls: no wait is named");
}

#[cfg(feature = "plane-decisions")]
/// VERIFY: a unit presented by a key that names only another pool is refused before Admit draws a
/// bucket and before its dial, the refusal sealed on the audit chain as the unit's end; the same
/// door serves the key granted every pool (the control). The served door judges the key's pool
/// grant at its approve seat (`ScopeDenied`), as every served door does. RED: with the key granted
/// every pool the unit is served and the far end hears it, so the refusal assertions fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decisions_unit_from_a_key_naming_another_pool_is_refused_before_its_dial() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-verify";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let other = Some(vec!["elsewhere".to_string()]);
    let serving = serve_governed(&crate::LINKED, instance, port, Vec::new(), 0, other).await;
    let (status, _wait, reached) = call_through(&serving, &mut heard).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a pool the key does not name is not served"
    );
    assert!(!reached, "the far end is never dialled");
    let records = serving.audit_records();
    assert_eq!(records.len(), 1, "the refusal is sealed: {records:?}");
    assert!(
        matches!(
            records[0].outcome.unit_end,
            busbar_contract::caps::Outcome::Refused(
                busbar_contract::caps::StepName::Approve,
                ReasonCode::ScopeDenied
            )
        ),
        "refused on its pool grant, before admit: {:?}",
        records[0].outcome
    );
    drop(serving);

    // THE CONTROL: the same door, the key granted every pool, is served and dials.
    let instance = "serve-door-verify-control";
    let _published = Published(instance);
    let (port, mut heard) = far_end().await;
    let serving = serve_governed(&crate::LINKED, instance, port, Vec::new(), 0, None).await;
    let (status, _wait, reached) = call_through(&serving, &mut heard).await;
    assert_eq!(status, StatusCode::OK, "the granted key is served");
    assert!(reached, "and dispatched");
}

#[cfg(feature = "plane-decisions")]
/// THE DECISIONS DOOR LISTS ITS MODELS (THE DESIGN §2, DECISIONS D8): through the one loader, the
/// door's facing carries every model its section configures, in name order, for the kernel to
/// scope-filter and `/v1/models` to append; a section that configures none lists nothing. RED: a
/// generation whose snapshot lists nothing faces the world with no names.
#[test]
fn the_decisions_doors_facing_lists_its_configured_models() {
    let reg = crate::root::loader::dispatch::kinds::plane::registration(
        crate::root::loader::dispatch::kinds::plane::linked_probe(
            decisions_door,
            "decisions-listed",
        ),
    )
    .expect("the linked door binds");
    let facing = (reg.facing)(
        // No provider facts reach a bare facing probe, so each model states its own `protocol` (#51).
        br#"{"decisions":{"models":{"b":{"provider":"typesafe","protocol":"jev"},"a":{"provider":"typesafe","protocol":"jev"}}}}"#,
        b"",
        None,
        &[],
    )
    .expect("the door faces the world");
    assert_eq!(facing.listed, vec!["a".to_string(), "b".to_string()]);
    let none = (reg.facing)(b"{}", b"", None, &[]).expect("the door faces the world");
    assert!(
        none.listed.is_empty(),
        "no models, no names: {:?}",
        none.listed
    );
}

/// AN UNKNOWN MODEL THROUGH THE SERVED DOOR (F25 rows 194, 423 and 725; legacy
/// `forward_pool_integration_tests::test_openai_ingress_unknown_model`,
/// `ingress_integration_tests::test_unknown_model_404_uses_canonical_openai_type` and
/// `unit/tests/route.rs::route_step_refuses_an_unresolved_destination_without_a_terminal`): a chat
/// naming a model no `models:` entry or pool defines is 1.5.5's 404 in the caller's dialect, its
/// error type `not_found_error` and its message 1.5.5's sentence naming the model
/// (`v1.5.5 crates/busbar/src/ingress/mod.rs:1011`). No far end is dialled. RED: the plane's
/// no-destination refusal reaching the caller as the kernel's 503, or the sentence not naming the
/// model.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_answers_an_unknown_model_with_1_5_5s_404_naming_it() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-unknown-model";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, SERVED_BY_TWIN).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "nope",
                "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
    assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON error body");
    assert_eq!(answer["error"]["type"], "not_found_error", "{answer}");
    assert_eq!(
        answer["error"]["message"],
        "The model 'nope' does not exist or you do not have access to it.",
        "{answer}"
    );
    assert_eq!(far.served(), 0, "no far end is dialled");
}

/// AN UNTRANSLATABLE 2XX BILLS NO TOKENS (F25 row 333, `$`; legacy
/// `ingress_indistinguishability_tests::test_untranslatable_2xx_does_not_charge_tokens`): a far end
/// in another dialect answers 2xx with usage stated (7 in, 3 out), but its reader refuses the answer
/// (a role no answer has), so it cannot be written in the caller's dialect. The caller gets its own
/// dialect's 500 with no completion in it, and the key's ledger holds 0 tokens: 1.5.5 billed tokens
/// only for an answer it delivered. RED: the stated usage (10 tokens) billed, or a floor estimate
/// standing in for it.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_no_tokens_for_an_answer_it_cannot_translate() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-untranslatable-2xx";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, door_word("unreadable_answer")).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some(door_word("untranslatable_dialect")),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 500, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON error body");
    assert!(
        answer.get("error").is_some(),
        "the caller's own error: {answer}"
    );
    assert!(
        answer.get("choices").is_none(),
        "no completion reaches the caller: {answer}"
    );
    assert_eq!(far.served(), 1, "the far end answered once");
    assert_eq!(
        rig.tokens_after().await,
        0,
        "an untranslated answer bills no tokens"
    );
}

// THE DOOR PATH'S MONEY CELLS that succeed the node's legacy answer path's own (`plane_node.rs`,
// retired by #1161): each a gap that path alone witnessed, or one of its money cells whose door
// successor asserted only part of it.
#[cfg(linked_driver_proofs)]
#[path = "serve_door_money_gaps.rs"]
mod door_money_gaps;

/// AN UNTRANSLATABLE 2XX GIVES THE LANE'S BUDGET UNIT BACK (`$`; legacy
/// `crossproto_delivery_billing_tests::untranslatable_500_does_not_charge` and
/// `ingress_indistinguishability_tests::test_untranslatable_2xx_refunds_budget_and_trips_breaker`):
/// a far end in another dialect answers 2xx that its reader refuses, so the caller gets its own
/// 500 and nothing is delivered. The member's lifetime request budget is refunded whole (5 stays
/// 5), as 1.5.5's spend guard refunded every non-delivery, and no tokens bill.
/// RED: the unit spent at the dial kept for an answer the caller never received (5 -> 4).
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_refunds_the_budget_unit_of_an_answer_it_cannot_translate() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-untranslatable-budget";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, door_word("unreadable_answer")).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some(door_word("untranslatable_dialect")),
            lane_budget: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(far.served(), 1, "the far end was dialled and answered");
    assert_eq!(
        rig.app.store.lane_budget_remaining(0),
        Some(5),
        "a non-delivery refunds the budget unit"
    );
    assert_eq!(rig.tokens_after().await, 0, "and bills no tokens");
}

/// A DELIVERED CROSS-DIALECT ANSWER BILLS ONCE AND KEEPS ITS BUDGET UNIT (`$`; legacy
/// `crossproto_delivery_billing_tests::delivered_cross_protocol_response_bills_once`): a far end
/// in another dialect answers a whole message (1 in, 1 out) that is translated and delivered to
/// the caller. Its two tokens bill exactly once, and the member's lifetime budget unit spent at
/// the dial is kept (5 -> 4).
/// RED: a delivered answer refunded as a non-delivery (5 stays 5), or its tokens billed twice.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pools_door_bills_a_delivered_cross_dialect_answer_once_and_keeps_its_budget_unit() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-crossdialect-delivered-budget";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, door_word("messages_answer")).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some(door_word("messages_dialect")),
            lane_budget: Some(5),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON answer");
    assert!(
        answer.get("choices").is_some(),
        "the caller's own dialect: {answer}"
    );
    assert_eq!(
        rig.tokens_after().await,
        2,
        "its 1 + 1 tokens bill exactly once"
    );
    assert_eq!(
        rig.app.store.lane_budget_remaining(0),
        Some(4),
        "a delivered answer keeps the budget unit"
    );
}

// ── THE 1.5.5 LIFECYCLE ON THE DOOR: NO ALARM, NO DISPUTE ──────────────────────────────────────────
//
// MOVED HERE from `crates/busbar/tests/alarm_silence_cross_plane.rs`, assertions unchanged
// (DEV-GREEN row 83, ARCHITECT option (a) on #1161): the kernel's router alone serves no model unit
// any more (the retired engine crate's arrivals are gone); the door serving the `pools` map does,
// so the lifecycle is driven through the data router built with the door's claims.

/// The words no 1.5.5-shaped deployment's tracing event or metric name may carry.
#[cfg(linked_driver_proofs)]
const SILENCE_MARKERS: &[&str] = &["alarm", "dispute"];

#[cfg(linked_driver_proofs)]
fn mentions_a_silence_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SILENCE_MARKERS.iter().any(|m| lower.contains(m))
}

/// The metric name an exposition line carries: the family a `# HELP`/`# TYPE` line names, or the
/// series name before its labels or value.
#[cfg(linked_driver_proofs)]
fn exposition_metric_name(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("# ") {
        let mut it = rest.split_whitespace();
        let _kind = it.next()?;
        return it.next();
    }
    let end = line.find(['{', ' ']).unwrap_or(line.len());
    let name = &line[..end];
    (!name.is_empty()).then_some(name)
}

/// LEGACY `crates/busbar/tests/alarm_silence_cross_plane.rs::a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric`.
/// A 1.5.5-SHAPED LIFECYCLE EMITS NO ALARM OR DISPUTE EVENT OR METRIC: two pools over the
/// messages wire, no governance beyond the keyed caller, one pool's member answering and the other's
/// at a closed port, then `/healthz` and `/stats`. The successful request comes back 200, the dead
/// member's does not, the probe answers; no tracing event at DEBUG or above (on the test's thread
/// or any of its runtime's workers) and no metric name mentions an alarm or a dispute.
/// RED: any event or family that names either word on this deployment.
#[cfg(linked_driver_proofs)]
#[test]
fn a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric() {
    use busbar_kernel::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    busbar_kernel::snapshot::init();
    let cap = WarnCapture::capturing_debug();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry().with(cap.clone()));
    let mut statuses: Vec<(&str, u16)> = Vec::new();
    tracing::dispatcher::with_default(&dispatch, || {
        let on_workers = dispatch.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .on_thread_start(move || {
                // Every worker's events reach the capture, for the thread's whole life.
                std::mem::forget(tracing::dispatcher::set_default(&on_workers));
            })
            .enable_all()
            .build()
            .expect("a runtime");
        rt.block_on(async {
            let _one = ONE_PUBLISHER.lock().await;
            let instance = "serve-door-alarm-silence";
            let _published = Withdrawn(instance);
            let far = seat_far_end(200, door_word("messages_answer")).await;
            // Member 1 sits at a closed port, so pool `pb`'s request fails upstream: the path a
            // stall or lane alarm would ride.
            let rig = rig(
                instance,
                RigOpts {
                    members: &[(far.port, 1), (1, 1)],
                    dialect: Some(door_word("messages_dialect")),
                    pooled: Some(1),
                    more_pools: &[("pb", &[(1, 1)])],
                    ..RigOpts::default()
                },
            )
            .await;
            let ask = |pool: &str| {
                serde_json::json!({
                    "model": pool,
                    "messages": [{"role": "user", "content": "hi"}],
                    "max_tokens": 8
                })
            };
            let path = door_word("messages_path");
            statuses.push(("ok request", rig.send("POST", path, Some(ask("p"))).await.0));
            statuses.push((
                "failed-upstream request",
                rig.send("POST", path, Some(ask("pb"))).await.0,
            ));
            statuses.push(("healthz", rig.send("GET", "/healthz", None).await.0));
            statuses.push(("stats", rig.send("GET", "/stats", None).await.0));
        });
    });

    // The lifecycle really happened: the successful request reached the far end and came back 200,
    // the dead-member request did NOT succeed, and the probe answered.
    let status_of = |what: &str| {
        statuses
            .iter()
            .find(|(w, _)| *w == what)
            .map(|(_, s)| *s)
            .unwrap()
    };
    assert_eq!(status_of("ok request"), 200, "statuses: {statuses:?}");
    assert_ne!(
        status_of("failed-upstream request"),
        200,
        "statuses: {statuses:?}"
    );
    assert_eq!(status_of("healthz"), 200, "statuses: {statuses:?}");

    // No event at DEBUG or above mentions an alarm or a dispute, in its message or in any field.
    let events = cap.messages();
    let hits: Vec<&String> = events
        .iter()
        .filter(|m| mentions_a_silence_marker(m))
        .collect();
    assert!(
        hits.is_empty(),
        "no tracing event may carry an alarm/dispute message or field on a 1.5.5-shaped \
         deployment; found:\n{}",
        hits.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // No metric name carries either word.
    let exposition = busbar_kernel::snapshot::render();
    let leaked: Vec<&str> = exposition
        .lines()
        .filter_map(exposition_metric_name)
        .filter(|n| mentions_a_silence_marker(n))
        .collect();
    assert!(
        leaked.is_empty(),
        "no metric name may mention an alarm or a dispute on a 1.5.5-shaped deployment; found: \
         {leaked:?}"
    );
}

// ── A KEY ROW'S `expires_at` ON THE DOOR: UNENFORCED, AS 1.5.5 ──────────────────────────────────────
//
// MOVED HERE from `crates/busbar/tests/key_expires_at_cross_plane.rs`, assertions unchanged
// (DEV-GREEN row 83, ARCHITECT option (a) on #1161): the request is served by the door serving the
// `pools` map, through the data router built with its claims.

/// LEGACY `crates/busbar/tests/key_expires_at_cross_plane.rs::a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane`.
/// End to end on the data plane through the `keys` chain: the request is admitted (200 from the far
/// end) with the key row's `expires_at` stamped 30 days in the past (the token's own `exp` still in
/// the future), while a wrong token is still refused (401) on the same app — so the admission is a
/// real gate, not an open chain. Measured on the published 1.5.5 AND on HEAD's release binary
/// (shadow-oracle script cell key-expired-out-of-band.sh): both answer 200.
/// RED: a stored `expires_at` enforced on the data plane (the request refused).
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-key-row-expired";
    let _published = Withdrawn(instance);
    let far = seat_far_end(200, door_word("messages_answer")).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some(door_word("messages_dialect")),
            allowed_pools: Some(&["p"]),
            ..RigOpts::default()
        },
    )
    .await;
    // Stamp the minted key's row with an `expires_at` in the past, as an operator (or a migrated
    // 1.5.5 database) would, and reload the caches. Mint never stamps it.
    let store = rig.gov.store();
    let mut row = store
        .get_key(&rig.key_id)
        .expect("store read")
        .expect("the minted row");
    assert_eq!(
        row.expires_at, None,
        "mint never stamps expires_at; it is a stored field nothing in the engine writes"
    );
    row.expires_at = Some(busbar_kernel::store::now() - 30 * 86_400);
    store.put_key(&row).expect("rewrite the row");
    rig.gov.refresh().expect("reload caches");

    let ask = serde_json::json!({
        "model": "p",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8
    });
    let path = door_word("messages_path");
    let (admitted, _, body) = rig.send("POST", path, Some(ask.clone())).await;
    assert_eq!(
        admitted,
        200,
        "a key row with a past expires_at is still admitted (1.5.5 never enforced it; measured): {}",
        String::from_utf8_lossy(&body)
    );
    let (refused, _, _) = rig
        .send_bare(
            "POST",
            path,
            Some(ask),
            &[("authorization", "Bearer bbk_not_a_real_token")],
        )
        .await;
    assert_eq!(
        refused, 401,
        "the keys chain is a real gate on this app: a bad token is refused"
    );
}

// ── THE MODEL PLANE'S `/metrics` ON THE DOOR: COUNTED ONCE, v1.5.4-SHAPED ──────────────────────────
//
// MOVED HERE from `crates/busbar/tests/plane_integration.rs`, assertions unchanged (DEV-GREEN row
// 83, ARCHITECT option (a) on #1161): a model request is served by the door that serves the `pools`
// map, so it is driven through the data router built with the door's claims; the kernel's router
// alone serves no model unit any more.

/// The label keys of one exposition line, sorted.
#[cfg(linked_driver_proofs)]
fn exposition_label_keys(line: &str) -> Vec<String> {
    line.split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .map(|(inner, _)| {
            let mut ks: Vec<String> = inner
                .split(',')
                .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string()))
                .collect();
            ks.sort();
            ks
        })
        .unwrap_or_default()
}

/// Every non-comment exposition line of `family`.
#[cfg(linked_driver_proofs)]
fn exposition_family<'a>(exposition: &'a str, family: &str) -> Vec<&'a str> {
    exposition
        .lines()
        .filter(|l| !l.starts_with('#') && l.starts_with(family))
        .collect()
}

/// LEGACY `crates/busbar/tests/plane_integration.rs::a_model_plane_request_is_counted_exactly_once`.
/// A MODEL-plane request is counted EXACTLY ONCE: one request produces ONE count on
/// `busbar_requests_total` for its pool, not one from the request's own finish plus one from the
/// plane ingress boundary. The far end is a closed port, so the request fails to forward, which is
/// deliberate: what is under test is how many times it is counted, not what it returned.
/// RED: a boundary that counts everything (2), or a model request counted nowhere (0).
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_model_plane_request_is_counted_exactly_once() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-counted-once";
    let _published = Withdrawn(instance);
    busbar_kernel::snapshot::init();
    let rig = rig(
        instance,
        RigOpts {
            members: &[(1, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    // The model plane's `busbar_requests_total` carries NO `plane` label (v1.5.4-identical); the
    // test runs in a process of its own, so the pool's label pins the delta.
    let labels = [("pool", "p")];
    let before =
        busbar_kernel::test_support::metric_sum(busbar_kernel::snapshot::REQUESTS_TOTAL, &labels);
    let _ = rig.chat().await;
    let after =
        busbar_kernel::test_support::metric_sum(busbar_kernel::snapshot::REQUESTS_TOTAL, &labels);
    assert_eq!(
        (after - before).round() as u64,
        1,
        "one model-plane request must produce ONE count, not one from `finish_inner` plus one from \
         the plane ingress boundary"
    );
}

/// LEGACY the model-plane half of
/// `crates/busbar/tests/plane_integration.rs::metrics_scrape::mounted_plane_traffic_appears_on_a_real_metrics_scrape`
/// (its door- and agent-plane half stays there, on the kernel's router).
/// THE MODEL PLANE STAYS v1.5.4-IDENTICAL on a scrape: after model traffic, `busbar_requests_total`
/// carries a series with exactly the 1.5.4 label set {ingress_protocol, pool, outcome} and NO `plane`
/// label, `busbar_request_duration_seconds` carries a series, and neither family carries a `plane`
/// label anywhere in the exposition. An unroutable model is deliberate: the request finishes
/// without an upstream, which is all the series shape needs.
/// RED: a `plane` label on either model family (the BI-2 regression), or no model series at all.
#[cfg(linked_driver_proofs)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_model_plane_families_stay_v1_5_4_shaped_on_a_real_scrape() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-model-families";
    let _published = Withdrawn(instance);
    busbar_kernel::snapshot::init();
    let rig = rig(
        instance,
        RigOpts {
            members: &[(1, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (model_status, _, _) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({
                "model": "no-such-model",
                "messages": [{ "role": "user", "content": "hi" }],
            })),
        )
        .await;
    let exposition = busbar_kernel::snapshot::render();
    let model_counters = exposition_family(&exposition, busbar_kernel::snapshot::REQUESTS_TOTAL);
    assert!(
        model_counters.iter().any(|line| exposition_label_keys(line)
            == vec![
                "ingress_protocol".to_string(),
                "outcome".to_string(),
                "pool".to_string()
            ]),
        "no v1.5.4-shaped `{}` series {{ingress_protocol,pool,outcome}} after driving model traffic \
         (model {model_status}). Exposition:\n{exposition}",
        busbar_kernel::snapshot::REQUESTS_TOTAL,
    );
    assert!(
        !exposition_family(
            &exposition,
            busbar_kernel::snapshot::REQUEST_DURATION_SECONDS
        )
        .is_empty(),
        "no `{}` series after driving model traffic. Exposition:\n{exposition}",
        busbar_kernel::snapshot::REQUEST_DURATION_SECONDS,
    );
    for family in [
        busbar_kernel::snapshot::REQUESTS_TOTAL,
        busbar_kernel::snapshot::REQUEST_DURATION_SECONDS,
    ] {
        for line in exposition_family(&exposition, family) {
            assert!(
                !line.contains("plane=\""),
                "a `plane` label leaked onto the v1.5.4 model family `{family}`: {line}"
            );
        }
    }
}
