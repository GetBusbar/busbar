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
const CLAIMED: &str = "/v1/systemone";

#[cfg(feature = "plane-decisions")]
/// The provider's credential, as its file holds it.
const CREDENTIAL: &str = "sk-door-test";

#[cfg(feature = "plane-decisions")]
/// The far end's answer: a decision, and the one unit it reports using.
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

#[cfg(feature = "plane-decisions")]
/// A POST of the caller's decision state to `path` on `router`, with `token` as its bearer or with
/// none: the response.
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

#[cfg(feature = "plane-decisions")]
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
mod mcp {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::http::StatusCode;
    use busbar_kernel::governance::PLANE_LANE_SEP;

    use crate::root::door_steps::tests::hook_parity;
    use crate::root::door_steps::tests::tool_door::{
        down_port, grant, protocol_version, rig_tools, send, send_as, surface, three_tools,
        tool_digest, tool_listing, tool_schema, tool_server, tool_server_listing,
        tool_server_replying, Footing, Rig, CALL, TOOL_DESCRIPTION,
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

    /// `tool` called on `rig` as `token`: the status, the response head and the JSON-RPC answer.
    async fn call_with_head(
        rig: &Rig,
        token: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}", surface("endpoint_section")))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header(surface("protocol_header"), protocol_version())
            .header(surface("method_header"), "tools/call")
            .header(surface("name_header"), tool)
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(call_of(tool, arguments)))
            .expect("a request");
        let response = rig.router.clone().oneshot(req).await.expect("answers");
        let (status, head) = (response.status(), response.headers().clone());
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let answer = serde_json::from_slice(&body)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
        (status, head, answer)
    }

    /// `tool` called on `rig` as `token`: the status and the JSON-RPC answer.
    async fn call(
        rig: &Rig,
        token: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, answer) = call_with_head(rig, token, tool, arguments).await;
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
        busbar_kernel::metrics::render()
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

    /// BREAKER-TRIP: a registration whose server answers a call with a transient failure records
    /// that answer into ITS breaker cell (the walk's, keyed by the member's lane) and the cell opens:
    /// the failure is counted on `/metrics` under that lane, the next call to it is refused as the
    /// open breaker without reaching the server — and a healthy registration on the same door, its
    /// own cell, is untouched and still served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_tool_server_trips_its_breaker_cell_through_the_composed_door() {
        busbar_kernel::metrics::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mcp-trip";
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

        let (status, answer) =
            call(&rig, &rig.token, "tripper_read_file", serde_json::json!({})).await;
        assert_eq!(status.as_u16(), 503, "{answer}");
        assert_eq!(
            answer["error"]["message"],
            busbar_contract::caps::ReasonCode::BreakerOpen.as_str(),
            "refused as the open cell: {answer}"
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

    /// BREAKER-FASTFAIL: once a member's cell is open, a call is refused BEFORE dispatch, in
    /// milliseconds — no byte reaches the server and no attempt's timeout is waited out — and the
    /// refusal is the open breaker's, rendered in the plane's words.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_tool_server_is_refused_before_dispatch_without_waiting() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mcp-fastfail";
        let _published = Published(instance);
        let (port, mut heard) = answering_calls_with(503).await;
        let rig = rig_tools(instance, port, registration("flaky", port, ""), &|app| app);
        let _ = call(&rig, &rig.token, "flaky_read_file", serde_json::json!({})).await;
        assert!(
            drain(&mut heard).contains(&"call"),
            "the failure that opens the cell"
        );

        let started = Instant::now();
        let (status, answer) =
            call(&rig, &rig.token, "flaky_read_file", serde_json::json!({})).await;
        let took = started.elapsed();
        assert_eq!(status.as_u16(), 503, "{answer}");
        assert_eq!(
            answer["error"]["message"],
            busbar_contract::caps::ReasonCode::BreakerOpen.as_str(),
            "{answer}"
        );
        assert!(
            took < Duration::from_millis(500),
            "refused at once, not after a timeout: {took:?}"
        );
        assert!(drain(&mut heard).is_empty(), "nothing reached the server");
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// FAILOVER-REROUTE: a pool of two registrations walked by the kernel's ONE walk. The primary's
    /// transient failure fails the call over to its twin before the caller hears anything (the pool
    /// names the tool repeatable), and the primary's cell, now open, keeps the NEXT call off it
    /// entirely: the walk admits the twin first, and the primary is never touched again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_pool_member_reroutes_the_next_call_to_its_twin_through_the_walk() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mcp-reroute";
        let _published = Published(instance);
        let (bad, mut bad_heard) = answering_calls_with(503).await;
        let (good, mut good_heard) = tool_server().await;
        let d = tool_digest();
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{bad}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
             fs2:\n  url: \"http://127.0.0.1:{good}/rpc\"\n  {PIN}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
             pools:\n  twins: {{ members: [fs, fs2], repeatable: [read_file], member_granted: true }}\n"
        ))
        .expect("a section");
        let rig = rig_tools(instance, bad, tools, &|app| app);

        let (status, answer) = call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "the twin answered: {answer}");
        assert_eq!(
            answer["result"]["content"][0]["text"], "from the server",
            "{answer}"
        );
        assert_eq!(
            drain(&mut bad_heard)
                .iter()
                .filter(|w| **w == "call")
                .count(),
            1,
            "the primary was tried first"
        );
        assert_eq!(
            drain(&mut good_heard)
                .iter()
                .filter(|w| **w == "call")
                .count(),
            1,
            "and the call failed over to its twin"
        );

        let (status, answer) = call(&rig, &rig.token, "fs_read_file", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert!(
            !drain(&mut bad_heard).contains(&"call"),
            "the primary's open cell kept the next call off it"
        );
        assert_eq!(
            drain(&mut good_heard)
                .iter()
                .filter(|w| **w == "call")
                .count(),
            1,
            "the walk rerouted the next call straight to the twin"
        );
        assert_eq!(rig.admitted(), 2, "two calls, two units");
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
        let instance = "serve-door-mcp-tap";
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
        let instance = "serve-door-mcp-gate";
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

    /// The call log's chained records on `rig`, oldest first: each record's `(seq, prev_hash,
    /// hash)` as the host chained it.
    fn call_chain(rig: &Rig) -> Vec<(u64, String, String)> {
        use busbar_contract::records::{PlaneSelector, RecordStore as _};
        let kind = surface("record_kind_call");
        let parents = rig.store.list_plane_record_parents(kind).expect("a read");
        assert_eq!(parents.len(), 1, "one chain, the caller's: {parents:?}");
        let chained = rig
            .store
            .list_plane_records(kind, &PlaneSelector::Parent(parents[0].as_str().into()))
            .expect("a read");
        let mut links: Vec<(u64, String, String)> = chained
            .iter()
            .map(|body| {
                let body: serde_json::Value =
                    serde_json::from_slice(body).expect("the journal's envelope");
                (
                    body["seq"].as_u64().expect("a sequence"),
                    body["prev_hash"].as_str().expect("a link").to_string(),
                    body["hash"].as_str().expect("a digest").to_string(),
                )
            })
            .collect();
        links.sort_by_key(|l| l.0);
        links
    }

    /// AUDIT-CHAIN: every call through the door lands in two tamper-evident chains. The plane's
    /// CALL LOG is a chained kind: each call's record is appended to the host's record chain, each
    /// one linking the digest before it. And the unit's AUDIT ROW is written on the kernel's own
    /// audit chain under the principal the kernel verified: a served call `applied`, a refused one
    /// `rejected`, each row linked to the row before it on the chain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_call_is_chained_on_the_call_log_and_the_kernels_audit_chain() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mcp-audit";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let rig = rig_tools(instance, port, registration("audited", port, ""), &|app| {
            app
        });

        for _ in 0..2 {
            let (status, answer) =
                call(&rig, &rig.token, "audited_read_file", serde_json::json!({})).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
        }
        let (status, _) = call(&rig, &rig.token, "audited_unlisted", serde_json::json!({})).await;
        assert_ne!(status, StatusCode::OK, "an unknown tool is refused");

        // THE CALL LOG: three records, one chain, each linking the one before.
        let chain = call_chain(&rig);
        assert_eq!(
            chain.len(),
            3,
            "every call, served or refused, is logged: {chain:?}"
        );
        for pair in chain.windows(2) {
            assert_eq!(pair[1].0, pair[0].0 + 1, "consecutive: {chain:?}");
            assert_eq!(
                pair[1].1, pair[0].2,
                "each record links the digest before it: {chain:?}"
            );
            assert!(!pair[1].2.is_empty() && pair[1].2 != pair[0].2, "{chain:?}");
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
        assert!(
            refused
                .iter()
                .any(|e| e.principal == rig.key.id && e.outcome == "rejected"),
            "the refused call audited rejected: {refused:?}"
        );
        let all = log.list_filtered(0, 1000, None, None);
        for row in &mine {
            assert!(!row.hash.is_empty(), "a sealed row: {row:?}");
            if let Some(before) = all.iter().find(|e| e.seq + 1 == row.seq) {
                assert_eq!(row.prev_hash, before.hash, "linked to the row before it");
            }
        }
    }
}
