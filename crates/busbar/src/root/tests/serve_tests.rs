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

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use busbar_contract::caps::ReasonCode;
use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, PLANE_LANE_SEP};
use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
use busbar_plane_decisions::plane_door::door as decisions_door;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::{composed_services, money, Published, PUBLISHING};
use super::{compose_planes, compose_planes_over, door_routes, DoorEgress};
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
const CLAIMED: &str = "/v1/systemone";

/// The provider's credential, as its file holds it.
const CREDENTIAL: &str = "sk-door-test";

/// The far end's answer: a decision, and the one unit it reports using.
const ANSWER: &str = r#"{"id":"d-1","decision":"approve","usage":{"units":1}}"#;

/// A far end's transient failure, as [`far_end_failing_first`] answers it.
const UNAVAILABLE: &str = r#"{"error":"unavailable"}"#;

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

/// A far end on loopback answering every request with [`ANSWER`]; what it was sent comes back on
/// the channel, one request head per connection.
async fn far_end() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    far_end_failing_first(0).await
}

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

/// How the far end answers one connection.
#[derive(Debug, Clone, Copy)]
enum Answer {
    /// A status line and a JSON body.
    Says(&'static str, &'static str),
    /// Nothing: the request is read and the connection held open, unanswered.
    Holds,
}

/// How the far end answers its `n`th connection (from zero).
type Script = Arc<dyn Fn(usize) -> Answer + Send + Sync>;

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
        !head.contains(token.expose_secret()),
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

/// What a served door's data router needs kept alive beside it, and what a test reads back off
/// the composition it served through.
struct Serving {
    router: axum::Router,
    token: String,
    _handle: Arc<busbar_kernel::state::AppHandle>,
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
}

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

/// The model's one member: the first (and only) entry its egress seals.
const MEMBER: busbar_contract::DestinationId = busbar_contract::DestinationId::new(0);

/// The sum of `family`'s series on `exposition` whose `lane` label is `lane`.
fn counted(exposition: &str, family: &str, lane: &str) -> f64 {
    let lane = format!("lane=\"{lane}\"");
    exposition
        .lines()
        .filter(|l| l.starts_with(&format!("{family}{{")) && l.contains(&lane))
        .filter_map(|l| l.rsplit_once(' ')?.1.parse::<f64>().ok())
        .sum()
}

/// THE DECISIONS DOOR SERVED OVER `linked`, composed as the exit test above composes it (the
/// connector over the linked transport doors, the door bound through the loader's one load, one
/// model whose provider is the far end on `port`, a keyed caller): the composition reads the door
/// plane's declared facts off `linked`.
async fn serve_over(linked: &crate::root::linked::Linked, instance: &str, port: u16) -> Serving {
    serve_limited(linked, instance, port, Vec::new()).await
}

/// [`serve_over`], its caller's key bound to a group that states `limits`.
async fn serve_limited(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
) -> Serving {
    serve_governed(linked, instance, port, limits, 0).await
}

/// [`serve_limited`], the plane stating its own per-request fee (its section's reserved
/// `fees.per_request`, #47), in minor units.
async fn serve_governed(
    linked: &crate::root::linked::Linked,
    instance: &str,
    port: u16,
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    fee: i64,
) -> Serving {
    // The scrape sink's `/metrics` is mounted on a test app built with the recorder installed.
    busbar_kernel::snapshot::init();
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
    Serving {
        router,
        token: token.expose_secret().to_string(),
        _handle: handle,
        egress,
        plane,
        book: Arc::clone(&book.durability),
        gov,
        key: key.id.to_string(),
        app,
    }
}

/// The decisions door's `declares` section stating the breaker fact false (ARCHITECT Q4).
const STATES_NO_BENCH: &str = r#"{"breaker":{"bench_below_trip_threshold":false}}"#;

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

/// The decisions door's Statement name: the name the root finds its declared facts by.
fn decisions_name() -> String {
    let row = LinkedRow::of(decisions_door).expect("the door states its Statement");
    busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads")
        .name
}

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

// ── the core capabilities on the decisions plane (qa/capability-equality.json) ─────────────────
//
// The decisions plane is served only through its door on the kernel's plane driver, so each cell
// below is the plane's proof and the `root-decisions` leg's at once: every unit is a keyed
// caller's request on the data router, crossing the composition production seals.

/// How many failing calls a breaker cell is given to open before the run calls it stuck.
const MAX_FAILURES: usize = 8;

/// A caller fault, as the far end words it.
const CALLER_FAULT: &str = r#"{"error":"the state names no amount"}"#;

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
            busbar_plane_decisions::driven::tail::OP_CLASSES[0].as_str(),
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

/// GOVERNANCE-BUDGET: a decisions unit's spend (the plane's own per-request fee, its section's
/// `fees.per_request`) is charged to the presenting key, and the key's group BUDGET refuses the unit
/// past it before its dial, 429, naming in `Retry-After` the seconds until the budget's window rolls,
/// as the llm plane names them (1.5.5's governance refusal). A window that never rolls (`per:
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
    )
    .await;
    assert_eq!(call_through(&serving, &mut heard).await.0, StatusCode::OK);
    let (status, wait, reached) = call_through(&serving, &mut heard).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!reached);
    assert_eq!(wait, None, "a total never rolls: no wait is named");
}
