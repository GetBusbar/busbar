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

/// THE DECISIONS PLANE'S DOOR CELLS, compiled where that plane is linked.
#[cfg(feature = "plane-decisions")]
mod decisions_door {
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

    use super::super::planes_tests::{composed_services, money, Published, PUBLISHING};
    use super::super::{compose_planes, compose_planes_over, door_routes, DoorEgress};
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
    async fn send(
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
        let key_file =
            std::env::temp_dir().join(format!("busbar-serve-door-{}", std::process::id()));
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
        let (bare, _admin, _handle) = busbar_kernel::build_split_routers_serving(
            Arc::clone(&app),
            Vec::new(),
            1 << 20,
            0,
            false,
        );
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
            door_routes(super::super::Served::default(), || CARD.pin(), &[], &[])
                .expect("nothing to mount")
                .is_empty(),
            "a composition that claims nothing mounts nothing"
        );
    }

    /// What a served door's data router needs kept alive beside it.
    struct Serving {
        router: axum::Router,
        token: String,
        _handle: Arc<busbar_kernel::state::AppHandle>,
    }

    /// THE DECISIONS DOOR SERVED OVER `linked`, composed as the exit test above composes it (the
    /// connector over the linked transport doors, the door bound through the loader's one load, one
    /// model whose provider is the far end on `port`, a keyed caller): the composition reads the door
    /// plane's declared facts off `linked`.
    async fn serve_over(
        linked: &crate::root::linked::Linked,
        instance: &str,
        port: u16,
    ) -> Serving {
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
}

/// THE AGENT PLANE'S ROOT LEG, through its door: the agent plane's
/// root cells are units driven on the root's door path: the door linked and bound
/// through the loader's one load, opened with its `agents:` section and the deployment's public
/// base URL, its claims mounted on the data router at its construction, a keyed caller's request
/// admitted and charged by the door steps and answered by the door.
#[cfg(linked_plane_sections)]
mod agent_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::abi::mechanism::door::DoorFn;
    use busbar_contract::conn::DeclaredConns;
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

    use super::super::planes_tests::{Published, PUBLISHING};
    use super::super::{compose_planes, door_routes};
    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{load_linked, Bind, LinkedRow, NoSink};
    use crate::root::plane_node::{Node, NodeEndPost};

    /// The deployment's dated card history, billing off (one entry, no price).
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

    /// The governance book's admin token.
    const ADMIN_TOKEN: &str = "admintok";

    /// The plane's wire words its Statement does not carry, as DATA
    /// (`tests/fixtures/agent_door_wire.txt`): one `key = value` per line, `#` a comment.
    fn surface(key: &str) -> &'static str {
        include_str!("fixtures/agent_door_wire.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("fixtures/agent_door_wire.txt has no `{key}` row"))
    }

    /// The mount the door's claims sit under.
    fn mount() -> &'static str {
        surface("mount")
    }

    /// THE AGENT DOOR: of the linked plane doors, the one whose Statement DECLARES the section the
    /// fixture names (found by binding each, once). This module compiles only where a linked row
    /// drives the plane-sections seam, and the build that does links the door: `None` is a defect,
    /// never a skip (every cell that drives the door fails through [`door`]).
    fn linked_door() -> Option<DoorFn> {
        static DOOR: std::sync::OnceLock<Option<DoorFn>> = std::sync::OnceLock::new();
        *DOOR.get_or_init(|| {
            let section = surface("section");
            let dispatcher = Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            ));
            crate::LINKED.plane_doors.iter().copied().find(|&door| {
                let Ok(row) = LinkedRow::of(door) else {
                    return false;
                };
                load_linked::<Plane>(
                    &row,
                    Bind {
                        instance: Arc::from("agent-door-probe"),
                        max_inflight_cap: 64,
                        sink: Arc::new(NoSink),
                        dispatcher: dispatcher.adopter(),
                        conns: crate::root::loader::dispatch::ConnTable::Probe,
                    },
                )
                .is_ok_and(|plane| plane.served().section == section)
            })
        })
    }

    /// The agent door, which a cell's `Served` needs (see [`linked_door`]).
    fn door() -> DoorFn {
        linked_door().expect("a linked plane door owns the agents section")
    }

    /// RFC 8785 for the cells' own cards (strings, small integers, objects, arrays): keys sorted,
    /// compact, as the plane canonicalizes a card it signs or pins.
    fn canonical(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let members: Vec<String> = keys
                    .into_iter()
                    .map(|k| {
                        format!(
                            "{}:{}",
                            serde_json::Value::String(k.clone()),
                            canonical(&map[k])
                        )
                    })
                    .collect();
                format!("{{{}}}", members.join(","))
            }
            serde_json::Value::Array(items) => {
                format!(
                    "[{}]",
                    items.iter().map(canonical).collect::<Vec<_>>().join(",")
                )
            }
            other => other.to_string(),
        }
    }

    /// A card's JWS payload: the canonical card with its `signatures` removed.
    fn signing_payload(card: &serde_json::Value) -> String {
        let mut stripped = card.clone();
        if let Some(obj) = stripped.as_object_mut() {
            obj.remove("signatures");
        }
        canonical(&stripped)
    }

    /// A card's pinned fingerprint: the tagged sha256 of the canonical whole card.
    fn card_fingerprint(card: &serde_json::Value) -> String {
        busbar_contract::abi::sdk::digest::sha256_tagged(canonical(card).as_bytes())
    }

    /// One a2a door served on a data router, as production composes it, and the admin router the
    /// door's stated admin routes mount on.
    struct Served {
        router: axum::Router,
        admin: axum::Router,
        gov: Arc<GovState>,
        app: Arc<busbar_kernel::state::App>,
        key: busbar_contract::records::VirtualKey,
        token: String,
        /// The handle a config apply swaps the serving generation on.
        handle: Arc<busbar_kernel::state::AppHandle>,
        /// The node's book: every unit's one line.
        book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
        /// The node's end post: the units whose facts are still open.
        post: Arc<NodeEndPost>,
        /// The paths the door's routes were mounted at on the data router, as its construction
        /// was handed them.
        routes: Vec<String>,
    }

    /// How the cell's App faces the world beside the door's routes.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Facing {
        /// The `agents:` section written; the App's plane table binds nothing for the door.
        Routes,
        /// The section written, and the App's plane table mounting the door's claims and binding
        /// the audience and metadata document its snapshot states, as boot's `build_dispatch`
        /// binds a door's facing: a token presented on the door must be bound to its audience,
        /// and a refusal there is the RFC 6750 challenge naming its metadata document.
        Admitted,
        /// No `agents:` section at all: the plane loads iff its section is present (LAW 7).
        Unconfigured,
    }

    /// The a2a door linked and bound through the loader's one load (its host services and the
    /// process's connector, whose destination guard keeps the deployment's default private-address
    /// stance and refuses loopback outright when `block_loopback`), its egress sealed by the composition itself (each registered agent a member
    /// route at its own `url`), opened with
    /// `section` as its `agents:` section and a public base URL, its claims mounted on the data
    /// router at its construction, with one keyed caller minted on a signing governance book (its
    /// grant `allowed_pools`: `None` = every scope, a list = those pools and no agent).
    fn served(
        instance: &'static str,
        section: &str,
        block_loopback: bool,
        allowed_pools: Option<Vec<String>>,
    ) -> Served {
        served_trusting(instance, section, block_loopback, allowed_pools, None)
    }

    /// [`served`], its connector also trusting `root` (a test root's DER) beside the platform
    /// roots, so a loopback TLS agent whose certificate it issued completes the chain check.
    fn served_trusting(
        instance: &'static str,
        section: &str,
        block_loopback: bool,
        allowed_pools: Option<Vec<String>>,
        root: Option<Vec<u8>>,
    ) -> Served {
        // The deployment's default stance (`advanced.block_private_addresses: true`); with
        // `block_loopback`, loopback is refused outright as well.
        served_under(
            instance,
            section,
            busbar_kernel::config::Destinations {
                block_private_addresses: true,
                blocked: if block_loopback {
                    vec!["127.0.0.1".to_string()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
            allowed_pools,
            root,
        )
    }

    /// [`served`] under the deployment's destination settings `destinations`, its connector also
    /// trusting `root` when given ([`served_trusting`]).
    fn served_under(
        instance: &'static str,
        section: &str,
        destinations: busbar_kernel::config::Destinations,
        allowed_pools: Option<Vec<String>>,
        root: Option<Vec<u8>>,
    ) -> Served {
        served_full(
            instance,
            section,
            destinations,
            allowed_pools,
            root,
            None,
            None,
            Facing::Routes,
        )
    }

    /// [`served`] with the keyed caller bound to a group that admits `requests` requests in all.
    fn served_limited(instance: &'static str, section: &str, requests: u64) -> Served {
        served_full(
            instance,
            section,
            busbar_kernel::config::Destinations {
                block_private_addresses: true,
                ..Default::default()
            },
            None,
            None,
            None,
            Some(requests),
            Facing::Routes,
        )
    }

    /// [`served`] facing the world as `facing` says, loopback admitted.
    fn served_facing(instance: &'static str, section: &str, facing: Facing) -> Served {
        served_full(
            instance,
            section,
            busbar_kernel::config::Destinations {
                block_private_addresses: true,
                ..Default::default()
            },
            None,
            None,
            None,
            None,
            facing,
        )
    }

    /// The hooks the deployment attaches to one agent (`agents.<agent>.hooks:`): the loaded hook
    /// plugin environment, the `hooks:` definitions, and the agent they attach to.
    struct AgentHooks {
        env: busbar_kernel::hooks::HookEnv,
        defs: Vec<(String, serde_json::Value)>,
        agent: &'static str,
    }

    /// [`served_under`], the deployment's `hooks:` attached to one agent when `hooks` is given, the
    /// door's hook stage bound as production binds it (gate-first, the door's tail states it), and
    /// the keyed caller bound to a group admitting `requests` requests in all when given; the App
    /// facing the world as `facing` says.
    #[allow(clippy::too_many_arguments)]
    fn served_full(
        instance: &'static str,
        section: &str,
        destinations: busbar_kernel::config::Destinations,
        allowed_pools: Option<Vec<String>>,
        root: Option<Vec<u8>>,
        hooks: Option<AgentHooks>,
        requests: Option<u64>,
        facing: Facing,
    ) -> Served {
        // The caller's group, when it is limited: `requests` requests in all.
        let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = requests
            .map(|amount| {
                let limit = busbar_kernel::config::groups::LimitCfg {
                    metric: busbar_kernel::config::groups::LimitMetric::Requests,
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
        let cost = if groups.is_empty() {
            CostModel::flat(1)
        } else {
            CostModel::resolve_parts(None, 1, &groups)
        };
        // The generation's engine host the hook stage reads per unit, set once the App is built.
        let live: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
        let judge = crate::root::connector::guard_for(&destinations).expect("the guard");
        // The door's own requests (a card fetch, a mirrored push config) are made on a dispatcher
        // worker, off any runtime: their sockets register on the process's reactor, which the boot
        // path installs (`root::connector::boot`) and this cell installs the same way.
        crate::root::connector::install_io_reactor();
        // THE GOVERNANCE BOOK over a store opened through its door, so its record slots are the
        // kernel's record store (ARCHITECT Q-L3B-RECORDS): the door's task rows are kept there.
        let axis = crate::root::loader::store_v3::DoorStoreAxis {
            dispatcher: Arc::new(crate::root::loader::dispatch::Dispatcher::new(
                crate::root::loader::dispatch::DispatchConfig::default(),
            )),
            logs: crate::root::boot::plugin_logs().clone(),
            conns: crate::root::loader::dispatch::ConnTable::NoNeeds,
            mint: busbar_kernel::door::op_id,
        };
        let opened = busbar_contract::store_calls::StoreAxis::open(
            &axis,
            busbar_contract::store_calls::StoreDoor::Linked(
                crate::LINKED
                    .stores
                    .iter()
                    .find(|s| s.1)
                    .expect("the build links an ephemeral store")
                    .2,
            ),
            instance,
            b"{}",
        )
        .expect("the default store opens through its door");
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let gov = Arc::new(
            GovState::new_with_signer(
                Arc::clone(&opened.records),
                Some(ADMIN_TOKEN.to_string()),
                Some(signer),
            )
            .expect("governance"),
        );
        assert!(gov.attach_store_calls(
            opened
                .calls
                .expect("a door-opened store has its record slots")
        ));
        let services = super::super::LateServices::new();
        // The kernel's services judge every destination by the deployment's one guard, as boot
        // composes them (`dest.judge`: the card fetch's per-hop guard reads it).
        let kernel = Arc::new(super::super::kernel_services(
            Arc::clone(&judge) as Arc<dyn busbar_kernel::host_services::DestJudge>
        ));
        services
            .install_kernel(
                Arc::clone(&kernel),
                Arc::clone(&kernel) as Arc<dyn busbar_contract::services::HostServices>,
            )
            .expect("installed once");
        // THE LATE ATTACH, as the first app build runs it: the runtime's blocking pool and the
        // governance store as the record store.
        super::super::attach(
            &services,
            Some(&gov),
            Some(Arc::clone(&gov) as Arc<dyn busbar_kernel::host_services::SignKey>),
            &Arc::new(super::super::DemotionRecord::default()),
            &[],
        );
        let dispatcher = Arc::new(crate::root::dispatch::build(
            1,
            Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
        ));
        // Its connection reads through a ticket (a trust verb's card fetch) wake on the dispatcher.
        let settings = busbar_contract::transport::TransportSettings::default();
        let connector = match root {
            None => busbar_core_connector::process::build(
                || crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings),
                judge,
                &[],
                dispatcher.conn_waker(),
                crate::root::connector::pool_posture(&settings),
            )
            .expect("the connector builds"),
            Some(root) => {
                let tls = busbar_core_connector::tls::client::build_client_config(
                    &busbar_contract::transport::trust::EgressTrust {
                        extra_anchors: vec![root],
                        ..Default::default()
                    },
                )
                .expect("the client config");
                let view = busbar_core_connector::registry::Transports::new(
                    crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
                        .expect("the entries"),
                )
                .expect("the view");
                Arc::new(busbar_core_connector::Connector::serving(
                    view,
                    busbar_core_connector::process::judge(judge, &[]),
                    Some(Arc::new(tls)),
                    dispatcher.conn_waker(),
                ))
            }
        };
        let row = LinkedRow::of(door()).expect("the door states its Statement");
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

        let (key, token) = gov
            .mint_signed(
                NewKeySpec {
                    name: "delegator".to_string(),
                    allowed_pools,
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
        let end = Arc::clone(&post);
        let site = Arc::clone(&post);
        let book_money = Arc::clone(&gov);
        let plane_money = move || {
            Arc::new(PlaneMoney::new(
                Arc::clone(&book_money),
                Arc::clone(&site) as Arc<dyn EndPost>,
            ))
        };
        let mut sections = BTreeMap::new();
        if facing != Facing::Unconfigured {
            sections.insert(
                section_key,
                serde_yaml::from_str(section).expect("a section"),
            );
        }
        // THE EGRESS, AS PRODUCTION SEALS IT: no provider (an agent is reached at its own `url`),
        // the process's connector, the node's journal.
        let providers = std::collections::BTreeMap::new();
        let secrets: Arc<dyn busbar_contract::secret::SecretResolve> =
            Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
        let auths = crate::root::door_steps::OutboundAuths::new(
            Arc::clone(&dispatcher),
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::Host(
                Arc::clone(&connector) as Arc<dyn DeclaredConns>
            ),
        );
        let reach = crate::root::door_steps::DoorReach {
            providers: &providers,
            secrets: Arc::clone(&secrets),
            auths: Arc::new(auths),
            conns: Arc::clone(&connector) as Arc<dyn busbar_contract::conn::PollConns>,
            stream_ceiling_secs: 600,
            upgrades: Vec::new(),
        };
        let mut composed = compose_planes(
            &[(instance.to_string(), plane)],
            &dispatcher,
            &services,
            &sections,
            Some("https://gw.example"),
            &plane_money,
            Some(&super::super::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            }),
            hooks
                .as_ref()
                .map(|_| super::super::HookStage {
                    host: {
                        let live = Arc::clone(&live);
                        Arc::new(move || {
                            busbar_kernel::plane_host::engine_host(
                                live.get().expect("the App is built before a unit runs"),
                            )
                        })
                    },
                    gov: Arc::clone(&gov),
                })
                .as_ref(),
        )
        .expect("the agent door composes");
        composed.post = Some(post);
        // THE DOOR'S FACING, as boot's `build_dispatch` reads it off the door: each claim mounted
        // at its literal prefix, and the audience and metadata document its snapshot states.
        let facing_of: Vec<(Vec<String>, busbar_kernel::plane::PlaneAdmission)> =
            if facing == Facing::Admitted {
                composed
                    .planes
                    .iter()
                    .filter_map(|p| {
                        let admission = busbar_kernel::plane::PlaneAdmission {
                            audience: p.snapshot.audience.clone()?,
                            resource_metadata: p.snapshot.resource_metadata.clone()?,
                        };
                        let paths = p
                            .snapshot
                            .claims
                            .iter()
                            .map(|c| {
                                let literal = c.target.split("/{").next().unwrap_or(&c.target);
                                literal.trim_end_matches('/').to_string()
                            })
                            .filter(|path| !path.is_empty())
                            .collect();
                        Some((paths, admission))
                    })
                    .collect()
            } else {
                Vec::new()
            };
        // THE ADMIN SURFACE, as boot mounts it: the admin mount, and the operator credential's row
        // on the auth axis the admin chain authenticates `x-admin-token` with.
        busbar_core_admin::install();
        // THE DOOR'S REGISTRY ROW, folded from its Statement and installed as the composition root
        // installs it (DECL-FOLD): the admin router mounts the door's stated admin routes off it.
        let folded = {
            use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
            busbar_kernel::plane::door::fold(
                registration(linked_probe(door(), "serve-agent-row")).expect("the door binds"),
            )
            .expect("the door folds")
        };
        busbar_kernel::plane::registry::register_test_plane(folded);
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::preflight::install_auth_axis(crate::root::dispatch::auth_axis);
        let mut builder = busbar_kernel::test_support::TestApp::new()
            .keys_chain()
            .admin_chain(vec![busbar_kernel::config::operator_provider().to_string()])
            .governance(Arc::clone(&gov));
        for (name, cfg) in &groups {
            builder = builder.group(name, cfg.clone());
        }
        builder = builder.cost(cost);
        if let Some(hooks) = hooks {
            let names: Vec<String> = hooks.defs.iter().map(|(n, _)| n.clone()).collect();
            builder = builder.hook_env(hooks.env);
            for (name, def) in hooks.defs {
                builder = builder.hook(
                    &name,
                    serde_json::from_value(def).expect("a hooks: definition"),
                );
            }
            builder.set_container_hooks(
                surface("plane_key"),
                vec![(hooks.agent.to_string(), names)],
                Vec::new(),
            );
        }
        for (paths, admission) in facing_of {
            for path in &paths {
                builder.mount_plane(
                    surface("plane_key"),
                    path,
                    busbar_kernel::plane::WIRE_JSONRPC,
                );
            }
            builder.admit_plane(surface("plane_key"), admission);
        }
        let app = builder.build();
        let _ = live.set(Arc::clone(&app));
        let appliers = composed.appliers();
        let doors = door_routes(composed, || CARD.pin(), &[], &[]).expect("its claims mount");
        let routes = doors.iter().map(|r| r.path.clone()).collect();
        let (router, admin, handle) =
            busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);
        // Every config apply refreshes the door, as production binds it.
        handle.on_apply(Box::new(move |app| appliers.apply(app)));
        Served {
            router,
            admin,
            gov,
            app,
            key,
            token: token.expose_secret().to_string(),
            handle,
            book: Arc::clone(&book.durability),
            post: end,
            routes,
        }
    }

    /// A JSON-RPC `method` POSTed to the agent `agent`'s claim (`""` = the plane's own unaddressed
    /// endpoint, `/a2a`), bearing `token` or none.
    fn rpc(
        agent: &str,
        method: &str,
        params: &str,
        token: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let path = if agent.is_empty() {
            mount().to_string()
        } else {
            format!("{}/agents/{agent}", mount())
        };
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        req.body(axum::body::Body::from(format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#
        )))
        .expect("a request")
    }

    /// The response's status and body text.
    async fn answered(
        router: &axum::Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> (StatusCode, String) {
        use tower::ServiceExt as _;
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The root cell `governance-budget × a2a-server`: a keyed caller's unit addressed to one
    /// approved agent (the task list, which the door answers from host records with no far end,
    /// routed over the addressed agent's entry) is SERVED through the door, 200, and the governance
    /// ledger holds its one admitted request on the presenting key; an unkeyed caller on the same
    /// claim is refused before the door and charges nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_served_through_its_door_charges_the_presenting_key() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, _) = answered(&s.router, rpc("planner", "tasks/list", "{}", None)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an unkeyed caller is refused at the door's claim"
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served through the door: {body}");
        let usage = s
            .gov
            .usage_for(&s.app.cost, &s.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists");
        assert_eq!(
            usage.requests, 1,
            "one admitted request, on the presenting key"
        );
    }

    /// The far agent's healthy answer: one JSON-RPC message result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"message","messageId":"m-far","role":"agent","parts":[{"kind":"text","text":"done"}]}}"#;

    /// A far agent on loopback answering every request with one JSON-RPC message result; each
    /// request it was sent comes back on the channel, whole.
    async fn far_agent() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end(200, ANSWER).await
    }

    /// A far end on loopback answering every request `status` with `answer`; each request it was
    /// sent comes back on the channel, whole.
    async fn far_end(
        status: u16,
        answer: &'static str,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end_answering(Arc::new(move |_| {
            Some(FarReply::of(status, answer.to_string()))
        }))
        .await
    }

    /// What a far end answers one request: its status, its extra head fields, its body, and how
    /// long it takes to answer.
    struct FarReply {
        status: u16,
        fields: Vec<(&'static str, String)>,
        body: String,
        delay_ms: u64,
    }

    impl FarReply {
        fn of(status: u16, body: String) -> Self {
            Self {
                status,
                fields: Vec::new(),
                body,
                delay_ms: 0,
            }
        }
    }

    /// What a far end answers one request (the request whole), or `None` to close the connection
    /// unanswered (an agent that is down).
    type Answering = Arc<dyn Fn(&str) -> Option<FarReply> + Send + Sync>;

    /// The path an agent serves its card at, on its origin.
    const CARD_PATH: &str = "GET /.well-known/agent-card.json ";

    /// A far end on loopback answering each request as `answering` says; each request it was sent,
    /// but a `GET` (a fetch of its card), comes back on the channel, whole.
    async fn far_end_answering(
        answering: Answering,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        far_end_over(answering, None).await
    }

    /// One accepted far-end connection, in the clear or under TLS.
    trait FarSocket: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> FarSocket for T {}

    /// [`far_end_answering`], each connection secured by `tls` when given (a handshake that fails
    /// is dropped unanswered).
    async fn far_end_over(
        answering: Answering,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((plain, _)) = listener.accept().await {
                let sent = sent.clone();
                let answering = Arc::clone(&answering);
                let tls = tls.clone();
                tokio::spawn(async move {
                    let mut socket: Box<dyn FarSocket> = match tls {
                        None => Box::new(plain),
                        Some(tls) => match tls.accept(plain).await {
                            Ok(secured) => Box::new(secured),
                            Err(_) => return,
                        },
                    };
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
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
                    let text = String::from_utf8_lossy(&got).to_string();
                    let answered = answering(&text);
                    if !text.starts_with("GET ") {
                        let _ = sent.send(text);
                    }
                    let Some(FarReply {
                        status,
                        fields,
                        body: answer,
                        delay_ms,
                    }) = answered
                    else {
                        return;
                    };
                    if delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                    let extra: String = fields
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}\r\n"))
                        .collect();
                    // JSON, unless the reply's own fields name its media type.
                    let typed = fields
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
                    let json = if typed {
                        ""
                    } else {
                        "content-type: application/json\r\n"
                    };
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\n{json}{extra}content-length: {}\r\n\
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

    /// The agents section registering `planner` (and, given, `scout`) at loopback `port`.
    fn agents(port: u16, scout: bool) -> String {
        let mut section = format!(
            "planner: {{url: 'http://127.0.0.1:{port}/planner', pin: {{mechanism: unpinned}}}}"
        );
        if scout {
            section.push_str(&format!(
                "\nscout: {{url: 'http://127.0.0.1:{port}/scout', pin: {{mechanism: unpinned}}}}"
            ));
        }
        section
    }

    /// The presenting key's admitted requests on the governance ledger.
    fn admitted(s: &Served) -> u64 {
        s.gov
            .usage_for(&s.app.cost, &s.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists")
            .requests
    }

    /// The `message/send` the relayed cells send.
    const SEND: &str = r#"{"message":{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"plan"}]}}"#;

    /// The root cell `net-guard × a2a-client`: an agent is reached over its member route (its own
    /// `url`) only where the deployment's destination guard admits its address: with private
    /// addresses refused, its card cannot be fetched (`connect` reports the refusal, the agent never
    /// hears it), it can never be approved, and a relayed unit to it never dials; with loopback
    /// admitted it is approved, dialled at its own path, and its answer relayed whole.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_dials_only_the_address_the_guard_admits() {
        let _one = PUBLISHING.lock().await;
        let mut agent = Agent::start(200, ANSWER).await;
        let section = agent.entry("planner", "1h");

        let blocked = "serve-agent-door-guarded";
        let published = Published(blocked);
        let s = served(blocked, &section, true, None);
        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(
            preview["state"], "error",
            "the guard refused the card fetch: {preview}"
        );
        assert_eq!(agent.fetches(), 0, "the agent never heard the card fetch");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a refused address is never served: {body}"
        );
        assert!(!agent.relayed(), "the far agent was never dialled");
        drop(published);

        let open = "serve-agent-door-open";
        let _published = Published(open);
        let s = served(open, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        assert!(
            body.contains("m-far"),
            "the far agent's answer, relayed: {body}"
        );
        let head = agent.heard.recv().await.expect("the far agent was dialled");
        assert!(head.starts_with("POST /planner "), "{head}");
    }

    /// The root cell `governance-budget × a2a-client`: a relayed unit addressed to one agent is
    /// served at that agent and its one admitted request is attributed to the presenting key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_agent_unit_charges_the_presenting_key() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-charged";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        agent.heard.recv().await.expect("the far agent was dialled");
        assert_eq!(
            admitted(&s),
            1,
            "one admitted request, on the presenting key"
        );
    }

    /// The audit rows of the kernel's one chain, oldest first.
    fn chain() -> Vec<busbar_kernel::audit_ring::AuditEntry> {
        let mut rows =
            busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(0, usize::MAX, None, None);
        rows.reverse();
        rows
    }

    /// The root cells `audit-chain × a2a`, and the teller steps AUDIT, METER and EXIT over the
    /// agent door: one relayed unit lands exactly ONE audit row on the kernel's chain (its action
    /// the plane's, applied, naming the agent it reached), sealed to the row before it; posts
    /// exactly ONE line on the node's book under that agent's lane; and ends once, every fact of it
    /// closed at its end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_agent_unit_is_audited_on_the_chain_and_posts_one_line_once() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-audited";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("auditor", "1h"), false, None);
        approve(&s, "auditor").await;
        let resource = format!("{}:auditor", surface("resource_kind"));
        let before = chain().last().map_or(0, |e| e.seq);
        let (status, body) = answered(
            &s.router,
            rpc("auditor", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        agent.heard.recv().await.expect("the far agent was dialled");
        let all = chain();
        let rows: Vec<_> = all
            .iter()
            .filter(|e| e.seq > before && e.resource == resource)
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "exactly one audit row for the unit: {rows:?}"
        );
        let row = rows[0];
        assert_eq!(row.action, surface("audit_action"), "{row:?}");
        assert_eq!(row.outcome, "applied", "a served unit is applied: {row:?}");
        assert!(!row.hash.is_empty(), "the row is sealed: {row:?}");
        if let Some(prev) = all.iter().find(|e| e.seq + 1 == row.seq) {
            assert_eq!(
                row.prev_hash, prev.hash,
                "the row is chained to the one before it"
            );
        }
        let lines = s.book.lock().expect("unpoisoned").read_back();
        let ours: Vec<_> = lines
            .iter()
            .filter(|l| {
                l.counts
                    .as_ref()
                    .is_some_and(|c| c.lane.ends_with(resource.as_str()))
            })
            .collect();
        assert_eq!(ours.len(), 1, "one line on the node's book: {lines:?}");
        assert_eq!(s.post.open_units(), 0, "the unit's facts closed at its end");
        assert_eq!(admitted(&s), 1, "one admitted request");
    }

    /// The teller step ADMIT over the agent door: a caller whose group admits one request is
    /// relayed once, and its second unit is refused `429` at admission, before the agent is dialled,
    /// charging nothing more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_past_its_callers_request_limit_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-limited";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served_limited(instance, &agent.entry("rationed", "1h"), 1);
        approve(&s, "rationed").await;
        let (status, body) = answered(
            &s.router,
            rpc("rationed", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the first unit is admitted: {body}");
        assert!(agent.relayed(), "the first unit dialled");
        let (status, body) = answered(
            &s.router,
            rpc("rationed", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "the second unit is refused at admission: {body}"
        );
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
        assert!(doc["error"]["code"].is_i64(), "{body}");
        assert!(!agent.relayed(), "the refused unit never dialled");
        assert_eq!(admitted(&s), 1, "the refusal charged nothing");
    }

    /// The teller step DECODE over the agent door: a body that is not JSON is refused with the
    /// parse error's own `-32700` at the door's arrival, and nothing is relayed or charged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_whose_body_is_not_json_is_refused_at_its_arrival() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-undecoded";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("parser", "1h"), false, None);
        approve(&s, "parser").await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("{}/agents/parser", mount()))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", s.token))
            .body(axum::body::Body::from("{ this is not json"))
            .expect("a request");
        let (status, body) = answered(&s.router, req).await;
        assert!(status.is_client_error(), "{status} {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
        assert_eq!(doc["error"]["code"], -32700, "{body}");
        assert!(!agent.relayed(), "nothing was relayed");
        assert_eq!(admitted(&s), 0, "nothing was charged");
    }

    /// A NOTIFICATION over the agent door (a JSON-RPC message with no `id`): acknowledged `202`
    /// with no body at all, and never relayed, as the served engine answered it
    /// (`jsonrpc::accepted`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_notification_is_acknowledged_202_with_no_body_and_dials_nothing() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-notified";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("notified", "1h"), false, None);
        approve(&s, "notified").await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("{}/agents/notified", mount()))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", s.token))
            .body(axum::body::Body::from(format!(
                r#"{{"jsonrpc":"2.0","method":"message/send","params":{SEND}}}"#
            )))
            .expect("a request");
        let (status, body) = answered(&s.router, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert!(body.is_empty(), "a notification is never answered: {body}");
        assert!(!agent.relayed(), "nothing was relayed");
    }

    /// SELECT, ONE REACHES (ARCHITECT Q-DEL-A2A-SELECT): an unaddressed unit on the plane's own
    /// endpoint is routed by the caller's scope to the one agent its grant reaches, as 1.5.5 chose
    /// it, and relayed to that agent's own path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_agent_unit_is_routed_to_the_one_agent_the_grant_reaches() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-select-one";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "routed by scope and relayed: {body}"
        );
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        let head = agent.heard.recv().await.expect("the one agent was dialled");
        assert!(head.starts_with("POST /planner "), "{head}");
    }

    /// SELECT, SEVERAL REACH: with two approved agents in the caller's grant, the unaddressed unit
    /// is refused before any dial, in 1.5.5's words (`-32602`, 400), naming the agents it reaches so
    /// it can address one; while neither is approved, none serves, and it is 1.5.5's none-refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_agent_unit_several_agents_reach_is_refused_naming_them() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-select-several";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scout", "1h")
        );
        let s = served(instance, &section, false, None);
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(
            (
                doc["error"]["code"].clone(),
                doc["error"]["message"].clone()
            ),
            (
                (-32004).into(),
                "no agent this key may reach can serve this shape of task".into()
            ),
            "neither is approved, so none serves: {body}"
        );
        approve(&s, "planner").await;
        approve(&s, "scout").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(doc["error"]["code"], -32602, "{body}");
        assert_eq!(
            doc["error"]["message"],
            format!(
                "2 agents this key may reach can serve this shape of task, so this endpoint \
                 cannot choose one for you. Address the agent directly at `{}/agents/{{id}}` — \
                 the ids are: planner, scout",
                mount()
            )
            .as_str(),
            "{body}"
        );
        assert!(!agent.relayed(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// SELECT, NONE REACHES: a caller whose grant names no agent gets, on the unaddressed endpoint,
    /// 1.5.5's answer (`-32004`, 400), the same a caller with no grant gets for a named agent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_agent_unit_no_agent_reaches_is_refused_in_its_1_5_5_words() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-select-none";
        let _published = Published(instance);
        let (port, mut heard) = far_agent().await;
        let s = served(instance, &agents(port, true), false, Some(Vec::new()));
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "no agent this key may reach can serve this shape of task",
            "{body}"
        );
        assert!(heard.try_recv().is_err(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// The root cell `catalogue × a2a-server`: a unit addressed to an agent outside the caller's
    /// grant is refused before it dials, and charges nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-ungranted";
        let _published = Published(instance);
        let (port, mut heard) = far_agent().await;
        let s = served(instance, &agents(port, false), false, Some(Vec::new()));
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "refused: {body}");
        assert!(
            body.contains("scope_denied"),
            "the kernel's refusal, in the plane's words: {body}"
        );
        assert!(heard.try_recv().is_err(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// The caller's key must be LIVE for busbar to spend its hop on the caller's behalf (predev's
    /// `creds::authorise_egress`, `KeyNotLive`): a key deleted after it was served is refused at
    /// the door's next unit, and the agent is never dialled for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_from_a_key_that_is_no_longer_live_never_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-key-gone";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the live key is served: {body}");
        assert!(agent.relayed(), "the live key's unit dialled");
        let _ = s.gov.delete_key(&s.key.id);
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            status.is_client_error(),
            "a key that is not live is refused: {status} {body}"
        );
        assert!(!agent.relayed(), "and the agent is never dialled for it");
    }

    /// The root cell `disposition × a2a-client`: a relayed unit to an approved agent that has gone
    /// down (its verification still fresh, so the hop is sent) ends inside its unit — the caller
    /// answered in the plane's own envelope, not left hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_agent_unit_to_an_agent_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-down";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
        agent.go_down();
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            status.is_server_error(),
            "a down agent is the far end's failure: {status} {body}"
        );
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the plane's envelope");
        assert_eq!(doc["jsonrpc"], "2.0", "{body}");
        assert!(doc["error"]["code"].is_i64(), "{body}");
    }

    /// The root cells `breaker-trip` and `breaker-fastfail × a2a-client`: an approved agent that
    /// keeps failing records into its member's breaker until it opens, and the next unit is refused
    /// `breaker_open` before it dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failing_agent_trips_its_breaker_and_the_next_unit_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-breaker";
        let _published = Published(instance);
        let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let mut dials = 0usize;
        let mut tripped = None;
        for call in 0..32 {
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            while agent.heard.try_recv().is_ok() {
                dials += 1;
            }
            if body.contains("breaker_open") {
                tripped = Some((call, dials));
                break;
            }
        }
        let (_, dialled) = tripped.expect("the breaker opened within 32 failing calls");
        assert!(
            dialled > 0,
            "it tripped on failures the agent answered: {dialled}"
        );
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(
            body.contains("breaker_open"),
            "a tripped agent fast-fails: {body}"
        );
        assert!(!agent.relayed(), "the fast-failed unit never dialled");
    }

    /// The node's book lines whose counts name agent `agent`'s lane, in book order.
    fn agent_counts(s: &Served, agent: &str) -> Vec<crate::root::durability::UnitCounts> {
        let resource = format!("{}:{agent}", surface("resource_kind"));
        s.book
            .lock()
            .expect("unpoisoned")
            .read_back()
            .into_iter()
            .filter_map(|l| l.counts)
            .filter(|c| c.lane.ends_with(resource.as_str()))
            .collect()
    }

    /// The count a line carries under `class`, `0` when it carries none.
    fn counted(counts: &crate::root::durability::UnitCounts, class: &str) -> u64 {
        counts.classes.get(class).copied().unwrap_or(0)
    }

    /// The root cells `billed-bytes × a2a-client` and the agent fee unit: a served hop's one line
    /// counts the request body it sent and the response body it read, both ways, under the plane's
    /// bytes class, and the plane's per-request fee unit exactly once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_hop_ledgers_the_bodies_it_moved_and_its_fee_unit_once() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-billed-bytes";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let heard = agent.heard.recv().await.expect("the far agent was dialled");
        let sent = heard.split_once("\r\n\r\n").map_or(0, |(_, b)| b.len());
        assert!(sent > 0, "the hop carried a body: {heard}");
        let lines = agent_counts(&s, "planner");
        assert_eq!(lines.len(), 1, "one line for the unit: {lines:?}");
        assert_eq!(
            counted(&lines[0], surface("bytes_class")),
            (sent + ANSWER.len()) as u64,
            "the request body sent and the response body read: {lines:?}"
        );
        // The fee unit rides the line as its billable count (`UnitCounts::fee_count`, priced as
        // the card's fee line): a fee unit is no usage class (`report_of`).
        assert_eq!(lines[0].fee_count, 1, "the fee unit, once: {lines:?}");
    }

    /// The root cells `billed-bytes` and the agent fee unit, refused before the socket: every hop
    /// that LEFT for a failing agent counts the bodies it moved (its request and the agent's
    /// refusal) and keeps its fee; once the breaker is open, a unit refused before it dials counts
    /// no bytes and keeps no fee.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_hop_refused_before_the_socket_counts_no_bytes_and_keeps_no_fee() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-refused-unbilled";
        let _published = Published(instance);
        let failing = r#"{"error":"down"}"#;
        let mut agent = Agent::start(503, failing).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let mut tripped = false;
        for _ in 0..32 {
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            if body.contains("breaker_open") {
                tripped = true;
                break;
            }
        }
        assert!(tripped, "the breaker opened within 32 failing calls");
        let left = agent_counts(&s, "planner");
        assert!(!left.is_empty(), "the hops that left were ledgered");
        let dialled: Vec<_> = left
            .iter()
            .filter(|c| counted(c, surface("bytes_class")) > 0)
            .collect();
        assert!(
            !dialled.is_empty(),
            "a hop that left counts its bodies: {left:?}"
        );
        for c in &dialled {
            assert!(
                counted(c, surface("bytes_class")) > failing.len() as u64,
                "its request and the agent's refusal: {c:?}"
            );
            assert_eq!(c.fee_count, 1, "a hop that left keeps its fee: {c:?}");
        }
        let before = left.len();
        while agent.heard.try_recv().is_ok() {}
        let (_, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert!(body.contains("breaker_open"), "fast-failed: {body}");
        let after = agent_counts(&s, "planner");
        for c in after.iter().skip(before) {
            assert_eq!(
                counted(c, surface("bytes_class")),
                0,
                "a unit refused before the socket counts no bytes: {c:?}"
            );
            assert_eq!(c.fee_count, 0, "and keeps no fee: {c:?}");
        }
        assert!(!agent.relayed(), "the fast-failed unit never dialled");
    }

    /// The agent section's fees: `per_request` is the unit the plane counts, so it validates, and
    /// `per_session` (a unit the plane never counts, so it would charge nothing) is refused naming
    /// the counted list, by the kernel's one rule over the door's declared fee units.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_sections_per_request_fee_validates_and_per_session_is_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-fees";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        // Composing the door registers its folded declaration, as boot installs it.
        let _s = served(instance, &agent.entry("planner", "1h"), false, None);
        let with_fees = |per_request: i64, per_session: i64| {
            let mut cfg = busbar_kernel::test_support::cfg_with_provider_api_key(
                busbar_kernel::config::SecretRef::none(),
            );
            cfg.plane_fees = [(
                surface("plane_key").to_string(),
                busbar_kernel_ledger::cost::PlaneFees {
                    per_request,
                    per_session,
                },
            )]
            .into_iter()
            .collect();
            busbar_kernel::config_validate::validate(&cfg)
                .err()
                .unwrap_or_default()
        };
        let refusal = format!(
            "{}.fees.{} is not counted by this plane (counted: {}); remove it",
            surface("section"),
            busbar_contract::plane::PER_SESSION,
            busbar_contract::plane::PER_REQUEST
        );
        assert!(
            with_fees(0, 40).contains(&refusal),
            "per_session is refused: {:?}",
            with_fees(0, 40)
        );
        assert!(
            !with_fees(2, 0).iter().any(|e| e.contains(".fees.")),
            "a counted fee validates: {:?}",
            with_fees(2, 0)
        );
    }

    /// RED (ARCHITECT breaker ruling, the plane's reading): an agent that answers each unit with an
    /// error the protocol defines — TaskNotFound, under a `502` — is the destination ANSWERING, the
    /// work failing and not the wire (the engine's `classify_hop`: a well-formed backend error is a
    /// success to the breaker). Six in a row, past the trip's five outcomes, never open its cell:
    /// every unit is dialled and answered in the agent's own words.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_answering_protocol_errors_never_trips_its_breaker() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-breaker-protocol-error";
        let _published = Published(instance);
        let mut agent = Agent::start(
            502,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}"#,
        )
        .await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        for call in 0..6 {
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert!(
                !body.contains("breaker_open"),
                "call {call}: a protocol error is no fault of the agent's: {body}"
            );
            assert!(agent.relayed(), "call {call} was dialled: {body}");
        }
    }

    /// What the presenting key's ledger holds, over every lane of its bucket: its admitted requests,
    /// the fee units its admissions charged and its ends kept, the bytes ledgered, and its spend.
    #[derive(Debug, Clone, Copy)]
    struct Billed {
        requests: u64,
        fees: u64,
        bytes: u64,
        spend: i64,
    }

    impl Billed {
        fn of(s: &Served) -> Self {
            let now = busbar_kernel::store::now();
            let usage = s
                .gov
                .usage_for(&s.app.cost, &s.key.id, now)
                .expect("a read")
                .expect("the key exists");
            let lanes = s.gov.bucket_model_tokens(
                &s.app.cost,
                &s.key.id,
                busbar_kernel::governance::WINDOW_TOTAL,
                now,
            );
            let sum = |class: &str| -> u64 {
                lanes
                    .iter()
                    .map(|(_, units)| units.get(class).copied().unwrap_or(0))
                    .sum()
            };
            Billed {
                requests: usage.requests,
                fees: sum(busbar_contract::plane::PER_REQUEST),
                bytes: sum(surface("bytes_class")),
                spend: usage.spend_cents,
            }
        }
    }

    /// R2 (ruled; the kernel owns metering): A HOP THE BREAKER REFUSED COUNTS ITS REQUEST AND BILLS
    /// NO FEE, NO BYTES AND NO SPEND. 1.5.5's llm rule, as its golden cells `cooldown|trip-then-serve`,
    /// `concurrency|lane-atcapacity|n4` and `queue|timeout|n2` hold it: a request refused after its
    /// admission is counted, and nothing it never consumed is billed.
    ///
    /// DIVERGES from origin/predev's `metered_verbs_tests.rs::a_hop_the_breaker_refused_bills_nothing`,
    /// which asserted the refused hop wrote NO metering row at all: here the admission's
    /// check-then-charge consumed the request (requests +1), the plane reported no fee unit for a
    /// hop that never left (the admission's fee unit is refunded), and no byte is ledgered.
    ///
    /// RED arm: the first hop DID reach the failing agent, so it keeps its fee unit and its bytes —
    /// a fix that simply stopped billing failing hops fails here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hop_the_breaker_refused_counts_its_request_and_bills_no_fee_no_bytes_no_spend() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-breaker-billed";
        let _published = Published(instance);
        let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let mut reached = false;
        for call in 0..32 {
            let before = Billed::of(&s);
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            let dialled = agent.relayed();
            let after = Billed::of(&s);
            if body.contains("breaker_open") {
                assert!(reached, "the RED arm ran first: a hop reached the agent");
                assert!(!dialled, "the refused hop never dialled: {body}");
                assert_eq!(
                    after.requests - before.requests,
                    1,
                    "the refused hop's request is counted: {before:?} -> {after:?}"
                );
                assert_eq!(
                    after.fees, before.fees,
                    "the refused hop bills no fee: {before:?} -> {after:?}"
                );
                assert_eq!(
                    after.bytes, before.bytes,
                    "the refused hop bills no bytes: {before:?} -> {after:?}"
                );
                assert_eq!(
                    after.spend, before.spend,
                    "the refused hop spends nothing: {before:?} -> {after:?}"
                );
                return;
            }
            if dialled && !reached {
                assert_eq!(
                    after.requests - before.requests,
                    1,
                    "call {call}: {before:?} -> {after:?}"
                );
                assert_eq!(
                    after.fees - before.fees,
                    1,
                    "call {call}: a hop that reached the agent keeps its fee: {before:?} -> {after:?}"
                );
                assert!(
                    after.bytes > before.bytes,
                    "call {call}: a hop that reached the agent bills its bytes: {before:?} -> {after:?}"
                );
                reached = true;
            }
        }
        panic!("the breaker opened within 32 failing calls");
    }

    /// B2 (restored, #42, #77(5)): A PRESENT AGENTS CARD SILENT ABOUT AN AGENT REFUSES THE CONFIG,
    /// at boot and on every apply, naming a paste-ready stub for exactly the agents it misses — in
    /// origin/predev's words (`billed_bytes_tests.rs::
    /// a_present_agents_card_silent_about_an_agent_refuses_the_config`). The agent set is config,
    /// so the gap is known before any hop: no hop to it is ever served and ledgered on a lane no
    /// card prices. The card is lifted off the section before the door sees it (#40), so the
    /// kernel's judge of the door's section holds the card to its registrations
    /// (`DoorSection::ledger_lanes`). A card pricing every agent boots.
    #[test]
    fn a_present_agents_card_silent_about_an_agent_refuses_the_config() {
        let folded = {
            use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
            busbar_kernel::plane::door::fold(
                registration(linked_probe(door(), "serve-agent-card-row")).expect("the door binds"),
            )
            .expect("the door folds")
        };
        let _registry = busbar_kernel::plane::registry::TestRegistryIsolation::seeded(&[
            busbar_kernel::test_support::neutral_fallback_plane(),
            folded,
        ]);
        let (section, kind) = (surface("section"), surface("resource_kind"));
        let resolved = |card: &str| {
            let text = format!(
                "store: {{module: memory}}\nproviders: {{}}\nmodels: {{}}\n{section}:\n  \
                 planner: {{ url: https://planner.example/rpc, pin: {{ mechanism: unpinned }} }}\n  \
                 payments: {{ url: https://payments.example/rpc, pin: {{ mechanism: unpinned }} }}\n  \
                 rate_card:\n{card}"
            );
            let deploy =
                busbar_kernel::config::deploy_from_yaml_str(&text).expect("the config parses");
            busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves")
        };
        let silent = resolved(&format!(
            "    {kind}:payments: {{ units: {{ bytes: 10000 }} }}\n"
        ));
        assert_eq!(
            busbar_kernel::config_validate::validate(&silent),
            Err(vec![format!(
                "{section}.rate_card is present but 1 {noun} has no rate entry (a present card is \
                 AUTHORITATIVE and COMPLETE: you either price nothing or price everything).\n\
                 Paste these under {section}.rate_card and fill in your rates:\n\n    \
                 {kind}:planner: {{ units: {{ bytes: 0 }} }}\n",
                noun = surface("subject_noun"),
            )]),
            "a card silent about `planner` refuses before any hop to it can be ledgered"
        );
        let complete = resolved(&format!(
            "    {kind}:payments: {{ units: {{ bytes: 10000 }} }}\n    \
             {kind}:planner: {{ units: {{ bytes: 0 }} }}\n"
        ));
        assert_eq!(
            busbar_kernel::config_validate::validate(&complete),
            Ok(()),
            "a card pricing every agent boots"
        );
    }

    /// The root cell `egress-auth × a2a-client`: the agent is handed only the credential the egress
    /// plans for its member — none is configured here — and never the caller's own token, which
    /// authenticated the caller to busbar and stops there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_agent_unit_never_hands_the_agent_the_callers_token() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-egress-auth";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "relayed through the door: {body}");
        let head = agent.heard.recv().await.expect("the far agent was dialled");
        assert!(
            !head.contains(&s.token),
            "the caller's token never leaves busbar: {head}"
        );
        assert!(
            !head
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("authorization:")),
            "no credential is planned for this member, so none is presented: {head}"
        );
    }

    // ── THE TRUST VERBS (ARCHITECT Q-L3B-VERBS) ──────────────────────────────────────────────────

    /// One admin request on `s`'s admin router: `POST /api/v1/admin{path}` with `body` (JSON): its
    /// status and JSON body.
    /// A GET of `path` on the admin router, under the operator credential: its status and body.
    async fn admin_get(s: &Served, path: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .body(axum::body::Body::empty())
            .expect("a request");
        let (status, text) = answered(&s.admin, req).await;
        let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, body)
    }

    /// Agent `name`'s trust key on the kernel's trust book, as `GET /trust` lists it
    /// (`<instance>/<agent>`), and its state.
    async fn trust_key(s: &Served, name: &str) -> (String, String) {
        let (status, book) = admin_get(s, "/trust").await;
        assert_eq!(status, StatusCode::OK, "{book}");
        let row = book["keys"]
            .as_array()
            .and_then(|keys| {
                keys.iter()
                    .find(|k| k["counterparty"] == name && k["item"].is_null())
            })
            .unwrap_or_else(|| panic!("the trust book lists no key for `{name}`: {book}"));
        (
            row["key"].as_str().unwrap_or_default().to_string(),
            row["state"].as_str().unwrap_or_default().to_string(),
        )
    }

    async fn admin(s: &Served, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let (status, text) = answered(&s.admin, req).await;
        let body = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (status, body)
    }

    /// The agent card `port` serves, its one skill described as `description`.
    fn card(port: u16, description: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "planner",
            "description": "plans the work it is given",
            "url": format!("http://127.0.0.1:{port}/planner"),
            "version": "1.0.0",
            "capabilities": {},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "plan", "name": "Plan", "description": description, "tags": ["plan"]}],
        })
    }

    /// `card` signed by `issuer` as an A2A card is signed: one detached EdDSA signature over the
    /// canonical card with its `signatures` member removed.
    fn signed(card: &serde_json::Value, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = signing_payload(card);
        let protected = b64.encode(br#"{"alg":"EdDSA"}"#);
        let signature = issuer.sign(format!("{protected}.{}", b64.encode(payload)).as_bytes());
        let mut signed = card.clone();
        signed["signatures"] = serde_json::json!([
            {"protected": protected, "signature": b64.encode(signature.to_bytes())}
        ]);
        signed
    }

    /// `issuer`'s public key as the operator pins it: base64 Ed25519 SubjectPublicKeyInfo.
    fn key_info(issuer: &ed25519_dalek::SigningKey) -> String {
        use base64::Engine as _;
        // The DER head of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4).
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(issuer.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// AN AGENT ON LOOPBACK PINNED BY ITS SIGNING KEY: it serves the card `card` holds (signed by
    /// `issuer` when it is asked, so the card may change under it) at its origin's well-known path,
    /// counting each fetch, and answers anything else `status` with `answer` — or nothing at all
    /// while it is `down`. Each request but a card fetch comes back on `heard`, whole.
    struct Agent {
        port: u16,
        heard: tokio::sync::mpsc::UnboundedReceiver<String>,
        card: Arc<std::sync::Mutex<serde_json::Value>>,
        issuer: ed25519_dalek::SigningKey,
        fetches: Arc<std::sync::atomic::AtomicUsize>,
        down: Arc<std::sync::atomic::AtomicBool>,
        /// `0`: the card is served at the well-known path; `1`: the well-known path redirects to
        /// `/cards/card.json`, which serves it; `2`: every `GET` redirects, forever; `3`: every
        /// `GET` redirects at the cloud-metadata address; `4`: every `GET` redirects at a
        /// cloud-metadata NAME; `5`: the well-known path redirects to `/cards/one`, which redirects
        /// to `/cards/card.json`, which serves the card.
        redirect: Arc<std::sync::atomic::AtomicU8>,
        /// How long the next card fetch takes to answer (the ones after it answer at once).
        card_delay_ms: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Agent {
        /// An agent answering every relayed request `status` with `answer`, its card describing
        /// its one skill as "plans the work".
        async fn start(status: u16, answer: &'static str) -> Self {
            Self::start_over(status, answer, None).await
        }

        /// [`Agent::start`], its connections secured by `tls` when given.
        async fn start_over(
            status: u16,
            answer: &'static str,
            tls: Option<tokio_rustls::TlsAcceptor>,
        ) -> Self {
            Self::start_with(status, answer, Vec::new(), tls).await
        }

        /// [`Agent::start_over`], each relayed request answered with the head fields `fields`
        /// beside its status and body.
        async fn start_with(
            status: u16,
            answer: &'static str,
            fields: Vec<(&'static str, String)>,
            tls: Option<tokio_rustls::TlsAcceptor>,
        ) -> Self {
            Self::start_core(
                status,
                Arc::new(move |_: &str| answer.to_string()),
                fields,
                tls,
            )
            .await
        }

        /// An agent answering each relayed request `status` with what `answer_of` makes of the
        /// request (its whole text), its card describing its one skill as "plans the work".
        async fn start_answering(
            status: u16,
            answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
        ) -> Self {
            Self::start_answering_over(status, answer_of, None).await
        }

        /// [`Agent::start_answering`], its connections secured by `tls` when given.
        async fn start_answering_over(
            status: u16,
            answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
            tls: Option<tokio_rustls::TlsAcceptor>,
        ) -> Self {
            Self::start_core(status, answer_of, Vec::new(), tls).await
        }

        /// The agent every constructor starts: each relayed request answered `status` with what
        /// `answer_of` makes of it and the head fields `fields`, its connections secured by `tls`.
        async fn start_core(
            status: u16,
            answer_of: Arc<dyn Fn(&str) -> String + Send + Sync>,
            fields: Vec<(&'static str, String)>,
            tls: Option<tokio_rustls::TlsAcceptor>,
        ) -> Self {
            use std::sync::atomic::Ordering;
            let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let card = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
            let fetches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let redirect = Arc::new(std::sync::atomic::AtomicU8::new(0));
            let card_delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (served, signer, counted, off, moved, slow) = (
                Arc::clone(&card),
                issuer.clone(),
                Arc::clone(&fetches),
                Arc::clone(&down),
                Arc::clone(&redirect),
                Arc::clone(&card_delay_ms),
            );
            let (port, heard) = far_end_over(
                Arc::new(move |request: &str| {
                    if off.load(Ordering::SeqCst) {
                        return None;
                    }
                    if request.starts_with("GET ") {
                        let to = |location: &str| FarReply {
                            status: 302,
                            fields: vec![("location", location.to_string())],
                            body: String::new(),
                            delay_ms: 0,
                        };
                        match moved.load(Ordering::SeqCst) {
                            2 => return Some(to("/loop")),
                            3 => return Some(to(
                                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                            )),
                            4 => {
                                return Some(to(
                                    "http://metadata.google.internal/computeMetadata/v1/",
                                ))
                            }
                            1 if request.starts_with(CARD_PATH) => {
                                return Some(to("/cards/card.json"))
                            }
                            5 if request.starts_with(CARD_PATH) => return Some(to("/cards/one")),
                            5 if request.starts_with("GET /cards/one ") => {
                                return Some(to("/cards/card.json"))
                            }
                            _ => {}
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        let card = served.lock().map(|c| c.clone()).unwrap_or_default();
                        return Some(FarReply {
                            delay_ms: slow.swap(0, Ordering::SeqCst),
                            ..FarReply::of(200, signed(&card, &signer).to_string())
                        });
                    }
                    Some(FarReply {
                        fields: fields.clone(),
                        ..FarReply::of(status, answer_of(request))
                    })
                }),
                tls,
            )
            .await;
            *card.lock().expect("the card") = self::card(port, "plans the work");
            Self {
                port,
                heard,
                card,
                issuer,
                fetches,
                down,
                redirect,
                card_delay_ms,
            }
        }

        /// The card it serves now, as the operator's `connect` reads it: its fingerprint.
        fn fingerprint(&self) -> String {
            let card = self.card.lock().expect("the card").clone();
            card_fingerprint(&signed(&card, &self.issuer))
        }

        /// Its card re-issued under the same key with its one skill described as `description`.
        fn reissue(&self, description: &str) {
            *self.card.lock().expect("the card") = card(self.port, description);
        }

        /// How many times its card was fetched.
        fn fetches(&self) -> usize {
            self.fetches.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// It stops answering.
        fn go_down(&self) {
            self.down.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        /// Whether it was sent a relayed request since it was last asked.
        fn relayed(&mut self) -> bool {
            let mut relayed = false;
            while self.heard.try_recv().is_ok() {
                relayed = true;
            }
            relayed
        }

        /// The `agents:` entry registering `name` at this agent's path `/<name>`, pinned by its
        /// signing key, re-verified within `reverify_ttl`.
        fn entry(&self, name: &str, reverify_ttl: &str) -> String {
            self.entry_with(name, reverify_ttl, "")
        }

        /// [`Agent::entry`] with `more` (`key: value` pairs, comma-separated) added to it.
        fn entry_with(&self, name: &str, reverify_ttl: &str, more: &str) -> String {
            let more = if more.is_empty() {
                String::new()
            } else {
                format!(", {more}")
            };
            format!(
                "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
                 '{reverify_ttl}', pin: {{mechanism: jws_issuer_key, key: '{}'}}{more}}}",
                self.port,
                key_info(&self.issuer)
            )
        }

        /// Its card from now on declares that it answers in events (`capabilities.streaming`).
        fn streams(&self) {
            let mut card = self.card.lock().expect("the card");
            card["capabilities"] = serde_json::json!({ "streaming": true });
        }
    }

    impl Agent {
        /// The `agents:` entry registering `name` at this agent's SECURE path `/<name>`, pinned at
        /// the transport by `mechanism` to the far end's key `key`, re-verified within an hour.
        fn entry_pinned(&self, name: &str, mechanism: &str, key: &str) -> String {
            format!(
                "{name}: {{url: 'https://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
                 '1h', pin: {{mechanism: {mechanism}, key: '{key}'}}}}",
                self.port
            )
        }
    }

    /// The server key a TLS agent presents, swappable under it.
    type ServingKey = Arc<std::sync::Mutex<Arc<rustls::sign::CertifiedKey>>>;

    /// A TLS agent's server certificate resolver: whatever key it is serving now.
    #[derive(Debug)]
    struct Serving(ServingKey);

    impl rustls::server::ResolvesServerCert for Serving {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0.lock().expect("the key")))
        }
    }

    /// A TEST ROOT FOR LOOPBACK TLS AGENTS: the root's DER (the connector is told to trust it), the
    /// issuer of each leaf, and the key the agent serves now.
    struct AgentTls {
        root: Vec<u8>,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        serving: ServingKey,
    }

    impl AgentTls {
        fn new() -> Self {
            busbar_core_connector::tls::install_crypto_provider();
            let kp = rcgen::KeyPair::generate().expect("a key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let root = params.self_signed(&kp).expect("the root").der().to_vec();
            let issuer = rcgen::Issuer::new(params, kp);
            let (first, _) = Self::issue(&issuer);
            Self {
                root,
                issuer,
                serving: Arc::new(std::sync::Mutex::new(first)),
            }
        }

        /// A fresh leaf for `127.0.0.1` under the root: the key it is served with, and its key's
        /// pin, taken off the key pair itself.
        fn issue(
            issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
        ) -> (Arc<rustls::sign::CertifiedKey>, String) {
            use rcgen::PublicKeyData as _;
            let kp = rcgen::KeyPair::generate().expect("a key");
            let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
            params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::LOCALHOST,
            ))];
            let leaf = params.signed_by(&kp, issuer).expect("the leaf");
            let key = rustls::sign::CertifiedKey::from_der(
                vec![leaf.der().clone()],
                rustls_pki_types::PrivateKeyDer::try_from(kp.serialize_der()).expect("a key"),
                &rustls::crypto::ring::default_provider(),
            )
            .expect("a certified key");
            (
                Arc::new(key),
                busbar_contract::transport::trust::key_pin(&kp.subject_public_key_info()),
            )
        }

        /// A new key under the root, served from now on: its pin.
        fn rekey(&self) -> String {
            let (key, pin) = Self::issue(&self.issuer);
            *self.serving.lock().expect("the key") = key;
            pin
        }

        /// The acceptor serving whatever key is current, and REQUIRING a client certificate that
        /// chains to `client_root` (a DER root): a mutual-TLS peer that admits one client CA only.
        fn mutual_acceptor(&self, client_root: &[u8]) -> tokio_rustls::TlsAcceptor {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls_pki_types::CertificateDer::from(client_root.to_vec()))
                .expect("a client root");
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .expect("a client verifier");
            let config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::new(Serving(Arc::clone(&self.serving))));
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        }

        /// The acceptor serving whatever key is current.
        fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Serving(Arc::clone(&self.serving))));
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        }
    }

    /// THE TRANSPORT PIN THROUGH THE DOOR (ARCHITECT 2026-10-03, L3B round-4 TRANSPORT PIN:
    /// "the connector enforces pins itself"): an agent served over TLS on loopback and registered
    /// `pin: {mechanism: cert_spki, key: <its key's pin>}` has that pin sealed into its member
    /// route, and the connector holds every connection to it to the key.
    ///
    /// * `connect` fetches its card over the agent's own need; the connector observed the far end's
    ///   key, it is the pinned one, so the card is observed: `pending`, `cert_spki`, the card's
    ///   fingerprint to approve, no failure;
    /// * `approve` locks it, and a relayed unit is served, dialled at the agent;
    /// * the agent's key changes (the same root, the same name): the next relayed unit is refused by
    ///   the connector before a request byte reaches the agent, and `connect` reports the mismatch
    ///   in the served engine's words, naming the key it served and the key pinned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cert_spki_agent_is_observed_approved_served_and_refused_once_its_key_changes() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-spki";
        let _published = Published(instance);
        let tls = AgentTls::new();
        let pin = tls.rekey();
        let mut agent = Agent::start_over(200, ANSWER, Some(tls.acceptor())).await;
        let section = agent.entry_pinned("planner", "cert_spki", &pin);
        let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "pending", "{preview}");
        assert_eq!(preview["pin_mechanism"], "cert_spki", "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(
            preview["fingerprint"],
            agent.fingerprint().as_str(),
            "{preview}"
        );
        approve(&s, "planner").await;
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "the pinned agent is served: {body}");
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        assert!(agent.relayed(), "the pinned agent was dialled");

        let served_now = tls.rekey();
        let (status, body) = answered(&s.router, send()).await;
        assert_ne!(status, StatusCode::OK, "another key is refused: {body}");
        assert!(
            !agent.relayed(),
            "no request byte reached the agent serving another key"
        );
        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "error", "{preview}");
        assert_eq!(
            preview["failure"],
            format!(
                "`pin.mechanism: cert_spki`: the card endpoint served a certificate whose \
                 subject-public-key-info is `{served_now}`, and the operator pinned `{pin}`. The \
                 endpoint answered and it is not the endpoint the operator supplied a root for."
            )
            .as_str(),
            "{preview}"
        );
    }

    /// THE OPERATOR'S CEREMONY for agent `name` (ARCHITECT Q-L3B-VERBS, over the kernel's trust
    /// book, FLIP-A2A): `connect` to see its card (the look sights its fingerprint on the book),
    /// `approve` the fingerprint seen (the book approves the agent's key). It then serves.
    async fn approve(s: &Served, name: &str) {
        let (status, preview) = admin(s, &format!("/agents/{name}/connect"), "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let fingerprint = preview["fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("connect reported no fingerprint: {preview}"))
            .to_string();
        let (status, approved) = admin(
            s,
            &format!("/agents/{name}/approve"),
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["state"], "approved", "{approved}");
    }

    /// Decide agent `name`'s trust key on the generic `/trust` (`approve` or `revoke`), at what it
    /// was last sighted at.
    async fn decide_key(s: &Served, name: &str, decision: &str) -> (StatusCode, serde_json::Value) {
        let (key, _) = trust_key(s, name).await;
        let body = serde_json::json!({ "key": key }).to_string();
        admin(s, &format!("/trust/{decision}"), &body).await
    }

    /// The root cells `trust-pinning × a2a-client` and `trust-pinning × a2a-server`, on the KERNEL'S
    /// trust book (ARCHITECT FLIP-A2A: the plane sights, the kernel pins, quarantines and keeps the
    /// operator's decision; the door's own `approve` verb and the generic `/trust` both decide it):
    ///
    /// * an agent registered with an out-of-band issuer key and nothing approved is refused
    ///   (`403`, `-32004`, "fronted agent `planner` is not serving (Pending)") and never dialled;
    /// * `connect` fetches the card at the agent origin's well-known path, has the kernel verify
    ///   its signature against the pinned key and SIGHTS its fingerprint: a `pending` preview, the
    ///   fingerprint a human is asked to approve; `/trust` lists the key `new`; still refused;
    /// * the door's `approve` naming that fingerprint approves the key: `approved`, and it serves;
    /// * `/trust/revoke` refuses it again (`403`); `/trust/approve` serves it again;
    /// * the card is re-issued under the right key with a skill the operator never read (the
    ///   rug-pull): the next relay re-verifies on call (`reverify_ttl: 0s`), the kernel quarantines
    ///   the moved card, and the hop's gate refuses (`503`, "this agent is not currently serving",
    ///   naming its task) without dialling; restoring the approved card does not lift it ("... is
    ///   not serving (Quarantined)"); `connect` reports `quarantined`; an `approve` of the old
    ///   fingerprint is refused (`400`), one of the fingerprint it now serves serves it;
    /// * an `unpinned` registration is captured by `connect` with no fingerprint: the door's
    ///   `approve` refuses it (`400`, no authenticity root), `/trust/approve` finds nothing sighted
    ///   (`409`), and it is never served; an unregistered name is `404`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_kernel_trust_book_pins_an_agent_card_and_the_relay_serves_only_the_approved_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-trust";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let fingerprint = agent.fingerprint();
        let scout = "allow_private: true, pin: {mechanism: unpinned}";
        let section = format!(
            "{}\nscout: {{url: 'http://127.0.0.1:{}/scout', {scout}}}",
            agent.entry("planner", "0s"),
            agent.port
        );
        let s = served(instance, &section, false, None);
        let send = |to: &str| rpc(to, "message/send", SEND, Some(&s.token));
        let untrusted = |status: StatusCode, body: &str, agent: &str, state: &str| {
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            let doc: serde_json::Value = serde_json::from_str(body).expect("an envelope");
            assert_eq!(doc["error"]["code"], -32004, "{body}");
            assert_eq!(
                doc["error"]["message"],
                format!("fronted agent `{agent}` is not serving ({state})"),
                "{body}"
            );
        };

        let (status, body) = answered(&s.router, send("planner")).await;
        untrusted(status, &body, "planner", "Pending");
        assert!(!agent.relayed(), "a refused unit is never dialled");

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(
            preview["state"], "pending",
            "a preview grants nothing: {preview}"
        );
        assert_eq!(preview["pin_mechanism"], "jws_issuer_key", "{preview}");
        assert_eq!(preview["fingerprint"], fingerprint.as_str(), "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(
            agent.fetches(),
            1,
            "the card was fetched at the well-known path"
        );
        let (_, state) = trust_key(&s, "planner").await;
        assert_eq!(state, "new", "the sighting is new until approved");
        let (status, body) = answered(&s.router, send("planner")).await;
        untrusted(status, &body, "planner", "Pending");
        assert!(!agent.relayed(), "a refused unit is never dialled");

        // THE DOOR'S OWN VERB approves the key on the kernel's book.
        let (status, approved) = admin(
            &s,
            "/agents/planner/approve",
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{approved}");
        assert_eq!(approved["state"], "approved", "{approved}");
        assert_eq!(approved["fingerprint"], fingerprint.as_str(), "{approved}");
        let fetched = agent.fetches();
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the approved agent is served: {body}"
        );
        assert!(body.contains("m-far"), "the far agent's answer: {body}");
        assert!(agent.relayed(), "the approved agent was dialled");
        assert!(
            agent.fetches() > fetched,
            "its card was re-verified on call"
        );

        // THE GENERIC `/trust`: a revoke refuses it, an approve serves it again.
        let (status, revoked) = decide_key(&s, "planner", "revoke").await;
        assert_eq!(status, StatusCode::OK, "{revoked}");
        let (status, body) = answered(&s.router, send("planner")).await;
        untrusted(status, &body, "planner", "Pending");
        assert!(!agent.relayed(), "a revoked agent is never dialled");
        let (status, reapproved) = decide_key(&s, "planner", "approve").await;
        assert_eq!(status, StatusCode::OK, "{reapproved}");
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(status, StatusCode::OK, "approved on /trust, served: {body}");
        assert!(agent.relayed(), "dialled again");

        // THE RUG-PULL: the right issuer key, a skill the operator never read.
        agent.reissue("plans the work and forwards it on");
        let fetched = agent.fetches();
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "this agent is not currently serving",
            "{body}"
        );
        assert!(
            doc["error"]["data"].as_array().is_some_and(|d| d
                .iter()
                .any(|e| e["resourceType"] == surface("task_resource_type"))),
            "the refusal names its task: {body}"
        );
        assert!(
            agent.fetches() > fetched,
            "the drift was found by a live re-fetch"
        );
        assert!(!agent.relayed(), "a demoted agent is never dialled");
        // Restored, the agent stays out of service: the kernel's quarantine holds.
        agent.reissue("plans the work");
        let (status, body) = answered(&s.router, send("planner")).await;
        untrusted(status, &body, "planner", "Quarantined");
        assert!(!agent.relayed(), "a quarantined agent is never dialled");
        agent.reissue("plans the work and forwards it on");
        let (status, drifted) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{drifted}");
        assert_eq!(drifted["state"], "quarantined", "{drifted}");
        assert_ne!(drifted["fingerprint"], fingerprint.as_str(), "{drifted}");
        let (_, state) = trust_key(&s, "planner").await;
        assert_eq!(state, "quarantined", "the book holds the quarantine");
        let (status, stale) = admin(
            &s,
            "/agents/planner/approve",
            &format!(r#"{{"fingerprint": "{fingerprint}"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{stale}");
        assert_eq!(stale["error"]["code"], "invalid_request", "{stale}");
        approve(&s, "planner").await;
        let (status, body) = answered(&s.router, send("planner")).await;
        assert_eq!(status, StatusCode::OK, "re-approved, it is served: {body}");

        // AN UNPINNED REGISTRATION: captured, nothing sighted, never approved, never served.
        let (status, captured) = admin(&s, "/agents/scout/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{captured}");
        assert_eq!(captured["state"], "pending", "{captured}");
        assert_eq!(captured["pin_mechanism"], "unpinned", "{captured}");
        assert_eq!(
            captured["fingerprint"],
            serde_json::Value::Null,
            "{captured}"
        );
        let (status, capped) = admin(
            &s,
            "/agents/scout/approve",
            r#"{"fingerprint": "sha256:any"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{capped}");
        let (status, unsighted) = decide_key(&s, "scout", "approve").await;
        assert_eq!(status, StatusCode::CONFLICT, "never sighted: {unsighted}");
        let (status, body) = answered(&s.router, send("scout")).await;
        untrusted(status, &body, "scout", "Pending");

        let (status, unknown) = admin(&s, "/agents/nobody/connect", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");
        assert_eq!(unknown["error"]["code"], "not_found", "{unknown}");
    }

    /// SINGLE-FLIGHT VERIFY-ON-CALL (the engine's `VerifyGate`): two units due on one agent at once
    /// (`reverify_ttl: 0s`, its card slow to answer) share ONE look at its card and its verdict, and
    /// both are served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_units_due_on_one_agent_share_one_card_look() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-single-flight";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "0s"), false, None);
        approve(&s, "planner").await;
        agent
            .card_delay_ms
            .store(300, std::sync::atomic::Ordering::SeqCst);
        let fetched = agent.fetches();
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let ((first, a), (second, b)) =
            tokio::join!(answered(&s.router, send()), answered(&s.router, send()));
        assert_eq!(first, StatusCode::OK, "{a}");
        assert_eq!(second, StatusCode::OK, "{b}");
        assert_eq!(
            agent.fetches() - fetched,
            1,
            "the two due units shared one look at the card"
        );
    }

    /// THE CARD FETCH'S GUARD AND REDIRECTS, as 1.5.5 fetched a card: a card behind a redirect is
    /// followed and approved; a chain past three redirects is refused in 1.5.5's words; a
    /// registration that does not allow private addresses has its loopback card refused by the
    /// guard in 1.5.5's words, and the agent never hears the fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_follows_redirects_and_is_guarded_in_its_1_5_5_words() {
        use std::sync::atomic::Ordering;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-card-fetch";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\nscout: {{url: 'https://127.0.0.1:{}/scout', pin: {{mechanism: jws_issuer_key, \
             key: '{}'}}}}",
            agent.entry("planner", "1h"),
            agent.port,
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);

        agent.redirect.store(1, Ordering::SeqCst);
        approve(&s, "planner").await;

        agent.redirect.store(2, Ordering::SeqCst);
        let (status, looped) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{looped}");
        assert_eq!(looped["state"], "error", "{looped}");
        assert_eq!(
            looped["failure"],
            format!(
                "agent card fetch exceeded 3 redirect(s), still redirecting at \
                 `http://127.0.0.1:{}/loop`",
                agent.port
            ),
            "{looped}"
        );

        agent.redirect.store(0, Ordering::SeqCst);
        let fetched = agent.fetches();
        let (status, guarded) = admin(&s, "/agents/scout/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{guarded}");
        assert_eq!(
            guarded["failure"],
            "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
             address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
             deliberate. A cloud-metadata address is refused whatever that is set to.",
            "{guarded}"
        );
        assert_eq!(
            agent.fetches(),
            fetched,
            "the agent never heard the refused fetch"
        );
    }

    /// A REDIRECT IS A URL A STRANGER CHOSE, judged from scratch at the hop that names it: a card
    /// whose well-known path redirects at the cloud-metadata ADDRESS, and one that redirects at a
    /// cloud-metadata NAME, are each refused at that hop in 1.5.5's words whatever the
    /// registration's `allow_private` says (the registration here is one that allows it), and the
    /// card is never obtained.
    /// Ported from busbar-a2a a2a/tests/fetch_tests.rs::a_redirect_to_the_cloud_metadata_address_is_refused_at_the_hop_that_names_it
    /// and a2a/tests/fetch_tests.rs::a_redirect_to_a_metadata_dns_name_is_refused_before_it_is_resolved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_redirected_at_cloud_metadata_is_refused_at_the_hop_that_names_it() {
        use std::sync::atomic::Ordering;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-card-redirect-metadata";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        for (mode, words) in [
            (
                3,
                "SSRF guard refused the agent card fetch: host `169.254.169.254` resolved to the \
                 internal address 169.254.169.254; set this registration's `allow_private: true` \
                 if reaching it is deliberate. A cloud-metadata address is refused whatever that \
                 is set to.",
            ),
            (
                4,
                "SSRF guard refused the agent card fetch: host `metadata.google.internal` is a \
                 cloud-metadata name",
            ),
        ] {
            agent.redirect.store(mode, Ordering::SeqCst);
            let (status, view) = admin(&s, "/agents/planner/connect", "").await;
            assert_eq!(status, StatusCode::OK, "{view}");
            assert_eq!(view["state"], "error", "mode {mode}: {view}");
            assert_eq!(view["failure"], words, "mode {mode}: {view}");
        }
        assert_eq!(agent.fetches(), 0, "the card was never obtained");
    }

    /// A LEGAL CHAIN IS FOLLOWED HOP BY HOP: a card behind two redirects (the well-known path to
    /// `/cards/one` to `/cards/card.json`) is fetched, verified and approved, each hop judged and
    /// dialled in its own right. The count of lookups and the address each hop was pinned to are the
    /// host's, not observable from here; that every hop was followed to the document is.
    /// Ported from busbar-a2a a2a/tests/fetch_tests.rs::every_hop_of_a_legal_chain_is_resolved_and_pinned_separately.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_hop_of_a_legal_chain_is_followed_to_the_card() {
        use std::sync::atomic::Ordering;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-card-redirect-chain";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        agent.redirect.store(5, Ordering::SeqCst);
        approve(&s, "planner").await;
        assert!(
            agent.fetches() >= 1,
            "the card was obtained at the end of the chain"
        );
    }

    /// THE CHECK ORDER, as 1.5.5's admission kept it: the caller's grant, then the agent's trust,
    /// then its card's fit. A request naming a skill the card does not declare is refused as
    /// not-serving (`403`, the kernel's trust refusal) while the agent is unapproved, and by the
    /// catalogue (`403`,
    /// `SkillNotDeclared("fly")`) once it is approved — never dialled either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_the_card_does_not_fit_is_judged_after_the_trust_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-fit-order";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        let fly = r#"{"message":{"kind":"message","messageId":"m-2","role":"user","parts":[{"kind":"text","text":"go"}]},"metadata":{"skill":"fly"}}"#;
        let send = || rpc("planner", "message/send", fly, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "trust first: {body}");
        assert!(
            body.contains("is not serving (Pending)"),
            "the trust refusal, not the card's fit: {body}"
        );
        approve(&s, "planner").await;
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "then the card's fit: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "SkillNotDeclared(\"fly\")",
            "{body}"
        );
        assert_eq!(doc["id"], serde_json::Value::Null, "{body}");
        assert!(!agent.relayed(), "an unfit request is never dialled");
    }

    /// THE GATE (ARCHITECT Q-DEL-A2A-GATE: refused -> audits the refusal; nothing was charged): a
    /// unit addressed to an agent that is not serving is judged by the caller's grant first (`403`
    /// for a caller the agent is not granted to), then refused in predev's admission words at the
    /// kernel's trust status (`403`, "fronted agent `planner` is not serving (Pending)") — a relayed
    /// call and a locally answered
    /// one alike — and the key is charged for neither.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_unit_to_an_agent_that_is_not_serving_is_refused_after_its_grant_and_charges_nothing()
    {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-gate";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        for (method, params) in [("message/send", SEND), ("tasks/list", "{}")] {
            let (status, body) =
                answered(&s.router, rpc("planner", method, params, Some(&s.token))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
            let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
            assert_eq!(doc["error"]["code"], -32004, "{body}");
            assert_eq!(
                doc["error"]["message"], "fronted agent `planner` is not serving (Pending)",
                "{body}"
            );
        }
        assert!(!agent.relayed(), "never dialled");
        assert_eq!(admitted(&s), 0, "a refused unit is charged nothing");
        drop(s);
        drop(_published);

        let ungranted = "serve-agent-door-gate-ungranted";
        let _published = Published(ungranted);
        let s = served(
            ungranted,
            &agent.entry("planner", "1h"),
            false,
            Some(Vec::new()),
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the grant is judged first: {body}"
        );
        assert!(body.contains("scope_denied"), "{body}");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// SCOPE AND STANDING (ARCHITECT Q-DEL-A2A-SCOPE-TRUST): an unaddressed unit is routed over the
    /// caller's grant intersected with the agents that would serve it — two agents granted, one of
    /// them approved, is routed to the approved one (as predev's trust-gated catalogue chose it),
    /// not refused as several.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unaddressed_unit_is_routed_to_the_one_granted_agent_that_serves() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-scope-trust";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scout", "1h")
        );
        let s = served(instance, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) =
            answered(&s.router, rpc("", "message/send", SEND, Some(&s.token))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "routed to the one that serves: {body}"
        );
        assert!(body.contains("m-far"), "{body}");
        assert!(agent.relayed(), "the approved agent was dialled");
    }

    /// A CONFIG APPLY (ARCHITECT Q-DEL-A2A-APPLY) bumps the door's refresh generation and the door
    /// re-reads its section, but the operator's approval is the KERNEL'S trust book's (ARCHITECT
    /// FLIP-A2A: pinning is kernel state, an operator's decision is durable): a registration the
    /// apply keeps under the same pin keeps its approval, and the approved agent is still served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_config_apply_keeps_the_operators_approval() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-apply";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "approved, served: {body}");
        assert!(agent.relayed());

        s.handle.swap(Arc::clone(&s.app));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the approval outlives the apply: {body}"
        );
    }

    /// THE CARD FETCH'S GUARD WORDS, as 1.5.5 printed them (ARCHITECT Q-DEL-A2A-GUARD-WORDS): a
    /// registration without `allow_private` is refused a private card host whatever the
    /// deployment's `block_private_addresses` says (here `false`), the address or loopback name
    /// named; a host that does not resolve is refused with the resolver's reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_is_refused_in_1_5_5_words_whatever_the_deployment_private_stance() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-guard-words";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let pin = format!(
            "pin: {{mechanism: jws_issuer_key, key: '{}'}}",
            key_info(&agent.issuer)
        );
        let section = format!(
            "literal: {{url: 'https://127.0.0.1:{port}/literal', {pin}}}\n\
             named: {{url: 'https://localhost:{port}/named', {pin}}}\n\
             nowhere: {{url: 'https://card-host.invalid/nowhere', {pin}}}",
            port = agent.port
        );
        let s = served_under(
            instance,
            &section,
            busbar_kernel::config::Destinations {
                block_private_addresses: false,
                ..Default::default()
            },
            None,
            None,
        );
        let failure = |name: &'static str| {
            let s = &s;
            async move {
                let (status, view) = admin(s, &format!("/agents/{name}/connect"), "").await;
                assert_eq!(status, StatusCode::OK, "{view}");
                assert_eq!(view["state"], "error", "{view}");
                view["failure"].as_str().unwrap_or_default().to_string()
            }
        };
        assert_eq!(
            failure("literal").await,
            "SSRF guard refused the agent card fetch: host `127.0.0.1` resolved to the internal \
             address 127.0.0.1; set this registration's `allow_private: true` if reaching it is \
             deliberate. A cloud-metadata address is refused whatever that is set to."
        );
        assert_eq!(
            failure("named").await,
            "SSRF guard refused the agent card fetch: host `localhost` is a loopback name; set \
             this registration's `allow_private: true` if that is deliberate"
        );
        assert_eq!(agent.fetches(), 0, "the agent never heard a refused fetch");
        // PREDEV'S RESOLVER WORDS, byte for byte: its card fetch resolved through tokio's
        // `lookup_host("{host}:0")` and printed that error's text.
        let predev = match tokio::net::lookup_host("card-host.invalid:0").await {
            Ok(_) => panic!("a `.invalid` name never resolves"),
            Err(e) => e.to_string(),
        };
        assert_eq!(
            failure("nowhere").await,
            format!("agent card host `card-host.invalid` did not resolve: {predev}")
        );
    }

    /// A CARD FETCH WHOSE FAR END CLOSES BEFORE REPLYING, in predev's exact words: its engine's
    /// HTTP client named it `client error (SendRequest): connection closed before message
    /// completed` (hyper's incomplete message) — here a far end that accepts, reads the request
    /// and closes without a byte of reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_whose_far_end_closes_unanswered_fails_in_predev_words() {
        use tokio::io::AsyncReadExt;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-closed-unanswered";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut heard = Vec::new();
                let mut buf = [0_u8; 1024];
                while !heard.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => heard.extend_from_slice(&buf[..n]),
                    }
                }
                drop(socket);
            }
        });
        let section = format!(
            "silent: {{url: 'http://127.0.0.1:{port}/silent', allow_private: true, pin: \
             {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);
        let (status, view) = admin(&s, "/agents/silent/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "{view}");
        assert_eq!(
            view["failure"],
            format!(
                "agent card fetch of `http://127.0.0.1:{port}/.well-known/agent.json` failed: \
                 client error (SendRequest): connection closed before message completed"
            ),
            "{view}"
        );
    }

    /// A CARD FETCH THE CONNECTION FAILS, in predev's exact words (ARCHITECT
    /// Q-DEL-A2A-GUARD-WORDS): "agent card fetch of `{url}` failed: {err}", the err the engine's
    /// HTTP client rendered with its cause chain (`client error (Connect): tcp connect error:
    /// <the socket's own error>`) — here a closed loopback port, the socket's error the one this
    /// host's own connect to that port answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_fetch_to_a_closed_port_fails_in_predev_words() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-closed-port";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a port")
            .local_addr()
            .expect("its address")
            .port();
        let refused_here = std::net::TcpStream::connect(("127.0.0.1", closed))
            .expect_err("nothing listens on the closed port")
            .to_string();
        let section = format!(
            "closed: {{url: 'https://127.0.0.1:{closed}/closed', allow_private: true, pin: \
             {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&agent.issuer)
        );
        let s = served(instance, &section, false, None);
        let (status, view) = admin(&s, "/agents/closed/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "{view}");
        assert_eq!(
            view["failure"],
            format!(
                "agent card fetch of `https://127.0.0.1:{closed}/.well-known/agent.json` failed: \
                 client error (Connect): tcp connect error: {refused_here}"
            ),
            "{view}"
        );
    }

    /// THE AGENT DOOR'S TRUST VERBS' DECLARED ERRORS, driven through the admin router by the door's
    /// own `serve` op (ARCHITECT Q-L3B-VERBS), the door published as the root publishes it. Moved
    /// here from busbar-core-admin's `drive_door_verb_errors` (P2 D4: that crate links no loader,
    /// so it witnesses the same taxonomy over its door double):
    /// * an unregistered name is `404 not_found` on `connect` and `approve` (before anything is
    ///   read);
    /// * `approve` whose body is not the one-field `{"fingerprint": …}` document (an unknown field
    ///   beside it) is `400 invalid_request`, naming the one field the body may carry;
    /// * `approve` naming a fingerprint for an agent whose card cannot be fetched (nothing listens
    ///   on its port) is `400 invalid_request`: the look reports the card unauthenticated, which no
    ///   approval can agree with.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_agent_doors_trust_verbs_refuse_in_their_declared_taxonomy() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-verb-errors";
        let _published = Published(instance);
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a port")
            .local_addr()
            .expect("its address")
            .port();
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let section = format!(
            "closed: {{url: 'http://127.0.0.1:{closed}/closed', allow_private: true, pin: \
             {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&issuer)
        );
        let s = served(instance, &section, false, None);
        for path in ["/agents/nope/connect", "/agents/nope/approve"] {
            let (status, body) = admin(&s, path, r#"{"fingerprint": "sha256:aa"}"#).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
            assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
        }
        let (status, body) = admin(
            &s,
            "/agents/closed/approve",
            r#"{"fingerprint": "sha256:aa", "and": "more"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request", "{body}");
        assert!(
            body.to_string().contains("fingerprint"),
            "the malformed-body refusal names the one field the body may carry: {body}"
        );
        let (status, body) = admin(
            &s,
            "/agents/closed/approve",
            r#"{"fingerprint": "sha256:aa"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request", "{body}");
        assert!(
            body.to_string().contains("nothing to approve"),
            "the invalid-config refusal says the card could not be authenticated: {body}"
        );
    }

    /// The registration facts `reg` states, as data: every field but its two judges.
    fn statement_of(reg: &busbar_contract::plane_calls::PlaneRegistration) -> serde_json::Value {
        let routes: Vec<serde_json::Value> = reg
            .admin_routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "verb": r.verb,
                    "target": r.target,
                    "flags": r.flags,
                    "audit_verb": r.audit_verb,
                })
            })
            .collect();
        let trust_keys: Vec<serde_json::Value> = reg
            .trust_keys
            .iter()
            .map(|k| {
                let mechanisms: Vec<serde_json::Value> = k
                    .mechanisms
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "token": m.token,
                            "root": m.root,
                            "peer_key": m.peer_key,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "key": k.key,
                    "role": format!("{:?}", k.role),
                    "fingerprint": k.fingerprint,
                    "default": k.default,
                    "mechanisms": mechanisms,
                })
            })
            .collect();
        let openapi = reg.admin_openapi.map(|b| {
            serde_json::from_slice::<serde_json::Value>(b).expect("the admin OpenAPI blob is JSON")
        });
        serde_json::json!({
            "key": reg.key,
            "section": reg.section,
            "owns": reg.owns,
            "consumes": reg.consumes,
            "secret_refs": reg.secret_refs,
            "admin_routes": routes,
            "admin_openapi": openapi,
            "label": reg.label,
            "subject_noun": reg.subject_noun,
            "admin_noun": reg.admin_noun,
            "audit_kind": reg.audit_kind,
            "signing": reg.signing.map(|(d, p)| [d, p]),
            "dialects": reg.dialects,
            "scope_kinds": reg.scope_kinds,
            "billable_classes": reg.billable_classes.iter().map(|(c, f)| [*c, *f]).collect::<Vec<_>>(),
            "fee_units": reg.fee_units,
            "record_kinds": reg.record_kinds,
            "trust_keys": trust_keys,
            "caller_credential_refusal": reg.caller_credential_refusal,
        })
    }

    /// THE ADMIN CRATE'S DOOR DOUBLE STATES WHAT THE LINKED DOOR STATES. busbar-core-admin links no
    /// loader (P2 D4), so its tests fold a double of this door from data
    /// (`busbar-core-admin/src/tests/door_double_statement.json`): its admin routes, the OpenAPI
    /// fragment its committed `openapi.json` carries, its nouns, its trust keys and every other fact
    /// a registration states. Here, where the loader links, that data is pinned to the linked
    /// door's own Statement, read through the loader's one load and its registration reader, as
    /// the composition root folds it: the admin crate's drift test holds the door's entry, not a
    /// copy that drifted from it.
    #[test]
    fn the_admin_crates_door_double_states_the_linked_doors_statement() {
        // A build that links no agent door has nothing for this cell to pin.
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        let reg =
            registration(linked_probe(door(), "agent-door-statement")).expect("the door binds");
        let stated = statement_of(&reg);
        let double: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../busbar-core-admin/src/tests/door_double_statement.json"
        ))
        .expect("the double's statement is JSON");
        assert_eq!(
            stated,
            double,
            "busbar-core-admin's door double no longer states the linked door's Statement; the door \
             states:\n{}",
            serde_json::to_string_pretty(&stated).unwrap_or_default()
        );
    }

    /// CANCELLATION IS A WAKE (ARCHITECT Q-DEL-A2A-TIMED-WAKE): the unit holding an agent's card
    /// look is abandoned mid-look (its caller goes away while the card is slow), and the unit
    /// waiting on that look proceeds at once — it takes the flight over, looks for itself and is
    /// served — rather than stalling on a look that will never land.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_card_look_wakes_its_waiters_at_once() {
        use std::time::Duration;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-abandoned-look";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "0s"), false, None);
        approve(&s, "planner").await;
        agent
            .card_delay_ms
            .store(30_000, std::sync::atomic::Ordering::SeqCst);
        let fetched = agent.fetches();
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let abandoned =
            tokio::time::timeout(Duration::from_millis(400), answered(&s.router, send()));
        let waiting = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tokio::time::timeout(Duration::from_secs(5), answered(&s.router, send())).await
        };
        let (gone, waited) = tokio::join!(abandoned, waiting);
        assert!(gone.is_err(), "the first caller went away mid-look");
        let (status, body) = waited.expect("the waiter proceeded without stalling on the look");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            agent.fetches() - fetched,
            2,
            "the waiter took the abandoned flight over and looked for itself"
        );
    }

    // ── VERIFY-ON-CALL'S PARITY CELLS (the engine's `verify_tests`, through the agent door) ───────

    /// AN UNREACHABLE CARD AT VERIFY FAILS CLOSED ON THE CALL PATH (the engine's
    /// `verify_tests::an_unreachable_card_at_verify_fails_closed_on_the_call_path`; ARCHITECT
    /// 2026-10-07: the background reverify keeps the kernel's last verdict, the call-path verify of
    /// a hop fails closed). The approved agent goes dark between two delegations: the next one's
    /// look cannot reach its card, and the hop is refused with the hop gate's predev bytes (`503`,
    /// `-32004`, "this agent is not currently serving", naming its task) without dialling; the
    /// kernel's verdict is untouched (still `approved`), so once the card answers again the next
    /// call's look serves it. RED before the fix: the door served the hop on the kernel's kept
    /// verdict and dialled the dark agent (`agent.relayed()` true, no `503`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreachable_card_at_verify_fails_closed_on_the_call_path() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-unreachable-on-call";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "0s"), false, None);
        approve(&s, "planner").await;
        let send = || rpc("planner", "message/send", SEND, Some(&s.token));
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the approved agent is served: {body}"
        );
        assert!(agent.relayed(), "the approved agent was dialled");

        // THE VENDOR GOES DARK between the approval and the next delegation.
        agent.go_down();
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a card busbar could not re-verify on the call path fails the hop closed: {body}"
        );
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert_eq!(
            doc["error"]["message"], "this agent is not currently serving",
            "{body}"
        );
        assert!(
            doc["error"]["data"].as_array().is_some_and(|d| d
                .iter()
                .any(|e| e["resourceType"] == surface("task_resource_type"))),
            "the refusal names its task: {body}"
        );
        assert!(!agent.relayed(), "the refused hop never reached the agent");
        let (_, state) = trust_key(&s, "planner").await;
        assert_eq!(
            state, "approved",
            "the kernel's last verdict is untouched by an unreachable card"
        );

        // BACK UP: the next call looks again and is served on the verdict the kernel kept.
        agent.down.store(false, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = answered(&s.router, send()).await;
        assert_eq!(status, StatusCode::OK, "reachable again, served: {body}");
        assert!(agent.relayed(), "dialled again");
    }

    /// A CARD SIGNED BY THE WRONG KEY IS REFUSED AND RECORDED AS A FAILED CONTACT (the engine's
    /// `verify_tests::a_card_signed_by_the_wrong_key_is_refused_and_recorded_as_a_failed_contact`):
    /// a perfectly valid signed card, not signed by the key the operator supplied out of band.
    /// `connect` reports the registration `error` in the engine's words with no fingerprint to
    /// approve, the card was fetched once (a card that failed verification is never retried at the
    /// legacy path), an approval of it is refused, and a delegation to it is never dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_signed_by_the_wrong_key_is_refused_and_recorded_as_a_failed_contact() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-wrong-key";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let operator = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let section = format!(
            "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, reverify_ttl: \
             '0s', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
            agent.port,
            key_info(&operator)
        );
        let s = served(instance, &section, false, None);
        let (status, view) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(
            view["state"], "error",
            "a card we could not authenticate must not present as an agent that is fine: {view}"
        );
        assert_eq!(
            view["failure"], "the agent card is signed, but not by the pinned issuer key",
            "{view}"
        );
        assert_eq!(view["fingerprint"], serde_json::Value::Null, "{view}");
        assert_eq!(agent.fetches(), 1, "fetched once, at the canonical path");
        let (status, refused) = admin(
            &s,
            "/agents/planner/approve",
            &format!(r#"{{"fingerprint": "{}"}}"#, agent.fingerprint()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(
            !agent.relayed(),
            "an unauthenticated agent is never dialled"
        );
    }

    /// THE LEGACY WELL-KNOWN PATH IS TRIED ONLY WHEN THE CANONICAL ONE SERVED NOTHING (the engine's
    /// `verify_tests::the_legacy_well_known_path_is_tried_only_when_the_canonical_one_served_nothing`):
    /// a canonical path that answers nothing usable falls back to the legacy one, whose signed card
    /// is observed; a canonical path that serves a card signed by the WRONG key is refused there,
    /// and the good card at the legacy path is never reached (retrying would let an upstream serve a
    /// signed card at one path and a hostile one at the other).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_legacy_well_known_path_is_tried_only_when_the_canonical_one_served_nothing() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const LEGACY_PATH: &str = "GET /.well-known/agent.json ";
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-legacy-path";
        let _published = Published(instance);
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let impostor = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        // `split` false: the canonical path answers 404; true: it serves the impostor's card.
        let split = Arc::new(AtomicBool::new(false));
        let (canonical, legacy) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let served_card = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
        let (port, _heard) = {
            let (split, canonical, legacy, served_card) = (
                Arc::clone(&split),
                Arc::clone(&canonical),
                Arc::clone(&legacy),
                Arc::clone(&served_card),
            );
            let (issuer, impostor) = (issuer.clone(), impostor.clone());
            far_end_answering(Arc::new(move |request: &str| {
                let card = served_card.lock().map(|c| c.clone()).unwrap_or_default();
                if request.starts_with(CARD_PATH) {
                    canonical.fetch_add(1, Ordering::SeqCst);
                    return Some(if split.load(Ordering::SeqCst) {
                        FarReply::of(200, signed(&card, &impostor).to_string())
                    } else {
                        FarReply::of(404, String::new())
                    });
                }
                if request.starts_with(LEGACY_PATH) {
                    legacy.fetch_add(1, Ordering::SeqCst);
                    return Some(FarReply::of(200, signed(&card, &issuer).to_string()));
                }
                Some(FarReply::of(200, ANSWER.to_string()))
            }))
            .await
        };
        let good = card(port, "plans the work");
        *served_card.lock().expect("the card") = good.clone();
        let section = format!(
            "planner: {{url: 'http://127.0.0.1:{port}/planner', allow_private: true, \
             reverify_ttl: '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
            key_info(&issuer)
        );
        let s = served(instance, &section, false, None);

        let (status, view) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(
            view["failure"],
            serde_json::Value::Null,
            "the legacy path is tolerated: {view}"
        );
        assert_eq!(
            view["fingerprint"],
            card_fingerprint(&signed(&good, &issuer)).as_str(),
            "{view}"
        );
        assert_eq!(
            canonical.load(Ordering::SeqCst),
            1,
            "canonical is tried FIRST"
        );
        assert_eq!(
            legacy.load(Ordering::SeqCst),
            1,
            "and the legacy path after it"
        );

        split.store(true, Ordering::SeqCst);
        let (status, view) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(view["state"], "error", "{view}");
        assert_eq!(
            view["failure"], "the agent card is signed, but not by the pinned issuer key",
            "a verification failure at the canonical path must NOT fall through to the legacy \
             one: {view}"
        );
        assert_eq!(canonical.load(Ordering::SeqCst), 2, "{view}");
        assert_eq!(
            legacy.load(Ordering::SeqCst),
            1,
            "the good card at the legacy path was never reached"
        );
    }

    // ── THE HOOK PARITY CELLS ON THE DOOR PATH (the engine's `hook_gate_tests` / `hook_tap_tests`,
    //    each driven through the a2a door and the driver's gate-first hook stage). ────────────────

    /// The kernel's hook double behind the `test-hook` alias (OWNER 2026-10-03, no test plugins):
    /// its row states the manifest needs a dropped-in hook's signed manifest does, and the hook
    /// port answers it in process through the frame the kernel built.
    fn hook_env() -> busbar_kernel::hooks::HookEnv {
        use crate::root::loader::sign::{HookNeeds, NeedLevel};
        busbar_kernel::test_support::test_hook_env(
            &["test-hook"],
            HookNeeds {
                prompt: NeedLevel::Rw,
                user: NeedLevel::Ro,
            },
        )
    }

    /// A `hooks:` definition on the kernel's hook double, as an operator writes it, its `prompt:` grant
    /// `prompt` and its plugin `settings`. Not the 1 ms default deadline: these cells assert the
    /// hook's verdict, and on a loaded machine the deadline fires on scheduling delay.
    fn hook_def(prompt: &str, settings: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "kind": "gate",
            "module": "test-hook",
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": prompt,
            "user": "ro",
            "priority": 0,
            "settings": settings,
        })
    }

    /// The door served with the hook `def`, named `name`, attached to the agent `planner`
    /// (`agents.planner.hooks: [name]`), its egress the deployment's default stance.
    fn hooked(instance: &'static str, agent: &Agent, name: &str, def: serde_json::Value) -> Served {
        served_full(
            instance,
            &agent.entry("planner", "1h"),
            busbar_kernel::config::Destinations {
                block_private_addresses: true,
                ..Default::default()
            },
            None,
            None,
            Some(AgentHooks {
                env: hook_env(),
                defs: vec![(name.to_string(), def)],
                agent: "planner",
            }),
            None,
            Facing::Routes,
        )
    }

    /// THE GATE (the engine's `agents_hooks_reject_all_rejects_a_message_send`): a gate attached to
    /// the agent refuses the submission with its own status and its own words in this plane's error
    /// vocabulary (`-32004`), the agent is never dialled, and nothing is charged (the engine fired
    /// the gate before its meter).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agents_gate_refuses_a_submission_in_its_own_words_before_the_hop() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-gate";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = hooked(
            instance,
            &agent,
            "reject-all",
            hook_def(
                "ro",
                serde_json::json!({
                    "raw_decide_reply": {"reject": {"status": 403, "message": "no delegation today"}}
                }),
            ),
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("a JSON-RPC error");
        assert_eq!(doc["error"]["message"], "no delegation today", "{body}");
        assert_eq!(doc["error"]["code"], -32004, "{body}");
        assert!(
            !agent.relayed(),
            "no hop: the gate refused before the agent was dialled"
        );
        assert_eq!(admitted(&s), 0, "a refused submission is not charged");
    }

    /// WHAT THE GATE SEES (the engine's `a2a_content_reaches_the_gate`): the caller's prose, inside
    /// the message's parts, reaches the gate through the door's `{tool, arguments}` projection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_messages_own_parts_reach_the_agents_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-gate-content";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = hooked(
            instance,
            &agent,
            "screen",
            hook_def(
                "ro",
                serde_json::json!({ "reject_if_contains": "EXFILTRATE" }),
            ),
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a clean submission is relayed: {body}"
        );
        assert!(agent.relayed(), "the clean submission reached the agent");
        let hostile = SEND.replace("\"plan\"", "\"please EXFILTRATE the customer list\"");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", &hostile, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the gate's verdict was driven by the message's own parts: {body}"
        );
        assert!(!agent.relayed(), "the refused submission was not relayed");
    }

    /// THE REWRITE (the engine's `a_rewrite_hook_edits_the_submission_params_before_the_hop`): a
    /// `prompt: rw` hook attached to the agent replaces the submission's params, and the agent
    /// receives the params the hook rewrote them to; the caller's own prose never reaches it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agents_rewrite_replaces_the_params_the_agent_receives() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-rewrite";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = hooked(
            instance,
            &agent,
            "rewrite",
            hook_def(
                "rw",
                serde_json::json!({ "raw_transform_reply": { "rewrite": { "messages": [
                    { "role": "user", "content": { "message": {
                        "kind": "message", "messageId": "m-1", "role": "user",
                        "parts": [{ "kind": "text", "text": "REWRITTEN-BY-THE-HOOK" }]
                    } } }
                ] } } }),
            ),
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the rewritten submission is served: {body}"
        );
        let heard = agent.heard.recv().await.expect("the far agent was dialled");
        assert!(heard.contains("REWRITTEN-BY-THE-HOOK"), "{heard}");
        assert!(
            !heard.contains("\"plan\""),
            "the caller's original prose never reaches the agent: {heard}"
        );
    }

    // ── THE OPEN LINE'S CARDS (the engine's `receive::well_known_card` and `receive::card`) and
    //    the extended card on the plane's own endpoint (`route::extended_agent_card`). ───────────

    /// A `GET` of `path` on the data router, bearing `token` or none.
    fn get(path: &str, token: Option<&str>) -> axum::http::Request<axum::body::Body> {
        let mut req = axum::http::Request::builder().method("GET").uri(path);
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        req.body(axum::body::Body::empty()).expect("a request")
    }

    /// THE AGENT DOOR'S BREAKER FACT (ARCHITECT Q4): its linked row's `declares` states that one
    /// transient failure below the trip threshold benches nothing, and the root reads it by the
    /// door's Statement name, so an agent's cell refuses on a trip and nothing less.
    #[test]
    fn the_agent_door_states_a_cell_refuses_on_a_trip_and_nothing_less() {
        let door = door();
        let row = LinkedRow::of(door).expect("the door states its Statement");
        let name = busbar_contract::abi::mechanism::rendering::read(&row.statement)
            .expect("its Statement reads")
            .name;
        let stated = crate::root::linked::door_breaker(&crate::LINKED, None, &name)
            .expect("its declares section reads");
        assert_eq!(stated.map(|b| b.bench_below_trip_threshold), Some(false));
    }

    /// BUSBAR'S OWN CARD at the well-known path: unauthenticated, cacheable for an hour, describing
    /// busbar (every binding it serves, no fronted agent enumerated) and signed with busbar's key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busbars_own_card_is_served_at_the_well_known_path_signed_and_naming_no_agent() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-own-card";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        let response = s
            .router
            .clone()
            .oneshot(get("/.well-known/agent-card.json", None))
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "public, max-age=3600");
        assert_eq!(
            response.headers()["content-type"],
            "application/json; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let card: serde_json::Value = serde_json::from_slice(&body).expect("a card");
        assert_eq!(card["name"], "busbar");
        assert_eq!(card["skills"], serde_json::json!([]));
        assert_eq!(
            card["supportedInterfaces"][0],
            serde_json::json!({
                "url": format!("https://gw.example{}", mount()),
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            })
        );
        let protected = card["signatures"][0]["protected"]
            .as_str()
            .expect("signed with busbar's key");
        assert!(!protected.is_empty());
        assert!(
            !String::from_utf8_lossy(&body).contains("planner"),
            "no agent is enumerated"
        );
    }

    /// A FRONTED AGENT'S CARD behind the caller's credential: refused without one, and once the
    /// agent is approved, its card with every URL busbar's and busbar's own scheme and signature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fronted_agents_card_is_served_rewritten_through_busbar_behind_its_grant() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-agent-card";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        let (status, _) =
            answered(&s.router, get(&format!("{}/agents/planner", mount()), None)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the card needs a credential"
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            get(&format!("{}/agents/planner", mount()), Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
        assert!(
            !body.contains(&format!("127.0.0.1:{}", agent.port)),
            "the backend authority is never published: {body}"
        );
        assert_eq!(
            card["securityRequirements"],
            serde_json::json!([{ "schemes": { "busbarA2aInbound": { "list": [] } } }])
        );
        assert_eq!(card["capabilities"]["extendedAgentCard"], true);
        assert!(card["signatures"][0]["protected"].is_string(), "{body}");
    }

    /// A CARD READ IS NOT SCREENED: with a gate attached to the agent that refuses every
    /// submission, the agent's card is still served to a granted caller (1.5.5 answered a card read
    /// with no hook in the way), while a submission to the same agent is refused by the gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gated_agents_card_is_still_served_and_its_submission_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-gated-card";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = hooked(
            instance,
            &agent,
            "reject-all",
            hook_def(
                "ro",
                serde_json::json!({
                    "raw_decide_reply": {"reject": {"status": 403, "message": "no delegation today"}}
                }),
            ),
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            get(&format!("{}/agents/planner", mount()), Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the card is served: {body}");
        let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
        assert!(card["name"].is_string(), "{body}");
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!agent.relayed(), "the refused submission was not relayed");
    }

    /// BUSBAR'S EXTENDED CARD on the plane's own endpoint: one skill per agent the caller's own
    /// catalogue holds, answered by busbar, never relayed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_extended_card_on_the_planes_endpoint_names_the_callers_agents() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-extended-card";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        assert_eq!(doc["id"], 1);
        let skills = doc["result"]["skills"].as_array().expect("skills");
        assert_eq!(skills.len(), 1, "{body}");
        assert_eq!(skills[0]["id"], "planner");
        assert!(
            !agent.relayed(),
            "the extended card is busbar's, never relayed"
        );
    }
    /// A unit addressed to an agent nothing registered is a `404`, never dialled and charging
    /// nothing; it does not read as an out-of-scope one (that is the grant's refusal, in
    /// `an_agent_unit_outside_the_callers_grant_is_refused_before_it_dials`).
    /// Ported from busbar-a2a a2a/tests/inbound_tests.rs::an_unknown_agent_is_a_404_and_an_out_of_scope_one_says_so.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_unit_to_an_unregistered_agent_is_a_404() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-unregistered";
        let _published = Published(instance);
        let (port, mut heard) = far_agent().await;
        let s = served(instance, &agents(port, false), false, None);
        let (status, body) = answered(
            &s.router,
            rpc("nonexistent", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(
            !body.contains("scope_denied"),
            "an unregistered agent is not an out-of-scope one: {body}"
        );
        assert!(heard.try_recv().is_err(), "nothing was dialled");
        assert_eq!(admitted(&s), 0, "nothing charged");
    }

    /// A tripped agent refuses a fresh submission with `503` and a `Retry-After` of at least one
    /// second, on the JSON-RPC line and on the HTTP+JSON line, and never dials.
    /// PARTIAL PORT: predev also answered a `rejected` task with an id to poll; HEAD refuses before
    /// any task row exists, so that half is dropped.
    /// Ported from busbar-a2a a2a/tests/breaker_fastfail_tests.rs::a_tripped_agent_rejects_fresh_submissions_on_the_jsonrpc_binding
    /// and ::a_tripped_agent_rejects_fresh_submissions_on_the_httpjson_binding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tripped_agent_refuses_a_fresh_submission_with_503_and_retry_after() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-breaker-503";
        let _published = Published(instance);
        let mut agent = Agent::start(503, r#"{"error":"down"}"#).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let mut tripped = false;
        for _ in 0..32 {
            let (_, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            if body.contains("breaker_open") {
                tripped = true;
                break;
            }
        }
        assert!(tripped, "the breaker opened within 32 failing calls");
        agent.relayed();
        let rest = axum::http::Request::builder()
            .method("POST")
            .uri(format!("{}/message:send", mount()))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", s.token))
            .body(axum::body::Body::from(format!(
                r#"{{"message":{}}}"#,
                &SEND[11..SEND.len() - 1]
            )))
            .expect("a request");
        for (line, req) in [
            (
                "JSON-RPC",
                rpc("planner", "message/send", SEND, Some(&s.token)),
            ),
            ("HTTP+JSON", rest),
        ] {
            let response = s.router.clone().oneshot(req).await.expect("answers");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{line}");
            let wait: u64 = response
                .headers()
                .get("retry-after")
                .unwrap_or_else(|| panic!("{line}: no Retry-After"))
                .to_str()
                .expect("text")
                .parse()
                .expect("seconds");
            assert!(wait >= 1, "{line}: Retry-After {wait}");
            let body = axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .expect("body");
            let body = String::from_utf8_lossy(&body);
            assert!(body.contains("breaker_open"), "{line}: {body}");
            assert!(
                body.contains("agent `planner`"),
                "{line}: the refusal names the agent the unit was routed to: {body}"
            );
        }
        assert!(!agent.relayed(), "a tripped agent is never dialled");
    }

    /// THE EXTENDED CARD IS METERED: busbar answers it out of its own state, and it is still one
    /// admitted request on the presenting key, with no token accrual (a verb answered locally
    /// selects no upstream and relays no frame, so no per-request token fee can land on it).
    /// Ported from busbar-a2a a2a/tests/metered_verbs_tests.rs::the_catalogue_card_verb_is_metered_against_the_plane_pool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_extended_card_is_metered_as_one_request_and_no_tokens() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-extended-card-metered";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        assert_eq!(admitted(&s), 0, "nothing billed before the call");
        let (status, body) = answered(
            &s.router,
            rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the card is still answered: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        assert!(
            doc.get("result").is_some(),
            "the card verb must still return a card, not merely a bill: {body}"
        );
        let usage = s
            .gov
            .usage_for(&s.app.cost, &s.key.id, busbar_kernel::store::now())
            .expect("a read")
            .expect("the key exists");
        assert_eq!(usage.requests, 1, "one call, one request accrual");
        assert_eq!(usage.tokens, 0, "a locally answered verb accrues no tokens");
        assert!(
            !agent.relayed(),
            "the extended card is busbar's, never relayed"
        );
    }

    // ── PORTED FROM busbar-a2a (A2A-FLIP): what a caller of the deleted plane saw, on the door ────

    use busbar_contract::records::{ScopeRef, VirtualKey};

    /// The `message/stream` params the streamed cells send.
    const STREAM: &str = r#"{"message":{"kind":"message","messageId":"m-s","role":"user","contextId":"ctx-scan","parts":[{"kind":"text","text":"STREAM THE PLAN"}]}}"#;

    /// A far agent's answer in events: one frame carrying its finished task.
    const STREAMED: &str = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"kind\":\"task\",\"id\":\"B1\",\"contextId\":\"BC\",\"status\":{\"state\":\"completed\"}}}\n\n";

    /// The media type an answer in events is served as.
    const EVENTS: &str = "text/event-stream";

    /// The credential busbar itself presents to an agent (its `upstream_credential:`), as its
    /// secret file holds it.
    const LEASED: &str = "leased-outbound-cred-BUSBAR-PRESENTS-THIS-7f3a";

    /// The `upstream_credential:` pair presenting [`LEASED`] as a bearer: its secret a file under
    /// the system temp directory, written here, one per instance.
    fn leased(instance: &str) -> String {
        let path = std::env::temp_dir().join(format!("{instance}-{}.lease", std::process::id()));
        std::fs::write(&path, LEASED).expect("the lease's secret file");
        format!(
            "upstream_credential: {{secret: {{file: '{}'}}, lease_ttl_ms: 60000}}",
            path.display()
        )
    }

    /// Encodings a secret could plausibly be smuggled in. A scan that only looked for the
    /// plaintext would be defeated by `base64` and would say so with a green tick.
    fn encodings(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
        use base64::Engine as _;
        use sha2::Digest as _;
        vec![
            ("plain", secret.as_bytes().to_vec()),
            (
                "base64",
                base64::engine::general_purpose::STANDARD
                    .encode(secret)
                    .into_bytes(),
            ),
            (
                "base64url-nopad",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(secret)
                    .into_bytes(),
            ),
            ("hex", hex::encode(secret).into_bytes()),
            // "we only sent a hash of it" is still sending a value derived from a credential to a
            // party that has no business holding one.
            (
                "sha256-hex",
                hex::encode(sha2::Sha256::digest(secret.as_bytes())).into_bytes(),
            ),
        ]
    }

    /// Whether `needle` occurs in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Everything the far agent was sent since it was last asked, end to end.
    fn wire(agent: &mut Agent) -> Vec<u8> {
        let mut all = Vec::new();
        while let Ok(request) = agent.heard.try_recv() {
            all.extend_from_slice(request.as_bytes());
        }
        all
    }

    /// [`rpc`] presenting `value` in the head field `field` as its credential, and no bearer.
    fn rpc_presenting(
        agent: &str,
        method: &str,
        params: &str,
        field: &'static str,
        value: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let mut req = rpc(agent, method, params, None);
        req.headers_mut().insert(
            field,
            axum::http::HeaderValue::from_str(value).expect("a head value"),
        );
        req
    }

    /// The cell's own token's binding generation, as the book minted it.
    fn generation_of(s: &Served) -> Option<String> {
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        busbar_kernel::governance::signing::TokenVerifier::single(
            signer.kid(),
            signer.verifying_key(),
        )
        .verify(&s.token, 1_700_000_000, None)
        .expect("the cell's own token verifies")
        .generation
    }

    /// The cell's own key's token bound to the resource `audience` (RFC 8707), as the book's
    /// signing key mints one.
    fn bound_to(s: &Served, audience: &str) -> String {
        TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID).mint_for_audience(
            &s.key.id,
            4_000_000_000,
            generation_of(s).as_deref(),
            audience,
            None,
        )
    }

    /// The grant naming agent `agent`.
    fn agent_scope(agent: &str) -> ScopeRef {
        ScopeRef {
            kind: surface("scope_kind").to_string(),
            value: agent.to_string(),
        }
    }

    /// Another caller on `s`'s book: a key minted beside the cell's own, its grant then written as
    /// exactly `scopes` (`None` = every scope); its row and its token.
    fn another_caller(
        s: &Served,
        name: &str,
        scopes: Option<Vec<ScopeRef>>,
    ) -> (VirtualKey, String) {
        let (key, token) = s
            .gov
            .mint_signed(
                NewKeySpec {
                    name: name.to_string(),
                    allowed_pools: None,
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .expect("mint");
        let mut row = s
            .gov
            .store()
            .get_key(&key.id)
            .expect("a read")
            .expect("the key's row");
        row.allowed_scopes = scopes;
        s.gov.store().put_key(&row).expect("the grant is written");
        s.gov.refresh().expect("the book reloads");
        (row, token.expose_secret().to_string())
    }

    /// The agents busbar's extended card names for the caller presenting `token`: its status, and
    /// each skill's id, sorted.
    async fn agents_seen(s: &Served, token: &str) -> (StatusCode, Vec<String>) {
        let (status, body) = answered(
            &s.router,
            rpc("", "GetExtendedAgentCard", "{}", Some(token)),
        )
        .await;
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let mut ids: Vec<String> = doc["result"]["skills"]
            .as_array()
            .map(|skills| {
                skills
                    .iter()
                    .filter_map(|s| s["id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        (status, ids)
    }

    /// The `agents:` section registering `planner` and `scout` on `agent`, both pinned by its key.
    fn two_agents(agent: &Agent) -> String {
        format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scout", "1h")
        )
    }

    /// Ported from busbar-a2a ingress_tests.rs::no_agents_configured_means_no_route_in_the_table_at_all.
    ///
    /// THE GATE, asserted on the mounted surface: a deployment that writes no `agents:` section
    /// mounts not one route of the agent door — not under its mount, not its RFC 9728 document,
    /// not busbar's own card at the well-known path — and a keyed caller asking there reaches no
    /// agent. The control: the same door, its section written, mounts every one of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deployment_writing_no_agents_section_mounts_no_agent_route_at_all() {
        let _one = PUBLISHING.lock().await;
        let mut agent = Agent::start(200, ANSWER).await;
        let section = agent.entry("planner", "1h");
        let metadata = format!("/.well-known/oauth-protected-resource{}", mount());
        let card = "/.well-known/agent-card.json";
        let agent_routes = |routes: &[String]| -> Vec<String> {
            routes
                .iter()
                .filter(|p| p.starts_with(mount()) || **p == metadata || p.as_str() == card)
                .cloned()
                .collect()
        };

        let configured = "serve-agent-door-configured";
        let published = Published(configured);
        let s = served_facing(configured, &section, Facing::Routes);
        let mounted = agent_routes(&s.routes);
        assert!(
            mounted.contains(&metadata)
                && mounted.iter().any(|p| p == card)
                && mounted
                    .iter()
                    .any(|p| p.starts_with(&format!("{}/agents", mount()))),
            "the control: a written section mounts the door's routes: {:?}",
            s.routes
        );
        drop(published);

        let absent = "serve-agent-door-unconfigured";
        let _published = Published(absent);
        let s = served_facing(absent, &section, Facing::Unconfigured);
        assert!(
            agent_routes(&s.routes).is_empty(),
            "a deployment with no `agents:` mounted an agent route: {:?}",
            s.routes
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "nothing serves it: {body}");
        let (status, body) = answered(&s.router, get(card, None)).await;
        assert_ne!(status, StatusCode::OK, "no card is served: {body}");
        assert!(!agent.relayed(), "no agent was dialled");
    }

    /// Ported from busbar-a2a ingress_tests.rs::an_anonymous_caller_is_refused_and_told_where_to_get_a_token.
    ///
    /// The refusal owes a machine-readable challenge naming the door's metadata document. Without
    /// it a conforming client has no entrance: it knows it was refused and not where to go.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_anonymous_caller_is_refused_and_told_where_to_get_a_token() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-anonymous";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served_facing(instance, &agent.entry("planner", "1h"), Facing::Admitted);
        let response = s
            .router
            .clone()
            .oneshot(rpc("planner", "message/send", SEND, None))
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let document = format!(
            "https://gw.example/.well-known/oauth-protected-resource{}",
            mount()
        );
        assert!(
            challenge.contains(&document),
            "the challenge does not name the door's metadata document: {challenge:?}"
        );
        assert!(!agent.relayed(), "a refused caller dials nothing");
    }

    /// Ported from busbar-a2a ingress_tests.rs::the_metadata_document_advertises_the_audience_the_verifier_demands.
    ///
    /// The RFC 9728 document is readable with no credential and advertises the very audience the
    /// door's admission demands, so a client that does what the document says obtains a token
    /// this server accepts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metadata_document_advertises_the_audience_the_verifier_demands() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-metadata";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served_facing(instance, &agent.entry("planner", "1h"), Facing::Admitted);
        approve(&s, "planner").await;
        let expected = s
            .app
            .planes
            .admission_for(&format!("{}/agents/planner", mount()))
            .expect("the door's claim is audience-bound")
            .audience
            .clone();
        // No credential presented, and that is the point: this route is open.
        let (status, body) = answered(
            &s.router,
            get(
                &format!("/.well-known/oauth-protected-resource{}", mount()),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("the document");
        assert_eq!(
            doc["resource"],
            expected.as_str(),
            "the document advertises an audience the verifier does not demand"
        );
        let token = bound_to(&s, doc["resource"].as_str().expect("its resource"));
        let (status, body) =
            answered(&s.router, rpc("planner", "tasks/list", "{}", Some(&token))).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a token bound to the advertised resource is admitted: {body}"
        );
    }

    /// Ported from busbar-a2a inbound_tests.rs::a_credential_of_another_kind_is_refused_with_401_and_never_names_a_backend.
    ///
    /// Only a busbar key for this resource admits a caller to an agent: the operator's credential
    /// (as a bearer or on its own carrier), a bearer busbar never minted, a basic credential and a
    /// key bound to another resource are each refused `401` before any agent is named or dialled,
    /// and the refusal names no backend.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_credential_of_another_kind_is_refused_with_401_and_never_names_a_backend() {
        use base64::Engine as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-other-kind";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let elsewhere = bound_to(&s, "https://other.example/resource");
        let basic = base64::engine::general_purpose::STANDARD.encode("delegator:secret");
        for (what, field, value) in [
            (
                "the operator credential as a bearer",
                "authorization",
                format!("Bearer {ADMIN_TOKEN}"),
            ),
            (
                "the operator credential on its own carrier",
                "x-admin-token",
                ADMIN_TOKEN.to_string(),
            ),
            (
                "a bearer busbar never minted",
                "authorization",
                "Bearer sk-not-a-busbar-key".to_string(),
            ),
            (
                "a basic credential",
                "authorization",
                format!("Basic {basic}"),
            ),
            (
                "a key bound to another resource",
                "authorization",
                format!("Bearer {elsewhere}"),
            ),
        ] {
            let (status, body) = answered(
                &s.router,
                rpc_presenting("planner", "message/send", SEND, field, &value),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
            assert!(
                !body.contains("127.0.0.1"),
                "{what}: the refusal named the backend: {body}"
            );
            assert!(!agent.relayed(), "{what}: no agent was dialled");
        }
        assert_eq!(admitted(&s), 0, "nothing was charged");
    }

    /// Ported from busbar-a2a relay_stream_tests.rs::the_callers_busbar_key_is_absent_from_the_stream_wire_too.
    ///
    /// The root cell `egress-auth × a2a-client` on the STREAMED hop: everything the agent is sent
    /// for a `message/stream` unit is scanned for the caller's busbar key in every encoding it
    /// could be smuggled in, and none is there; the control, that the scanner sees what IS
    /// forwarded: busbar's own leased credential for the agent is on the same wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_callers_busbar_key_is_absent_from_the_stream_wire_too() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-stream-scan";
        let _published = Published(instance);
        let mut agent = Agent::start_with(
            200,
            STREAMED,
            vec![("content-type", EVENTS.to_string())],
            None,
        )
        .await;
        agent.streams();
        let section = agent.entry_with("planner", "1h", &leased(instance));
        let s = served(instance, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/stream", STREAM, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "streamed through the door: {body}");
        assert!(
            body.contains("completed"),
            "the agent's event, relayed: {body}"
        );

        let wire = wire(&mut agent);
        assert!(wire.len() > 100, "the scan has nothing to scan");
        assert!(
            contains(&wire, b"STREAM THE PLAN"),
            "the streamed hop carried the caller's message"
        );
        for (encoding, bytes) in &encodings(&s.token) {
            assert!(
                !contains(&wire, bytes),
                "the caller's busbar key reached the agent on the STREAM path, as {encoding}"
            );
        }
        assert!(
            contains(&wire, LEASED.as_bytes()),
            "the control: the scanner must find the credential that IS legitimately forwarded"
        );
    }

    /// Ported from busbar-a2a relay_stream_tests.rs::a_stream_hop_that_fails_before_its_first_event_is_a_busbar_attributed_error.
    ///
    /// An approved agent that has gone down before its first event (the connection closed
    /// unanswered) is busbar's `502` to the caller, and the refusal names no backend endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stream_hop_that_fails_before_its_first_event_is_a_busbar_attributed_error() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-stream-down";
        let _published = Published(instance);
        let agent = Agent::start_with(
            200,
            STREAMED,
            vec![("content-type", EVENTS.to_string())],
            None,
        )
        .await;
        agent.streams();
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        // THE AGENT'S CARD IS FRESHLY VERIFIED, as the engine's cell held it (predev
        // tests/relay_harness.rs `approve_card`: approved over a cached card, no look due; predev
        // verbs.rs `approve` stamps no look, so the first call looks): one stream is served while
        // the agent is up, so the call below meets no look and its HOP is what fails.
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/stream", STREAM, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
        agent.go_down();
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/stream", STREAM, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(
            body.contains(surface("task_resource_type")),
            "the hop's task is named, failed as the engine's `fail_task` failed it: {body}"
        );
        assert!(
            !body.contains("127.0.0.1"),
            "the refusal named the backend endpoint: {body}"
        );
    }

    /// Ported from busbar-a2a catalogue_tests.rs::scope_decides_visibility_and_a_pool_only_key_sees_nothing.
    ///
    /// A key granted one agent sees that agent and no other; a key granted only a pool sees no
    /// agent at all (an explicit grant is exhaustive across every kind: cross-kind admission is
    /// fail-closed), and addressing one is refused before it dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scope_decides_visibility_and_a_pool_only_key_sees_nothing() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-visibility";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &two_agents(&agent), false, None);
        approve(&s, "planner").await;
        approve(&s, "scout").await;

        let (_, narrowed) = another_caller(&s, "narrowed", Some(vec![agent_scope("planner")]));
        assert_eq!(
            agents_seen(&s, &narrowed).await,
            (StatusCode::OK, vec!["planner".to_string()])
        );
        let (_, pool_only) = another_caller(&s, "pool-only", Some(vec![ScopeRef::pool("fast")]));
        assert_eq!(
            agents_seen(&s, &pool_only).await,
            (StatusCode::OK, Vec::new()),
            "cross-kind admission is fail-closed"
        );
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&pool_only)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(body.contains("scope_denied"), "{body}");
        assert!(!agent.relayed(), "nothing was dialled");
    }

    /// Ported from busbar-a2a catalogue_tests.rs::no_principal_sees_another_principals_agents.
    ///
    /// Two callers granted one agent each see disjoint, non-empty catalogues, and the addressed
    /// read agrees with the listing: naming the other's agent is refused with the scope reason,
    /// before it dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_principal_sees_another_principals_agents() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-principals";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &two_agents(&agent), false, None);
        approve(&s, "planner").await;
        approve(&s, "scout").await;

        let (_, alice) = another_caller(&s, "alice", Some(vec![agent_scope("planner")]));
        let (_, bob) = another_caller(&s, "bob", Some(vec![agent_scope("scout")]));
        let (status, alice_sees) = agents_seen(&s, &alice).await;
        assert_eq!(status, StatusCode::OK);
        let (status, bob_sees) = agents_seen(&s, &bob).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(alice_sees, vec!["planner".to_string()]);
        assert_eq!(bob_sees, vec!["scout".to_string()]);
        assert!(
            alice_sees.iter().all(|a| !bob_sees.contains(a)),
            "one principal's catalogue appeared in the other's: {alice_sees:?} / {bob_sees:?}"
        );

        for (who, token, theirs) in [("alice", &alice, "scout"), ("bob", &bob, "planner")] {
            let (status, body) =
                answered(&s.router, rpc(theirs, "message/send", SEND, Some(token))).await;
            assert_ne!(status, StatusCode::OK, "{who} reached `{theirs}`: {body}");
            assert!(
                body.contains("scope_denied"),
                "{who}: refused for scope: {body}"
            );
            assert!(!agent.relayed(), "{who}: nothing was dialled");
        }
    }

    /// Ported from busbar-a2a catalogue_tests.rs::a_key_that_is_no_longer_live_sees_no_agent_at_all.
    ///
    /// A key deleted, disabled or expired sees no agent at all: its catalogue read and an
    /// addressed unit are each refused `401`, and nothing is dialled. The control: a live key of
    /// the same grant sees both agents.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_that_is_no_longer_live_sees_no_agent_at_all() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-not-live";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &two_agents(&agent), false, None);
        approve(&s, "planner").await;
        approve(&s, "scout").await;
        assert_eq!(
            agents_seen(&s, &s.token).await,
            (
                StatusCode::OK,
                vec!["planner".to_string(), "scout".to_string()]
            ),
            "the control must pass, or the rows below prove nothing"
        );

        for what in ["deleted", "disabled", "expired"] {
            let (key, token) = another_caller(&s, what, None);
            match what {
                "deleted" => s.gov.delete_key(&key.id).expect("deleted"),
                "disabled" => {
                    s.gov
                        .update_key(&key.id, Some(false), None)
                        .expect("a write")
                        .expect("the key");
                }
                _ => {
                    let mut row = key.clone();
                    row.expires_at = Some(1);
                    s.gov.store().put_key(&row).expect("expired");
                    s.gov.refresh().expect("the book reloads");
                }
            }
            let (status, seen) = agents_seen(&s, &token).await;
            assert_eq!(
                (status, seen),
                (StatusCode::UNAUTHORIZED, Vec::new()),
                "a {what} key must see no agent"
            );
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&token)),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
            assert!(!agent.relayed(), "{what}: nothing was dialled");
        }
    }

    /// Ported from busbar-a2a inbound_jws_tests.rs::the_seam_refuses_a_wrong_key_and_a_malformed_key_exactly_as_the_free_function
    /// (its wrong-key half, on the door's one verify path; the malformed key is the kernel's
    /// `trust_verify_tests::a_root_key_that_is_not_a_key_is_malformed_before_anything_else`).
    ///
    /// One signed card, fetched for two registrations: pinned to the key that signed it, it
    /// verifies (`pending`, its fingerprint, no failure); pinned to another key, `connect` reports
    /// 1.5.5's refusal, and the impostor registration is never served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_card_signed_by_another_key_than_the_pinned_one_is_refused_and_never_served() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-wrong-key";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let section = format!(
            "{}\nimpostor: {{url: 'http://127.0.0.1:{}/impostor', allow_private: true, \
             reverify_ttl: '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
            agent.entry("planner", "1h"),
            agent.port,
            key_info(&other)
        );
        let s = served(instance, &section, false, None);

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "pending", "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(
            preview["fingerprint"],
            agent.fingerprint().as_str(),
            "{preview}"
        );

        let (status, preview) = admin(&s, "/agents/impostor/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["state"], "error", "{preview}");
        assert!(
            preview["failure"].as_str().is_some_and(
                |f| f.contains("the agent card is signed, but not by the pinned issuer key")
            ),
            "{preview}"
        );
        let (status, body) = answered(
            &s.router,
            rpc("impostor", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(!agent.relayed(), "the impostor was never dialled");
    }

    /// THE AGENT'S OWN CREDENTIAL THROUGH THE DOOR (`upstream_credential:`): busbar's credential
    /// for a registration, bound by the composition, re-resolved on every hop and presented by the
    /// auth kind's per-request call (the plane never holds it); the door's public and verification
    /// card fetches waive it; a credential that stops resolving refuses each hop in the served
    /// engine's words (`receive.rs`, the `mint_from` arm, and `originate`).
    mod upstream_credential {
        use super::*;

        /// The far agent's answer to every relayed request: a task it is working on, under its own
        /// id, so busbar holds the task live and learns the agent's id for it.
        const WORKING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"far-1","contextId":"far-c","status":{"state":"working"}}}"#;

        /// AN AGENT THAT KEEPS EVERY REQUEST IT IS SENT, WHOLE — its card fetches included: it
        /// serves its card signed at its origin's well-known path and answers anything else
        /// `answer`.
        struct Recorded {
            port: u16,
            issuer: ed25519_dalek::SigningKey,
            log: Arc<std::sync::Mutex<Vec<String>>>,
        }

        impl Recorded {
            async fn start(answer: &'static str) -> Self {
                let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
                let log = Arc::new(std::sync::Mutex::new(Vec::new()));
                let held = Arc::new(std::sync::Mutex::new(serde_json::Value::Null));
                let (served_card, signer, kept) =
                    (Arc::clone(&held), issuer.clone(), Arc::clone(&log));
                let (port, _heard) = far_end_over(
                    Arc::new(move |request: &str| {
                        kept.lock().expect("the log").push(request.to_string());
                        if request.starts_with("GET ") {
                            let doc = served_card.lock().map(|c| c.clone()).unwrap_or_default();
                            return Some(FarReply::of(200, signed(&doc, &signer).to_string()));
                        }
                        Some(FarReply::of(200, answer.to_string()))
                    }),
                    None,
                )
                .await;
                *held.lock().expect("the card") = card(port, "plans the work");
                Self { port, issuer, log }
            }

            /// The `agents:` entry registering `planner` here, pinned by its signing key,
            /// re-verified within `reverify_ttl`, stating `upstream_credential` when given.
            fn entry(&self, reverify_ttl: &str, credential: Option<&str>) -> String {
                let credential = credential
                    .map(|c| format!(", upstream_credential: {c}"))
                    .unwrap_or_default();
                format!(
                    "planner: {{url: 'http://127.0.0.1:{}/planner', allow_private: true, \
                     reverify_ttl: '{reverify_ttl}', pin: {{mechanism: jws_issuer_key, key: \
                     '{}'}}{credential}}}",
                    self.port,
                    key_info(&self.issuer)
                )
            }

            /// Every request it was sent since it was last asked, in order.
            fn take(&self) -> Vec<String> {
                std::mem::take(&mut *self.log.lock().expect("the log"))
            }
        }

        /// The `upstream_credential` block over the secret file `path`, presented at `placement`.
        fn own(path: &std::path::Path, placement: &str) -> String {
            format!(
                "{{secret: {{file: '{}'}}, placement: {placement}, lease_ttl_ms: 60000}}",
                path.display()
            )
        }

        /// A secret file of this cell's own, holding `value`.
        fn secret_file(name: &str, value: &str) -> std::path::PathBuf {
            let path = std::env::temp_dir().join(format!(
                "busbar-serve-agent-cred-{name}-{}",
                std::process::id()
            ));
            std::fs::write(&path, value).expect("write the secret");
            path
        }

        /// ROTATE the secret at `path` to `value` as a secret store does: written aside, renamed
        /// over it.
        fn rotate(path: &std::path::Path, value: &str) {
            let aside = path.with_extension("rotating");
            std::fs::write(&aside, value).expect("write the rotated secret");
            std::fs::rename(&aside, path).expect("swap it in");
        }

        /// The value of head field `name` in the whole request `request` (case-insensitive).
        fn header(request: &str, name: &str) -> Option<String> {
            let head = request.split("\r\n\r\n").next()?;
            head.lines().skip(1).find_map(|line| {
                let (n, v) = line.split_once(':')?;
                n.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().to_string())
            })
        }

        /// The card fetches (`GET`) and the other requests (`POST`) of `log`.
        fn split(log: Vec<String>) -> (Vec<String>, Vec<String>) {
            log.into_iter().partition(|r| r.starts_with("GET "))
        }

        /// Every card fetch in `gets` carries no credential at all.
        fn no_credential_on(gets: &[String], at: &str) {
            for get in gets {
                assert_eq!(header(get, "authorization"), None, "{at}: {get}");
                assert_eq!(header(get, "x-api-key"), None, "{at}: {get}");
            }
        }

        /// The busbar task id a relayed answer names.
        fn task_of(body: &str) -> String {
            let doc: serde_json::Value = serde_json::from_str(body).expect("an answer");
            doc["result"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("no task in {body}"))
                .to_string()
        }

        /// `placement: bearer`: the agent's relayed hop, its extended card read through the relay,
        /// and busbar's own originated requests (the `ListTasks` refresh, the push-config mirror)
        /// each carry `authorization: Bearer <secret>`; the door's card fetches — `connect`'s look
        /// and verify-on-call's (`reverify_ttl: 0s`, so every hop re-fetches) — carry NONE (the
        /// waiver: predev fetched cards with no credential).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn the_agents_own_bearer_rides_its_hops_and_never_its_card_fetches() {
            let _one = PUBLISHING.lock().await;
            let instance = "serve-agent-cred-bearer";
            let _published = Published(instance);
            let path = secret_file("bearer", "vendor-token-1\n");
            let agent = Recorded::start(WORKING).await;
            let s = served(
                instance,
                &agent.entry("0s", Some(&own(&path, "bearer"))),
                false,
                None,
            );
            approve(&s, "planner").await;
            let (gets, posts) = split(agent.take());
            assert!(!gets.is_empty(), "connect fetched the card");
            assert!(posts.is_empty(), "{posts:?}");
            no_credential_on(&gets, "connect's card fetch");

            let bearer = Some("Bearer vendor-token-1".to_string());
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let task = task_of(&body);
            let (gets, posts) = split(agent.take());
            assert!(!gets.is_empty(), "verify-on-call re-fetched the card");
            no_credential_on(&gets, "verify-on-call's card fetch");
            assert_eq!(posts.len(), 1, "{posts:?}");
            assert_eq!(header(&posts[0], "authorization"), bearer, "{}", posts[0]);
            assert!(
                !posts[0].contains(&s.token),
                "never the caller's token: {}",
                posts[0]
            );

            let (status, body) = answered(
                &s.router,
                rpc("planner", "GetExtendedAgentCard", "{}", Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (gets, posts) = split(agent.take());
            no_credential_on(&gets, "verify-on-call's card fetch");
            assert_eq!(posts.len(), 1, "the extended card, relayed: {posts:?}");
            assert!(posts[0].contains("GetExtendedAgentCard"), "{}", posts[0]);
            assert_eq!(header(&posts[0], "authorization"), bearer, "{}", posts[0]);

            let (status, body) = answered(
                &s.router,
                rpc("planner", "tasks/list", "{}", Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (_, posts) = split(agent.take());
            assert!(
                posts.iter().any(|p| p.contains("ListTasks")),
                "busbar refreshed the agent's task list: {posts:?}"
            );
            for post in &posts {
                assert_eq!(header(post, "authorization"), bearer, "{post}");
            }

            let set = format!(
                r#"{{"taskId":"{task}","pushNotificationConfig":{{"url":"https://93.184.215.14/cb"}}}}"#
            );
            let (status, body) = answered(
                &s.router,
                rpc(
                    "planner",
                    "tasks/pushNotificationConfig/set",
                    &set,
                    Some(&s.token),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (_, posts) = split(agent.take());
            assert!(
                posts
                    .iter()
                    .any(|p| p.contains("CreateTaskPushNotificationConfig")),
                "busbar mirrored its own callback onto the agent: {posts:?}"
            );
            for post in &posts {
                assert_eq!(header(post, "authorization"), bearer, "{post}");
            }
            let _ = std::fs::remove_file(&path);
        }

        /// `placement: {header: X-API-Key}`: the relayed hop carries the secret verbatim in that
        /// header and no `authorization`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_named_header_placement_carries_the_secret_verbatim() {
            let _one = PUBLISHING.lock().await;
            let instance = "serve-agent-cred-header";
            let _published = Published(instance);
            let path = secret_file("header", "abc123");
            let agent = Recorded::start(WORKING).await;
            let s = served(
                instance,
                &agent.entry("1h", Some(&own(&path, "{header: X-API-Key}"))),
                false,
                None,
            );
            approve(&s, "planner").await;
            no_credential_on(&split(agent.take()).0, "connect's card fetch");
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (_, posts) = split(agent.take());
            assert_eq!(posts.len(), 1, "{posts:?}");
            assert_eq!(
                header(&posts[0], "x-api-key").as_deref(),
                Some("abc123"),
                "{}",
                posts[0]
            );
            assert_eq!(header(&posts[0], "authorization"), None, "{}", posts[0]);
            let _ = std::fs::remove_file(&path);
        }

        /// R5 (coordinator ruling: as predev): an agent registered with NO `upstream_credential` is
        /// dialled unauthenticated — no credential header on any request, card fetch or hop.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_agent_with_no_upstream_credential_is_dialled_with_none() {
            let _one = PUBLISHING.lock().await;
            let instance = "serve-agent-cred-none";
            let _published = Published(instance);
            let agent = Recorded::start(WORKING).await;
            let s = served(instance, &agent.entry("1h", None), false, None);
            approve(&s, "planner").await;
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let (gets, posts) = split(agent.take());
            assert_eq!(posts.len(), 1, "{posts:?}");
            no_credential_on(&gets, "a card fetch");
            no_credential_on(&posts, "the relayed hop");
        }

        /// ROTATION: the secret's source changes between two hops; the very next hop presents the
        /// new value (re-resolved per hop, as predev minted a lease per hop).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_rotated_secret_is_presented_on_the_very_next_hop() {
            let _one = PUBLISHING.lock().await;
            let instance = "serve-agent-cred-rotate";
            let _published = Published(instance);
            let path = secret_file("rotate", "before-rotation");
            let agent = Recorded::start(WORKING).await;
            let s = served(
                instance,
                &agent.entry("1h", Some(&own(&path, "bearer"))),
                false,
                None,
            );
            approve(&s, "planner").await;
            let _ = agent.take();
            for value in ["before-rotation", "after-rotation"] {
                rotate(&path, value);
                let (status, body) = answered(
                    &s.router,
                    rpc("planner", "message/send", SEND, Some(&s.token)),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                let (_, posts) = split(agent.take());
                assert_eq!(posts.len(), 1, "{posts:?}");
                assert_eq!(
                    header(&posts[0], "authorization"),
                    Some(format!("Bearer {value}")),
                    "{}",
                    posts[0]
                );
            }
            let _ = std::fs::remove_file(&path);
        }

        /// A CREDENTIAL THAT STOPS RESOLVING (its secret file removed) refuses every hop, in the
        /// served engine's bytes, and dials nothing:
        ///
        /// * a relayed task hop: `502`, `-32006` "the backend agent did not complete this task"
        ///   naming the task (`fail_task`), and the task row is closed `failed`;
        /// * the extended card read through the relay: `502`, `-32006` "the extended agent card
        ///   could not be fetched", naming no task;
        /// * busbar's own originated requests (the `ListTasks` refresh, the push-config mirror): no
        ///   hop at all (`originate` returned none), the caller's own answer unchanged (`200`).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_vanished_secret_refuses_each_hop_in_the_engines_words() {
            let _one = PUBLISHING.lock().await;
            let instance = "serve-agent-cred-vanished";
            let _published = Published(instance);
            let path = secret_file("vanished", "soon-gone");
            let agent = Recorded::start(WORKING).await;
            let s = served(
                instance,
                &agent.entry("1h", Some(&own(&path, "bearer"))),
                false,
                None,
            );
            approve(&s, "planner").await;
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "served while it resolves: {body}");
            let live = task_of(&body);
            std::fs::remove_file(&path).expect("the secret vanishes");
            let _ = agent.take();

            let info = serde_json::json!({
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "domain": surface("error_info_domain"),
                "reason": "INVALID_AGENT_RESPONSE",
            });
            let (status, body) = answered(
                &s.router,
                rpc("planner", "message/send", SEND, Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
            let doc: serde_json::Value = serde_json::from_str(&body).expect("the envelope");
            let failed = doc["error"]["data"][1]["resourceName"]
                .as_str()
                .unwrap_or_else(|| panic!("the refusal names its task: {body}"))
                .to_string();
            assert_eq!(
                doc,
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                    "code": -32006,
                    "message": "the backend agent did not complete this task",
                    "data": [info.clone(), {
                        "@type": "type.googleapis.com/google.rpc.ResourceInfo",
                        "resourceType": surface("task_resource_type"),
                        "resourceName": failed,
                    }],
                } }),
                "{body}"
            );
            let (status, body) = answered(
                &s.router,
                rpc(
                    "planner",
                    "tasks/get",
                    &format!(r#"{{"id":"{failed}"}}"#),
                    Some(&s.token),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let row: serde_json::Value = serde_json::from_str(&body).expect("the task");
            assert_eq!(
                row["result"]["status"]["state"], "failed",
                "the task row is closed failed: {body}"
            );

            let (status, body) = answered(
                &s.router,
                rpc("planner", "GetExtendedAgentCard", "{}", Some(&s.token)),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).expect("the envelope"),
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": {
                    "code": -32006,
                    "message": "the extended agent card could not be fetched",
                    "data": [info],
                } }),
                "{body}"
            );

            let (status, body) = answered(
                &s.router,
                rpc("planner", "tasks/list", "{}", Some(&s.token)),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "the caller's own answer stands: {body}"
            );
            let set = format!(
                r#"{{"taskId":"{live}","pushNotificationConfig":{{"url":"https://93.184.215.14/cb"}}}}"#
            );
            let (status, body) = answered(
                &s.router,
                rpc(
                    "planner",
                    "tasks/pushNotificationConfig/set",
                    &set,
                    Some(&s.token),
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "the caller's own answer stands: {body}"
            );
            assert_eq!(
                agent.take(),
                Vec::<String>::new(),
                "no hop reached the agent"
            );
        }
    }

    /// One length-prefixed message (`frame`'s bytes), as a gRPC far end writes it.
    fn grpc_framed(message: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
        out.extend_from_slice(message);
        out
    }

    /// A send's answer, its protobuf written out field by field: a task (field 1) whose id
    /// (field 1) is `far-task` and whose status (field 3) is working (state field 1, `2`).
    fn grpc_working_answer() -> Vec<u8> {
        let status = [0x08, 0x02];
        let mut task = vec![0x0a, 8];
        task.extend_from_slice(b"far-task");
        task.extend_from_slice(&[0x1a, 2]);
        task.extend_from_slice(&status);
        let mut answer = vec![0x0a, u8::try_from(task.len()).expect("small")];
        answer.extend_from_slice(&task);
        grpc_framed(&answer)
    }

    /// A gRPC AGENT ON LOOPBACK, pinned by its signing key: its card (naming only the gRPC binding)
    /// at its origin's well-known path over HTTP/1.1, and every rpc on the same port over HTTP/2
    /// (prior knowledge), each answered `answer` (one length-prefixed message) with `grpc-status:
    /// 0` in the trailers. Each rpc's path and request bytes come back on `heard`.
    struct GrpcAgent {
        port: u16,
        heard: tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
        issuer: ed25519_dalek::SigningKey,
    }

    impl GrpcAgent {
        async fn start(answer: Vec<u8>) -> Self {
            use http_body_util::BodyExt as _;
            type Frames = Vec<Result<http_body::Frame<bytes::Bytes>, std::convert::Infallible>>;
            let issuer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port");
            let port = listener.local_addr().expect("its address").port();
            let mut held = card(port, "plans the work");
            held["supportedInterfaces"] = serde_json::json!([{
                "url": format!("http://127.0.0.1:{port}/planner"),
                "protocolBinding": surface("grpc_binding"),
                "protocolVersion": "1.0",
            }]);
            let served = signed(&held, &issuer).to_string();
            let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let (sent, served, answer) = (sent.clone(), served.clone(), answer.clone());
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(
                            move |req: hyper::Request<hyper::body::Incoming>| {
                                let (sent, served, answer) =
                                    (sent.clone(), served.clone(), answer.clone());
                                async move {
                                    let get = req.method() == hyper::Method::GET;
                                    let path = req.uri().path().to_string();
                                    let body = req
                                        .into_body()
                                        .collect()
                                        .await
                                        .map(|c| c.to_bytes().to_vec())
                                        .unwrap_or_default();
                                    let (media, frames): (&str, Frames) = if get {
                                        (
                                            "application/json",
                                            vec![Ok(http_body::Frame::data(bytes::Bytes::from(
                                                served,
                                            )))],
                                        )
                                    } else {
                                        let _ = sent.send((path, body));
                                        let mut trailers = http::HeaderMap::new();
                                        trailers.insert(
                                            "grpc-status",
                                            http::HeaderValue::from_static("0"),
                                        );
                                        (
                                            "application/grpc",
                                            vec![
                                                Ok(http_body::Frame::data(bytes::Bytes::from(
                                                    answer,
                                                ))),
                                                Ok(http_body::Frame::trailers(trailers)),
                                            ],
                                        )
                                    };
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", media)
                                        .body(http_body_util::StreamBody::new(
                                            futures::stream::iter(frames),
                                        ))
                                }
                            },
                        );
                        let _ = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                        .await;
                    });
                }
            });
            Self {
                port,
                heard,
                issuer,
            }
        }

        /// The `agents:` entry registering `name` at this agent's path `/<name>`, pinned by its
        /// signing key.
        fn entry(&self, name: &str) -> String {
            format!(
                "{name}: {{url: 'http://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
                 '1h', pin: {{mechanism: jws_issuer_key, key: '{}'}}}}",
                self.port,
                key_info(&self.issuer)
            )
        }
    }

    /// THE DOOR DIALS A gRPC AGENT (the engine's `grpc_client_issues_send_message`, end to end
    /// through the composition): an agent whose card names only the gRPC binding is approved over
    /// its card (HTTP/1.1, on the agent's own need), and a relayed `SendMessage` reaches it over
    /// HTTP/2 on the door's gRPC need, which its registration rides: the rpc's own path under the
    /// service, one length-prefixed request message carrying the caller's content; the agent's
    /// answer message reaches the caller as the JSON-RPC result, under busbar's task identity. RED:
    /// the card was unspeakable and the hop refused by name, never dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_whose_card_names_only_grpc_is_dialled_over_grpc() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-grpc";
        let _published = Published(instance);
        let mut agent = GrpcAgent::start(grpc_working_answer()).await;
        let s = served(instance, &agent.entry("planner"), false, None);
        approve(&s, "planner").await;
        let params = r#"{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"PLAN THE MIGRATION"}]}}"#;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "SendMessage", params, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (path, sent) = agent
            .heard
            .try_recv()
            .unwrap_or_else(|_| panic!("the agent was not dialled over gRPC: {body}"));
        assert_eq!(path, format!("{}/SendMessage", surface("grpc_service")));
        assert!(sent.len() > 5, "a length-prefixed message: {sent:?}");
        assert_eq!(sent[0], 0, "no compression");
        let len = u32::from_be_bytes([sent[1], sent[2], sent[3], sent[4]]) as usize;
        assert_eq!(sent.len(), 5 + len, "exactly one length-prefixed message");
        let content = b"PLAN THE MIGRATION";
        assert!(
            sent.windows(content.len()).any(|w| w == content),
            "the caller's content survives the transcode into the request message"
        );
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        assert_eq!(doc["id"], 1);
        assert_eq!(
            doc["result"]["task"]["status"]["state"], "TASK_STATE_WORKING",
            "{body}"
        );
        assert_ne!(
            doc["result"]["task"]["id"], "far-task",
            "the answer leaves under busbar's task identity: {body}"
        );
    }

    /// The far agent's own id for the task the port cells open.
    const FAR_TASK: &str = "far-task";

    /// An agent's answer to `request` (its whole text) for the port cells: a send is answered
    /// with its own task in `send_state`, busbar's registration with that registration, and a
    /// `ListTasks` with its own task in `listed_state`.
    fn far_answer(request: &str, send_state: &str, listed_state: &str) -> String {
        let originated = |result: serde_json::Value| {
            serde_json::json!({ "jsonrpc": "2.0", "id": "busbar-originated", "result": result })
                .to_string()
        };
        if request.contains("\"CreateTaskPushNotificationConfig\"") {
            return originated(serde_json::json!({ "taskId": FAR_TASK, "id": "busbar-far-task" }));
        }
        if request.contains("\"ListTasks\"") {
            return originated(serde_json::json!({ "tasks": [
                { "id": FAR_TASK, "status": { "state": listed_state } }
            ] }));
        }
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {
            "kind": "task", "id": FAR_TASK, "contextId": "far-context",
            "status": { "state": send_state }
        } })
        .to_string()
    }

    /// Open one task on `planner` with the cells' `message/send`: busbar's id for it.
    async fn open_task(s: &Served) -> String {
        let (status, body) = answered(
            &s.router,
            rpc("planner", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the submission is served: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        let id = doc["result"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("the submission answered no task id: {body}"))
            .to_string();
        assert_ne!(id, FAR_TASK, "busbar's own id: {body}");
        id
    }

    /// The caller's own registration of its webhook on `task`.
    fn create_config(task: &str) -> String {
        serde_json::json!({
            "taskId": task, "id": "caller-config", "url": "https://1.1.1.1/hook",
            "authentication": { "scheme": "Bearer", "credentials": "caller-secret" },
        })
        .to_string()
    }

    /// Every request the agent was sent since last asked, whole.
    fn heard(agent: &mut Agent) -> Vec<String> {
        let mut heard = Vec::new();
        while let Ok(request) = agent.heard.try_recv() {
            heard.push(request);
        }
        heard
    }

    /// The capability busbar registered with the agent, read off the registration it sent (never
    /// minted by the test).
    fn token_sent(requests: &[String]) -> String {
        let create = requests
            .iter()
            .find(|r| r.contains("\"CreateTaskPushNotificationConfig\""))
            .unwrap_or_else(|| panic!("busbar registered nothing with the agent: {requests:?}"));
        let body = create.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        let doc: serde_json::Value = serde_json::from_str(body).expect("a JSON-RPC request");
        doc["params"]["authentication"]["credentials"]
            .as_str()
            .unwrap_or_else(|| panic!("the registration carried no capability: {doc}"))
            .to_string()
    }

    /// An agent's report that its task is now `state`, to busbar's own callback, bearing `token`.
    fn push(token: &str, state: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(surface("push_path"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(
                serde_json::json!({ "id": FAR_TASK, "kind": "task", "status": { "state": state } })
                    .to_string(),
            ))
            .expect("a request")
    }

    /// The state the caller's own list shows for `task`.
    async fn listed_state(s: &Served, task: &str) -> String {
        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the list is served: {body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        doc["result"]["tasks"]
            .as_array()
            .and_then(|tasks| tasks.iter().find(|t| t["id"] == task))
            .and_then(|t| t["status"]["state"].as_str())
            .unwrap_or_else(|| panic!("the caller's own task is not in its own list: {body}"))
            .to_string()
    }

    /// `the_refreshed_state_reaches_the_callers_own_list` (the engine's client-leg cell): the agent
    /// moved the task on out of band, and the caller's next list says so, because busbar asked the
    /// agent (`ListTasks`) for the rows it holds there before answering.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_refreshed_state_reaches_the_callers_own_list() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-refresh";
        let _published = Published(instance);
        let mut agent = Agent::start_answering(
            200,
            Arc::new(|r: &str| far_answer(r, "working", "completed")),
        )
        .await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let task = open_task(&s).await;
        let _ = heard(&mut agent);
        let state = listed_state(&s, &task).await;
        assert!(
            heard(&mut agent)
                .iter()
                .any(|r| r.contains("\"ListTasks\"")),
            "busbar asked the agent for the rows it holds there"
        );
        assert!(
            ["completed", "TASK_STATE_COMPLETED"].contains(&state.as_str()),
            "the state the agent reported reaches the caller's list: {state}"
        );
    }

    /// `a_list_with_no_open_task_of_this_callers_makes_no_hop` (the engine's client-leg cell): a
    /// caller with nothing live on the agent asks the agent nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_list_with_no_open_task_of_this_callers_makes_no_hop() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-list-no-hop";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("planner", "tasks/list", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !agent.relayed(),
            "busbar made a hop for a caller with no open task on the agent"
        );
    }

    /// `a_terminal_task_is_not_armed_at_the_backend` (the engine's pushback cell): the caller's own
    /// registration on a task busbar holds as terminal is still busbar's to accept, and busbar
    /// registers nothing with the agent for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_terminal_task_is_not_armed_at_the_backend() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-terminal-unarmed";
        let _published = Published(instance);
        let mut agent = Agent::start_answering(
            200,
            Arc::new(|r: &str| far_answer(r, "completed", "completed")),
        )
        .await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let task = open_task(&s).await;
        let _ = heard(&mut agent);
        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "CreateTaskPushNotificationConfig",
                &create_config(&task),
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let sent = heard(&mut agent);
        assert!(
            sent.is_empty(),
            "busbar must make NO hop for a task it holds as terminal: {sent:?}"
        );
    }

    /// `a_token_is_not_spent_by_being_used_while_the_task_is_live` (the engine's pushback cell):
    /// busbar's capability for the task, read off the registration it sent the agent, admits every
    /// report while the task lives, its ending included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_is_not_spent_by_being_used_while_the_task_is_live() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-token-live";
        let _published = Published(instance);
        let mut agent =
            Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working")))
                .await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let task = open_task(&s).await;
        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "CreateTaskPushNotificationConfig",
                &create_config(&task),
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = token_sent(&heard(&mut agent));
        for state in ["input-required", "working", "completed"] {
            let (status, body) = answered(&s.router, push(&token, state)).await;
            assert_eq!(
                status,
                StatusCode::ACCEPTED,
                "the token was refused for `{state}` on a task that had not ended: {body}"
            );
        }
    }

    /// `a_token_for_a_task_that_has_ended_authorises_nothing` (the engine's pushback cell): the
    /// agent's report of the ending is taken; a replay of it, or a report of another terminal state,
    /// is `401`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_for_a_task_that_has_ended_authorises_nothing() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-token-ended";
        let _published = Published(instance);
        let mut agent =
            Agent::start_answering(200, Arc::new(|r: &str| far_answer(r, "working", "working")))
                .await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let task = open_task(&s).await;
        let (status, body) = answered(
            &s.router,
            rpc(
                "planner",
                "CreateTaskPushNotificationConfig",
                &create_config(&task),
                Some(&s.token),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = token_sent(&heard(&mut agent));
        let (status, body) = answered(&s.router, push(&token, "completed")).await;
        assert_eq!(status, StatusCode::ACCEPTED, "the ending is taken: {body}");
        for state in ["completed", "failed"] {
            let (status, body) = answered(&s.router, push(&token, state)).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "a token for an ended task authorised a `{state}` report: {body}"
            );
        }
    }

    // ── PORTED FROM THE ENGINE'S `serve_tests`, `sign_tests` AND `relay_leg_metrics_tests` ─────────

    /// Ported from busbar-a2a a2a/tests/serve_tests.rs::an_agent_outside_this_callers_catalogue_appears_nowhere_in_the_extended_card.
    /// Two agents are configured and only one is approved: the one outside the caller's catalogue
    /// is named nowhere in the serialised extended card (checked over the whole document, because
    /// the hazard is a member nobody thought to check).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_agent_outside_this_callers_catalogue_appears_nowhere_in_the_extended_card() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-extended-outside";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let section = format!(
            "{}\n{}",
            agent.entry("planner", "1h"),
            agent.entry("scheduler", "1h")
        );
        let s = served(instance, &section, false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        let ids: Vec<&str> = doc["result"]["skills"]
            .as_array()
            .expect("skills")
            .iter()
            .filter_map(|k| k["id"].as_str())
            .collect();
        assert_eq!(ids, ["planner"], "{body}");
        assert!(body.contains("planner"), "{body}");
        assert!(
            !body.contains("scheduler"),
            "an agent outside this caller's catalogue is named in its extended card: {body}"
        );
        assert!(
            !agent.relayed(),
            "the extended card is busbar's, never relayed"
        );
    }

    /// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_caller_entitled_to_no_agent_gets_an_empty_extended_card_rather_than_a_refusal.
    /// A caller whose grant names no agent gets a card with nothing in it, not a refusal: "you may
    /// reach no agent here" is a statement about the caller, while the refusal is reserved for a
    /// deployment that fronts nothing at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_entitled_to_no_agent_gets_an_empty_extended_card_rather_than_a_refusal() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-extended-empty";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(
            instance,
            &agent.entry("planner", "1h"),
            false,
            Some(Vec::new()),
        );
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            rpc("", "GetExtendedAgentCard", "{}", Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let doc: serde_json::Value = serde_json::from_str(&body).expect("an answer");
        assert_eq!(doc["result"]["skills"], serde_json::json!([]), "{body}");
        assert_eq!(doc["result"]["capabilities"]["extendedAgentCard"], true);
        assert!(!body.contains("planner"), "{body}");
        assert!(
            !agent.relayed(),
            "the extended card is busbar's, never relayed"
        );
    }

    /// Verify `card`'s one signature as an outside caller does: the signing input is
    /// `protected.b64url(canonical card minus signatures)`, checked under busbar's published card
    /// key (the deployment's signer, derived for the door's signing domain).
    fn card_signature_verifies(card: &serde_json::Value) -> Result<String, &'static str> {
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let key = ed25519_dalek::SigningKey::from_bytes(
            &signer.derived_subkey_seed(surface("card_signing_domain")),
        )
        .verifying_key();
        let sig = card["signatures"].get(0).ok_or("no signature")?;
        let protected = sig["protected"].as_str().ok_or("no protected header")?;
        let raw: [u8; 64] = b64
            .decode(sig["signature"].as_str().ok_or("no signature value")?)
            .map_err(|_| "signature is not base64url")?
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let input = format!("{protected}.{}", b64.encode(signing_payload(card)));
        key.verify(
            input.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&raw),
        )
        .map_err(|_| "signature does not verify")?;
        let header: serde_json::Value =
            serde_json::from_slice(&b64.decode(protected).map_err(|_| "header")?)
                .map_err(|_| "header")?;
        Ok(header["kid"].as_str().unwrap_or_default().to_string())
    }

    /// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_signature_is_taken_over_the_document_that_is_actually_served.
    /// The fronted card as SERVED (busbar's endpoints and scheme, the backend nowhere in it) carries
    /// exactly one signature, it verifies under busbar's published key over that document, and one
    /// changed character breaks it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_signature_is_taken_over_the_document_that_is_actually_served() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-signed-card";
        let _published = Published(instance);
        let agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("planner", "1h"), false, None);
        approve(&s, "planner").await;
        let (status, body) = answered(
            &s.router,
            get(&format!("{}/agents/planner", mount()), Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let card: serde_json::Value = serde_json::from_str(&body).expect("a card");
        assert!(
            !body.contains(&format!("127.0.0.1:{}", agent.port)),
            "the backend must not appear in the served card at all: {body}"
        );
        assert_eq!(
            card["url"],
            format!("https://gw.example{}/agents/planner", mount()),
            "{body}"
        );
        assert!(card["securitySchemes"].get("busbarA2aInbound").is_some());
        assert_eq!(
            card["signatures"].as_array().map(Vec::len),
            Some(1),
            "the vendor's signature is gone and busbar's is the only one: {body}"
        );
        let kid = card_signature_verifies(&card)
            .unwrap_or_else(|why| panic!("the served card must verify: {why}: {body}"));
        assert!(kid.starts_with("busbar-a2a-card-"), "{kid}");

        let mut tampered = card.clone();
        let name = tampered["name"].as_str().expect("a name").to_string();
        tampered["name"] = serde_json::Value::String(format!("{name}x"));
        assert_eq!(
            card_signature_verifies(&tampered),
            Err("signature does not verify"),
            "the signature covers the document that is served"
        );
    }

    /// The exposition lines of `family` whose `pool` label is `pool` and `lane` label is `lane`.
    fn series_of(family: &str, pool: &str, lane: &str) -> Vec<String> {
        busbar_kernel::snapshot::render()
            .lines()
            .filter(|l| l.starts_with(&format!("{family}{{")))
            .filter(|l| l.contains(&format!("pool=\"{pool}\"")))
            .filter(|l| l.contains(&format!("lane=\"{lane}\"")))
            .map(str::to_string)
            .collect()
    }

    /// The sum of the values of `lines`.
    fn total(lines: &[String]) -> f64 {
        lines
            .iter()
            .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .sum()
    }

    /// Ported from busbar-a2a a2a/tests/relay_leg_metrics_tests.rs::a_relayed_task_counts_an_upstream_attempt_naming_the_agent_it_was_issued_to.
    /// A relayed agent unit counts `busbar_upstream_attempts_total{pool,lane}` with the agent it was
    /// issued to as its `pool` and the binding the hop went out on as its `lane`, as predev's cell
    /// held it (predev relay_leg_metrics_tests.rs:107 `pool="planner"`, :122
    /// `lane=WIRE_JSONRPC`), in the model plane's series shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_task_counts_an_upstream_attempt_naming_the_agent_it_was_issued_to() {
        busbar_kernel::snapshot::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-metered";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("metered", "1h"), false, None);
        approve(&s, "metered").await;
        let family = busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL;
        let jsonrpc = surface("binding_document");
        let before = total(&series_of(family, "metered", jsonrpc));
        let (status, body) = answered(
            &s.router,
            rpc("metered", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(agent.relayed(), "the unit reached the agent");
        let lines = series_of(family, "metered", jsonrpc);
        assert!(
            !lines.is_empty(),
            "a relayed unit left no `{family}` series naming the agent it was issued to and its \
             binding: {}",
            busbar_kernel::snapshot::render()
        );
        assert!(
            total(&lines) > before,
            "the relayed unit was not counted as an attempt: {lines:?}"
        );
        for line in &lines {
            assert!(
                line.contains("pool=\"") && !line.contains("disposition="),
                "the model plane's series shape is pool and lane alone: {line}"
            );
        }
    }

    /// Ported from busbar-a2a a2a/tests/relay_leg_metrics_tests.rs::a_backend_that_cannot_be_reached_is_counted_as_a_transient_upstream_failure.
    /// An agent that stops answering lands on `busbar_upstream_failures_total` under the model
    /// plane's own `transient` disposition, so a dead agent is not 100% healthy on a rate panel;
    /// its series names the agent as `pool` and the hop's binding as `lane` (predev
    /// relay_leg_metrics_tests.rs:157 `pool="planner"`; relay.rs:1737-1741).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_that_cannot_be_reached_is_counted_as_a_transient_upstream_failure() {
        busbar_kernel::snapshot::init();
        let _one = PUBLISHING.lock().await;
        let instance = "serve-agent-door-unreachable";
        let _published = Published(instance);
        let mut agent = Agent::start(200, ANSWER).await;
        let s = served(instance, &agent.entry("unreached", "1h"), false, None);
        approve(&s, "unreached").await;
        // THE AGENT'S CARD IS FRESHLY VERIFIED before it goes down: an approval does not stamp the
        // look (predev verbs.rs `approve`: the sighting and the cached card, no ledger stamp), so the
        // first call looks (predev receive.rs:1947 `verify_agent_on_call`, before the hop). One call
        // is served while the agent is up; the call below meets no look and its HOP is what fails,
        // as predev's cell (whose harness held no card fetcher) drove it.
        let (status, body) = answered(
            &s.router,
            rpc("unreached", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "served while it is up: {body}");
        assert!(agent.relayed(), "the warm call reached the agent");
        agent.go_down();
        let family = busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL;
        let jsonrpc = surface("binding_document");
        let before = total(&series_of(family, "unreached", jsonrpc));
        let (status, body) = answered(
            &s.router,
            rpc("unreached", "message/send", SEND, Some(&s.token)),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a hop that never reached the agent: {body}"
        );
        let lines = series_of(family, "unreached", jsonrpc);
        assert!(
            total(&lines) > before,
            "the backend was unreachable and left no `{family}` count for its lane: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains(&format!(
                "disposition=\"{}\"",
                busbar_kernel::proxy::DISPOSITION_TRANSIENT
            ))),
            "the failure carries the model plane's own disposition word: {lines:?}"
        );
        assert!(lines.iter().all(|l| l.contains("pool=\"")), "{lines:?}");
    }

    /// A CLIENT CERTIFICATE for registration `who`, issued by a root of its own: that root's DER
    /// (what the registration's peer admits), and the paths of the certificate and key it is
    /// written to as PEM files (what the registration's `client_identity:` references).
    fn client_identity_files(instance: &str, who: &str) -> (Vec<u8>, String, String) {
        let ca_key = rcgen::KeyPair::generate().expect("a key");
        let mut ca = rcgen::CertificateParams::new(Vec::new()).expect("params");
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = ca.self_signed(&ca_key).expect("the root").der().to_vec();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let key = rcgen::KeyPair::generate().expect("a key");
        let leaf = rcgen::CertificateParams::new(vec!["busbar.example".to_string()])
            .expect("params")
            .signed_by(&key, &issuer)
            .expect("the client leaf");
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("{instance}-{who}-cert.pem"));
        let key_path = dir.join(format!("{instance}-{who}-key.pem"));
        std::fs::write(&cert_path, leaf.pem()).expect("the certificate file");
        std::fs::write(&key_path, key.serialize_pem()).expect("the key file");
        (
            root,
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        )
    }

    /// The `agents:` entry registering `name` at `agent`'s secure path, pinned at the transport by
    /// `mtls` to the far end's key `pin`, presenting the certificate and key in the two PEM files.
    fn mutual_entry(agent: &Agent, name: &str, pin: &str, cert: &str, key: &str) -> String {
        format!(
            "{name}: {{url: 'https://127.0.0.1:{}/{name}', allow_private: true, reverify_ttl: \
             '1h', pin: {{mechanism: mtls, key: '{pin}'}}, client_identity: {{cert: {{file: \
             '{cert}'}}, key: {{file: '{key}'}}}}}}",
            agent.port
        )
    }

    /// Ported from busbar-a2a a2a/tests/transport_mutual_tls_tests.rs::the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate.
    /// `connect` (the verb layer's card look) reaches a mutual-TLS vendor with THAT registration's
    /// client certificate: the peer admits one client root only, the registration's own certificate
    /// chains to it, and the card comes back sighted. The control is the same peer registered with
    /// no client identity, which the peer refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate(
    ) {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mtls-probe";
        let _published = Published(instance);
        let tls = AgentTls::new();
        let pin = tls.rekey();
        let (client_root, cert, key) = client_identity_files(instance, "planner");
        let agent = Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&client_root))).await;
        let section = format!(
            "{}\n{}",
            mutual_entry(&agent, "planner", &pin, &cert, &key),
            agent.entry_pinned("bare", "cert_spki", &pin)
        );
        let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

        let (status, preview) = admin(&s, "/agents/planner/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["failure"], serde_json::Value::Null, "{preview}");
        assert_eq!(preview["state"], "pending", "{preview}");
        assert_eq!(preview["pin_mechanism"], "mtls", "{preview}");
        assert_eq!(
            preview["fingerprint"],
            agent.fingerprint().as_str(),
            "the card came back whole and sighted: {preview}"
        );

        let (status, bare) = admin(&s, "/agents/bare/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{bare}");
        assert!(
            bare["failure"].is_string(),
            "a registration presenting no certificate is refused by the mutual-TLS peer: {bare}"
        );
        assert_eq!(bare["state"], "error", "{bare}");
        let _ = (std::fs::remove_file(&cert), std::fs::remove_file(&key));
    }

    /// Ported from busbar-a2a a2a/tests/transport_mutual_tls_tests.rs::each_registration_presents_its_own_certificate_and_not_another_registrations.
    /// Two registrations, two client certificates, two peers that each admit only their own
    /// registration's client root: each registration is admitted at its own peer, and a third
    /// presenting the other's certificate at the first peer is refused, so the certificate each hop
    /// carries is its own registration's and never another's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_registration_presents_its_own_certificate_and_not_another_registrations() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-mtls-isolation";
        let _published = Published(instance);
        let tls = AgentTls::new();
        let pin = tls.rekey();
        let (planner_root, planner_cert, planner_key) = client_identity_files(instance, "planner");
        let (payments_root, payments_cert, payments_key) =
            client_identity_files(instance, "payments");
        let planner_peer =
            Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&planner_root))).await;
        let payments_peer =
            Agent::start_over(200, ANSWER, Some(tls.mutual_acceptor(&payments_root))).await;
        let section = [
            mutual_entry(&planner_peer, "planner", &pin, &planner_cert, &planner_key),
            mutual_entry(
                &payments_peer,
                "payments",
                &pin,
                &payments_cert,
                &payments_key,
            ),
            // The payments certificate, at the planner's peer.
            mutual_entry(
                &planner_peer,
                "stranger",
                &pin,
                &payments_cert,
                &payments_key,
            ),
        ]
        .join("\n");
        let s = served_trusting(instance, &section, false, None, Some(tls.root.clone()));

        for own in ["planner", "payments"] {
            let (status, preview) = admin(&s, &format!("/agents/{own}/connect"), "").await;
            assert_eq!(status, StatusCode::OK, "{preview}");
            assert_eq!(
                preview["failure"],
                serde_json::Value::Null,
                "a registration's own certificate is admitted by its own peer: {preview}"
            );
        }
        let (status, foreign) = admin(&s, "/agents/stranger/connect", "").await;
        assert_eq!(status, StatusCode::OK, "{foreign}");
        assert!(
            foreign["failure"].is_string(),
            "another registration's certificate must not authenticate at this peer: {foreign}"
        );
        for path in [&planner_cert, &planner_key, &payments_cert, &payments_key] {
            let _ = std::fs::remove_file(path);
        }
    }
}
