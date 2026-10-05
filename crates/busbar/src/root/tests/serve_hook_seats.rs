// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAT ORDER OF THE REQUEST-STAGE HOOKS, ON THE DOOR (ported from the predev-only `busbar-llm`
//! test `hook_seat_order_tests`, BUSBAR-1.6.0.md Part 5 F25: before any engine deletion every test
//! names its new home). The llm plane served through its door, end to end: a keyed caller behind
//! the data listener's auth gate, admitted and charged by the door's money steps, its unit's hooks
//! bound by the kernel's hook stage (the global rewrite, the request-stage tap, a decision gate and
//! the candidate tap), its far end a real loopback upstream through the process connector. The
//! admission door charges the request first, then the global rewrite runs, then the request-stage
//! tap observes the REWRITTEN request, then the decision gate decides, and only after the gate does
//! the candidate tap fire. A gate reject refunds the billable request (the fee base) but keeps the
//! admission count.
//!
//! Every seat is proven structurally rather than by wall-clock order where the seat is a detached
//! task (taps are fire-and-forget): the rewrite hook reads the ledger AT the moment it runs, the
//! request tap's payload carries the rewritten prompt, and a rejecting gate stops everything seated
//! after it — so a request tap that still arrives was seated before the gate and a candidate tap
//! that never arrives was seated after it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_contract::hooks::{
    Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest, TransformOutcome,
};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::hooks::ResolvedPolicy;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::{composed_services, Published, PUBLISHING};
use super::{compose_planes, door_routes, DoorEgress, HookStage};
use crate::root::door_steps::{kernel_sections, provider_routes, DoorReach, OutboundAuths};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::root::plane_node::{Node, NodeEndPost};

// The plane the node is handed, as the manifest's linked table names it (the `node` axis): the
// legacy row's test seams the registry rows that own the `pools:`/`models:` sections come from.
include!(concat!(env!("OUT_DIR"), "/node_plane.rs"));

/// THE LINKED DOOR THAT SERVES THE `pools` MAP, found by what its Statement declares (the composition
/// root names no plane): every linked plane door bound on a probe dispatcher of its own, the one
/// whose declaring section is `pools` kept.
fn pools_door() -> busbar_contract::abi::mechanism::door::DoorFn {
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find(|door| {
            let probe = Dispatcher::new(DispatchConfig::default());
            let row = LinkedRow::of(*door).expect("a linked door states itself");
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("pools-door-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: probe.adopter(),
                    conns: None,
                },
            )
            .expect("a linked door binds")
            .served()
            .section
                == busbar_contract::section::RESERVED_POOLS_KEY
        })
        .expect("the fold switch links the door serving the `pools` map")
}

/// The card history the served unit is pinned to at its door: one entry, no price.
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

/// The marker the rewrite hook plants in the prompt; a tap payload carrying it saw the rewrite.
const REWRITTEN: &str = "rewritten-by-the-global-rewrite-seat";

/// The far end's answer: an openai chat completion.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// One probe policy playing one seat: it appends its seat name to the shared log when it runs and
/// (for the rewrite seat) samples the key's admission count at that instant.
struct SeatProbe {
    seat: &'static str,
    log: Arc<Mutex<Vec<String>>>,
    /// Rewrite seat only: reads the key's `requests` count when the rewrite runs.
    requests_now: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
    /// Gate seat only: the reject the gate answers with.
    reject: Option<(u16, &'static str)>,
    /// Tap seats: the last delivered projection.
    last_payload: Mutex<Option<Vec<u8>>>,
}

impl SeatProbe {
    fn new(seat: &'static str, log: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            seat,
            log: log.clone(),
            requests_now: None,
            reject: None,
            last_payload: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for SeatProbe {
    async fn decide(
        &self,
        _req: &RoutingRequest<'_>,
        _candidates: &[Candidate<'_>],
        _ctx: &RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> PolicyResult {
        self.log.lock().unwrap().push(self.seat.to_string());
        Ok(match self.reject {
            Some((status, message)) => RoutingDecision::Reject {
                status,
                message: message.to_string(),
            },
            None => RoutingDecision::Abstain,
        })
    }
    fn name(&self) -> &'static str {
        self.seat
    }
    async fn transform(
        &self,
        _req: &RoutingRequest<'_>,
        _budget: std::time::Duration,
    ) -> TransformOutcome {
        let requests = self.requests_now.as_ref().map(|f| f());
        self.log
            .lock()
            .unwrap()
            .push(format!("{}:requests={:?}", self.seat, requests));
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![serde_json::json!({"role": "user", "content": REWRITTEN})],
            tools: vec![],
        })
    }
    async fn notify(
        &self,
        tap: std::sync::Arc<busbar_contract::abi::host::hook::NotifyFrame>,
        _budget: std::time::Duration,
    ) {
        let projection = serde_json::to_vec(&tap.projection_json()).expect("the tap's JSON");
        self.log.lock().unwrap().push(self.seat.to_string());
        *self.last_payload.lock().unwrap() = Some(projection);
    }
}

fn gate(policy: Arc<dyn RoutingPolicy>) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: busbar_kernel::config::PolicyOnError::default(),
        on_error_chain: Vec::new(),
        timeout: std::time::Duration::from_millis(500),
        send_prompt: false,
        send_user: false,
        on_empty: busbar_kernel::config::PolicyOnError::Reject,
    }
}

/// Poll a tap probe until its detached delivery lands (bounded), or return `None`.
async fn delivered(tap: &SeatProbe, budget_ms: u64) -> Option<Vec<u8>> {
    for _ in 0..(budget_ms / 10) {
        if let Some(p) = tap.last_payload.lock().unwrap().clone() {
            return Some(p);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    None
}

/// A far end on loopback answering every request with [`ANSWER`].
async fn far_end() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
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
    port
}

/// The key's ledger as the test reads it: (admission count, derived spend in cents, the durable
/// row's admission count, the durable row's billable count).
type Ledger = (u64, i64, u64, u64);

/// What a run left: the caller's status, the seat log, the two tap probes and the ledger reader.
struct Ran {
    status: u16,
    log: Arc<Mutex<Vec<String>>>,
    request_tap: Arc<SeatProbe>,
    candidate_tap: Arc<SeatProbe>,
    read: Arc<dyn Fn() -> Ledger + Send + Sync>,
}

/// ONE KEYED REQUEST through the llm door with the four probed seats installed, a rejecting gate
/// when `reject_at_gate`.
async fn run(instance: &'static str, reject_at_gate: bool) -> Ran {
    // The registry rows that own the `pools:`/`models:` sections the deployment writes.
    node_plane::testkit::install_test_seams();
    let port = far_end().await;
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

    // THE LLM DOOR, linked, bound through the loader's one load, its needs declared on the
    // connector.
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(pools_door()).expect("the door states itself");
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

    // THE DEPLOYMENT: one openai provider on the far end, one model, pool `p` over it.
    let key_file = std::env::temp_dir().join(format!(
        "busbar-hook-seats-{}-{instance}",
        std::process::id()
    ));
    std::fs::write(&key_file, "sk-seats").expect("the credential file");
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&format!(
        "providers:\n  oai:\n    api_key: {{ file: '{}' }}\nmodels:\n  m0:\n    provider: oai\n\
         pools:\n  p:\n    members:\n      - model: m0\n",
        key_file.display()
    ))
    .expect("a deployment");
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> = serde_yaml::from_str(&format!(
        "oai:\n  protocol: openai\n  base_url: 'http://127.0.0.1:{port}'\n"
    ))
    .expect("the providers");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let providers = provider_routes(&cfg.providers);
    let sections = kernel_sections(&cfg);
    let model_pools = crate::root::model_egress::ModelPools::of(&cfg);

    // THE MONEY: a signing governance book with one minted key, the node's book bound.
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "seats".to_string(),
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

    // THE GENERATION: the lane, the pool, the flat 1-cent fee, and the four seats.
    let mut app = busbar_kernel::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov))
        .cost(CostModel::flat(1))
        .lane(busbar_kernel::test_support::LaneSpec::new(
            "m0",
            "openai",
            &format!("http://127.0.0.1:{port}"),
        ))
        .pool("p", &[(0, 1)])
        .build();
    let log = Arc::new(Mutex::new(Vec::new()));
    let read: Arc<dyn Fn() -> Ledger + Send + Sync> = {
        let (gov, cost, key_id) = (Arc::clone(&gov), app.cost.clone(), key.id.clone());
        Arc::new(move || {
            let u = gov
                .usage_for(cost.as_ref(), &key_id, busbar_kernel::store::now())
                .expect("usage read")
                .expect("the key exists");
            gov.flush_budgets();
            // Window 0 is the key's all-time bucket.
            let row = gov.store().get_usage(&key_id, 0).expect("ledger row");
            (
                u.requests,
                u.spend_cents,
                row.requests,
                row.billable_requests,
            )
        })
    };
    let mut rewrite = SeatProbe::new("rewrite", &log);
    let read_for_rewrite = Arc::clone(&read);
    rewrite.requests_now = Some(Box::new(move || read_for_rewrite().0));
    let request_tap = Arc::new(SeatProbe::new("request-tap", &log));
    let candidate_tap = Arc::new(SeatProbe::new("candidate-tap", &log));
    let mut gate_probe = SeatProbe::new("gate", &log);
    if reject_at_gate {
        gate_probe.reject = Some((451, "the gate says no"));
    }
    {
        let a = Arc::get_mut(&mut app).expect("sole owner");
        a.rewrite_hooks = vec![(std::time::Duration::from_millis(500), Arc::new(rewrite))];
        // The request tap holds the prompt grant so its payload carries the (rewritten) messages.
        let rt: Arc<dyn RoutingPolicy> = request_tap.clone();
        a.tap_hooks = vec![(std::time::Duration::from_millis(500), true, rt, Vec::new())];
        let ct: Arc<dyn RoutingPolicy> = candidate_tap.clone();
        a.tap_hooks_candidate =
            vec![(std::time::Duration::from_millis(500), false, ct, Vec::new())];
        a.global_gates = vec![(0u16, gate(Arc::new(gate_probe)))];
    }

    // THE COMPOSITION, as production seals it: the door opened with the deployment's sections,
    // its egress the model-serving walk over the kernel's lane cells, its hooks the kernel's stage.
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let auths = Arc::new(OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        None,
    ));
    let models = crate::root::model_egress::ModelServing {
        pools: model_pools,
        lanes: HashMap::from([("m0".to_string(), 0)]),
        app: {
            let app = Arc::clone(&app);
            Arc::new(move || Arc::clone(&app))
        },
    };
    let reach = DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths,
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        models: Some(&models),
        upgrades: Vec::new(),
    };
    let stage = HookStage {
        host: {
            let app = Arc::clone(&app);
            Arc::new(move || busbar_kernel::plane_host::engine_host(&app))
        },
        gov: Arc::clone(&gov),
    };
    let sections: BTreeMap<&'static str, serde_yaml::Value> = sections;
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
        Some(&stage),
    )
    .expect("the door serving the pools map composes");
    let _ = std::fs::remove_file(&key_file);
    served.post = Some(Arc::clone(&post));
    let doors = door_routes(
        served,
        || CARD.pin(),
        &[],
        &busbar_kernel::base_data_core_lines(&app),
    )
    .expect("its claims mount");
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), doors, 1 << 20, 0, false);

    // THE REQUEST, as the keyed caller.
    let response = {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("authorization", format!("Bearer {}", token.expose_secret()))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"model": "p", "max_tokens": 16,
                    "messages": [{"role": "user", "content": "the original prompt"}]})
                .to_string(),
            ))
            .expect("a request");
        router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers")
    };
    let status = response.status().as_u16();
    let _ = axum::body::to_bytes(response.into_body(), 1 << 16).await;
    Ran {
        status,
        log,
        request_tap,
        candidate_tap,
        read,
    }
}

/// A rejecting decision gate: the admission charge, the rewrite and the request tap all happened
/// before it; the candidate tap never fires; the billable request is refunded and the admission
/// count is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrated_request_hook_seats_after_admit_before_candidate() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-hook-seats-reject";
    let _published = Published(instance);
    let ran = run(instance, true).await;
    assert_eq!(
        ran.status, 451,
        "the gate's reject is what the caller receives"
    );

    // Admission door before rewrite: the rewrite seat saw the request already counted.
    let log = ran.log.lock().unwrap().clone();
    assert!(
        log.iter().any(|e| e == "rewrite:requests=Some(1)"),
        "the rewrite seat must run AFTER the admission door charged the request; log: {log:?}"
    );
    // Rewrite before the request tap: the tap's payload carries the rewritten prompt, and the tap
    // was delivered at all even though the gate rejected (so it was seated before the gate).
    let payload = delivered(&ran.request_tap, 2_000)
        .await
        .expect("the request-stage tap fires before the gate and is delivered despite the reject");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.contains(REWRITTEN),
        "the request tap must observe the REWRITTEN request: {text}"
    );
    assert!(
        !text.contains("the original prompt"),
        "the request tap must not see the pre-rewrite prompt: {text}"
    );
    // The gate ran (it produced the 451) and the candidate tap, seated after the gates, never
    // fires on a rejected request.
    assert!(
        log.iter().any(|e| e == "gate"),
        "the gate seat ran; log: {log:?}"
    );
    assert!(
        delivered(&ran.candidate_tap, 300).await.is_none(),
        "the candidate tap is seated after the gates, so a gate reject must never reach it"
    );
    // The reject consumed the requests slot but refunded the fee base (a flat 1-cent fee per
    // billable request, so derived spend reads the billable count directly).
    let (requests, spend, row_requests, row_billable) = (ran.read)();
    assert_eq!(requests, 1, "the admission count is never refunded");
    assert_eq!(
        spend, 0,
        "the billable request (the fee base) is refunded on a gate reject"
    );
    assert_eq!(
        (row_requests, row_billable),
        (1, 0),
        "the durable ledger row keeps the admission and drops the billable request"
    );
}

/// The positive twin: an abstaining gate lets the request through, the candidate tap fires AFTER
/// the gate decided, and a served request keeps its billable request (one fee).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_tap_fires_after_an_abstaining_gate_and_a_served_request_bills_once() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-hook-seats-serve";
    let _published = Published(instance);
    let ran = run(instance, false).await;
    assert_eq!(ran.status, 200, "the live lane serves the request");
    assert!(
        delivered(&ran.candidate_tap, 2_000).await.is_some(),
        "the candidate tap fires on a request the gates let through"
    );
    let log = ran.log.lock().unwrap().clone();
    let gate_at = log.iter().position(|e| e == "gate").expect("the gate ran");
    let cand_at = log
        .iter()
        .position(|e| e == "candidate-tap")
        .expect("the candidate tap was delivered");
    let rewrite_at = log
        .iter()
        .position(|e| e.starts_with("rewrite:"))
        .expect("the rewrite ran");
    assert!(
        rewrite_at < gate_at && gate_at < cand_at,
        "seat order must be rewrite, gate, candidate tap; log: {log:?}"
    );
    // The unit's money settles at its end, which the caller's last byte may precede: read the
    // ledger once it has (bounded).
    let mut ledger = (ran.read)();
    for _ in 0..200 {
        if ledger.3 == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        ledger = (ran.read)();
    }
    let (requests, spend, row_requests, row_billable) = ledger;
    assert_eq!((requests, row_requests), (1, 1));
    assert_eq!(
        (spend, row_billable),
        (1, 1),
        "a served request keeps its one billable request (1-cent flat fee)"
    );
}
