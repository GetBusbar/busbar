// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST WORK-BUDGET GATE (REQUEST-PATH-BUDGET, decision 206).
//!
//! One request in the linked LLM plane's own dialect (its door word `dialect`), buffered and
//! streamed, through the real door path: the linked plane door serving the `pools` map, bound
//! through the loader, composed by the root, its money on the node's book in the native store
//! plugin, and a far end on loopback. Counts the work it does, not how long it takes, and fails
//! when any count is above `perf/work-budget.toml`. An item with no entry there is measured and
//! printed (`WORK-COUNT section=<s> <item>=<n>`), not enforced.
//!
//! Counted: heap allocations (the test build's counting global allocator), plugin crossings (at
//! the loader boundary, `busbar_contract::work_count::Work::Crossing`, so the gate keeps working
//! when MIN-3 replaces the mechanism behind that boundary) and store round trips. A request's
//! count is the lowest of [`RUNS`] identical requests after [`WARM`] warm-up requests, so lazy
//! first-use work and stray background work cannot raise it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_contract::work_count::Tally;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::composed_services;
use super::{compose_planes_over, door_mounts, DoorEgress, HookStage};
use crate::root::door_steps::{kernel_sections, provider_routes, DoorReach, OutboundAuths};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow};
use crate::root::plane_node::{Node, NodeEndPost};

include!(concat!(env!("OUT_DIR"), "/driver_words.rs"));

const BUDGET: &str = include_str!("../../../../../perf/work-budget.toml");

/// Requests answered before counting, to take first-use work out of the measurement.
const WARM: usize = 1;
/// Requests counted; each count is the lowest of these.
const RUNS: usize = 3;

/// The counted items, in the order they are reported, with their names in the budget file.
const ITEMS: [&str; 3] = ["allocations", "plugin_crossings", "store_round_trips"];

const POOL: &str = "p";
const LANE: &str = "m0";
const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// The two served ends the gate counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixture {
    /// The whole loop, delivered, buffered.
    BufferedOk,
    /// The same loop with the accrual landing at stream end rather than at the buffered tap.
    StreamedOk,
}

impl Fixture {
    fn body(self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "model": POOL,
            "messages": [{"role": "user", "content": "hi"}],
        });
        if self == Fixture::StreamedOk {
            v["stream"] = serde_json::Value::Bool(true);
        }
        v
    }

    /// The far end's whole HTTP/1.1 reply.
    fn reply(self) -> String {
        let (content_type, body) = match self {
            Fixture::BufferedOk => (
                "application/json",
                serde_json::json!({
                    "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                })
                .to_string(),
            ),
            Fixture::StreamedOk => (
                "text/event-stream",
                [
                    serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                                       "created": 0, "model": LANE,
                                       "choices": [{"index": 0, "delta": {"role": "assistant",
                                                                          "content": "hello"}}]})
                    .to_string(),
                    serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                                       "created": 0, "model": LANE,
                                       "choices": [{"index": 0, "delta": {},
                                                    "finish_reason": "stop"}],
                                       "usage": {"prompt_tokens": INPUT,
                                                 "completion_tokens": OUTPUT,
                                                 "total_tokens": INPUT + OUTPUT}})
                    .to_string(),
                    "[DONE]".to_string(),
                ]
                .iter()
                .map(|event| format!("data: {event}\n\n"))
                .collect(),
            ),
        };
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    }
}

fn word(key: &str) -> &'static str {
    DRIVER_WORDS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("the plane's door words have no `{key}` row"))
}

/// A loopback far end answering every request it reads whole with `fixture`'s reply.
async fn far_end(fixture: Fixture) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let reply = fixture.reply();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let reply = reply.clone();
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
                                let (n, v) = l.split_once(':')?;
                                n.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            break;
                        }
                    }
                }
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    port
}

/// The linked door serving the `pools` map, composed by the root over one member on `port`,
/// behind the keys chain, mounted on the data router.
struct Rig {
    router: axum::Router,
    token: String,
}

async fn rig(instance: &'static str, port: u16) -> Rig {
    crate::dist_root_install::install();
    let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations::default())
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
        busbar_core_connector::spawn_env::linked_spawn_secret,
    )
    .expect("the connector builds");

    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let door = super::door_rig::door_declaring(busbar_contract::section::RESERVED_POOLS_KEY)
        .expect("a linked door serves the `pools` map");
    let row = LinkedRow::of(door).expect("the door states itself");
    let plane = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: Arc::from(instance),
                max_inflight_cap: 64,
                sink: Arc::new(crate::root::loader::dispatch::NoSink),
                dispatcher: dispatcher.adopter(),
                conns: crate::root::loader::dispatch::ConnTable::Host(
                    crate::root::connector::admit(Arc::clone(&connector) as Arc<dyn DeclaredConns>),
                ),
            },
        )
        .expect("the linked door binds"),
    );

    let key_file = std::env::temp_dir().join(format!(
        "busbar-work-budget-{}-{instance}",
        std::process::id()
    ));
    std::fs::write(&key_file, "sk-work-budget").expect("the credential file");
    let signing_file = key_file.with_extension("signing");
    std::fs::write(&signing_file, [7u8; 32]).expect("the token signing secret");
    let store_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the actual configured Store image"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&store_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store states its contract");
    let store_module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let store_settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".to_string());
    let store_settings: serde_json::Value =
        serde_json::from_str(&store_settings).expect("the actual Store settings are JSON");
    let yaml = format!(
        "providers:\n  oai0:\n    api_key: {{ file: '{key}' }}\n\
         models:\n  {LANE}:\n    provider: oai0\n\
         pools:\n  {POOL}:\n    members:\n      - model: {LANE}\n        weight: 1\n\
         auth:\n  chain: [keys]\n  admin_auth: []\n  signing_key: {{ file: '{signing}' }}\n\
         store:\n  module: {store_module}\n  settings: {store_settings}\n",
        key = key_file.display(),
        signing = signing_file.display(),
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("the deployment");
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> = serde_yaml::from_str(&format!(
        "oai0:\n  protocol: {}\n  base_url: 'http://127.0.0.1:{port}'\n",
        word("dialect")
    ))
    .expect("the providers");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("the configuration resolves: {}", e.join("; ")));
    let providers = provider_routes(
        &cfg.providers,
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let sections = kernel_sections(&cfg).expect("the kernel's sections");
    let model_pools = crate::root::model_egress::ModelPools::of(&cfg);

    let store = super::door_tests::process_store().await;
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_core(store.clone(), None, Some(signer))
            .await
            .expect("governance"),
    );
    cfg.per_request_fee = 1;
    let cost = busbar_kernel::cost::CostModel::flat(1);
    gov.hydrate_budgets_async(&cost, 0).await.expect("hydrate");

    let node = Arc::new(Node::new());
    let budget = busbar_kernel::persistence::journal::runtime::BufferBudget {
        records: 4096,
        bytes: 16 * 1024 * 1024,
    };
    let book = crate::root::durability::node_book(
        busbar_kernel::persistence::journal::runtime::RuntimeJournal::open(
            gov.core_store_handle().expect("native Store"),
            busbar_kernel::door::op_id().counter().max(1),
            budget,
        )
        .await
        .expect("native journal"),
        budget,
    )
    .await
    .expect("native node book");
    let mut durability = book.durability;
    super::door_tests::bind_process_amendments(&mut durability, gov.amendments()).await;
    node.bind_book(Arc::clone(&durability));
    let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
    let site = Arc::clone(&post);
    let book_money = Arc::clone(&gov);
    let plane_money = move || {
        Arc::new(PlaneMoney::new(
            Arc::clone(&book_money),
            Arc::clone(&site) as Arc<dyn EndPost>,
        ))
    };

    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(store.clone()),
        false,
    )
    .await
    .expect("the app builds");
    limits.stage_boot();
    super::door_tests::attach_process_prices(&app)
        .await
        .expect("the prices attach");
    limits.keep().await.expect("the limits keep");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let (_, token) = gov
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "work-budget".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
        .expect("mint");
    app.amendments = Arc::clone(gov.amendments());
    app.governance = Some(Arc::clone(&gov));
    app.cost = Arc::new(cost);
    let app = Arc::new(app);

    let secrets: Arc<dyn busbar_contract::secret::SecretResolve> = app.secret_resolver.clone();
    let auths = Arc::new(OutboundAuths::new(
        Arc::clone(&dispatcher),
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
        busbar_kernel::diagnostics::Catalogue::NEUTRAL,
    ));
    let models = crate::root::model_egress::ModelServing {
        pools: model_pools,
        lanes: [(LANE.to_string(), 0)].into_iter().collect(),
        app: crate::root::model_egress::LiveApp::fixed(Arc::clone(&app)),
    };
    let clock: Arc<dyn busbar_kernel_egress::ports::Clock> =
        Arc::new(crate::root::egress_ports::NodeClock::new());
    let reach = DoorReach {
        providers: &providers,
        secrets,
        auths,
        conns: Arc::clone(&connector) as Arc<dyn PollConns>,
        stream_ceiling_secs: 600,
        models: Some(&models),
        catalog: None,
        upgrades: Vec::new(),
    };
    let stage = HookStage {
        host: {
            let app = Arc::clone(&app);
            Arc::new(move || busbar_kernel::plane_driver::engine_host(&app))
        },
        gov: Arc::clone(&gov),
        journal: Some(Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>),
    };
    let sections: BTreeMap<&'static str, serde_yaml::Value> = sections;
    let served = compose_planes_over(
        &crate::LINKED,
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        Some(&stage),
        &clock,
        &busbar_contract::config_time::ConfigScope::config_time(),
        &app.serve_tables,
    )
    .await;
    let _ = std::fs::remove_file(&signing_file);
    let _ = std::fs::remove_file(&key_file);
    let mut served = served.unwrap_or_else(|e| panic!("the door serving the pools map: {e}"));
    served.post = Some(Arc::clone(&post));
    let mounts = door_mounts(
        served,
        || crate::root::kernel::ROOT_CARD.pin(),
        &[],
        &busbar_kernel::base_data_core_lines(&app),
        &[],
        &[],
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
    Rig {
        router,
        token: token.expose(&busbar_kernel::seal::lend()).to_string(),
    }
}

fn item(work: Tally, name: &str) -> u64 {
    match name {
        "allocations" => work.allocations,
        "plugin_crossings" => work.crossings,
        "store_round_trips" => work.store_round_trips,
        other => unreachable!("not a counted item: {other}"),
    }
}

/// One section of the budget file: `name = number` lines under `[section]`. An item with no line
/// has no budget yet: it is measured and reported, not enforced.
fn budget(section: &str) -> [Option<u64>; 3] {
    let mut current = "";
    let mut out = [None; 3];
    for line in BUDGET.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.trim();
            continue;
        }
        if current != section {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("perf/work-budget.toml: `{line}` is not `name = number`"));
        let value: u64 = value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("perf/work-budget.toml: `{line}` is not a whole number"));
        let at = ITEMS
            .iter()
            .position(|name| *name == key.trim())
            .unwrap_or_else(|| {
                panic!("perf/work-budget.toml: unknown count `{key}` in [{section}]")
            });
        assert!(
            out[at].replace(value).is_none(),
            "perf/work-budget.toml: `{key}` named twice in [{section}]"
        );
    }
    out
}

/// One request through the door, counted from hand-off until its last body byte is read.
async fn counted(rig: &Rig, fixture: Fixture) -> Tally {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", format!("Bearer {}", rig.token))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(fixture.body().to_string()))
        .expect("a request");
    let before = Tally::now();
    let resp = rig
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    let work = Tally::now().since(before);
    let body = body.expect("the answer's body reads to its end");
    assert_eq!(
        status,
        200,
        "{fixture:?} must be served to count its work: {}",
        String::from_utf8_lossy(&body)
    );
    work
}

/// Lowest count of each kind over [`RUNS`] requests, after [`WARM`] warm-up requests.
async fn measure(instance: &'static str, fixture: Fixture) -> Tally {
    let rig = rig(instance, far_end(fixture).await).await;
    for _ in 0..WARM {
        let _ = counted(&rig, fixture).await;
    }
    let mut low = Tally {
        allocations: u64::MAX,
        crossings: u64::MAX,
        store_round_trips: u64::MAX,
    };
    for _ in 0..RUNS {
        let work = counted(&rig, fixture).await;
        low.allocations = low.allocations.min(work.allocations);
        low.crossings = low.crossings.min(work.crossings);
        low.store_round_trips = low.store_round_trips.min(work.store_round_trips);
    }
    low
}

fn gate(section: &str, fixture: Fixture, measured: Tally) {
    let budget = budget(section);
    let mut over = Vec::new();
    for (name, max) in ITEMS.iter().zip(budget) {
        let got = item(measured, name);
        // Fixed, greppable: one line per item, read to write the first budget.
        println!("WORK-COUNT section={section} {name}={got}");
        match max {
            None => println!(
                "work-budget [{section}] {fixture:?}: {name} has no budget yet; measured, not \
                 enforced (add `{name} = {got}` to perf/work-budget.toml)"
            ),
            Some(max) if got > max => over.push(format!("{name} = {got} (budget {max})")),
            Some(max) if got < max => println!(
                "work-budget [{section}] {fixture:?}: {name} = {got} fell below its budget {max}; \
                 lower perf/work-budget.toml to it in this change (budgets only ratchet down)"
            ),
            Some(_) => {}
        }
    }
    assert!(
        over.is_empty(),
        "[{section}] {fixture:?}: per-request work went UP; remove the work, never raise \
         perf/work-budget.toml: {over:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_openai_request_stays_within_its_work_budget() {
    let measured = measure("work-budget-buffered", Fixture::BufferedOk).await;
    gate("buffered", Fixture::BufferedOk, measured);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_openai_request_stays_within_its_work_budget() {
    let measured = measure("work-budget-streamed", Fixture::StreamedOk).await;
    gate("streamed", Fixture::StreamedOk, measured);
}
