// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE'S DOOR RIG: the linked plane door serving the `pools` map, bound through the loader
//! and composed by the root over one member (model `m0` in pool `p`, speaking the plane's own
//! `dialect` door word) on a loopback far end, behind the keys chain, its money on a node's book in
//! the native store. The node's cells drive units through it as a client does, through the router.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::planes_tests::composed_services;
use super::{compose_planes_over, door_mounts, DoorEgress};
use crate::root::door_steps::{kernel_sections, provider_routes, DoorReach, OutboundAuths};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow};
use crate::root::plane_node::{Node, NodeEndPost};

include!(concat!(env!("OUT_DIR"), "/driver_words.rs"));

pub(crate) const POOL: &str = "p";
pub(crate) const LANE: &str = "m0";

pub(crate) fn word(key: &str) -> &'static str {
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

/// A whole HTTP/1.1 reply carrying `body` as `content_type`.
pub(crate) fn reply(content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A loopback far end answering every request it reads whole with `reply`.
pub(crate) async fn far_end(reply: String) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
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

/// How a rig is built.
#[derive(Default)]
pub(crate) struct NodeRigOpts {
    /// The node's arrival clock (`None`: the wall clock).
    pub clock: Option<Arc<dyn busbar_kernel::Clock>>,
    /// The deployment's `rate_card:` (`None`: billing off).
    pub rate_card: Option<BTreeMap<String, busbar_kernel::config::RateEntryCfg>>,
    /// The flat request fee, in cents.
    pub fee_cents: i64,
    /// One limit on the key's group (`None`: the key has no group).
    pub group_limit: Option<busbar_kernel::config::groups::LimitCfg>,
    /// The member's dialect (`None`: the door words' `dialect`).
    pub dialect: Option<&'static str>,
    /// The card history a unit is pinned to at its door (`None`: the root's own card).
    pub pin: Option<fn() -> Option<crate::root::kernel::PinnedHistory>>,
    /// The `rate_card:` exactly as written: the plane's billable classes are not added to it, so a
    /// card silent about a class stays silent.
    pub card_as_written: bool,
    /// The door asks no caller credential (an open front door).
    pub open_door: bool,
}

/// The composed door and what its cells read back.
pub(crate) struct NodeRig {
    pub router: axum::Router,
    pub token: String,
    pub app: Arc<busbar_kernel::state::App>,
    pub gov: Arc<busbar_kernel::governance::GovState>,
    pub key: busbar_contract::records::VirtualKey,
    pub group: String,
    /// The node's book: its journal and the audit records it sealed.
    pub book: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
}

impl NodeRig {
    /// One request through the router, as a client sends it, with the key's bearer token.
    pub(crate) async fn open(
        &self,
        path: &str,
        body: &(impl std::fmt::Display + ?Sized),
    ) -> axum::response::Response {
        self.open_raw(path, body.to_string(), true).await
    }

    /// One request through the router carrying `body` as written, with the key's bearer token or
    /// with no credential at all.
    pub(crate) async fn open_raw(
        &self,
        path: &str,
        body: String,
        bearer: bool,
    ) -> axum::response::Response {
        use tower::ServiceExt as _;
        let mut request = axum::http::Request::builder().method("POST").uri(path);
        if bearer {
            request = request.header("authorization", format!("Bearer {}", self.token));
        }
        let request = request
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .expect("a request");
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers")
    }
}

pub(crate) async fn node_rig(instance: &'static str, port: u16, opts: NodeRigOpts) -> NodeRig {
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
                accept: Default::default(),
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

    let key_file =
        std::env::temp_dir().join(format!("busbar-node-rig-{}-{instance}", std::process::id()));
    std::fs::write(&key_file, "sk-node-rig").expect("the credential file");
    let signing_file = key_file.with_extension("signing");
    std::fs::write(&signing_file, [7u8; 32]).expect("the token signing secret");
    let store_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the actual configured Store image"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&store_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store states its contract");
    let store_module = busbar_contract::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let store_settings =
        std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".to_string());
    let store_settings: serde_json::Value =
        serde_json::from_str(&store_settings).expect("the actual Store settings are JSON");
    let auth = if opts.open_door {
        "auth:\n  chain: []\n".to_string()
    } else {
        format!(
            "auth:\n  chain: [keys]\n  signing_key: {{ file: '{}' }}\n",
            signing_file.display()
        )
    };
    let yaml = format!(
        "providers:\n  oai0:\n    api_key: {{ file: '{key}' }}\n\
         models:\n  {LANE}:\n    provider: oai0\n\
         pools:\n  {POOL}:\n    members:\n      - model: {LANE}\n        weight: 1\n\
         {auth}\
         store:\n  module: {store_module}\n  settings: {store_settings}\n",
        key = key_file.display(),
    );
    let deploy =
        busbar_kernel::config::deploy_from_yaml_str(&yaml, &crate::root::boot::axis_test_grammar())
            .expect("the deployment");
    let defs: HashMap<String, busbar_kernel::config::ProviderDef> =
        busbar_contract::yaml::from_str(&format!(
            "oai0:\n  protocol: {}\n  base_url: 'http://127.0.0.1:{port}'\n",
            opts.dialect.unwrap_or_else(|| word("dialect"))
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
    let group = format!("{instance}-group");
    let groups: BTreeMap<String, busbar_kernel::config::GroupCfg> = opts
        .group_limit
        .map(|limit| {
            (
                group.clone(),
                busbar_kernel::config::GroupCfg {
                    parent: None,
                    enabled: true,
                    limits: vec![limit],
                    ..Default::default()
                },
            )
        })
        .into_iter()
        .collect();
    cfg.groups = groups.clone();
    cfg.per_request_fee = opts.fee_cents;
    let card_as_written = opts.card_as_written;
    let rate_card = opts.rate_card.map(|mut card| {
        let fill = if card_as_written {
            None
        } else {
            Some(card.values_mut())
        };
        for entry in fill.into_iter().flatten() {
            for class in &plane.served().billable_classes {
                if !busbar_contract::records::RESERVED_UNITS.contains(class)
                    && !plane.served().fee_units.contains(class)
                {
                    entry.units.entry((*class).to_string()).or_default();
                }
            }
        }
        card
    });
    cfg.rate_card = rate_card.clone();
    let cost = if groups.is_empty() && rate_card.is_none() {
        busbar_kernel::cost::CostModel::flat(opts.fee_cents)
    } else {
        busbar_kernel::cost::CostModel::resolve_parts(rate_card.as_ref(), opts.fee_cents, &groups)
    };
    gov.hydrate_budgets_async(&cost, 0).await.expect("hydrate");

    let node = Arc::new(match opts.clock {
        Some(clock) => Node::with_clock(clock),
        None => Node::new(),
    });
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
        crate::root::test_plugins::plaintext_listeners(cfg),
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
    let (key, token) = gov
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: instance.to_string(),
                group: groups.keys().next().cloned(),
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
    let clock = busbar_contract::clock::HostClock::system(crate::root::egress_ports::tokio_sleep);
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
    let journal = Arc::clone(&post) as Arc<dyn busbar_kernel::plane_driver::HookJournal>;
    let sections: BTreeMap<&'static str, busbar_contract::yaml::Value> = sections;
    let served = compose_planes_over(
        &crate::LINKED,
        &[(instance.to_string(), plane)],
        &dispatcher,
        &services,
        &sections,
        &Default::default(),
        None,
        &plane_money,
        Some(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        Some(&journal),
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
        opts.pin.unwrap_or(|| crate::root::kernel::ROOT_CARD.pin()),
        &[],
        &busbar_kernel::base_data_core_lines(&app),
        &[],
        &[],
    )
    .expect("its claims mount");
    let (router, _admin, _handle) = busbar_kernel::build_split_routers_serving_doors(
        Arc::clone(&app),
        mounts.routes,
        mounts.refusals,
        1 << 20,
        0,
        false,
    );
    NodeRig {
        router,
        token: token.expose(&busbar_kernel::seal::lend()).to_string(),
        app,
        gov,
        key,
        group,
        book: durability,
    }
}
