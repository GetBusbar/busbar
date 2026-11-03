// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tower::ServiceExt as _;

use crate::root::loader::dispatch::{
    kinds::{plane::Plane, transport::Transport},
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};

pub(super) async fn run() {
    assert!(
        include_str!(concat!(env!("OUT_DIR"), "/linked.rs"))
            .contains("&crate::root::plane_node::ROOT_UNIT,"),
        "the build must carry the node's actual root unit"
    );
    let signing_key = crate::root::loader::sign::SigningKey::from_bytes(&[0x5a; 32]);
    let initial = busbar_kernel::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nadvanced:\n  allow_destinations: [127.0.0.1]\n",
    )
    .expect("the loopback deployment parses");
    let initial = busbar_kernel::config::resolve(&initial, &Default::default()).unwrap();
    let judge = crate::root::connector::dest_judge(&initial);
    let late = super::super::LateServices::new();
    let dispatcher = crate::root::dispatch::boot(1, &late);
    crate::root::doors::install_dispatcher(dispatcher);
    let (credentials, _credentials_handle) = crate::root::credentials::AppCredentials::late();
    super::super::compose(judge.clone(), &late, credentials);
    crate::register_protocols();
    crate::register_planes();
    crate::register_diagnostics();
    crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
    let on = crate::root::dispatch::dispatcher();
    crate::root::connector::install_io(&on);
    let mut transports = Vec::new();
    for variable in ["BUSBAR_TEST_TCP_CDYLIB", "BUSBAR_TEST_HTTP_CDYLIB"] {
        let path = std::path::PathBuf::from(std::env::var_os(variable).expect(variable));
        let statement = rendering_of_library(&path)
            .unwrap()
            .expect("the actual transport states itself");
        let plugin = load_dropped::<Transport>(
            &path,
            &statement,
            Bind {
                instance: Arc::from(variable),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: on.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the real transport image binds");
        let door = crate::root::doors::Dispatched::open_on(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
            on.clone(),
        )
        .expect("the real transport opens");
        transports.push(busbar_core_connector::registry::Entry {
            door: Arc::new(door),
            alpn: Vec::new(),
        });
    }
    let connector = busbar_core_connector::process::build_with_secrets(
        || Ok(transports),
        judge,
        &[],
        on.conn_waker(),
        busbar_core_connector::pool::PoolPosture::NONE,
        busbar_core_connector::spawn_env::linked_spawn_secret,
    )
    .expect("the production connector composes the real transport images");
    assert!(crate::root::connector::install(connector).is_ok());
    let rows = busbar_kernel::preflight::root_rows();
    assert!(rows.rate_apply.is_some() && rows.rate_epoch.is_some());

    let store_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the boot audit requires the freshly built actual Store image"),
    );
    let statement = rendering_of_library(&store_path)
        .expect("the actual Store image reads")
        .expect("the actual Store states its identity");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store Statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = crate::root::test_plugins::scratch("boot-audit-real-plane");
    let archive = crate::root::test_plugins::signed(
        &signing_key,
        manifest,
        &std::fs::read(store_path).expect("the actual Store bytes read"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("the actual Store settings are JSON");
    assert!(settings.is_object());
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": ["keys"], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .expect("the actual boot deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual boot deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config_with_key(&directory, &signing_key);
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_config) {
        step(&config.limits);
    }
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the boot deployment resolves for its owned build"),
        plugins.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the configured actual Store builds the boot app");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module).expect("the production boot book opens");
    limits
        .keep()
        .expect("the boot card activates in its actual Store");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(crate::root::kernel::ROOT_CARD.pin().is_some());
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_book) {
        step(&ctx);
    }

    let mut applied = config;
    applied.per_request_fee = 3;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        applied,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
    )
    .expect("the real deployment applies its changed rate");
    limits.keep().expect("the changed rate activates");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let pinned = {
        let history = crate::root::kernel::ROOT_CARD
            .pin()
            .expect("the boot card is installed");
        let view = history.view();
        let entry = view
            .entries()
            .last()
            .expect("the rate apply appended an entry");
        assert_ne!(
            entry.seq().get(),
            0,
            "the changed rate must append to the history"
        );
        entry.key().0
    };
    let gov = app
        .governance
        .as_ref()
        .expect("the real Store owns governance")
        .clone();
    let (key, token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "boot-audit".into(),
                ..Default::default()
            },
            4_000_000_000,
            busbar_kernel::store::now(),
        )
        .expect("the boot's actual governance mints a key");
    gov.hydrate_budgets(&app.cost, 0)
        .expect("the key's budgets hydrate");

    let _one = crate::root::PUBLISHING.lock().await;
    let services = super::super::planes_tests::composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let connector = crate::root::connector::the().clone();
    let plane_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_DECISIONS_CDYLIB")
            .expect("the boot audit requires the freshly built real Decisions image"),
    );
    let statement = rendering_of_library(&plane_path)
        .expect("the actual Decisions image reads")
        .expect("the actual Decisions image states itself");
    let plane = load_dropped::<Plane>(
        &plane_path,
        &statement,
        Bind {
            instance: Arc::from("boot-audit-decisions"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(connector.clone() as Arc<dyn DeclaredConns>),
        },
    )
    .expect("the real Decisions image binds");
    assert_eq!(plane.served().section, "decisions");
    let dialect = plane.served().dialects[0];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(10), async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut part = [0; 4096];
            loop {
                let n = socket.read(&mut part).await.unwrap();
                assert_ne!(n, 0, "the real plane must send a complete provider request");
                request.extend_from_slice(&part[..n]);
                assert!(request.len() <= 64 * 1024);
                if let Some(end) = request.windows(4).position(|s| s == b"\r\n\r\n") {
                    let head = std::str::from_utf8(&request[..end]).unwrap();
                    let length = head.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                    }).expect("the real product request has a bounded content length");
                    if request.len() >= end + 4 + length { break; }
                }
            }
            assert!(request.starts_with(b"POST "));
            const ANSWER: &str = r#"{"request_id":"boot-audit","usage":{"units":42,"input_tokens":7,"output_tokens":9},"answers":{}}"#;
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ANSWER}", ANSWER.len());
            socket.write_all(response.as_bytes()).await.unwrap();
        }).await.expect("the real provider exchange finishes within its bound");
    });
    let provider_cfg = serde_yaml::from_str::<busbar_kernel::config::ProviderCfg>(&format!(
        "protocol: {dialect}\nbase_url: 'http://{address}'\napi_key: none\nerror_map: {{}}"
    ))
    .unwrap();
    let providers = crate::root::door_steps::provider_routes(
        &std::collections::HashMap::from([(
            "typesafe".into(),
            busbar_kernel::config::ResolvedProvider::from(provider_cfg),
        )]),
        &Default::default(),
    );
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
        crate::root::plane_node::node(),
    ));
    let money = Arc::new(PlaneMoney::new(
        gov.clone(),
        post.clone() as Arc<dyn EndPost>,
    ));
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
            dispatcher.clone(),
            crate::LINKED.auths,
            None,
            ConnTable::Host(connector.clone() as Arc<dyn DeclaredConns>),
            busbar_kernel::diagnostics::Catalogue::NEUTRAL,
        )),
        conns: connector as Arc<dyn PollConns>,
        stream_ceiling_secs: 10,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let sections = BTreeMap::from([(
        "decisions",
        serde_yaml::from_str("models: {m: {provider: typesafe}}").unwrap(),
    )]);
    let mut served = super::super::compose_planes(
        &[("boot-audit-decisions".into(), Arc::new(plane))],
        &dispatcher,
        &services,
        &sections,
        None,
        &|| money.clone(),
        Some(&super::super::DoorEgress {
            reach: &reach,
            journal: post.clone() as Arc<dyn busbar_kernel_egress::ports::Journal>,
        }),
        None,
        &app.serve_tables,
    )
    .expect("the real Decisions plane composes with production money and egress");
    served.post = Some(post.clone());
    let routes =
        super::super::door_routes(served, || crate::root::kernel::ROOT_CARD.pin(), &[], &[])
            .unwrap();
    let (router, _, _) =
        busbar_kernel::build_split_routers_serving(app.clone(), routes, 1 << 20, 0, false);
    let lines = || {
        book.durability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .replay()
            .expect("the book replays")
            .expect("the chain verifies")
            .len()
    };
    let before = lines();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/systemone")
        .header(
            "authorization",
            format!("Bearer {}", token.expose(&busbar_kernel::seal::lend())),
        )
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            r#"{"state":{"session":"s"},"context":{}}"#,
        ))
        .unwrap();
    let response =
        tokio::time::timeout(std::time::Duration::from_secs(15), router.oneshot(request))
            .await
            .expect("the actual plane response is bounded")
            .unwrap();
    assert_eq!(
        response.status(),
        200,
        "the actual Decisions provider response succeeds"
    );
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        response.into_body().collect(),
    )
    .await
    .expect("the real response body completes within its bound")
    .unwrap()
    .to_bytes();
    assert!(std::str::from_utf8(&response)
        .unwrap()
        .contains("boot-audit"));
    provider
        .await
        .expect("the actual provider exchange completed");
    assert_eq!(
        gov.usage_for(&app.cost, &key.id, busbar_kernel::store::now())
            .unwrap()
            .unwrap()
            .requests,
        1
    );
    assert_eq!(post.open_units(), 0, "node facts close when the unit ends");
    assert!(lines() > before, "the real unit posts to the durable book");
    let durability = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let record = durability
        .audit_records
        .last()
        .expect("the unit seals an audit record");
    assert_eq!(
        record.usage.rate_card_version,
        Some(pinned),
        "the sealed usage names the actual card in force at admission"
    );
}
