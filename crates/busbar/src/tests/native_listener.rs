// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real admitted transport fixture for the root socket regression. The runner supplies a
//! supported configuration and signed, cohort-matched archives; absent inputs fail the test.

use super::*;

pub(super) async fn assert_real_http() {
    use crate::test_common::plugins;
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

    busbar_core_admin::install();
    root::connector::install_io_reactor();

    let directory = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_NATIVE_LISTENER_FIXTURE")
            .expect("BUSBAR_NATIVE_LISTENER_FIXTURE names the runner's signed native fixture"),
    );
    let plugins = plugins::trusted_config(&directory.join("plugins"));
    let grammar = root::min3_boot::fixture::grammar(&plugins)
        .expect("the actual admitted images supply the fixture grammar");
    let document = std::fs::read_to_string(directory.join("config.yaml"))
        .expect("the runner supplies a supported native configuration");
    let deploy = config::deploy_from_yaml_str(&document, &grammar)
        .expect("the actual native fixture configuration parses");
    let cfg = config::resolve(&deploy, &Default::default())
        .expect("the actual native fixture configuration resolves");
    assert!(
        cfg.plane_sections.is_empty() && cfg.min3.provisioning.is_empty(),
        "the public-listener fixture must not omit configured plane or provisioning consumers"
    );
    let store = cfg
        .store
        .as_ref()
        .expect("explicit fixture Store")
        .module
        .clone();
    let identity = std::fs::read_to_string(directory.join("transport-identity"))
        .expect("the fixture names its actual admitted HTTP image");
    let rules =
        Arc::new(root::door_steps::Rules::default()) as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (admitted, serving) = root::min3_boot::fixture::open(&cfg, &plugins, rules)
        .await
        .expect("admit the actual signed Store and transport cohort")
        .admit_serving()
        .await;
    let core = Arc::clone(&admitted.core);
    let (mut app, rotation, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg.clone(),
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &admitted.rules,
        Some(Arc::clone(&core)),
        false,
    )
    .await
    .expect("build the App over the transport fixture's original Store");
    limits.stage_boot();
    let book = root::boot::book(&app, &store)
        .await
        .expect("bind the actual Node book");
    limits
        .keep()
        .await
        .expect("confirm the fixture's actual limits");
    if let Some(rotation) = rotation {
        rotation.await;
    }
    let node = Arc::new(root::plane_node::Node::new());
    node.bind_book(Arc::clone(&book.durability));
    node.bind_response_intents(
        Arc::clone(&core),
        book.response_intents
            .as_ref()
            .expect("actual response-intent signer")
            .clone(),
    )
    .expect("bind the same Store, journal and incarnation");
    let mut transport = serving
        .transport(&cfg, identity.trim())
        .await
        .expect("open the actual native HTTP port through its admitted Registry");
    let owners = root::min3_admin_auth::owners(
        &app,
        &cfg.min3,
        &[],
        Arc::new(busbar_kernel::plugin_records::StoreRecords::new(core)),
    )
    .expect("build actual Store-backed credential and replay owners");
    let auth = Arc::new(
        root::min3_auth::AuthSet::new(
            Vec::new(),
            &transport.holds,
            owners,
            Duration::from_secs(cfg.min3.unknown_key_refresh_s),
        )
        .expect("the public fixture has no configured auth instances"),
    );
    let served = root::serve::Served {
        tables: app.serve_tables.clone(),
        ..Default::default()
    };
    let epoch = app
        .config_generation
        .load(std::sync::atomic::Ordering::Acquire);
    let owners = root::min3_physical::SlotOwners {
        auth,
        epoch,
        inventories: Arc::default(),
        keys: node.kernel_and_keys().1,
        core: root::min3_listener_plan::core_lines(&app, &served).into(),
    };
    let plan = root::min3_listener_plan::NativeListenerPlan::new(
        root::boot::ListenerNeeds {
            root_required: true,
            needs: Vec::new(),
            binds: vec![root::loader::boot::InboundBind {
                owner: root::loader::boot::BindOwner::Root,
                transport: String::new(),
                at: "listen".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                tls: None,
                max_conns: ROOT_BIND_LIMITS.max_conns as u64,
            }],
        },
        &root::min3_framers::NativeFramers::new(vec![
            root::min3_boot::transports::ServedTransport {
                instance: identity.trim().into(),
                port: transport.port.clone(),
            },
        ]),
    )
    .expect("select the actual declared initial listener supplier");
    let slots = plan
        .assemble(&app, &served, &owners)
        .expect("assemble every canonical public route before publishing App");
    root::serve::install_native_slots(&mut app, slots).unwrap();
    let resolver = Arc::clone(&app.secret_resolver);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));
    let budget = ProcessAdmission::with_limits(4, 32 * 1024 * 1024, 32 * 1024 * 1024);
    let native = Arc::new(
        root::listener_native::NativeListener::new(
            handle,
            "listen".into(),
            transport.port.clone(),
            budget,
            AdmissionClass::Data,
            Arc::new(root::serve::native_slot),
            root::listener_native::NativeLimits {
                max_connections: ROOT_BIND_LIMITS.max_conns,
                body_bytes: cfg.limits.request_body_max_bytes,
                stall_ms: None,
                handshake_timeout: ROOT_BIND_LIMITS.handshake_timeout,
                request_timeout: Duration::from_secs(cfg.limits.request_body_read_timeout_secs),
                write_timeout: Duration::from_secs(cfg.limits.upstream_request_timeout_secs),
                drain_grace: busbar_kernel::detached::DETACHED_DRAIN_GRACE,
            },
            None,
        )
        .expect("validate the actual native socket factory"),
    );
    let workers = std::mem::replace(
        &mut transport.workers,
        root::boot::workers::PreparedWorkers::new(),
    )
    .start();
    let listener = Listening::bind_stream(None, "127.0.0.1:0", ROOT_BIND_LIMITS).unwrap();
    let addr = listener.local_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let serve_handle = tokio::spawn(serve_listener(
        listener,
        native,
        node,
        transport
            .port
            .alpn(busbar_plugin_abi::transport::ROLE_SERVER)
            .to_vec(),
        None,
        resolver,
        "test".into(),
        recv_shutdown(shutdown_rx),
        None,
        true,
    ));
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{}", busbar_kernel::auth::LIVEZ_PATH))
        .send()
        .await
        .expect("serve_listener must actually accept and answer a real HTTP request");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), serve_handle)
        .await
        .expect("serve_listener must actually stop once shutdown fires")
        .unwrap();
    workers
        .stop()
        .await
        .expect("join the actual transport fixture workers");
    drop(transport);
}
