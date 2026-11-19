// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED NATIVE-LISTENER FIXTURE: the real native data listener served over the application
//! Store and its money book, built in-process the way `tests/native_listener.rs` builds its
//! listener (`min3_admin_auth::install`, `min3_physical::SlotOwners`, `min3_listener_plan`), with
//! every input staged by the fixture itself:
//!
//! - the application Store: the separately built Store image (`BUSBAR_TEST_SQLITE_CDYLIB`), signed
//!   and admitted through ordinary configured-publisher trust, as the distribution rig stages it;
//! - the transport: the image this build assigns the `http` carrier (`LINKED_CARRIERS`), opened
//!   through the fixture's admitted registry; the source names no plugin;
//! - the money book: the `NodeBook` the Store binds (rate-card history, usage recovery, journal,
//!   response intents), bound to the `Node` the listener posts to;
//! - the auth: the data chain is empty (the built-in `keys` arm needs a signing key and an admin
//!   minter, which a consumer states in its own extension); the admin chain is the native admin
//!   authority installed over Store-backed credential owners.
//!
//! MONEY: the fixture states no price. A test states its [`RateCard`] (the deployment's
//! `rate_card:` and `per_request_fee:`) and the fixture writes it verbatim; the resolved card is
//! handed back so a test compares against what it stated, never against a number the fixture
//! chose. The fixture serves no plane and opens no configured auth or provisioning instance: a
//! deployment that would configure one is refused, never silently omitted.
//!
//! Entry point: [`with_native_fixture`]. Serve with [`NativeFixture::spawn`].

use super::*;

use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

/// The prices a test states, written verbatim into the fixture's deployment.
pub(crate) struct RateCard {
    /// The `rate_card:` map, as the document writes it: lane -> entry (`input_utok`,
    /// `output_utok`, `cache_read_utok`, `cache_write_utok`, `units`).
    pub(crate) lanes: serde_json::Value,
    /// The `per_request_fee:` (flat cents per request).
    pub(crate) per_request_fee: i64,
}

/// One real native data listener over the application Store, its money book and its App. Every
/// [`NativeFixture::spawn`] serves the same listener on a fresh local socket.
pub(crate) struct NativeFixture {
    native: Arc<root::listener_native::NativeListener>,
    alpn: Vec<Box<str>>,
    resolver: Arc<busbar_kernel::config::secret::SecretResolver>,
    /// The node the listener posts every unit to, bound to [`NativeFixture::book`].
    pub(crate) node: Arc<root::plane_node::Node>,
    /// The money book the application Store bound before activation: its durability (journal,
    /// rate-card history), its response-intent service and its runtime journal.
    pub(crate) book: root::durability::NodeBook,
    /// The published App the listener serves (its governance mints and resolves keys).
    pub(crate) app: Arc<busbar_kernel::state::AppHandle>,
    /// The resolved `rate_card:`: exactly the test's [`RateCard::lanes`].
    pub(crate) rate_card: Option<std::collections::BTreeMap<String, config::RateEntryCfg>>,
    /// The resolved `per_request_fee:`: exactly the test's [`RateCard::per_request_fee`].
    pub(crate) per_request_fee: i64,
}

impl NativeFixture {
    /// Serve the listener on a new local socket until `shutdown` resolves.
    pub(crate) fn spawn(
        &self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = Listening::bind_stream("127.0.0.1:0", ROOT_BIND_LIMITS)
            .expect("bind the fixture's local socket");
        let addr = listener.local_addr();
        let serving = tokio::spawn(serve_listener(
            listener,
            Arc::clone(&self.native),
            Arc::clone(&self.node),
            self.alpn.clone(),
            None,
            Arc::clone(&self.resolver),
            "test".into(),
            shutdown,
            None,
            true,
        ));
        (addr, serving)
    }
}

/// Stage the application Store, build the App, its money book and the native data listener for
/// the test's `card`, hand them to `exercise`, then join the transport workers and remove the
/// staged directory.
pub(crate) async fn with_native_fixture<F, Fut>(card: RateCard, exercise: F)
where
    F: FnOnce(NativeFixture) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    crate::dist_root_install::install();
    busbar_core_admin::install();
    // The operator credential's binding, installed as the production boot installs it.
    busbar_kernel::preflight::install_operator(root::auth_bindings::operator_binding());
    root::connector::install_io_reactor();

    let library = root::test_plugins::application_store_library();
    let module = root::test_plugins::native_image(&library).name;
    let manifest = root::test_plugins::native_manifest(
        "store",
        &library,
        root::test_plugins::FIXTURE_PUBLISHER,
    );
    let directory = root::test_plugins::scratch("native-listener-fixture");
    std::fs::write(
        directory.join("store.tar.gz"),
        root::test_plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(&library).expect("the application Store image reads"),
        ),
    )
    .expect("stage the signed application Store");
    // The document names no secret reference: a test that needs a pinned signing key states its
    // secret source as a `secrets:` instance in its own extension of this fixture.
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [] },
        "store": {
            "module": module,
            "settings": root::test_plugins::application_store_settings(&directory),
        },
        "rate_card": card.lanes,
        "per_request_fee": card.per_request_fee,
        // The document states the very plugin policy the Store is admitted under, so the grammar
        // admission gives at open is the one the document was read under (BUSBAR-3170).
        "plugins": root::test_plugins::trusted_config_document(&directory),
    });
    let plugins = root::test_plugins::trusted_config(&directory);
    let grammar = root::min3_boot::fixture::grammar(&plugins)
        .expect("the fixture's admitted images supply its grammar");
    let deploy = config::deploy_from_deserializer(&document, &grammar)
        .expect("the fixture deployment parses");
    // RootCfg is not Clone (3e5b860ca5): each owner takes its own resolution of the one document.
    let resolve = || {
        root::test_plugins::plaintext_listeners(
            config::resolve(&deploy, &Default::default()).expect("the fixture deployment resolves"),
        )
    };
    let cfg = resolve();
    assert!(
        cfg.plane_sections.is_empty()
            && cfg.min3.provisioning.is_empty()
            && cfg.identity_providers.is_empty(),
        "the native-listener fixture serves no plane and opens no configured auth or provisioning \
         instance: it must not silently omit one"
    );

    let rules =
        Arc::new(root::door_steps::Rules::default()) as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (admitted, serving) = root::min3_boot::fixture::open(&cfg, &plugins, rules)
        .await
        .expect("admit the signed application Store")
        .admit_serving()
        .await;
    let core = Arc::clone(&admitted.core);
    let (mut app, rotation, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        resolve(),
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
    .expect("build the App over the application Store");
    limits.stage_boot();
    let book = root::boot::book(&app, &module)
        .await
        .expect("the application Store binds the money book before activation");
    limits.keep().await.expect("confirm the fixture's limits");
    if let Some(rotation) = rotation {
        rotation.await;
    }
    // The admission budget `tests/native_listener.rs` serves its listener under. The node's
    // terminal book is funded from it before anything enters, as the boot funds it from its own.
    let budget = ProcessAdmission::with_limits(4, 32 * 1024 * 1024, 32 * 1024 * 1024);
    let node = Arc::new(root::plane_node::Node::new());
    node.rebind_terminal_storage(&budget);
    node.bind_book(Arc::clone(&book.durability));
    // The node receives the original signed pages before any native admission, as at boot.
    node.bind_native_notary()
        .expect("bind the native audit notary to the money book");
    node.bind_response_intents(
        &core,
        book.response_intents
            .as_ref()
            .expect("the money book's response-intent signer")
            .clone(),
    )
    .expect("bind the same Store, journal and incarnation");

    let identity = root::min3_framers::assigned(crate::LINKED_CARRIERS)
        .expect("the build's carrier assignment admits")
        .get(busbar_plugin_abi::plane::CARRIER_HTTP)
        .ok()
        .cloned()
        .expect("the build assigns the http carrier to a linked transport image");
    let mut transport = serving
        .transport(&cfg, &identity)
        .await
        .expect("open the http carrier's transport through the admitted registry");
    let owners = root::min3_admin_auth::owners(
        &app,
        &cfg.min3,
        &[],
        Arc::new(busbar_kernel::plugin_records::StoreRecords::new(
            Arc::clone(&core),
        )),
    )
    .expect("build the Store-backed credential and replay owners");
    let auth = Arc::new(
        root::min3_auth::AuthSet::new(
            Vec::new(),
            &transport.holds,
            owners,
            Duration::from_secs(cfg.min3.unknown_key_refresh_s),
        )
        .expect("the fixture has no configured auth instances"),
    );
    let epoch = app
        .config_generation
        .load(std::sync::atomic::Ordering::Acquire);
    root::min3_admin_auth::install(&mut app, Arc::clone(&auth), epoch)
        .expect("install the native admin authority");
    let served = root::serve::Served::default();
    let owners = root::min3_physical::SlotOwners {
        auth,
        epoch,
        inventories: Arc::default(),
        keys: node.kernel_and_keys().1,
        core: root::min3_listener_plan::core_lines(&app, &served).into(),
    };
    let port = Arc::clone(&transport.port);
    let plan = root::min3_listener_plan::NativeListenerPlan::new(
        root::boot::ListenerNeeds {
            root_required: true,
            needs: Vec::new(),
            binds: vec![root::loader::boot::InboundBind {
                owner: root::loader::boot::BindOwner::Root,
                transport: String::new(),
                at: "listen".into(),
                listen: "127.0.0.1:0".parse().expect("a loopback socket address"),
                tls: None,
                max_conns: ROOT_BIND_LIMITS.max_conns as u64,
            }],
        },
        &root::min3_framers::NativeFramers::new(vec![
            root::min3_boot::transports::ServedTransport {
                instance: Arc::clone(&identity),
                port: Arc::clone(&port),
            },
        ]),
    )
    .expect("plan the fixture's one data listener");
    let slots = plan
        .assemble(&app, &served, &owners)
        .expect("assemble every canonical public route before publishing the App");
    root::serve::install_native_slots(&mut app, slots).expect("install the listener slots");
    let resolver = Arc::clone(&app.secret_resolver);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));
    let native = Arc::new(
        root::listener_native::NativeListener::new(
            Arc::clone(&handle),
            "listen".into(),
            Arc::clone(&port),
            root::listener_native::NativeAdmission {
                budget,
                class: AdmissionClass::Data,
            },
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
        .expect("validate the native socket factory"),
    );
    let workers = std::mem::replace(
        &mut transport.workers,
        root::boot::workers::PreparedWorkers::new(),
    )
    .start();
    exercise(NativeFixture {
        native,
        alpn: port
            .alpn(busbar_plugin_abi::transport::ROLE_SERVER)
            .to_vec(),
        resolver,
        node,
        book,
        app: handle,
        rate_card: cfg.rate_card.clone(),
        per_request_fee: cfg.per_request_fee,
    })
    .await;
    workers
        .stop()
        .await
        .expect("join the fixture's transport workers");
    drop(transport);
    drop(serving);
    drop(admitted);
    drop(core);
    std::fs::remove_dir_all(&directory).expect("remove the fixture's staged directory");
}

/// The fixture serves: its public liveness route answers over a real socket, the resolved rate
/// card is exactly the one the test stated, and a public probe leaves the money book empty.
#[tokio::test]
async fn native_listener_fixture() {
    // The listener's own refusals reach the test output.
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    // The prices this test states: the fixture configures no model, so its card prices no lane
    // (a rate entry is keyed by a configured model) and no request carries a flat fee.
    const PER_REQUEST_FEE: i64 = 0;
    let lanes = serde_json::json!({});
    let stated: std::collections::BTreeMap<String, config::RateEntryCfg> =
        serde_json::from_value(lanes.clone()).expect("the stated rate card is a card");
    with_native_fixture(
        RateCard {
            lanes,
            per_request_fee: PER_REQUEST_FEE,
        },
        |fixture| async move {
            // An absent card and an empty one price the same: nothing.
            assert_eq!(
                fixture.rate_card.clone().unwrap_or_default(),
                stated,
                "the resolved rate card is exactly the stated one"
            );
            assert_eq!(fixture.per_request_fee, PER_REQUEST_FEE);
            assert!(
                fixture.book.response_intents.is_some(),
                "the money book carries the response-intent service the node is bound to"
            );
            assert!(
                fixture.app.load().governance.is_some(),
                "the App governs keys on the application Store"
            );

            let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
            let (addr, serving) = fixture.spawn(recv_shutdown(shutdown_rx));
            let resp = reqwest::Client::new()
                .get(format!("http://{addr}{}", busbar_kernel::auth::LIVEZ_PATH))
                .send()
                .await
                .expect("the native listener answers a real HTTP request");
            assert_eq!(resp.status(), 200);
            assert_eq!(resp.text().await.expect("the liveness body reads"), "ok");
            assert_eq!(
                fixture.node.native_pending(),
                0,
                "a public probe opens no native unit"
            );
            assert_eq!(
                fixture.node.terminal_pending(),
                0,
                "a public probe leaves nothing in the terminal book"
            );

            shutdown_tx.send(()).expect("signal the listener to stop");
            tokio::time::timeout(std::time::Duration::from_secs(2), serving)
                .await
                .expect("the listener stops once shutdown fires")
                .expect("the listener task joins");
        },
    )
    .await;
}
