// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::root::doors::{bind_on, Dispatched};
use crate::root::inbound;
use crate::root::listener::framed::{self as listener_framed, FramerFor, DATA_SCHEME};
use crate::root::loader::dispatch::auth_handle::{
    AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, RefusalBytes,
    RefuseAsk, StreamPolicy, UnitSecret,
};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::test_common as common;
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_CONTAINS};
use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::framer::{Established, FramerDoor, Framing};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};

struct Provider {
    name: &'static str,
    units: Arc<Mutex<Vec<u64>>>,
}
fn provider(name: &'static str, units: &Arc<Mutex<Vec<u64>>>) -> Arc<Provider> {
    Arc::new(Provider {
        name,
        units: units.clone(),
    })
}

struct ObserveActual {
    actual: inbound::LoaderSide,
    calls: Arc<AtomicUsize>,
    units: Arc<Mutex<Vec<u64>>>,
}
fn record(units: &Mutex<Vec<u64>>, answer: &Result<AuthCallAnswer, &'static str>) {
    if let Ok(answer) = answer {
        units.lock().unwrap().push(answer.unit.id);
    }
}
impl AuthHandleHost for ObserveActual {
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret> {
        self.actual.unit_secret(owner, unit)
    }
    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let units = self.units.clone();
        let ran = self.actual.auth_call(
            ask,
            Box::new(move |answer| {
                record(&units, &answer);
                done(answer);
            }),
        );
        if let AuthRan::Now(answer) = &ran {
            record(&self.units, answer);
        }
        ran
    }
    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str> {
        self.actual.hand_in(ask)
    }
    fn hand_in_with_deadline(
        &self,
        ask: HandInAsk,
        deadline: Option<std::time::Duration>,
    ) -> Result<(u32, UnitRef), &'static str> {
        self.actual.hand_in_with_deadline(ask, deadline)
    }
    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        self.actual.refuse(ask)
    }
    fn framing_started(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
    ) -> Result<Option<StreamPolicy>, &'static str> {
        self.actual.framing_started(owner, listener, framing)
    }
    fn requires_scope(&self) -> bool {
        self.actual.requires_scope()
    }
    fn stream_open(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
        stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        self.actual.stream_open(owner, listener, framing, stream)
    }
    fn stream_ended(&self, owner: u64, framing: u64, stream: u64) {
        self.actual.stream_ended(owner, framing, stream)
    }
    fn framing_ready(&self, owner: u64, framing: u64) {
        self.actual.framing_ready(owner, framing)
    }
    fn framing_detached(&self, owner: u64, framing: u64) -> Result<(), &'static str> {
        self.actual.framing_detached(owner, framing)
    }
    fn framing_adopting(
        &self,
        source: busbar_contract::framing_scope::AdoptionSource,
        owner: u64,
        framing: u64,
    ) -> Result<busbar_contract::framing_scope::SessionTransfer, &'static str> {
        self.actual.framing_adopting(source, owner, framing)
    }
    fn framing_adopted(&self, owner: u64, framing: u64, conn: u64) -> Result<(), &'static str> {
        self.actual.framing_adopted(owner, framing, conn)
    }
    fn framing_ended(&self, framing: u64) {
        self.actual.framing_ended(framing)
    }
}

async fn settle(framing: &mut Framing) {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while framing.parked() {
            std::future::poll_fn(|cx| framing.poll_parked(cx))
                .await
                .expect("the actual pending OIDC admission completes");
        }
    })
    .await
    .expect("the actual OIDC admission is bounded");
}

async fn app(
    provider: &Arc<Provider>,
    prior: Option<&busbar_kernel::state::App>,
) -> Arc<busbar_kernel::state::App> {
    crate::dist_root_install::install();
    crate::root::linked::register_stores(&crate::LINKED);
    let store = if let Some(prior) = prior {
        prior
            .governance
            .as_ref()
            .expect("retained governance")
            .core_store_handle()
            .unwrap()
    } else {
        crate::root::real_store::core().await
    };
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the actual Store artifact is required"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store carries its statement");
    let store_name = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("actual native Store statement")
        .name;
    let mut manifest = common::plugins::manifest("store", &store_name, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let directory = common::plugins::scratch(&format!("{}-store", provider.name));
    let library = std::fs::read(&library_path).expect("the actual Store image reads");
    let archive = common::plugins::signed(&common::plugins::key(0x33), manifest, &library);

    if !crate::LINKED
        .stores
        .iter()
        .any(|row| row.0 == store_name.as_str())
    {
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("the actual signed Store is staged");
    }
    let mut store_plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    store_plugins
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(common::plugins::key(0x33).verifying_key().as_bytes()),
        });
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("the actual Store settings are JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "store": {"module": store_name.as_str(), "settings": settings},
    }))
    .expect("the ordinary reload deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the ordinary reload deployment resolves");
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (mut app, _rotation, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        store_plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        prior,
        &rules,
        Some(store),
        false,
    )
    .await
    .expect("the production builder owns the supplied actual Store");
    let artifact =
        common::plugins::token_verifier_cdylib_path().expect("the actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .unwrap()
        .unwrap();
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .unwrap()
        .name;
    let directory = common::plugins::scratch(provider.name);
    common::credentials::install_auth_plugin(&directory, &module, provider.name, false);
    let mut plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    plugins
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(common::plugins::key(0x33).verifying_key().as_bytes()),
        });
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the signed actual OIDC plugin is admitted");
    let mut auth = busbar_kernel::config::AuthCfg::default_none();
    let mut entry = busbar_kernel::config::AuthChainEntry::bare(provider.name);
    entry.settings = common::credentials::settings(provider.name).into();
    auth.chain.push(entry);

    app.auth = Arc::new(
        busbar_kernel::auth::AuthMiddleware::new(
            &auth,
            &registry,
            &busbar_kernel::config::secret::SecretResolver::builtins_only(),
        )
        .expect("the actual configured OIDC chain constructs"),
    );
    Arc::new(app)
}

fn stage(provider: &Provider) {
    stage_at(provider, "/");
}

fn stage_at(provider: &Provider, path: &str) {
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_CONTAINS,
            path: path.into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("reload-fixture".into()),
        dialect: 0,
        auth: LineAuth::Chain(vec![provider.name.into()], AuthPoints(POINT_HEAD)),
        upgrade: None,
        offered: AuthPoints(POINT_HEAD),
    }])
    .expect("a real authenticated listener list");
    inbound::stage(guests, Vec::new());
}

fn identities(provider: &Provider) -> Vec<Option<String>> {
    provider
        .units
        .lock()
        .unwrap()
        .iter()
        .filter_map(|unit| inbound::host().admitted(*unit))
        .filter(|admitted| admitted.provider == provider.name)
        .map(|admitted| Some(admitted.identity.subject))
        .collect()
}

pub(super) fn request(stream: u32, path: &str, preface: bool) -> Vec<u8> {
    assert!(path.len() < 127);
    let mut bytes = Vec::new();
    if preface {
        bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        bytes.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    }
    let mut fields = vec![0x83, 0x86, 0x04, path.len() as u8];
    fields.extend_from_slice(path.as_bytes());
    fields.extend_from_slice(&[0x01, 9]);
    fields.extend_from_slice(b"localhost");
    let len = fields.len() as u32;
    bytes.extend_from_slice(&len.to_be_bytes()[1..]);
    bytes.extend_from_slice(&[1, 4]);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(&fields);
    bytes
}

fn authenticated_request(stream: u32, path: &str, preface: bool, provider: &Provider) -> Vec<u8> {
    let mut bytes = request(stream, path, preface);
    let offset = if preface { 33 } else { 0 };
    let token = format!(
        "Bearer {}",
        common::credentials::token_for(provider.name, &[], provider.name)
    );

    bytes.extend_from_slice(&[0x1f, 8]);
    let mut len = token.len();
    if len < 127 {
        bytes.push(len as u8);
    } else {
        bytes.push(127);
        len -= 127;
        while len >= 128 {
            bytes.push((len as u8 & 127) | 128);
            len >>= 7;
        }
        bytes.push(len as u8);
    }
    bytes.extend_from_slice(token.as_bytes());
    let len = (bytes.len() - offset - 9) as u32;
    bytes[offset..offset + 3].copy_from_slice(&len.to_be_bytes()[1..]);
    bytes
}

#[tokio::test]
async fn a_live_listener_reloads_new_requests_and_pins_the_old_requests_app() {
    crate::dist_root_install::install();
    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let units = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(dispatcher.install_auth_handle(Arc::new(ObserveActual {
        actual: inbound::LoaderSide(inbound::host().clone()),
        calls: calls.clone(),
        units: units.clone()
    })));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door,
        bind_on(&dispatcher),
    );
    let door: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
            .expect("the real HTTP transport opens"),
    );
    let resolver: FramerFor =
        Arc::new(move |scheme| (scheme == DATA_SCHEME).then(|| Arc::clone(&door)));
    let listener = listener_framed::data_framer(resolver).expect("a real nonzero transport owner");
    let before = provider("before-reload", &units);
    let old_app = app(&before, None).await;
    let old_app_weak = Arc::downgrade(&old_app);
    stage(&before);
    assert!(inbound::publish(&old_app).is_some());

    let (mut framing, _) = Framing::begin_lent(
        Arc::clone(listener.door()),
        SIDE_ACCEPT,
        "",
        &Established {
            scheme: Established::scheme_of(false),
            ..Established::default()
        },
        listener.guests(),
    )
    .expect("the production listener's list begins a connection");
    let first = framing.ingest(
        &authenticated_request(1, "/tickets/first", true, &before),
        false,
    );
    settle(&mut framing).await;
    let before_reload = identities(&before);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one actual auth call for the first stream"
    );

    let after = provider("after-reload", &units);
    let new_app = app(&after, Some(&old_app)).await;
    drop(old_app);
    stage(&after);
    for _ in 0..3 {
        assert!(inbound::publish(&new_app).is_some());
    }
    let second = framing.ingest(
        &authenticated_request(3, "/tickets/next", false, &after),
        false,
    );
    settle(&mut framing).await;
    let after_reload = identities(&after);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one actual auth call for each stream"
    );
    let retained_identity = identities(&before);
    let retained_app = old_app_weak.upgrade().is_some();
    framing.finish(CLOSE_NORMAL);
    let released_app = old_app_weak.upgrade().is_none();

    assert!(
        first.is_ok(),
        "the configured auth must run for the actual owner"
    );
    assert_eq!(
        before_reload,
        vec![Some(common::credentials::principal_id(before.name))]
    );
    assert!(
        second.is_ok(),
        "the next stream must use the newly published list"
    );
    assert_eq!(
        after_reload,
        vec![Some(common::credentials::principal_id(after.name))]
    );
    assert_eq!(retained_identity, before_reload);
    assert!(
        retained_app,
        "an active old unit pins its policy App beyond two reloads"
    );
    assert!(
        released_app,
        "ending the connection releases the old policy App"
    );
}

#[tokio::test]
async fn a_need_listener_uses_its_selected_policy_across_reload_without_changing_the_data_list() {
    crate::dist_root_install::install();
    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_kernel::host_services::caller_binding(),
    ));
    let units = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(dispatcher.install_auth_handle(Arc::new(ObserveActual {
        actual: inbound::LoaderSide(inbound::host().clone()),
        calls: calls.clone(),
        units: units.clone()
    })));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door,
        bind_on(&dispatcher),
    );
    let door: Arc<dyn FramerDoor> =
        Arc::new(Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher).unwrap());
    let resolver: FramerFor =
        Arc::new(move |scheme| (scheme == DATA_SCHEME).then(|| Arc::clone(&door)));
    let data = listener_framed::data_framer(Arc::clone(&resolver)).unwrap();
    let selected = listener_framed::listener_framer(
        resolver,
        DATA_SCHEME,
        Arc::new(|published| {
            let mut listener = published.clone();
            let mut line = listener.guests.lines()[0].clone();
            line.route.path = "/tickets/".into();
            line.claimant = Claimant::Need("inbound-fixture".into(), 0);
            listener.guests = GuestList::seal(vec![line]).unwrap();
            Ok(listener)
        }),
    )
    .unwrap();
    let before = provider("need-before", &units);
    let old_app = app(&before, None).await;
    let old = Arc::downgrade(&old_app);
    stage_at(&before, "/data-only/");
    inbound::publish(&old_app).unwrap();
    selected.validate_policy().unwrap();

    let (mut framing, _) = Framing::begin_lent(
        Arc::clone(selected.door()),
        SIDE_ACCEPT,
        "",
        &Established {
            scheme: Established::scheme_of(false),
            ..Established::default()
        },
        selected.guests(),
    )
    .unwrap();
    framing
        .ingest(
            &authenticated_request(1, "/tickets/first", true, &before),
            false,
        )
        .unwrap();
    settle(&mut framing).await;
    let first = identities(&before);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one actual auth call for the selected stream"
    );
    assert_eq!(
        first,
        vec![Some(common::credentials::principal_id(before.name))]
    );
    let after = provider("need-after", &units);
    stage_at(&after, "/data-only/");
    let next = app(&after, Some(&old_app)).await;
    drop(old_app);
    for _ in 0..3 {
        inbound::publish(&next).unwrap();
    }
    framing
        .ingest(
            &authenticated_request(3, "/tickets/next", false, &after),
            false,
        )
        .unwrap();
    settle(&mut framing).await;
    assert_eq!(
        identities(&after),
        vec![Some(common::credentials::principal_id(after.name))]
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one actual auth call for each selected stream"
    );
    assert_eq!(identities(&before), first);
    assert!(old.upgrade().is_some());
    let (mut ordinary, _) = Framing::begin_lent(
        Arc::clone(data.door()),
        SIDE_ACCEPT,
        "",
        &Established {
            scheme: Established::scheme_of(false),
            ..Established::default()
        },
        data.guests(),
    )
    .unwrap();
    let before_miss = calls.load(Ordering::SeqCst);
    let yielded = ordinary
        .ingest(
            &authenticated_request(1, "/tickets/data-miss", true, &after),
            false,
        )
        .unwrap();
    settle(&mut ordinary).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before_miss,
        "a route miss never calls actual auth"
    );
    assert!(
        yielded.pieces.is_empty(),
        "the data listener does not acquire the other listener's route"
    );
    assert_eq!(
        identities(&after),
        vec![Some(common::credentials::principal_id(after.name))],
        "a route miss never invokes the selected listener's auth"
    );
    ordinary.finish(CLOSE_NORMAL);
    framing.finish(CLOSE_NORMAL);
    assert!(old.upgrade().is_none());
}
