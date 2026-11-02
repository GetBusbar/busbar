// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_CONTAINS};
use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT};
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::framer::{Established, FramerDoor, Framing};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};

use crate::root::doors::{bind_on, Dispatched};
use crate::root::inbound;
use crate::root::listener::framed::{self as listener_framed, FramerFor, DATA_SCHEME};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};

struct Provider {
    name: &'static str,
    units: Mutex<Vec<u64>>,
}

struct Answered(Option<VerifyAnswer>);
impl Future for Answered {
    type Output = VerifyAnswer;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.0.take().expect("one verification result"))
    }
}
impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}
impl AuthCalls for Provider {
    fn name(&self) -> &str {
        self.name
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        AuthPoints(POINT_HEAD)
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.units.lock().unwrap().push(request.unit);
        Box::new(Answered(Some(VerifyAnswer::from(Verified::Identity(
            VerifiedIdentity {
                subject: self.name.into(),
                ..VerifiedIdentity::default()
            },
        )))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn provider(name: &'static str) -> Arc<Provider> {
    Arc::new(Provider {
        name,
        units: Mutex::new(Vec::new()),
    })
}

fn app(provider: &Arc<Provider>) -> Arc<busbar_kernel::state::App> {
    let calls: Arc<dyn AuthCalls> = provider.clone();
    let store = crate::root::real_store::store();
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("the actual Store settings are JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "store": {"module": store.name(), "settings": settings},
    }))
    .expect("the ordinary reload deployment parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the ordinary reload deployment resolves");
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (mut app, _rotation, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
    )
    .expect("the production builder owns the supplied actual Store");
    // Only the host policy value varies between these Apps. The HTTP product
    // and listener still drive the actual admission and reload boundaries.
    app.auth = Arc::new(busbar_kernel::auth::AuthMiddleware::from_calls_for_test(
        vec![(provider.name.into(), calls)],
        &[],
    ));
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
        .map(|unit| inbound::host().admitted(*unit).map(|a| a.identity.subject))
        .collect()
}

// A literal HTTP/2 HEADERS block: POST, http, and a non-Huffman path. Keeping
// END_STREAM clear holds the real request open while later streams use a new policy.
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

#[tokio::test]
async fn a_live_listener_reloads_new_requests_and_pins_the_old_requests_app() {
    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(inbound::install(&dispatcher));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
        bind_on(&dispatcher),
    );
    let door: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
            .expect("the real HTTP transport opens"),
    );
    let resolver: FramerFor =
        Arc::new(move |scheme| (scheme == DATA_SCHEME).then(|| Arc::clone(&door)));
    let listener = listener_framed::data_framer(resolver).expect("a real nonzero transport owner");
    let before = provider("before-reload");
    let old_app = app(&before);
    let old_app_weak = Arc::downgrade(&old_app);
    stage(&before);
    assert!(inbound::publish(&old_app).is_some());
    drop(old_app);

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
    let first = framing.ingest(&request(1, "/tickets/first", true), false);
    let before_reload = identities(&before);

    let after = provider("after-reload");
    let new_app = app(&after);
    stage(&after);
    for _ in 0..3 {
        assert!(inbound::publish(&new_app).is_some());
    }
    let second = framing.ingest(&request(3, "/tickets/next", false), false);
    let after_reload = identities(&after);
    let retained_identity = identities(&before);
    let retained_app = old_app_weak.upgrade().is_some();
    framing.finish(CLOSE_NORMAL);
    let released_app = old_app_weak.upgrade().is_none();

    assert!(
        first.is_ok(),
        "the configured auth must run for the actual owner"
    );
    assert_eq!(before_reload, vec![Some(before.name.into())]);
    assert!(
        second.is_ok(),
        "the next stream must use the newly published list"
    );
    assert_eq!(after_reload, vec![Some(after.name.into())]);
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
    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(inbound::install(&dispatcher));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
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
    let before = provider("need-before");
    let old_app = app(&before);
    let old = Arc::downgrade(&old_app);
    stage_at(&before, "/data-only/");
    inbound::publish(&old_app).unwrap();
    selected.validate_policy().unwrap();
    drop(old_app);
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
        .ingest(&request(1, "/tickets/first", true), false)
        .unwrap();
    let first = identities(&before);
    assert_eq!(first, vec![Some(before.name.into())]);
    let after = provider("need-after");
    stage_at(&after, "/data-only/");
    let next = app(&after);
    for _ in 0..3 {
        inbound::publish(&next).unwrap();
    }
    framing
        .ingest(&request(3, "/tickets/next", false), false)
        .unwrap();
    assert_eq!(identities(&after), vec![Some(after.name.into())]);
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
    let yielded = ordinary
        .ingest(&request(1, "/tickets/data-miss", true), false)
        .unwrap();
    assert!(
        yielded.pieces.is_empty(),
        "the data listener does not acquire the other listener's route"
    );
    assert_eq!(
        identities(&after),
        vec![Some(after.name.into())],
        "a route miss never invokes the selected listener's auth"
    );
    ordinary.finish(CLOSE_NORMAL);
    framing.finish(CLOSE_NORMAL);
    assert!(old.upgrade().is_none());
}
