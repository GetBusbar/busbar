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
use busbar_kernel::test_support::TestApp;
use busbar_test_kit::root_door_fixtures::scoped_mux;

use crate::root::doors::{bind_on, Dispatched};
use crate::root::inbound;
use crate::root::listener_framed::{self, FramerFor, DATA_SCHEME};
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
    TestApp::new()
        .auth(Arc::new(
            busbar_kernel::auth::AuthMiddleware::from_doors_for_test(vec![(
                provider.name.into(),
                calls,
            )]),
        ))
        .build()
}

fn stage(provider: &Provider) {
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_CONTAINS,
            path: "/".into(),
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

#[tokio::test]
async fn a_live_listener_reloads_new_requests_and_pins_the_old_requests_app() {
    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(inbound::install(&dispatcher));
    let plugin =
        crate::root::test_plugins::linked_transport(scoped_mux::door, bind_on(&dispatcher));
    let door: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher)
            .expect("the real loaded fixture opens"),
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
    let first = framing.ingest(&[5], false);
    let before_reload = identities(&before);

    let after = provider("after-reload");
    let new_app = app(&after);
    stage(&after);
    for _ in 0..3 {
        assert!(inbound::publish(&new_app).is_some());
    }
    let second = framing.ingest(&[7], false);
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
