// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MOUNT'S OWN CELLS — what runs before a socket exists, and what has to have answered first.
//!
//! Everything here is driven over a REAL loopback server and a REAL client handshake, because the
//! claim is about the HANDSHAKE: an upgrade cannot be forged off a live connection (axum answers
//! `ConnectionNotUpgradable`), so an in-process call of the accept fn could never tell a 101 from a
//! refusal that never reached a socket. The client is the neutral guarded dialer — `Ok` is a 101,
//! `Err` is anything else, which is exactly the resolution these two cells need.
//!
//! The two claims are the two things that run BEFORE the protocol changes, in the order the module
//! header gives them:
//!
//! 1. **unit zero admitted** — the session opens on the driver, inside `open`, before the acceptor is
//!    asked for anything. A node whose units refuse the open binds NO socket.
//! 2. **the operator gate answered** — a `reject-all` gate attached to the plane's container refuses
//!    the open before the upgrade. This claim MOVED here from `busbar_voice::tests::hook_gate_tests`
//!    with the `ws_accept` body it used to drive: the WS front doors are mounted by this file now, so
//!    the gate on them is proven where the gate is fired.
//!
//! Each has a falsifiable CONTROL on the same composition — the identical dial that upgrades — so a
//! refusal cannot be a mount that was simply broken.

use std::sync::Arc;

use busbar_substrate::plane_host::{EngineHost, GateOutcome};
use busbar_substrate::testkit::fixture_host::{FixtureHost, GateScript};

use crate::root::units_voice::{ComposedUnits, VoiceIo};
use crate::root::ws_arrival::{MountedStreams, SessionDefaults};

/// The container the streams plane files its operator hooks under — the plane's own answer, read off
/// the projection it renders, never a second spelling here (this cell has to attach the gate where
/// the plane looks for it, so it asks the plane).
const GATE_CONTAINER: &str = "streams";

/// The one declared row these cells drive: the browser sideband, which dials nobody.
const MOUNT_PATH: &str = "/v1/realtime/sideband/{call_id}";
const DIAL_PATH: &str = "/v1/realtime/sideband/c-mount-0001";

/// COMPOSE THE MOUNT over a node the caller chose, leaked for the same reason production leaks it:
/// an accept fn registered into a process-wide registry outlives every session it serves.
fn mount(io: VoiceIo) -> &'static MountedStreams<ComposedUnits> {
    let node = Arc::new(crate::root::units_voice::tests::node(io));
    let kernel: &'static _ = Box::leak(Box::new(crate::root::kernel::new_kernel()));
    let units: &'static _ = Box::leak(Box::new(ComposedUnits::new(Arc::clone(&node))));
    let plane: &'static _ = Box::leak(Box::new(busbar_plane_streams::VoicePlane::new(&[])));
    let config: &'static _ = Box::leak(Box::new(SessionDefaults(String::new())));
    let gauge: &'static _ = Box::leak(Box::new(busbar_kernel::slice::ConcurrencyGauge::new()));
    let canary: &'static _ = Box::leak(Box::new(busbar_caps::Canary::new()));
    let driver: &'static _ = Box::leak(Box::new(
        crate::root::session_driver::SessionLoopDriver::new(
            kernel, units, plane, config, gauge, canary,
        ),
    ));
    let sealed = crate::root::registry::seal(crate::root::policy::client_settings(
        &busbar_substrate::config::limits::LimitsResolved::default(),
    ))
    .expect("the root seals");
    let egress: &'static _ = Box::leak(Box::new(crate::root::registry::WsLegEgress::new(
        Arc::clone(&sealed.transports.ws),
        busbar_contract::TransportKeyHandle::issue(&kernel.transport_key_token(), 0, ""),
        driver,
        crate::root::egress_guard::EgressGuard::default(),
        busbar_plane_streams::surface::MEDIA_JSON,
        busbar_contract::transport::session::EGRESS_DEPTH,
    )));
    Box::leak(Box::new(MountedStreams {
        driver,
        egress,
        surface: &busbar_plane_streams::surface::SURFACE,
        plane_key: busbar_voice::PLANE_DECL.key,
        media: busbar_plane_streams::surface::MEDIA_JSON,
        budgets: busbar_contract::transport::session::SessionBudgets { deadline: None },
    }))
}

/// A gate whose verdict is scripted verbatim — the shape the hermetic hook plugin reads off its own
/// settings, so the cell drives the seam production drives.
fn reject_all() -> GateScript {
    Arc::new(|_args_json: &[u8]| GateOutcome::Reject {
        status: 403,
        message: "no voice session today".to_string(),
        hook: "test-hook".to_string(),
    })
}

/// A host with nothing attached: the open proceeds past both hops untouched, which is the
/// byte-identical-when-unconfigured guarantee this file also exercises.
fn ungated_host() -> Arc<dyn EngineHost> {
    FixtureHost::new().into_host()
}

/// The same host with the gate filed under the PLANE's own decl key and container, exactly where a
/// configured deployment's resolved gate map puts it.
fn gated_host(script: GateScript) -> Arc<dyn EngineHost> {
    FixtureHost::new()
        .attach_gate(busbar_voice::PLANE_DECL.key, GATE_CONTAINER, script)
        .into_host()
}

/// DRIVE THE MOUNTED ARRIVAL over a real server and a real client handshake.
///
/// `Ok(())` is a 101 (the mount bound a socket), `Err(())` is anything else (it did not). The
/// arrival is built the way the core mount builds one — the declared bar is met by an Authorization
/// header, because the door is what the middleware already enforced by the time an accept fn runs.
async fn handshake(
    mount: &'static MountedStreams<ComposedUnits>,
    host: Arc<dyn EngineHost>,
) -> Result<(), ()> {
    let spec = mount
        .arrivals()
        .into_iter()
        .find(|spec| spec.path == MOUNT_PATH)
        .expect("the declared surface mounts the sideband row");
    let accept = Arc::clone(&spec.accept);

    #[derive(Clone)]
    struct S {
        accept: busbar_substrate::ingress::duplex_ws::WsAcceptFn,
        host: Arc<dyn EngineHost>,
    }
    async fn route(
        axum::extract::State(s): axum::extract::State<S>,
        upgrade: axum::extract::ws::WebSocketUpgrade,
    ) -> axum::response::Response {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer a-token-the-door-accepted"),
        );
        let arrival = busbar_substrate::ingress::duplex_ws::WsArrival {
            upgrade,
            gov: None,
            principal: None,
            caller_principal: Some("acct".to_string()),
            path: DIAL_PATH.to_string(),
            uri: axum::http::Uri::from_static(DIAL_PATH),
            headers,
            path_params: vec![("call_id".to_string(), "c-mount-0001".to_string())],
            host: s.host,
            slot: Arc::new(()),
        };
        (s.accept)(arrival).await
    }

    let app = axum::Router::new()
        .route(DIAL_PATH, axum::routing::get(route))
        .with_state(S { accept, host });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let policy = busbar_substrate::net_guard::GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..busbar_substrate::net_guard::GuardPolicy::default()
    };
    match busbar_substrate::egress::duplex_ws::dial(&format!("ws://{addr}{DIAL_PATH}"), policy)
        .await
    {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// THE SOCKET IS BOUND ONLY AFTER UNIT ZERO ADMITTED.
///
/// The opening unit runs inside `SessionDriver::open`, which the mount calls before it asks the
/// neutral acceptor for anything — so a session the unit loop refuses is answered as a STATUS on the
/// leg underneath and the protocol never changes. That ordering is why this mount composes no
/// admission of its own in front of the upgrade: there is exactly one admission, it is the unit
/// loop's, and it has already answered by the time a socket could exist.
///
/// Driven on the node's own refusal: a node with NO I/O half is refused at admit (its lease cannot be
/// taken), which is a refusal from unit zero and not from the door — the door is the same on both
/// sides of this cell, and the control below is the identical dial on a node that can pay.
#[tokio::test]
async fn the_socket_is_bound_only_after_unit_zero_admitted() {
    assert!(
        handshake(mount(VoiceIo::default()), ungated_host())
            .await
            .is_err(),
        "a node whose unit zero refuses the open must bind NO socket: the refusal is a status on \
         the leg underneath, answered before the protocol changed"
    );
    assert!(
        handshake(
            mount(crate::root::units_voice::tests::serviceable()),
            ungated_host()
        )
        .await
        .is_ok(),
        "the control: the SAME mount over a node unit zero admits upgrades (101), which is what \
         makes the refusal above a refusal and not a mount that never worked"
    );
}

/// A REJECT-ALL OPERATOR GATE REFUSES THE OPEN BEFORE THE UPGRADE.
///
/// MOVED here from the plane, with the body it drove. The WS front doors have no preceding one-shot
/// pass, so the operator gate on them is the only request screening a session gets before it runs —
/// and a mount that dropped the hop would be worse than not mounting. The gate fires through the
/// neutral `host.gate_decide` seam under the PLANE's own key and container, so what runs here is
/// what a configured deployment runs.
#[tokio::test]
async fn a_reject_all_operator_gate_refuses_the_open_before_the_upgrade() {
    let mount = mount(crate::root::units_voice::tests::serviceable());
    assert!(
        handshake(mount, ungated_host()).await.is_ok(),
        "with nothing attached the open proceeds past the gate and the socket upgrades (101)"
    );
    assert!(
        handshake(mount, gated_host(reject_all())).await.is_err(),
        "a reject-all gate attached to this plane's container must REFUSE the open before the \
         protocol changes — no socket, no session"
    );
}

/// THE MOUNT OPENS ONE SESSION, AND OPENS IT BEFORE THE SOCKET.
///
/// A structural cell, reading the door's own source, and it is here for the reason the plane's
/// deleted twin was there: the property lives in the SHAPE of the accept fn, not in any one run of
/// it. A second `open` added beside the first would be a session the unit loop judged twice; one
/// added AFTER the acceptor would be a session judged on a socket that was already bound, which is
/// the ordering the cells above prove the observable half of. Neither is reachable by driving a
/// handshake, because both are still one 101.
#[test]
fn the_mount_opens_one_session_and_opens_it_before_the_socket() {
    let door = include_str!("../ws_arrival.rs");
    let opens = door.matches("self.driver.open(").count();
    assert_eq!(
        opens, 1,
        "the mount opens exactly ONE session per upgrade; this file has {opens} open site(s)"
    );
    let open_at = door.find("self.driver.open(").expect("the one open site");
    let socket_at = door.find("accept_coded(").expect("the one acceptor site");
    assert!(
        open_at < socket_at,
        "the session opens BEFORE the acceptor is asked for a socket — a refusal past that point \
         has nowhere left to be answered but a close code on a socket nobody asked for"
    );
}
