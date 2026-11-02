// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real linked HTTP -> WS composition, rather than a simulated framer's upgrade result.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const VALID: &[u8] = b"GET /session HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

async fn real_framer() -> (tokio::sync::MutexGuard<'static, ()>, DataFramer) {
    use crate::root::doors::{bind_on, Dispatched};
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
    use busbar_contract::transport::TransportSettings;
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};

    let publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(crate::root::inbound::install(&dispatcher));
    let http = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door,
        bind_on(&dispatcher),
    );
    let ws = crate::root::test_plugins::linked_transport(
        busbar_transport_ws::door,
        bind_on(&dispatcher),
    );
    let http: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open_on(http, &TransportSettings::default(), dispatcher.clone()).unwrap(),
    );
    let ws: Arc<dyn FramerDoor> =
        Arc::new(Dispatched::open_on(ws, &TransportSettings::default(), dispatcher).unwrap());
    let framer = data_framer(Arc::new(move |scheme| match scheme {
        "http" => Some(http.clone()),
        "ws" => Some(ws.clone()),
        _ => None,
    }))
    .expect("real HTTP owns the accepted connection");
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_ANY,
            path_form: PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("real-session-fixture".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: Some("ws".into()),
        offered: AuthPoints(0),
    }])
    .unwrap();
    crate::root::inbound::stage(guests, Vec::new());
    let app = busbar_kernel_testkit::test_support::TestApp::new().build();
    assert!(crate::root::inbound::publish(&app).is_some());
    (publishing, framer)
}

fn route(effects: Arc<AtomicUsize>, accepted: bool) -> Router {
    Router::new().route(
        "/session",
        axum::routing::get(
            move |axum::Extension(slot): axum::Extension<
                busbar_kernel::plane_routes::FramedSession,
            >| {
                let effects = effects.clone();
                async move {
                    if !slot.admit().await {
                        return axum::http::Response::builder()
                            .status(403)
                            .body(axum::body::Body::from(
                                "extractor fallback must not replace transport refusal",
                            ))
                            .unwrap();
                    }
                    effects.fetch_add(1, Ordering::SeqCst);
                    if accepted {
                        let (to_session, _from_caller) = tokio::sync::mpsc::channel(1);
                        let (_to_caller, from_session) = tokio::sync::mpsc::channel(1);
                        slot.put(busbar_kernel::plane_routes::SessionPipe {
                            from_caller: to_session,
                            to_caller: from_session,
                        });
                        axum::http::Response::builder()
                            .status(101)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    } else {
                        axum::http::Response::builder()
                            .status(401)
                            .header("www-authenticate", "Bearer realm=\"real-plane\"")
                            .body(axum::body::Body::from(
                                "the actual plane refused completely",
                            ))
                            .unwrap()
                    }
                }
            },
        ),
    )
}

async fn exchange(framer: DataFramer, router: Router, request: &[u8], body: &[u8]) -> Vec<u8> {
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(5),
        stopped,
    ));
    let wire = tokio::time::timeout(Duration::from_secs(10), async {
        client.write_all(request).await.unwrap();
        let mut wire = Vec::new();
        loop {
            let mut chunk = [0; 1024];
            let count = client.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            wire.extend_from_slice(&chunk[..count]);
            assert!(wire.len() < 16 * 1024, "bounded wire response");
            if wire.windows(4).any(|part| part == b"\r\n\r\n")
                && (body.is_empty() || wire.windows(body.len()).any(|part| part == body))
            {
                break;
            }
        }
        wire
    })
    .await
    .expect("real transport answers without hanging");
    let _ = stop.send(true);
    drop(client);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("real transport actor terminates")
        .unwrap();
    wire
}

#[tokio::test]
async fn real_http_plain_get_refuses_upgrade_before_plane_effects() {
    let (_publishing, framer) = real_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let wire = exchange(
        framer,
        route(effects.clone(), false),
        b"GET /session HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"",
    )
    .await;
    assert!(wire.starts_with(b"HTTP/1.1 400"), "{wire:?}");
    assert!(!wire.windows(12).any(|part| part == b"HTTP/1.1 101"));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn real_ws_missing_key_refuses_before_plane_effects() {
    let (_publishing, framer) = real_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let wire = exchange(framer, route(effects.clone(), false), b"GET /session HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n", b"").await;
    assert!(
        wire.starts_with(b"HTTP/1.1 400") || wire.starts_with(b"HTTP/1.1 426"),
        "{wire:?}"
    );
    assert!(!wire.windows(12).any(|part| part == b"HTTP/1.1 101"));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn real_ws_admitted_plane_refusal_preserves_auth_head_and_complete_body() {
    let (_publishing, framer) = real_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let body = b"the actual plane refused completely";
    let wire = exchange(framer, route(effects.clone(), false), VALID, body).await;
    assert!(wire.starts_with(b"HTTP/1.1 401"), "{wire:?}");
    let text = String::from_utf8_lossy(&wire);
    assert!(
        text.to_ascii_lowercase()
            .contains("www-authenticate: bearer realm=\"real-plane\""),
        "{text}"
    );
    assert!(wire.windows(body.len()).any(|part| part == body));
    assert!(!wire.windows(12).any(|part| part == b"HTTP/1.1 101"));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn real_ws_admitted_pipe_commits_one_actual_handshake() {
    let (_publishing, framer) = real_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let wire = exchange(framer, route(effects.clone(), true), VALID, b"").await;
    assert!(wire.starts_with(b"HTTP/1.1 101"), "{wire:?}");
    let text = String::from_utf8_lossy(&wire).to_ascii_lowercase();
    assert!(
        text.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "{text}"
    );
    assert_eq!(text.matches("http/1.1 101").count(), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}
