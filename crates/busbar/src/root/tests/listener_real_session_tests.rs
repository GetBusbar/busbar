// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const VALID: &[u8] = b"GET /session HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn app() -> Arc<busbar_kernel::state::App> {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "real-session-app-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    drop(limits);
    drop(rotate);
    Arc::new(app)
}

async fn real_framer() -> (tokio::sync::MutexGuard<'static, ()>, DataFramer) {
    use crate::root::doors::{bind_on, Dispatched};
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
    use busbar_contract::transport::TransportSettings;
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};

    let publishing = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(crate::root::inbound::install(&dispatcher));
    let http = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
        bind_on(&dispatcher),
    );
    let ws = crate::root::test_plugins::linked_transport(
        busbar_transport_ws::door::door,
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
    let app = app();
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a real loopback TCP listener");
    let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .expect("the real peer connects");
    let (server, _) = listener
        .accept()
        .await
        .expect("the product accepts its peer");
    drop(listener);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(5),
        stopped,
    ));
    let mut wire = tokio::time::timeout(Duration::from_secs(10), async {
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

    let remaining = (16 * 1024 - wire.len() + 1) as u64;
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut client).take(remaining).read_to_end(&mut wire),
    )
    .await
    .expect("real transport reaches EOF after stop")
    .unwrap();
    assert!(wire.len() <= 16 * 1024, "bounded complete wire response");
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
