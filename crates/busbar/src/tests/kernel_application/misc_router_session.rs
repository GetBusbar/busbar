// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel as kernel;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_kernel::plane_routes::{
    PlaneReqCtx, PlaneSessionSpec, SessionAnswer, SessionOut, SessionPipe,
};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const OPEN: &str = "/session-route-test/live";
const REFUSED: &str = "/session-route-test/refused";

fn session(path: &'static str) -> PlaneSessionSpec {
    PlaneSessionSpec {
        path: path.to_string(),
        auth: RouteAuth::None,
        handler: Arc::new(move |ctx: PlaneReqCtx| {
            Box::pin(async move {
                if ctx.path == REFUSED {
                    let mut r = axum::response::Response::new(axum::body::Body::from("no"));
                    *r.status_mut() = axum::http::StatusCode::FORBIDDEN;
                    return SessionAnswer::Refused(r);
                }
                let (from_caller, mut from) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
                let (to, to_caller) = tokio::sync::mpsc::channel::<SessionOut>(8);
                tokio::spawn(async move {
                    while let Some(msg) = from.recv().await {
                        let bye = msg.as_slice() == b"bye";
                        let echo = [b"echo:".as_slice(), &msg].concat();
                        if to
                            .send(SessionOut {
                                bytes: echo,
                                text: true,
                            })
                            .await
                            .is_err()
                            || bye
                        {
                            return;
                        }
                    }
                });
                SessionAnswer::Accepted(SessionPipe {
                    from_caller,
                    to_caller,
                })
            })
        }),
    }
}

async fn real_session_framer(
    app: &Arc<kernel::state::App>,
) -> (
    tokio::sync::MutexGuard<'static, ()>,
    crate::root::listener::framed::DataFramer,
) {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
    use busbar_contract::transport::TransportSettings;
    use busbar_core_connector::framer::FramerDoor;
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
    use busbar_plugin_loader::dispatch::kinds::transport::Transport;
    use busbar_plugin_loader::dispatch::{
        load_dropped, rendering_of_library, DispatchConfig, Dispatcher,
    };

    let publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(crate::root::inbound::install(&dispatcher));
    let mut products = Vec::new();
    for variable in ["BUSBAR_TEST_HTTP_CDYLIB", "BUSBAR_TEST_WS_CDYLIB"] {
        let path = std::path::PathBuf::from(
            std::env::var_os(variable)
                .unwrap_or_else(|| panic!("{variable} names the freshly built actual transport")),
        );
        assert!(
            path.is_absolute() && path.is_file(),
            "{variable} is an absolute actual image"
        );
        let statement = rendering_of_library(&path)
            .expect("read the actual transport statement")
            .expect("the actual transport exports its statement");
        let product =
            load_dropped::<Transport>(&path, &statement, crate::root::doors::bind_on(&dispatcher))
                .expect("load the actual transport image");
        let door: Arc<dyn FramerDoor> = Arc::new(
            crate::root::doors::Dispatched::open_on(
                product,
                &TransportSettings::default(),
                dispatcher.clone(),
            )
            .expect("the actual transport opens"),
        );
        products.push(door);
    }
    let http = products.remove(0);
    let ws = products.remove(0);
    let framer = crate::root::listener::framed::data_framer(Arc::new(move |scheme| match scheme {
        "http" => Some(http.clone()),
        "ws" => Some(ws.clone()),
        _ => None,
    }))
    .expect("the actual HTTP framer accepts the connection");
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_ANY,
            path_form: PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("ordinary-session-capability".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: Some("ws".into()),
        offered: AuthPoints(0),
    }])
    .expect("the ordinary session route data seals");
    crate::root::inbound::stage(guests, Vec::new());
    assert!(crate::root::inbound::publish(app).is_some());
    (publishing, framer)
}

async fn serve() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::MutexGuard<'static, ()>,
) {
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
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "router-session-{}",
        kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
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
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the host deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let (publishing, framer) = real_session_framer(&app).await;
    let router = kernel::build_split_routers_serving_sessions(
        app,
        Vec::new(),
        vec![session(OPEN), session(REFUSED)],
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        crate::root::listener::serve_admitted_framed(
            crate::root::listener::SocketAdmits::new(listener),
            router,
            None,
            std::future::pending::<()>(),
            None,
            Some(framer),
        )
        .await
        .expect("the actual framed listener serves the session router")
    });
    (addr, server, publishing)
}

#[tokio::test]
async fn an_admitted_session_is_bridged_both_ways_until_the_session_ends() {
    let (addr, server, _publishing) = serve().await;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the real peer");
    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}{OPEN}"), stream)
        .await
        .expect("the upgrade is answered");
    for msg in ["one", "two"] {
        ws.send(Message::Text(msg.into())).await.unwrap();
        let back = ws.next().await.expect("an answer").expect("a message");
        assert_eq!(
            back,
            Message::Text(format!("echo:{msg}").into()),
            "text stays text"
        );
    }
    ws.send(Message::Binary(b"bye".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(
        ws.next()
            .await
            .expect("the last answer")
            .expect("a message"),
        Message::Text("echo:bye".into())
    );

    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the socket closed with the session");
    server.abort();
}

#[tokio::test]
async fn a_refused_session_answers_before_any_upgrade() {
    let (addr, server, _publishing) = serve().await;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the real peer");
    let refused = tokio_tungstenite::client_async(format!("ws://{addr}{REFUSED}"), stream).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
            assert_eq!(r.status().as_u16(), 403);
        }
        other => panic!("the refusal is the handler's 403: {:?}", other.map(|_| ())),
    }
    server.abort();
}

#[tokio::test]
async fn a_websocket_plane_receives_no_scheme_derived_from_a_raw_credential() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let (seen, sighting) = tokio::sync::oneshot::channel();
    let seen = Arc::new(std::sync::Mutex::new(Some(seen)));
    let spec = PlaneSessionSpec {
        path: OPEN.into(),
        auth: RouteAuth::Key,
        handler: Arc::new(move |ctx: PlaneReqCtx| {
            let seen = Arc::clone(&seen);
            Box::pin(async move {
                assert!(!ctx.headers.contains_key("x-api-key"));
                assert!(!ctx.headers.contains_key("authorization"));
                seen.lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(ctx.consumed_fields)
                    .unwrap();
                let mut response = axum::response::Response::new(axum::body::Body::empty());
                *response.status_mut() = axum::http::StatusCode::FORBIDDEN;
                SessionAnswer::Refused(response)
            })
        }),
    };
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
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "router-session-{}",
        kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
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
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the host deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let (_publishing, framer) = real_session_framer(&app).await;
    let router = kernel::build_split_routers_serving_sessions(
        app,
        Vec::new(),
        vec![spec],
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        crate::root::listener::serve_admitted_framed(
            crate::root::listener::SocketAdmits::new(listener),
            router,
            None,
            std::future::pending::<()>(),
            None,
            Some(framer),
        )
        .await
        .expect("the actual framed listener serves the session router")
    });
    let mut request = format!("ws://{addr}{OPEN}").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-api-key", "secret-prefix secret-tail".parse().unwrap());
    request
        .headers_mut()
        .insert("authorization", "Bearer caller-secret".parse().unwrap());
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the real peer");
    let response = tokio_tungstenite::client_async(request, stream).await;
    match response {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status().as_u16(), 403),
        other => panic!(
            "the plane saw the request before refusing: {:?}",
            other.map(|_| ())
        ),
    }
    let fields: Vec<(String, String)> = sighting.await.unwrap();
    server.abort();
    assert!(fields.contains(&("x-api-key".into(), String::new())));
    assert!(fields.contains(&("authorization".into(), "Bearer".into())));
    assert!(!format!("{fields:?}").contains("secret"));
}
