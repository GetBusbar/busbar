// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' SESSION ROUTES (ARCHITECT Q-L5B-SESSION-SERVE 2026-10-03; TRANSITIONAL with the
//! routes): a session route handed to `build_split_routers_serving_sessions` is mounted at the data
//! router's construction; its handler answers before any upgrade. An admitted session's socket is
//! bridged onto its pipe both ways, many messages each way (text stays text), and the session
//! dropping its sender closes the socket; a refusal goes out as it is and no socket binds.

use std::sync::Arc;

use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_kernel::plane_routes::{
    PlaneReqCtx, PlaneSessionSpec, SessionAnswer, SessionOut, SessionPipe,
};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

const OPEN: &str = "/session-route-test/live";
const REFUSED: &str = "/session-route-test/refused";

/// A session whose handler echoes each caller message as `echo:<msg>`, as one text message, and
/// ends after the caller's `bye`; or refuses with 403 before any upgrade.
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

async fn serve() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = crate::test_support::TestApp::new().build();
    let router = crate::build_split_routers_serving_sessions(
        app,
        Vec::new(),
        vec![session(OPEN), session(REFUSED)],
        busbar_kernel::proxy::max_translate_body_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, server)
}

#[tokio::test]
async fn an_admitted_session_is_bridged_both_ways_until_the_session_ends() {
    let (addr, server) = serve().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}{OPEN}"))
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
    // The session dropped its sender: the socket closes.
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
    let (addr, server) = serve().await;
    let refused = tokio_tungstenite::connect_async(format!("ws://{addr}{REFUSED}")).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
            assert_eq!(r.status().as_u16(), 403);
        }
        other => panic!("the refusal is the handler's 403: {:?}", other.map(|_| ())),
    }
    server.abort();
}
