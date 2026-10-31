// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DATA LISTENER IS SERVED THROUGH ITS FRAMER'S ACCEPT SIDE (status row R3, "data listener
//! served through the http transport"; `BUSBAR-1.6.0.md`, inbound listeners). Core never tests a
//! plugin: the framer here is the test kit's accepting HTTP/1.1 fixture
//! (`busbar_test_kit::root_door_fixtures::h1_accept`), found by its facts as the build's http
//! transport is.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use busbar_core_connector::framer::FramerDoor;
use busbar_test_kit::root_door_fixtures::h1_accept::H1Accept;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{data_framer, DataFramer, DATA_LINE, DATA_SCHEME};

/// The data listener's framer as the boot finds it: the one answering [`DATA_SCHEME`].
fn found(door: Arc<H1Accept>) -> Option<DataFramer> {
    let door: Arc<dyn FramerDoor> = door;
    data_framer(Arc::new(move |scheme: &str| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&door))
    }))
}

/// Read one answer whose head states its body's length.
async fn answer(s: &mut tokio::net::TcpStream) -> String {
    let mut got = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&got).into_owned();
        if let Some(at) = text.find("\r\n\r\n") {
            let len = text[..at]
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if got.len() >= at + 4 + len {
                return text;
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
            .await
            .expect("the answer arrives")
            .expect("the socket reads");
        if n == 0 {
            return String::from_utf8_lossy(&got).into_owned();
        }
        got.extend_from_slice(&buf[..n]);
    }
}

/// RED (R3): a request on the data listener is framed by the framer's accept side, lent the
/// listener's guest list (its one `none` line, with the host's handle), served by the data router
/// in process, and its answer goes down through the framer: the head with its status on the emit,
/// then the body, its length stated as the hyper loop stated it.
#[tokio::test]
async fn the_data_listener_is_served_through_its_framers_accept_side() {
    let door = Arc::new(H1Accept::new(true));
    let framer = found(Arc::clone(&door)).expect("an accepting framer is found by its facts");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let addr = listener.local_addr().expect("bound");
    let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(super::super::serve_admitted_framed(
        super::super::SocketAdmits::new(listener),
        router,
        None,
        async {
            let _ = stopped.await;
        },
        None,
        Some(framer),
    ));
    let mut s = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connects");
    s.write_all(b"GET /hello HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .expect("writes");
    let got = answer(&mut s).await;
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert!(got.contains("content-length: 2\r\n"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nhi"), "{got:?}");
    assert_eq!(
        *door.statuses.lock().unwrap(),
        vec![200],
        "the answer's head went down through the framer, its status on the emit"
    );
    assert_eq!(
        *door.begun.lock().unwrap(),
        vec![vec![(DATA_LINE, 0, true)]],
        "the framing was begun lent the listener's one `none` line, with the host's handle"
    );
    drop(s);
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the listener drains")
        .expect("joins")
        .expect("serves");
}

/// A framer whose tail does not state that it accepts is not the data listener's: the build
/// serves the listener as before.
#[test]
fn a_framer_that_does_not_accept_is_not_the_data_listeners() {
    assert!(found(Arc::new(H1Accept::new(false))).is_none());
}

/// RED (the framed data listener bounds a silent connection, as the hyper loop's HTTP/1 header
/// read bound did): a plain connection that sends nothing is closed once
/// the first-byte bound (30 s, the hyper loop's header read bound) passes with no byte, even though its framer states no deadline.
#[tokio::test(start_paused = true)]
async fn a_silent_connection_is_closed_at_the_first_byte_bound() {
    let door = Arc::new(H1Accept::new(true));
    let framer = found(door).expect("found");
    let (_client, server) = tokio::io::duplex(1024);
    let (_stop, stop) = tokio::sync::watch::channel(false);
    let router = Router::new();
    let served = super::serve(server, framer, router, false, Duration::from_secs(30), stop);
    tokio::time::timeout(Duration::from_secs(31), served)
        .await
        .expect("a connection that sends nothing is closed at the bound");
}

#[tokio::test]
async fn a_parked_response_head_keeps_its_body_until_the_head_resumes() {
    let door = Arc::new(busbar_test_kit::root_door_fixtures::pending_h1_accept::parked_head());
    let entry: Arc<dyn FramerDoor> = door.clone();
    let framer = data_framer(Arc::new(move |scheme: &str| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&entry))
    }))
    .expect("the accepting fixture is found");
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let router = Router::new().route("/hello", axum::routing::get(|| async { "hi" }));
    let mut served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client
        .write_all(b"GET /hello HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_head())
        .await
        .expect("the response head is parked");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut served)
            .await
            .is_err(),
        "a parked response head must not let its following body fail the connection"
    );
    door.release();
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(b"\r\n\r\nhi") {
                break;
            }
        }
        String::from_utf8(got).unwrap()
    })
    .await
    .expect("the resumed head and body arrive");
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert!(got.contains("content-length: 2\r\n"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nhi"), "{got:?}");
    assert_eq!(door.statuses(), vec![200]);
    drop(client);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the connection drains")
        .expect("the serving task joins");
}
