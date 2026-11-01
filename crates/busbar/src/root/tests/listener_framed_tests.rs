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

#[tokio::test]
async fn a_final_body_emit_remains_alive_through_graceful_drain() {
    use std::future::Future as _;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct ObservedBody {
        inner: axum::body::Body,
        done: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl http_body::Body for ObservedBody {
        type Data = bytes::Bytes;
        type Error = axum::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            http_body::Body::poll_frame(Pin::new(&mut self.get_mut().inner), cx)
        }

        fn size_hint(&self) -> http_body::SizeHint {
            http_body::Body::size_hint(&self.inner)
        }

        fn is_end_stream(&self) -> bool {
            http_body::Body::is_end_stream(&self.inner)
        }
    }

    impl Drop for ObservedBody {
        fn drop(&mut self) {
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
        }
    }

    let door =
        Arc::new(busbar_test_kit::root_door_fixtures::pending_h1_accept::parked_final_body());
    let entry: Arc<dyn FramerDoor> = door.clone();
    let framer = data_framer(Arc::new(move |scheme: &str| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&entry))
    }))
    .expect("the accepting fixture is found");
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let (done, produced) = tokio::sync::oneshot::channel();
    let done = Arc::new(std::sync::Mutex::new(Some(done)));
    let router = Router::new().route(
        "/hello",
        axum::routing::get(move || {
            let done = done.lock().unwrap().take();
            async move {
                axum::response::Response::new(axum::body::Body::new(ObservedBody {
                    inner: axum::body::Body::from("hi"),
                    done,
                }))
            }
        }),
    );
    let served = super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    );
    tokio::pin!(served);
    client
        .write_all(b"GET /hello HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            () = door.wait_for_emit() => {},
            () = &mut served => panic!("the connection ended before the final body emit parked"),
        }
        tokio::select! {
            result = produced => result.expect("the response producer has finished"),
            () = &mut served => panic!("the parked final emit ended its connection"),
        }
    })
    .await
    .expect("the final emit parks and its producer finishes");
    assert_eq!(door.completions(), 0);
    stop.send(true).unwrap();
    std::future::poll_fn(|cx| {
        let mut drain = std::pin::pin!(tokio::task::unconstrained(served.as_mut()));
        assert!(
            drain.as_mut().poll(cx).is_pending(),
            "graceful drain must await the final parked body emit"
        );
        Poll::Ready(())
    })
    .await;
    door.release();
    tokio::time::timeout(Duration::from_secs(10), &mut served)
        .await
        .expect("the released final emit allows graceful drain");
    let mut got = String::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_string(&mut got))
        .await
        .expect("the drained connection closes")
        .unwrap();
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert!(got.contains("content-length: 2\r\n"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nhi"), "{got:?}");
    assert_eq!(door.statuses(), vec![200]);
    assert_eq!(
        door.completions(),
        1,
        "the final emit completed exactly once"
    );
}

#[tokio::test]
async fn a_parked_stream_does_not_hold_an_independent_stream_behind_its_body() {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct FirstBody {
        bytes: Option<bytes::Bytes>,
        produced: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl http_body::Body for FirstBody {
        type Data = bytes::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(produced) = this.produced.take() {
                let _ = produced.send(());
            }
            Poll::Ready(
                this.bytes
                    .take()
                    .map(|bytes| Ok(http_body::Frame::data(bytes))),
            )
        }
    }

    let door = Arc::new(busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux::default());
    let entry: Arc<dyn FramerDoor> = door.clone();
    let framer = data_framer(Arc::new(move |scheme: &str| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&entry))
    }))
    .expect("the multiplexing accepting fixture is found");
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let (produced, first_body) = tokio::sync::oneshot::channel();
    let produced = Arc::new(std::sync::Mutex::new(Some(produced)));
    let router = Router::new()
        .route(
            "/first",
            axum::routing::get(move || {
                let produced = produced.lock().unwrap().take();
                async move {
                    axum::response::Response::new(axum::body::Body::new(FirstBody {
                        bytes: Some(bytes::Bytes::from_static(b"first")),
                        produced,
                    }))
                }
            }),
        )
        .route("/second", axum::routing::get(|| async { "second" }));
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_head())
        .await
        .expect("stream one's response head parks");
    tokio::time::timeout(Duration::from_secs(10), first_body)
        .await
        .expect("the first body is produced")
        .unwrap();
    // This current-thread task resumes after the producer yields at its data acknowledgement:
    // stream one's data is queued before opening stream three. No wall-clock sleep orders them.
    client.write_all(b"3").await.unwrap();
    let independent = tokio::time::timeout(Duration::from_secs(10), door.wait_for_second()).await;
    let before_release = door.emitted();
    door.release();
    drop(client);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("both streams drain after release")
        .expect("the serving task joins");
    assert!(
        independent.is_ok(),
        "a parked stream held its independent sibling behind its body"
    );
    assert!(
        before_release.iter().all(|emit| emit.stream == 3),
        "stream one stays parked"
    );
    assert_eq!(
        before_release
            .iter()
            .filter(|emit| emit.status == 0)
            .flat_map(|emit| emit.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"second",
    );
    let all = door.emitted();
    let first: Vec<_> = all.iter().filter(|emit| emit.stream == 1).collect();
    assert_eq!(first.iter().filter(|emit| emit.status != 0).count(), 1);
    assert_eq!(
        first
            .iter()
            .filter(|emit| emit.status == 0)
            .flat_map(|emit| emit.bytes.iter().copied())
            .collect::<Vec<_>>(),
        b"first"
    );
    assert_eq!(
        first
            .iter()
            .filter(|emit| emit.status == 0 && emit.end)
            .count(),
        1
    );
}

#[tokio::test]
async fn a_session_waits_for_its_parked_message_before_emitting_the_next() {
    use busbar_kernel::plane_routes::{FramedSession, SessionOut, SessionPipe};

    let door =
        Arc::new(busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux::with_session());
    let entry: Arc<dyn FramerDoor> = door.clone();
    let framer = data_framer(Arc::new(move |scheme: &str| {
        matches!(scheme, DATA_SCHEME | "ws").then(|| Arc::clone(&entry))
    }))
    .expect("the accepting and session claims are found");
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            |axum::Extension(session): axum::Extension<FramedSession>| async move {
                let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                let (outgoing, to_caller) = tokio::sync::mpsc::channel(2);
                outgoing
                    .try_send(SessionOut {
                        bytes: b"first".to_vec(),
                        text: true,
                    })
                    .unwrap();
                outgoing
                    .try_send(SessionOut {
                        bytes: b"second".to_vec(),
                        text: false,
                    })
                    .unwrap();
                drop(outgoing);
                session.put(SessionPipe {
                    from_caller,
                    to_caller,
                });
                axum::http::StatusCode::SWITCHING_PROTOCOLS
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_head())
        .await
        .expect("the first session message parks");
    let ended_before_release = served.is_finished();
    let before_release = door.emitted();
    door.release();
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the session drains after its parked message resumes")
        .expect("the serving task joins");
    assert!(
        !ended_before_release,
        "a pending session message must keep the connection alive"
    );
    assert!(
        before_release.is_empty(),
        "no session message completes before its gate"
    );
    let emitted = door.emitted();
    assert_eq!(
        emitted
            .iter()
            .map(|value| value.bytes.as_slice())
            .collect::<Vec<_>>(),
        [b"first".as_slice(), b"second".as_slice()],
        "both messages complete once and in order despite the already-closed sender"
    );
    assert!(emitted.iter().all(|value| value.stream == 1 && value.end));
}
