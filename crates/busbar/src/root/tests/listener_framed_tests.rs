// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use busbar_core_connector::framer::FramerDoor;
use busbar_test_kit::root_door_fixtures::h1_accept::H1Accept;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{data_framer, DataFramer, DATA_LINE, DATA_SCHEME};

fn h1_fixture_ingest_chunks(
    chunks: &[&[u8]],
) -> Vec<(busbar_contract::abi::mechanism::call::Outcome, u32)> {
    h1_fixture_ingest_chunks_with_cap(chunks, 1024)
}

fn h1_fixture_ingest_chunks_with_cap(
    chunks: &[&[u8]],
    frame_cap: usize,
) -> Vec<(busbar_contract::abi::mechanism::call::Outcome, u32)> {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::transport::{
        BeginIn, FramePiece, FramerOut, FramerSink, HeadSlots, IngestIn,
    };
    use busbar_core_connector::framer::Call;
    use busbar_test_kit::test_support::zeroed;

    let door = H1Accept::new(true);
    let mut begin: BeginIn = zeroed();
    let mut opened: FramerOut = zeroed();
    assert_eq!(
        door.cross(Call::Begin(&mut begin, &mut opened)).outcome,
        Outcome::Ready
    );
    let mut frame = [0_u8; 1024];
    let mut pieces: [FramePiece; 4] = [zeroed(); 4];
    let mut heads = [HeadSlots::default(); 2];
    chunks
        .iter()
        .map(|bytes| {
            let mut input: IngestIn = zeroed();
            input.framing = opened.framing;
            input.bytes = bytes.as_ptr();
            input.len = bytes.len();
            input.sink = FramerSink {
                frame: frame.as_mut_ptr(),
                frame_cap,
                pieces: pieces.as_mut_ptr(),
                pieces_cap: pieces.len(),
                heads: heads.as_mut_ptr(),
                heads_cap: heads.len(),
                ..zeroed()
            };
            let mut out: FramerOut = zeroed();
            let answer = door.cross(Call::Ingest(&mut input, &mut out));
            (answer.outcome, out.yielded.pieces_len)
        })
        .collect()
}

#[test]
fn h1_fixture_refuses_a_request_larger_than_the_lent_frame_capacity() {
    use busbar_contract::abi::mechanism::call::Outcome;

    let got = h1_fixture_ingest_chunks_with_cap(&[b"GET / HTTP/1.1\r\n\r\n"], 1);
    assert_eq!(got[0].0, Outcome::Failed);
}

#[test]
fn h1_fixture_refuses_complete_malformed_heads_without_waiting_for_more_bytes() {
    use busbar_contract::abi::mechanism::call::Outcome;
    for request in [
        b"POST / HTTP/1.1\r\nbroken-field\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\ncontent-length: nope\r\n\r\n".as_slice(),
    ] {
        assert_eq!(h1_fixture_ingest_chunks(&[request])[0].0, Outcome::Failed);
    }
    let overflow = format!("POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n", usize::MAX);
    assert_eq!(
        h1_fixture_ingest_chunks(&[overflow.as_bytes()])[0].0,
        Outcome::Failed
    );
}

#[test]
fn h1_fixture_keeps_incomplete_headers_and_bodies_until_they_complete() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let answers =
        h1_fixture_ingest_chunks(&[b"POST / HTTP/1.1\r\ncontent-length: 3\r\n", b"\r\na", b"bc"]);
    assert_eq!(
        answers,
        [
            (Outcome::Ready, 0),
            (Outcome::Ready, 0),
            (Outcome::Ready, 2)
        ]
    );
}

fn custody_conn(
    router: Router,
) -> (
    tokio::io::DuplexStream,
    super::Conn<tokio::io::DuplexStream>,
) {
    use busbar_core_connector::framer::{Established, Framing};
    let framer = found(Arc::new(H1Accept::new(true))).unwrap();
    let established = Established {
        scheme: Established::scheme_of(false),
        ..Established::default()
    };
    let (framing, _) = Framing::begin_lent(
        Arc::clone(framer.door()),
        busbar_contract::abi::transport::SIDE_ACCEPT,
        "",
        &established,
        framer.guests(),
    )
    .unwrap();
    let (client, server) = tokio::io::duplex(1024);
    let (tx, ops) = tokio::sync::mpsc::unbounded_channel();
    let (admission_tx, admissions) = tokio::sync::mpsc::unbounded_channel();
    (
        client,
        super::Conn {
            io: crate::root::listener::Lingering(Some(server)),
            framing: Some(framing),
            framer,
            router,
            secured: false,
            established,
            timeout: Duration::from_secs(30),
            out: Default::default(),
            read_done: false,
            ended: false,
            heads: Default::default(),
            inflows: Default::default(),
            tasks: tokio::task::JoinSet::new(),
            ops,
            tx,
            pending: Default::default(),
            admission_tx,
            admissions,
            staged: None,
            prewire: false,
            full: Default::default(),
            deadline: None,
            session: None,
            agreed: 0,
            stopping: false,
            failed: false,
            first_byte: None,
        },
    )
}

fn custody_piece(
    stream: u64,
    bytes: Vec<u8>,
    fields: bool,
    end: bool,
) -> busbar_core_connector::framer::Got {
    busbar_core_connector::framer::Got {
        stream,
        bytes,
        fields,
        end,
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        text: false,
        reason: None,
        failed: false,
    }
}

fn custody_head(conn: &mut super::Conn<tokio::io::DuplexStream>, stream: u64, target: &str) {
    conn.heads.insert(
        stream,
        busbar_core_connector::framer::Head {
            stream,
            method: Some(b"POST".to_vec()),
            target: Some(target.as_bytes().to_vec()),
            ..Default::default()
        },
    );
    conn.piece(custody_piece(stream, Vec::new(), true, false));
}

#[tokio::test]
async fn an_unread_body_is_refused_at_the_existing_limit_without_refusing_its_sibling() {
    let _publishing = anonymous_policy().await;
    let router = Router::new()
        .route(
            "/stall",
            axum::routing::post(|body: axum::body::Body| async move {
                std::future::pending::<()>().await;
                drop(body);
                "done"
            }),
        )
        .route(
            "/fast",
            axum::routing::post(|body: axum::body::Body| async move {
                axum::body::to_bytes(body, usize::MAX).await.unwrap()
            }),
        );
    let (_client, mut conn) = custody_conn(router);
    custody_head(&mut conn, 3, "/stall");
    custody_head(&mut conn, 5, "/fast");
    let limit = busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
        |limits| limits.request_body_max_bytes,
    );
    assert!(limit > 0, "the fixture uses the resolved finite default");
    let mut remaining = limit;
    while remaining != 0 {
        let count = remaining.min(super::READ_CHUNK);
        conn.piece(custody_piece(3, vec![b'x'; count], false, false));
        remaining -= count;
    }
    assert!(conn.pending.is_empty(), "exactly the ceiling is accepted");
    conn.piece(custody_piece(3, vec![b'x'], false, false));
    conn.piece(custody_piece(3, vec![b'y'], false, false));
    assert_eq!(
        conn.pending
            .iter()
            .filter(|(stream, op)| *stream == 3
                && matches!(
                    op,
                    super::Op::Refuse {
                        status: super::BODY_LIMIT_REFUSAL,
                        ..
                    }
                ))
            .count(),
        1
    );
    assert!(
        conn.inflows[&3].body.is_none(),
        "the oversized queue releases its sender"
    );
    assert!(
        conn.inflows[&5].body.is_some(),
        "the sibling remains readable"
    );
    assert!(
        !conn.failed,
        "one oversized stream does not fail the multiplexed connection"
    );
    let (done, said) = tokio::sync::oneshot::channel();
    conn.pending.push_back((
        3,
        super::Op::Head {
            status: 200,
            fields: Vec::new(),
            end: false,
            done,
        },
    ));
    let (done, trailers) = tokio::sync::oneshot::channel();
    conn.pending.push_back((
        3,
        super::Op::Trailers {
            fields: b"final-status: 0\r\n".to_vec(),
            done,
        },
    ));
    conn.apply_front();
    conn.apply_front();
    conn.apply_front();
    assert!(
        !said.await.unwrap_or(false),
        "a late success cannot follow the size refusal"
    );
    assert!(
        !trailers.await.unwrap_or(false),
        "late successful trailers cannot follow the size refusal"
    );
    conn.piece(custody_piece(5, b"sibling".to_vec(), false, true));
    let mut answer = Vec::new();
    loop {
        let (stream, op) = conn.ops.recv().await.expect("the sibling answers");
        match (stream, op) {
            (5, super::Op::Head { status, done, .. }) => {
                assert_eq!(status, 200);
                let _ = done.send(true);
            }
            (5, super::Op::Data { bytes, end, done }) => {
                answer.extend_from_slice(&bytes);
                let _ = done.send(true);
                if end {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(
        answer, b"sibling",
        "the other stream still delivers its body and answer"
    );
    conn.tasks.abort_all();
}

#[tokio::test(flavor = "current_thread")]
async fn abort_before_first_poll_retires_the_inflow_while_its_sibling_stays_live() {
    let _publishing = anonymous_policy().await;
    for reset in [false, true] {
        let routed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&routed);
        let router = Router::new().route(
            "/stall",
            axum::routing::post(move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::pending::<&'static str>()
            }),
        );
        let (_client, mut conn) = custody_conn(router);
        custody_head(&mut conn, 3, "/stall");
        custody_head(&mut conn, 5, "/stall");
        conn.inflows.get_mut(&3).unwrap().body_limit = 1;
        let mut terminal = custody_piece(3, b"xx".to_vec(), false, reset);
        terminal.failed = reset;
        conn.piece(terminal);
        assert_eq!(routed.load(std::sync::atomic::Ordering::SeqCst), 0);

        let joined = conn.tasks.join_next().await.unwrap();
        assert!(joined.unwrap_err().is_cancelled());
        let (stream, op) = conn
            .ops
            .recv()
            .await
            .expect("the aborted future owns retirement");
        assert_eq!(stream, 3);
        assert!(matches!(op, super::Op::Ended { .. }));
        conn.pending.push_back((stream, op));
        while !conn.pending.is_empty() {
            assert!(matches!(conn.apply_front(), super::Step::Done));
        }
        assert!(!conn.inflows.contains_key(&3));
        assert!(conn.inflows.contains_key(&5));
        assert!(conn.framing.is_some());
        assert!(conn.ops.try_recv().is_err(), "retirement is queued once");
        conn.tasks.abort_all();
    }
}

#[tokio::test]
async fn final_fields_follow_data_and_are_acknowledged_before_the_producer_returns() {
    use axum::http::{HeaderMap, HeaderValue};
    use bytes::Bytes;

    struct Frames(std::collections::VecDeque<http_body::Frame<Bytes>>);
    impl http_body::Body for Frames {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            std::task::Poll::Ready(self.get_mut().0.pop_front().map(Ok))
        }
    }

    for final_status in ["0", "7", "13", "1"] {
        let mut trailers = HeaderMap::new();
        trailers.append("final-status", HeaderValue::from_static(final_status));
        trailers.append("final-detail", HeaderValue::from_static("one"));
        trailers.append("final-detail", HeaderValue::from_static("two"));
        let body = Frames(
            [
                http_body::Frame::data(Bytes::from_static(b"reply")),
                http_body::Frame::trailers(trailers.clone()),
            ]
            .into(),
        );
        let (tx, mut ops) = tokio::sync::mpsc::unbounded_channel();
        let out = super::Emitter { stream: 3, tx };
        let producer = tokio::spawn(async move {
            super::respond(&out, axum::http::Response::new(axum::body::Body::new(body))).await;
        });
        match ops.recv().await.unwrap().1 {
            super::Op::Head { end, done, .. } => {
                assert!(!end);
                done.send(true).unwrap();
            }
            _ => panic!("head precedes body"),
        }
        match ops.recv().await.unwrap().1 {
            super::Op::Data { bytes, end, done } => {
                assert_eq!(bytes, b"reply".as_slice());
                assert!(!end);
                done.send(true).unwrap();
            }
            _ => panic!("data precedes final fields"),
        }
        match ops.recv().await.unwrap().1 {
            super::Op::Trailers { fields, done } => {
                assert_eq!(fields, super::field_block(&trailers));
                assert!(
                    !producer.is_finished(),
                    "trailer custody awaits acknowledgement"
                );
                done.send(true).unwrap();
            }
            _ => panic!("the terminal frame remains fields"),
        }
        producer.await.unwrap();
        assert!(
            ops.recv().await.is_none(),
            "no successful empty data ending follows trailers"
        );
    }
}

#[test]
fn an_early_closing_field_declaration_keeps_an_exact_body_from_becoming_sized() {
    let mut head = axum::http::HeaderMap::new();
    head.insert(
        "trailer",
        axum::http::HeaderValue::from_static("final-status"),
    );
    assert_eq!(
        super::head_block(200, &head, Some(5)),
        b"trailer: final-status\r\n"
    );
    head.remove("trailer");
    assert_eq!(
        super::head_block(200, &head, Some(5)),
        b"content-length: 5\r\n"
    );
}

#[tokio::test]
async fn a_full_session_pipe_stops_socket_reads_until_its_reader_takes_a_message() {
    let _publishing = anonymous_policy().await;
    let (mut client, mut conn) = custody_conn(Router::new());
    let (from_caller, mut received) = tokio::sync::mpsc::channel(1);
    let (_to, to_caller) = tokio::sync::mpsc::channel(1);
    conn.session = Some(super::Session::over(
        3,
        busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        },
    ));
    conn.piece(custody_piece(3, b"first".to_vec(), false, false));
    conn.piece(custody_piece(3, b"second".to_vec(), false, false));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    conn.pump_session(&mut cx);
    client.write_all(b"x").await.unwrap();
    assert!(
        !conn.read(&mut cx),
        "the full switched pipe must hold the next socket read"
    );
    assert_eq!(received.recv().await.unwrap(), b"first");
    conn.pump_session(&mut cx);
    assert_eq!(received.recv().await.unwrap(), b"second");
    assert!(
        conn.read(&mut cx),
        "consumption releases socket backpressure"
    );
    conn.session = None;
    assert!(
        received.recv().await.is_none(),
        "dropping the session retires every sender without a detached bridge task"
    );
}

#[tokio::test]
async fn switched_messages_use_the_existing_body_ceiling_before_reassembly() {
    let _publishing = anonymous_policy().await;
    let (_client, mut conn) = custody_conn(Router::new());
    let (from_caller, _received) = tokio::sync::mpsc::channel(1);
    let (_to, to_caller) = tokio::sync::mpsc::channel(1);
    conn.session = Some(super::Session::over(
        3,
        busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        },
    ));
    let limit = busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
        |l| l.request_body_max_bytes,
    );
    let mut piece = custody_piece(3, vec![0; limit], false, false);
    piece.end_of_frame = false;
    conn.piece(piece);
    assert!(!conn.failed);
    conn.piece(custody_piece(3, vec![0], false, false));
    assert!(
        conn.failed,
        "the next fragment cannot grow past the configured message bound"
    );
}

#[tokio::test]
async fn a_terminal_session_piece_delivers_its_payload_before_closing_the_pipe() {
    let _publishing = anonymous_policy().await;
    let (mut client, mut conn) = custody_conn(Router::new());
    let (from_caller, mut received) = tokio::sync::mpsc::channel(1);
    let (_to, to_caller) = tokio::sync::mpsc::channel(1);
    conn.session = Some(super::Session::over(
        3,
        busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        },
    ));
    conn.piece(custody_piece(3, b"last".to_vec(), false, true));
    client
        .write_all(b"POST /stall HTTP/1.1\r\nhost: fixture\r\ncontent-length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        conn.poll(&mut cx).is_ready(),
        "EOF ends both legs after delivering the terminal payload"
    );
    assert!(conn.session.is_none());
    assert!(conn.framing.is_none());
    assert!(
        conn.inflows.is_empty(),
        "queued bytes cannot become a new request after session EOF"
    );
    assert_eq!(received.recv().await.unwrap(), b"last");
    assert!(received.recv().await.is_none());
}

#[tokio::test]
async fn a_session_that_drops_its_reader_ends_without_waiting_for_its_writer() {
    let _publishing = anonymous_policy().await;
    let (mut client, mut conn) = custody_conn(Router::new());
    let (from_caller, received) = tokio::sync::mpsc::channel(1);
    let (_writer_still_alive, to_caller) = tokio::sync::mpsc::channel(1);
    conn.session = Some(super::Session::over(
        3,
        busbar_kernel::plane_routes::SessionPipe {
            from_caller,
            to_caller,
        },
    ));
    drop(received);
    conn.piece(custody_piece(3, b"unread".to_vec(), false, false));
    client
        .write_all(b"POST /stall HTTP/1.1\r\nhost: fixture\r\ncontent-length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        conn.poll(&mut cx).is_ready(),
        "failed delivery is terminal independently of the outgoing sender"
    );
    assert!(conn.session.is_none());
    assert!(conn.framing.is_none());
    assert!(
        conn.inflows.is_empty(),
        "failed delivery closes before ingesting a queued request"
    );
}

struct RefuseAnswer {
    inner: H1Accept,
    outcome: busbar_contract::abi::mechanism::call::Outcome,
}

impl FramerDoor for RefuseAnswer {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        self.inner.facts()
    }
    fn accepts(&self) -> bool {
        true
    }
    fn instance(&self) -> Option<u64> {
        self.inner.instance()
    }
    fn cross(
        &self,
        call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        use busbar_contract::abi::mechanism::call::Outcome;
        use busbar_core_connector::framer::{Call, Crossed};
        if matches!(&call, Call::Refuse(..)) && self.outcome != Outcome::Ready {
            return Crossed {
                outcome: self.outcome,
                error: Some(b"refusal rendering failed".to_vec()),
            };
        }
        self.inner.cross(call)
    }
}

#[tokio::test]
async fn a_failed_refusal_ends_the_connection_and_a_rendered_refusal_keeps_it_live() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_core_connector::framer::{Established, Framing};
    let _publishing = anonymous_policy().await;
    for outcome in [Outcome::Ready, Outcome::Refused, Outcome::Failed] {
        for head_sent in [false, true] {
            let door: Arc<dyn FramerDoor> = Arc::new(RefuseAnswer {
                inner: H1Accept::new(true),
                outcome,
            });
            let framer = data_framer(Arc::new(move |scheme| {
                (scheme == DATA_SCHEME).then(|| Arc::clone(&door))
            }))
            .unwrap();
            let established = Established {
                scheme: Established::scheme_of(false),
                ..Established::default()
            };
            let (framing, _) = Framing::begin_lent(
                Arc::clone(framer.door()),
                busbar_contract::abi::transport::SIDE_ACCEPT,
                "",
                &established,
                framer.guests(),
            )
            .unwrap();
            let (_client, server) = tokio::io::duplex(1024);
            let (tx, ops) = tokio::sync::mpsc::unbounded_channel();
            let (admission_tx, admissions) = tokio::sync::mpsc::unbounded_channel();
            let mut conn = super::Conn {
                io: crate::root::listener::Lingering(Some(server)),
                framing: Some(framing),
                framer,
                router: Router::new(),
                secured: false,
                established,
                timeout: Duration::from_secs(30),
                out: Default::default(),
                read_done: false,
                ended: false,
                heads: Default::default(),
                inflows: Default::default(),
                tasks: tokio::task::JoinSet::new(),
                ops,
                tx,
                pending: Default::default(),
                admission_tx,
                admissions,
                staged: None,
                prewire: false,
                full: Default::default(),
                deadline: None,
                session: None,
                agreed: 0,
                stopping: false,
                failed: false,
                first_byte: None,
            };
            conn.pending.push_back((
                3,
                super::Op::Refuse {
                    status: 400,
                    head_sent,
                },
            ));
            conn.apply_front();
            assert_eq!(
                conn.failed,
                outcome != Outcome::Ready,
                "{outcome:?}, head_sent={head_sent}"
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert_eq!(conn.poll(&mut cx).is_ready(), outcome != Outcome::Ready);
            assert_eq!(conn.framing.is_none(), outcome != Outcome::Ready);
        }
    }
}

async fn anonymous_policy() -> tokio::sync::MutexGuard<'static, ()> {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::transport::route::{METHOD_ANY, PATH_CONTAINS};
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};

    let publishing = crate::root::PUBLISHING.lock().await;
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_ANY,
            path_form: PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("listener-fixture".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: AuthPoints(0),
    }])
    .unwrap();
    crate::root::inbound::stage(guests, Vec::new());
    let app = busbar_kernel_testkit::test_support::TestApp::new().build();
    assert!(crate::root::inbound::publish(&app).is_some());
    publishing
}

#[tokio::test]
async fn reset_before_any_head_releases_the_old_app_but_body_end_keeps_its_loan() {
    use crate::root::doors::{bind_on, Dispatched};
    use crate::root::inbound;
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::transport::guest_policy::Open;
    use busbar_contract::abi::transport::route::{METHOD_POST, PATH_CONTAINS};
    use busbar_contract::transport::TransportSettings;
    use busbar_core_connector::framer::{Established, Framing, Got};
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
    use busbar_kernel_testkit::test_support::TestApp;
    use busbar_test_kit::root_door_fixtures::scoped_mux;

    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(inbound::install(&dispatcher));
    let plugin =
        crate::root::test_plugins::linked_transport(scoped_mux::door, bind_on(&dispatcher));
    let door: Arc<dyn FramerDoor> =
        Arc::new(Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher).unwrap());
    let framer = data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&door))
    }))
    .unwrap();
    let guests = GuestList::seal(vec![Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_CONTAINS,
            path: "/".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("body-wait-fixture".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: AuthPoints(0),
    }])
    .unwrap();
    inbound::stage(guests, Vec::new());
    let old_app = TestApp::new().build();
    let old = Arc::downgrade(&old_app);
    assert!(inbound::publish(&old_app).is_some());
    let established = Established {
        scheme: Established::scheme_of(false),
        ..Established::default()
    };
    let (framing, _) = Framing::begin_lent(
        Arc::clone(framer.door()),
        busbar_contract::abi::transport::SIDE_ACCEPT,
        "",
        &established,
        framer.guests(),
    )
    .unwrap();
    let scope = framing.scope().unwrap().clone();
    scope
        .open_stream(
            Ticket::NONE,
            Open {
                stream: 5,
                known_generation: 0,
            },
        )
        .unwrap();
    let generation = scope.policy_generation(5, false).unwrap();
    scope.operation_finished(Ticket::NONE, false);
    drop(old_app);
    let new_app = TestApp::new().build();
    for _ in 0..3 {
        assert!(inbound::publish(&new_app).is_some());
    }
    assert!(
        old.upgrade().is_some(),
        "the unadmitted stream pins its actual policy App"
    );

    let (_client, server) = tokio::io::duplex(1024);
    let (tx, ops) = tokio::sync::mpsc::unbounded_channel();
    let (admission_tx, admissions) = tokio::sync::mpsc::unbounded_channel();
    let mut conn = super::Conn {
        io: crate::root::listener::Lingering(Some(server)),
        framing: Some(framing),
        framer,
        router: Router::new(),
        secured: false,
        established,
        timeout: Duration::from_secs(30),
        out: Default::default(),
        read_done: false,
        ended: false,
        heads: Default::default(),
        inflows: Default::default(),
        tasks: tokio::task::JoinSet::new(),
        ops,
        tx,
        pending: Default::default(),
        admission_tx,
        admissions,
        staged: None,
        prewire: false,
        full: Default::default(),
        deadline: None,
        session: None,
        agreed: 0,
        stopping: false,
        failed: false,
        first_byte: None,
    };
    let terminal = |failed| Got {
        stream: 5,
        bytes: Vec::new(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields: false,
        text: false,
        reason: None,
        failed,
        end: true,
    };
    conn.piece(terminal(false));
    assert!(
        old.upgrade().is_some(),
        "body completion must preserve the policy until hand-in"
    );
    assert_eq!(scope.policy_generation(5, false), Some(generation));
    conn.piece(terminal(true));
    assert_eq!(scope.policy_generation(5, false), None);
    assert!(
        old.upgrade().is_none(),
        "a reset with no published head retires the grant and App"
    );
    assert!(
        conn.framing.is_some(),
        "retiring one stream leaves the connection live"
    );

    let hand_in = |conn: &mut super::Conn<tokio::io::DuplexStream>, stream| {
        scope
            .open_stream(
                Ticket::NONE,
                Open {
                    stream,
                    known_generation: 0,
                },
            )
            .unwrap();
        let generation = scope.policy_generation(stream, false).unwrap();
        let guests = conn.framer.guests().unwrap();
        inbound::host()
            .hand_in(busbar_kernel::inbound::HandIn {
                owner: scope.owner(),
                generation,
                auth: guests.lines()[0].auth.id,
                unit: busbar_contract::abi::host::service::UnitRef::NONE,
                line: 0,
                conn: conn.framing.as_ref().unwrap().token(),
                stream,
                framing: Some(scope.leg()),
                head: busbar_kernel::inbound::Head {
                    method: "POST".into(),
                    target: "/".into(),
                    authority: String::new(),
                    query: None,
                    fields: Vec::new(),
                },
            })
            .unwrap();
        custody_head(conn, stream, "/");
        assert!(
            conn.inflows.contains_key(&stream),
            "the actual hand-in was claimed"
        );
        scope.operation_finished(Ticket::NONE, false);
    };
    hand_in(&mut conn, 7);
    let admitted_app = Arc::downgrade(&new_app);
    drop(new_app);
    let latest = TestApp::new().build();
    for _ in 0..3 {
        assert!(inbound::publish(&latest).is_some());
    }
    hand_in(&mut conn, 9);
    assert!(
        admitted_app.upgrade().is_some(),
        "the admitted unit retains its App"
    );
    let mut reset = custody_piece(7, Vec::new(), false, true);
    reset.failed = true;
    conn.piece(reset);
    assert!(conn
        .tasks
        .join_next()
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
    let (stream, op) = conn
        .ops
        .recv()
        .await
        .expect("the never-polled owner retires");
    assert_eq!(stream, 7);
    assert!(matches!(op, super::Op::Ended { .. }));
    conn.pending.push_back((stream, op));
    assert!(matches!(conn.apply_front(), super::Step::Done));
    assert_eq!(scope.policy_generation(7, false), None);
    assert!(!conn.inflows.contains_key(&7));
    assert!(
        admitted_app.upgrade().is_none(),
        "the actual unit/table App is released"
    );
    assert!(
        conn.inflows.contains_key(&9),
        "the sibling remains admitted"
    );
    assert!(conn.framing.is_some());
    conn.tasks.abort_all();
}

fn found(door: Arc<H1Accept>) -> Option<DataFramer> {
    let door: Arc<dyn FramerDoor> = door;
    data_framer(Arc::new(move |scheme: &str| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&door))
    }))
}

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

#[tokio::test]
async fn the_data_listener_is_served_through_its_framers_accept_side() {
    let _publishing = anonymous_policy().await;
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

#[test]
fn a_framer_that_does_not_accept_is_not_the_data_listeners() {
    assert!(found(Arc::new(H1Accept::new(false))).is_none());
}

#[tokio::test]
async fn a_data_listener_without_an_accepting_framer_refuses_before_serving_http() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let routed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&routed);
    let router = Router::new().route(
        "/probe",
        axum::routing::get(move || {
            seen.fetch_add(1, Ordering::SeqCst);
            async { "must not bypass the transport" }
        }),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let served = tokio::spawn(super::super::serve_admitted_framed(
        super::super::SocketAdmits::new(socket),
        router,
        None,
        async {
            let _ = stopped.await;
        },
        None,
        None,
    ));
    let mut response = Vec::new();
    if let Ok(mut client) = tokio::net::TcpStream::connect(address).await {
        let _ = client
            .write_all(b"GET /probe HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
            .await;

        let _ = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response))
            .await
            .expect("the server refuses or answers the connection");
    }
    let _ = stop.send(());
    let result = tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    let error =
        result.expect_err("a missing data framer must refuse, not select the core HTTP loop");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("accepting transport framer"));
    assert_eq!(routed.load(Ordering::SeqCst), 0);
    assert!(response.is_empty());
}

#[tokio::test]
async fn the_admin_listener_still_serves_through_its_explicit_root_path() {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let router = Router::new().route(
        "/admin-probe",
        axum::routing::get(|| async { "admin alive" }),
    );
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let served = tokio::spawn(async move {
        crate::serve_listener(
            super::super::SocketAdmits::new(socket),
            router,
            None,
            Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
            "admin-fixture",
            async {
                let _ = stopped.await;
            },
            None,
            false,
            None,
        )
        .await;
    });
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET /admin-probe HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let response = answer(&mut client).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
    assert!(response.ends_with("admin alive"), "{response:?}");
    drop(client);
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_silent_connection_is_closed_at_the_first_byte_bound() {
    let _publishing = anonymous_policy().await;
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
    let _publishing = anonymous_policy().await;
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
    let _publishing = anonymous_policy().await;
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
    let _publishing = anonymous_policy().await;
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
    let _publishing = anonymous_policy().await;
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
                assert!(
                    session.admit().await,
                    "the session adoption is explicitly committed"
                );
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
    assert_eq!(
        door.committed_heads(),
        1,
        "one accepted head commits the session"
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

fn staged_mux_framer(
    door: Arc<busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux>,
) -> DataFramer {
    let entry: Arc<dyn FramerDoor> = door;
    data_framer(Arc::new(move |scheme: &str| {
        matches!(scheme, DATA_SCHEME | "ws").then(|| Arc::clone(&entry))
    }))
    .expect("the staged accepting and session claims are found")
}

fn held_session_refusal_route() -> (
    Router,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    use busbar_kernel::plane_routes::FramedSession;
    let (entered, admitted) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                async move {
                    assert!(session.admit().await, "the typed stage accepts admission");
                    let _ = entered.send(());
                    let _ = held.await;
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::UNAUTHORIZED)
                        .header(
                            axum::http::header::WWW_AUTHENTICATE,
                            "Bearer realm=\"staged\"",
                        )
                        .body(axum::body::Body::from("the staged plane refused"))
                        .unwrap()
                }
            },
        ),
    );
    (router, admitted, release)
}

#[tokio::test]
async fn an_ended_session_adoption_refuses_before_any_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::{Mux, SESSION_REFUSE_WIRE};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _publishing = anonymous_policy().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let door = Arc::new(Mux::with_refused_session());
    let (mut client, server) = tokio::io::duplex(4096);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut wire))
        .await
        .expect("the refused stage closes")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the refused actor terminates")
        .unwrap();
    assert_eq!(
        wire, SESSION_REFUSE_WIRE,
        "the actual adoption refusal is preserved"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "admission gates every plane effect"
    );
    assert_eq!(door.committed_heads(), 0);
    assert!(door.emitted().is_empty());
    assert!(
        door.responses().is_empty(),
        "no extractor fallback overwrites the stage refusal"
    );
}

#[tokio::test]
async fn a_staged_plane_refusal_keeps_its_head_and_body_without_committing_101() {
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::{Mux, SESSION_ACCEPT_WIRE};

    let _publishing = anonymous_policy().await;
    let door = Arc::new(Mux::with_session());
    let (router, admitted, release) = held_session_refusal_route();
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .expect("the typed stage reaches the route")
        .unwrap();
    let mut first = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut first))
            .await
            .is_err(),
        "adoption's 101 bytes stay held while the route decides"
    );
    assert_eq!(door.committed_heads(), 0);
    assert!(door.emitted().is_empty());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_response_end())
        .await
        .expect("the full refusal body finishes");
    let mut wire = Vec::new();
    while !wire.ends_with(b"the staged plane refused") {
        let mut bytes = [0; 512];
        let read = tokio::time::timeout(Duration::from_secs(10), client.read(&mut bytes))
            .await
            .expect("the plane refusal reaches the wire")
            .unwrap();
        assert_ne!(read, 0, "the response body is complete before EOF");
        wire.extend_from_slice(&bytes[..read]);
    }
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the refusing actor stops")
        .unwrap();
    client.read_to_end(&mut wire).await.unwrap();
    let responses = door.responses();
    let heads: Vec<_> = responses.iter().filter(|value| value.status != 0).collect();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].status, 401);
    assert!(busbar_contract::abi::transport::fields::lines(&heads[0].bytes)
        .any(|(name, value)| name == b"www-authenticate" && value == b"Bearer realm=\"staged\""));
    let body: Vec<_> = responses
        .iter()
        .filter(|value| value.status == 0)
        .flat_map(|value| value.bytes.iter().copied())
        .collect();
    assert_eq!(body, b"the staged plane refused");
    assert!(responses.last().is_some_and(|value| value.end));
    assert!(!wire
        .windows(SESSION_ACCEPT_WIRE.len())
        .any(|part| part == SESSION_ACCEPT_WIRE));
    assert_eq!(door.committed_heads(), 0);
    assert!(door.emitted().is_empty());
}

#[tokio::test(start_paused = true)]
async fn stopping_eof_and_timeout_abandon_uncommitted_sessions_without_wire() {
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux;

    let _publishing = anonymous_policy().await;
    for ending in ["stop", "eof", "timeout"] {
        let door = Arc::new(Mux::with_session());
        let (router, admitted, mut held) = held_session_refusal_route();
        let (mut client, server) = tokio::io::duplex(4096);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            staged_mux_framer(door.clone()),
            router,
            false,
            Duration::from_secs(60),
            stopped,
        ));
        client.write_all(b"1").await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), admitted)
            .await
            .expect("the route holds an admitted but uncommitted stage")
            .unwrap();
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err(),
            "{ending}: no provisional handshake or application frame reaches the wire"
        );
        match ending {
            "stop" => {
                stop.send(true).unwrap();
            }
            "eof" => {
                client.shutdown().await.unwrap();
            }
            "timeout" => {
                tokio::time::advance(Duration::from_secs(61)).await;
            }
            _ => unreachable!(),
        }
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("the abandoned staging actor terminates")
            .unwrap();
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(
            wire.is_empty(),
            "{ending}: neither held adoption nor finish wire may leak: {wire:?}"
        );
        assert_eq!(door.committed_heads(), 0, "{ending}");
        assert_eq!(
            door.session_finishes(),
            1,
            "{ending}: staged framing finishes exactly once"
        );
        assert!(door.emitted().is_empty(), "{ending}");
        tokio::time::timeout(Duration::from_secs(1), held.closed())
            .await
            .expect("the abandoned route receiver is cancelled");
        assert!(held.is_closed(), "{ending}: the pending route is cancelled");
    }
}

fn accepted_session_route() -> (
    Router,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::mpsc::Sender<busbar_kernel::plane_routes::SessionOut>,
) {
    use busbar_kernel::plane_routes::{FramedSession, SessionPipe};
    let (entered, admitted) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let (outgoing, to_caller) = tokio::sync::mpsc::channel(2);
    let to_caller = Arc::new(std::sync::Mutex::new(Some(to_caller)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let to_caller = to_caller.lock().unwrap().take().unwrap();
                async move {
                    if !session.admit().await {
                        return axum::http::StatusCode::REQUEST_TIMEOUT;
                    }
                    let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                    session.put(SessionPipe {
                        from_caller,
                        to_caller,
                    });
                    let _ = entered.send(());
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    (router, admitted, outgoing)
}

#[tokio::test]
async fn a_pending_session_adoption_admits_only_after_its_original_ticket_is_ready() {
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::{Mux, SESSION_ACCEPT_WIRE};
    let _publishing = anonymous_policy().await;
    let door = Arc::new(Mux::with_pending_adoption(false));
    let (router, mut admitted, _outgoing) = accepted_session_route();
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_adoption_pending())
        .await
        .expect("adoption actually pends");
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "pending adoption neither closes nor publishes handshake wire"
    );
    assert!(
        matches!(
            admitted.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "no route effect runs before the adoption ticket completes"
    );
    assert_eq!(door.commit_attempts(), 0);
    door.release_adoption();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .expect("ready adoption admits the route")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_commit())
        .await
        .expect("the accepted route commits once");
    let mut wire = vec![0; SESSION_ACCEPT_WIRE.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut wire))
        .await
        .expect("the committed handshake is published")
        .unwrap();
    assert_eq!(wire, SESSION_ACCEPT_WIRE);
    assert!(door.adopted_resumes() >= 1);
    assert_eq!(door.commit_attempts(), 1);
    assert_eq!(door.committed_heads(), 1);
    assert_eq!(door.cancellations(), 0);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_pending_session_adoption_that_refuses_never_admits_the_route() {
    use busbar_kernel::plane_routes::FramedSession;
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _publishing = anonymous_policy().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let observed = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = observed.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
            },
        ),
    );
    let door = Arc::new(Mux::with_pending_adoption(true));
    let (mut client, server) = tokio::io::duplex(4096);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_adoption_pending())
        .await
        .expect("the eventual refusal first pends");
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    door.release_adoption();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the refused adoption closes")
        .unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "no provisional acceptance or extractor fallback is sent"
    );
    assert!(door.adopted_resumes() >= 1);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(door.commit_attempts(), 0);
    assert_eq!(door.committed_heads(), 0);
    assert!(door.responses().is_empty());
}

#[tokio::test]
async fn a_pending_session_commit_holds_wire_and_application_calls_until_ready() {
    use busbar_kernel::plane_routes::SessionOut;
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::{Mux, SESSION_ACCEPT_WIRE};
    let _publishing = anonymous_policy().await;
    let door = Arc::new(Mux::with_pending_commit());
    door.release();
    let (router, admitted, outgoing) = accepted_session_route();
    outgoing
        .send(SessionOut {
            bytes: b"after-commit".to_vec(),
            text: true,
        })
        .await
        .unwrap();
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_commit_pending())
        .await
        .expect("the explicit acceptance commit actually pends");
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "the held handshake cannot publish while its commit ticket is pending"
    );
    assert_eq!(door.commit_attempts(), 1);
    assert_eq!(door.committed_heads(), 0);
    assert_eq!(
        door.message_attempts(),
        0,
        "application frames cannot cross a pending commit"
    );
    door.release_commit();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_commit())
        .await
        .unwrap();
    let mut wire = vec![0; SESSION_ACCEPT_WIRE.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire, SESSION_ACCEPT_WIRE);
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_message())
        .await
        .expect("application delivery follows ready commit");
    assert_eq!(door.committed_heads(), 1);
    assert_eq!(door.commit_attempts(), 1);
    assert_eq!(door.message_attempts(), 1);
    assert_eq!(door.emitted()[0].bytes, b"after-commit");
    assert_eq!(door.cancellations(), 0);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancelled_pending_adoption_and_commit_ignore_their_late_wakes() {
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux;
    let _publishing = anonymous_policy().await;
    for adopting in [true, false] {
        let door = Arc::new(if adopting {
            Mux::with_pending_adoption(false)
        } else {
            Mux::with_pending_commit()
        });
        let (router, mut admitted, _outgoing) = accepted_session_route();
        let (mut client, server) = tokio::io::duplex(4096);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            staged_mux_framer(door.clone()),
            router,
            false,
            Duration::from_secs(30),
            stopped,
        ));
        client.write_all(b"1").await.unwrap();
        if adopting {
            tokio::time::timeout(Duration::from_secs(10), door.wait_for_adoption_pending())
                .await
                .unwrap();
        } else {
            tokio::time::timeout(Duration::from_secs(10), &mut admitted)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(10), door.wait_for_commit_pending())
                .await
                .unwrap();
        }
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(door.committed_heads(), 0);
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("cancellation closes the staged actor")
            .unwrap();
        assert_eq!(
            door.cancellations(),
            1,
            "only the original parked ticket is cancelled"
        );
        assert_eq!(
            door.session_finishes(),
            u32::from(!adopting),
            "only a ready framing token finishes"
        );
        let resumes = door.adopted_resumes();
        door.release_adoption();
        door.release_commit();
        tokio::task::yield_now().await;
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(
            wire.is_empty(),
            "a stale ticket wake cannot publish held handshake or finish wire"
        );
        assert_eq!(door.committed_heads(), 0);
        assert_eq!(door.adopted_resumes(), resumes);
        assert_eq!(door.message_attempts(), 0);
        if adopting {
            assert!(
                admitted.await.is_err(),
                "a cancelled admission never acknowledges the route"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_dropped_pending_admission_ack_cannot_publish_a_late_acceptance() {
    use busbar_kernel::plane_routes::FramedSession;
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::Mux;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _publishing = anonymous_policy().await;
    let door = Arc::new(Mux::with_pending_adoption(false));
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let (dropped, ack_dropped) = tokio::sync::oneshot::channel();
    let dropped = Arc::new(std::sync::Mutex::new(Some(dropped)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                let dropped = dropped.lock().unwrap().take().unwrap();
                async move {
                    let admission =
                        tokio::time::timeout(Duration::from_millis(10), session.admit()).await;
                    if matches!(admission, Ok(true)) {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    assert!(
                        admission.is_err(),
                        "this route drops its still-pending admission future"
                    );
                    let _ = dropped.send(());
                    axum::http::StatusCode::REQUEST_TIMEOUT
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), door.wait_for_adoption_pending())
        .await
        .expect("the stage owns an actually pending adoption ticket");
    tokio::time::advance(Duration::from_millis(11)).await;
    tokio::time::timeout(Duration::from_secs(10), ack_dropped)
        .await
        .expect("the route drops the acknowledgement receiver")
        .unwrap();
    door.release_adoption();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("a dropped acknowledgement abandons the stage")
        .unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "a late typed acceptance has no live route to commit it"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(door.committed_heads(), 0);
    assert_eq!(door.commit_attempts(), 0);
    assert_eq!(door.message_attempts(), 0);
    assert!(door.responses().is_empty());
}

#[tokio::test]
async fn a_plain_request_that_declines_detach_keeps_http_400_and_runs_no_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use busbar_test_kit::root_door_fixtures::pending_mux_accept::{Mux, SESSION_REFUSE_WIRE};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _publishing = anonymous_policy().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let effects = route_effects.clone();
                async move {
                    if session.admit().await {
                        effects.fetch_add(1, Ordering::SeqCst);
                    }
                    axum::http::StatusCode::FORBIDDEN
                }
            },
        ),
    );
    let door = Arc::new(Mux::with_declined_detach());
    let (mut client, server) = tokio::io::duplex(4096);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        staged_mux_framer(door.clone()),
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(b"1").await.unwrap();
    let mut wire = vec![0; SESSION_REFUSE_WIRE.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut wire))
        .await
        .expect("the retained HTTP framing writes its real 400 refusal")
        .unwrap();
    assert_eq!(wire, SESSION_REFUSE_WIRE);
    assert_eq!(door.detach_attempts(), 1, "the actual detach refused");
    assert_eq!(
        door.adoption_attempts(),
        0,
        "the WS framer is never adopted"
    );
    assert_eq!(door.refusals(), vec![(1, 400, false)]);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(door.committed_heads(), 0);
    assert!(
        door.responses().is_empty(),
        "the route's fallback 403 is suppressed"
    );
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the retained HTTP actor closes normally")
        .unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "there is no duplicate refusal or 101 handshake"
    );
    assert_eq!(door.http_finishes(), 1);
    assert_eq!(door.session_finishes(), 0);
    assert_eq!(door.cancellations(), 0);
}

#[cfg(feature = "transport-ws")]
#[path = "listener_real_session_tests.rs"]
mod real_session_tests;
