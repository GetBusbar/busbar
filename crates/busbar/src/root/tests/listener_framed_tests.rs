// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use axum::Router;
use busbar_core_connector::framer::FramerDoor;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{data_framer, DataFramer, DATA_SCHEME};

fn actual_http_framing() -> (DataFramer, busbar_core_connector::framer::Framing) {
    use busbar_core_connector::framer::{Established, Framing};
    let framer = actual_http_framer();
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
    .expect("the actual HTTP framing opens on its root-owned policy");
    // The listener registration owns the published policy throughout decoding.
    (framer, framing)
}

#[tokio::test]
async fn actual_http_streams_a_request_larger_than_its_lent_frame_capacity() {
    let _publishing = anonymous_policy().await;
    let (_listener, mut framing) = actual_http_framing();
    let body = vec![b'x'; busbar_core_connector::framer::FRAME_CAP + 1];
    let mut request = format!(
        "POST /capture HTTP/1.1\r\nHost: t\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    // Every actual yield crosses Framing's production sink-bound checks before this aggregate
    // is returned. A valid request larger than one loan streams through successive bounded yields.
    let yielded = framing
        .ingest(&request, false)
        .expect("every real HTTP yield fits its lent buffers");
    let received: Vec<_> = yielded
        .pieces
        .iter()
        .filter(|piece| !piece.fields)
        .flat_map(|piece| piece.bytes.iter().copied())
        .collect();
    assert_eq!(
        received, body,
        "the capacity boundary loses or duplicates no payload"
    );
    assert!(yielded
        .pieces
        .iter()
        .any(|piece| !piece.fields && piece.end));
    assert_eq!(
        yielded.heads.len(),
        1,
        "one request publishes exactly one head"
    );
    assert_eq!(yielded.heads[0].method.as_deref(), Some(b"POST".as_slice()));
    assert!(yielded
        .heads
        .iter()
        .any(|head| head.target.as_deref() == Some(b"/capture".as_slice())));
    assert!(
        !framing.parked(),
        "anonymous admission completes without a fabricated pending ticket"
    );
}

#[tokio::test]
async fn actual_http_refuses_complete_malformed_heads_without_waiting_for_more_bytes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _publishing = anonymous_policy().await;
    let effects = Arc::new(AtomicUsize::new(0));
    for request in [
        b"POST / HTTP/1.1\r\nHost: t\r\nbroken-field\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: t\r\ncontent-length: nope\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: t\r\ncontent-length: 18446744073709551616\r\n\r\n".as_slice(),
    ] {
        let routed = effects.clone();
        let router = Router::new().route(
            "/",
            axum::routing::post(move || {
                routed.fetch_add(1, Ordering::SeqCst);
                async { "a malformed request must not reach the application" }
            }),
        );
        let (mut client, server) = tokio::io::duplex(4096);
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            actual_http_framer(),
            router,
            false,
            Duration::from_secs(30),
            stopped,
        ));
        client.write_all(request).await.unwrap();
        let mut wire = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            (&mut client).take(16 * 1024 + 1).read_to_end(&mut wire),
        )
        .await
        .expect("a complete malformed head closes without any further client byte")
        .unwrap();
        assert!(wire.len() <= 16 * 1024, "bounded protocol refusal");
        assert!(
            wire.is_empty() || wire.starts_with(b"HTTP/1.1 400"),
            "{wire:?}"
        );
        assert_eq!(
            effects.load(Ordering::SeqCst),
            0,
            "malformed heads publish no application request"
        );
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("the real HTTP actor terminates after its refusal")
            .unwrap();
    }
}

#[tokio::test]
async fn actual_http_keeps_fragmented_headers_and_body_until_their_complete_end() {
    let _publishing = anonymous_policy().await;
    let (_listener, mut framing) = actual_http_framing();
    let first = framing
        .ingest(
            b"POST /capture HTTP/1.1\r\nHost: t\r\ncontent-length: 3\r\n",
            false,
        )
        .unwrap();
    assert!(
        first.heads.is_empty() && first.pieces.is_empty(),
        "an incomplete header is not published"
    );
    let middle = framing.ingest(b"\r\na", false).unwrap();
    assert!(
        !middle.pieces.iter().any(|piece| !piece.fields && piece.end),
        "an incomplete body has no complete end"
    );
    let last = framing.ingest(b"bc", false).unwrap();
    let batches = [first, middle, last];
    let body: Vec<_> = batches
        .iter()
        .flat_map(|batch| &batch.pieces)
        .filter(|piece| !piece.fields)
        .flat_map(|piece| piece.bytes.iter().copied())
        .collect();
    assert_eq!(
        body, b"abc",
        "fragmentation neither loses nor duplicates body bytes"
    );
    let heads: Vec<_> = batches.iter().flat_map(|batch| &batch.heads).collect();
    assert_eq!(
        heads.len(),
        1,
        "only one complete request head is published"
    );
    assert_eq!(heads[0].method.as_deref(), Some(b"POST".as_slice()));
    assert_eq!(heads[0].target.as_deref(), Some(b"/capture".as_slice()));
    assert!(batches
        .last()
        .unwrap()
        .pieces
        .iter()
        .any(|piece| !piece.fields && piece.end));
}

// Ordinary root continuation tests below seed typed pieces after real host admission.
// Actual decoder, wire output and upgrade tests separately drive the real transport end to end.
fn custody_conn(
    router: Router,
) -> (
    tokio::io::DuplexStream,
    super::Conn<tokio::io::DuplexStream>,
) {
    custody_conn_with_framer(router, actual_http_framer())
}

fn custody_conn_with_framer(
    router: Router,
    framer: DataFramer,
) -> (
    tokio::io::DuplexStream,
    super::Conn<tokio::io::DuplexStream>,
) {
    use busbar_core_connector::framer::{Established, Framing};
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
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::transport::guest_policy::Open;
    let scope = conn
        .framing
        .as_ref()
        .and_then(|framing| framing.scope())
        .cloned();
    let opened = scope.as_ref().is_some_and(|scope| {
        if scope.policy_generation(stream, false).is_some() {
            return false;
        }
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
        let guests = conn
            .framer
            .guests()
            .expect("the actual listener lends its guest line");
        crate::root::inbound::host()
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
                    target: target.into(),
                    authority: String::new(),
                    query: None,
                    fields: Vec::new(),
                },
            })
            .expect("the actual host admits the continuation's request");
        true
    });
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
    if opened {
        scope.unwrap().operation_finished(Ticket::NONE, false);
    }
}

#[tokio::test]
async fn an_unread_body_continuation_queues_one_refusal_without_retiring_its_sibling() {
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
    // This test exercises typed root continuations, so inspect the refusal command rather
    // than asking the real decoder to render a stream it did not parse from wire input.
    let (stream, refusal) = conn
        .pending
        .pop_front()
        .expect("the size refusal is queued");
    assert_eq!(stream, 3);
    assert!(matches!(
        refusal,
        super::Op::Refuse {
            status: super::BODY_LIMIT_REFUSAL,
            head_sent: false
        }
    ));
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
    assert!(
        !conn.failed,
        "suppressing late success does not fail the connection"
    );
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
        let mut refusals = 0;
        while !conn.pending.is_empty() {
            if matches!(conn.pending.front(), Some((3, super::Op::Refuse { .. }))) {
                let (_, refusal) = conn.pending.pop_front().unwrap();
                assert!(matches!(
                    refusal,
                    super::Op::Refuse {
                        status: super::BODY_LIMIT_REFUSAL,
                        head_sent: false,
                    }
                ));
                refusals += 1;
            } else {
                assert!(matches!(conn.apply_front(), super::Step::Done));
            }
        }
        assert_eq!(
            refusals,
            usize::from(!reset),
            "only a size failure queues a wire refusal command"
        );
        assert!(
            !conn.failed,
            "retiring the synthetic continuation preserves its actual connection"
        );
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

#[tokio::test]
async fn framer_results_retire_failed_continuations_independent_of_response_head_state() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_core_connector::framer::{Refused, Yielded};
    let _publishing = anonymous_policy().await;
    for outcome in [Outcome::Ready, Outcome::Refused, Outcome::Failed] {
        for head_sent in [false, true] {
            let router = Router::new().route(
                "/stall",
                axum::routing::post(|body: axum::body::Body| async move {
                    std::future::pending::<()>().await;
                    drop(body);
                    "done"
                }),
            );
            let (_client, mut conn) = custody_conn(router);
            custody_head(&mut conn, 3, "/stall");
            conn.inflows.get_mut(&3).unwrap().head_sent = head_sent;
            // Test the root's existing Result continuation directly. These values do not claim
            // that a real transport produced an invented refusal outcome on a particular input.
            let result = if outcome == Outcome::Ready {
                Ok(Yielded::default())
            } else {
                Err(Refused {
                    outcome,
                    error: "refusal rendering failed".into(),
                })
            };
            assert_eq!(conn.took(result), outcome == Outcome::Ready);
            assert_eq!(
                conn.failed,
                outcome != Outcome::Ready,
                "{outcome:?}, head_sent={head_sent}"
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert_eq!(conn.poll(&mut cx).is_ready(), outcome != Outcome::Ready);
            assert_eq!(conn.framing.is_none(), outcome != Outcome::Ready);
            conn.tasks.abort_all();
        }
    }
}

async fn anonymous_policy() -> tokio::sync::MutexGuard<'static, ()> {
    anonymous_policy_with_upgrade(None).await
}

async fn anonymous_policy_with_upgrade(
    upgrade: Option<&str>,
) -> tokio::sync::MutexGuard<'static, ()> {
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
        upgrade: upgrade.map(str::to_owned),
        offered: AuthPoints(0),
    }])
    .unwrap();
    crate::root::inbound::stage(guests, Vec::new());
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
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
        "listener-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the listener-policy deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the listener-policy deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the listener-policy deployment");
    drop(limits);
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = std::sync::Arc::new(app);
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

    let _publishing = crate::root::PUBLISHING.lock().await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(inbound::install(&dispatcher));
    let plugin = crate::root::test_plugins::linked_transport(
        busbar_transport_http::door::door,
        bind_on(&dispatcher),
    );
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
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
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
        "listener-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the listener-policy deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the listener-policy deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the listener-policy deployment");
    drop(limits);
    if let Some(rotate) = rotate {
        rotate();
    }
    let old_app = std::sync::Arc::new(app);
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
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
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
        "listener-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the listener-policy deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the listener-policy deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the listener-policy deployment");
    drop(limits);
    if let Some(rotate) = rotate {
        rotate();
    }
    let new_app = std::sync::Arc::new(app);
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
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
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
        "listener-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the listener-policy deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the listener-policy deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the listener-policy deployment");
    drop(limits);
    if let Some(rotate) = rotate {
        rotate();
    }
    let latest = std::sync::Arc::new(app);
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

fn actual_transport_on(
    door: busbar_contract::abi::mechanism::door::DoorFn,
    dispatcher: Arc<crate::root::loader::dispatch::Dispatcher>,
) -> Arc<dyn FramerDoor> {
    use crate::root::doors::{bind_on, Dispatched};
    let plugin = crate::root::test_plugins::linked_transport(door, bind_on(&dispatcher));
    Arc::new(
        Dispatched::open_on(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
            dispatcher,
        )
        .expect("the actual transport opens through the root dispatcher"),
    )
}

fn actual_transport(door: busbar_contract::abi::mechanism::door::DoorFn) -> Arc<dyn FramerDoor> {
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(crate::root::inbound::install(&dispatcher));
    actual_transport_on(door, dispatcher)
}

fn actual_http_framer() -> DataFramer {
    let door = actual_transport(busbar_transport_http::door::door);
    data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&door))
    }))
    .expect("the actual HTTP transport accepts the data listener")
}

// Passive test-local instrumentation: no input, output, context, ticket or result is changed.
// Counts carry no pointers or borrowed payload, and every crossing delegates exactly once.
#[derive(Clone, Copy, Debug)]
enum ObservedCall {
    Begin {
        side: u32,
        lines: usize,
    },
    Finish,
    Detach,
    Adopt,
    Emit {
        status: u32,
        end: bool,
        len: usize,
    },
    EmitResult {
        status: u32,
        outcome: busbar_contract::abi::mechanism::call::Outcome,
        ticket: Option<busbar_contract::abi::mechanism::ticket::Ticket>,
        resume: bool,
    },
    Refuse {
        stream: u64,
        status: u32,
        head_sent: bool,
    },
    Cancel,
}

struct ObservedDoor {
    actual: Arc<dyn FramerDoor>,
    calls: std::sync::Mutex<Vec<ObservedCall>>,
}

impl ObservedDoor {
    fn new(actual: Arc<dyn FramerDoor>) -> Arc<Self> {
        Arc::new(Self {
            actual,
            calls: Default::default(),
        })
    }

    fn record(&self, call: &busbar_core_connector::framer::Call<'_>) {
        use busbar_core_connector::framer::Call;
        let observed = match call {
            Call::Begin(input, _) => Some(ObservedCall::Begin {
                side: input.side,
                lines: input.lines_len,
            }),
            Call::Finish(..) => Some(ObservedCall::Finish),
            Call::Detach(..) => Some(ObservedCall::Detach),
            Call::Adopt(..) => Some(ObservedCall::Adopt),
            Call::Emit(input, _) => Some(ObservedCall::Emit {
                status: input.status,
                end: input.end_of_frame != 0,
                len: input.len,
            }),
            Call::Refuse(input, _) => Some(ObservedCall::Refuse {
                stream: input.stream,
                status: input.status,
                head_sent: input.head_sent != 0,
            }),
            _ => None,
        };
        if let Some(observed) = observed {
            self.calls.lock().unwrap().push(observed);
        }
    }

    fn count(&self, matching: impl Fn(&ObservedCall) -> bool) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| matching(call))
            .count()
    }
}

impl FramerDoor for ObservedDoor {
    fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
        self.actual.facts()
    }
    fn seals_values(&self) -> bool {
        self.actual.seals_values()
    }
    fn accepts(&self) -> bool {
        self.actual.accepts()
    }
    fn instance(&self) -> Option<u64> {
        self.actual.instance()
    }
    fn io_owner(&self) -> Option<u64> {
        self.actual.io_owner()
    }
    fn side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
        self.actual.side()
    }
    fn framing_side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
        self.actual.framing_side()
    }
    fn cross(
        &self,
        call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        self.record(&call);
        self.actual.cross(call)
    }
    fn cross_on(
        &self,
        side: &dyn busbar_core_connector::carrier::Side,
        resume: bool,
        call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        self.record(&call);
        self.actual.cross_on(side, resume, call)
    }
    fn carry(
        &self,
        side: &dyn busbar_core_connector::carrier::Side,
        resume: bool,
        call: busbar_core_connector::carrier::Carry<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        if matches!(&call, busbar_core_connector::carrier::Carry::Cancel(..)) {
            self.calls.lock().unwrap().push(ObservedCall::Cancel);
        }
        self.actual.carry(side, resume, call)
    }
    fn framing_context(
        &self,
        listener: u64,
        connection: u64,
    ) -> Result<
        Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        busbar_core_connector::framer::Refused,
    > {
        self.actual.framing_context(listener, connection)
    }
    fn adopting_context(
        &self,
        source: Arc<dyn busbar_contract::framing_scope::FramingScope>,
    ) -> Result<
        Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        busbar_core_connector::framer::Refused,
    > {
        self.actual.adopting_context(source)
    }
    fn cross_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: Option<&dyn busbar_core_connector::carrier::Side>,
        resume: bool,
        call: busbar_core_connector::framer::Call<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        self.record(&call);
        let status = match &call {
            busbar_core_connector::framer::Call::Emit(input, _) => Some(input.status),
            _ => None,
        };
        let result = self.actual.cross_scoped(context, side, resume, call);
        if let Some(status) = status {
            self.calls.lock().unwrap().push(ObservedCall::EmitResult {
                status,
                outcome: result.outcome,
                ticket: side.map(busbar_core_connector::carrier::Side::ticket),
                resume,
            });
        }
        result
    }
    fn cancel_scoped(
        &self,
        context: Option<&Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        side: &dyn busbar_core_connector::carrier::Side,
        call: busbar_core_connector::carrier::Carry<'_>,
    ) -> busbar_core_connector::framer::Crossed {
        if matches!(&call, busbar_core_connector::carrier::Carry::Cancel(..)) {
            self.calls.lock().unwrap().push(ObservedCall::Cancel);
        }
        self.actual.cancel_scoped(context, side, call)
    }
}

async fn actual_session_framer() -> (
    tokio::sync::MutexGuard<'static, ()>,
    DataFramer,
    Arc<ObservedDoor>,
    Arc<ObservedDoor>,
) {
    use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
    let publishing = anonymous_policy_with_upgrade(Some("ws")).await;
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    assert!(crate::root::inbound::install(&dispatcher));
    let http = ObservedDoor::new(actual_transport_on(
        busbar_transport_http::door::door,
        dispatcher.clone(),
    ));
    #[cfg(feature = "transport-ws")]
    let ws = ObservedDoor::new(actual_transport_on(
        busbar_transport_ws::door::door,
        dispatcher,
    ));
    #[cfg(not(feature = "transport-ws"))]
    let ws = {
        use crate::root::loader::dispatch::{
            kinds::transport::Transport, load_dropped, rendering_of_library,
        };
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WS_CDYLIB")
                .expect("BUSBAR_TEST_WS_CDYLIB names the actual WS product when it is not linked"),
        );
        let statement = rendering_of_library(&path)
            .expect("the actual dropped WS statement reads")
            .expect("the actual dropped WS exports its statement");
        let plugin =
            load_dropped::<Transport>(&path, &statement, crate::root::doors::bind_on(&dispatcher))
                .expect("the actual dropped WS binds through its memory ABI");
        let door: Arc<dyn FramerDoor> = Arc::new(
            crate::root::doors::Dispatched::open_on(
                plugin,
                &busbar_contract::transport::TransportSettings::default(),
                dispatcher,
            )
            .expect("the actual dropped WS opens on the same root host"),
        );
        ObservedDoor::new(door)
    };
    let (http_door, ws_door): (Arc<dyn FramerDoor>, Arc<dyn FramerDoor>) =
        (http.clone(), ws.clone());
    let framer = data_framer(Arc::new(move |scheme| match scheme {
        DATA_SCHEME => Some(http_door.clone()),
        "ws" => Some(ws_door.clone()),
        _ => None,
    }))
    .expect("actual HTTP opens the connection and WS owns its admitted upgrade");
    (publishing, framer, http, ws)
}

const SESSION_REQUEST: &[u8] = b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

async fn read_reply(client: &mut tokio::io::DuplexStream, body: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut wire = Vec::new();
        loop {
            let mut bytes = [0; 1024];
            let count = client.read(&mut bytes).await.unwrap();
            assert_ne!(count, 0, "the real response completes before EOF: {wire:?}");
            wire.extend_from_slice(&bytes[..count]);
            assert!(wire.len() <= 16 * 1024, "bounded response");
            if let Some(head_end) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                if body.is_empty()
                    || wire[head_end + 4..]
                        .windows(body.len())
                        .any(|part| part == body)
                {
                    return wire;
                }
            }
        }
    })
    .await
    .expect("the actual transport delivers its complete response")
}

async fn drain_reply(client: &mut tokio::io::DuplexStream, wire: &mut Vec<u8>) {
    let room = 16 * 1024 - wire.len() + 1;
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut *client).take(room as u64).read_to_end(wire),
    )
    .await
    .expect("the actual transport reaches EOF after its actor stops")
    .unwrap();
    assert!(wire.len() <= 16 * 1024, "bounded complete response");
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
    let observed = ObservedDoor::new(actual_transport(busbar_transport_http::door::door));
    let door: Arc<dyn FramerDoor> = observed.clone();
    let framer = data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| door.clone())
    }))
    .unwrap();
    let declared = framer
        .guests()
        .expect("the listener publishes its guest lines");
    assert_eq!(
        declared
            .lines()
            .iter()
            .map(|line| (line.line, line.points, !line.auth.is_none()))
            .collect::<Vec<_>>(),
        vec![(0, 0, true)],
        "the sealed single anonymous declaration uses ordinal zero and a host-issued auth handle"
    );
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
        observed.count(|call| matches!(call, ObservedCall::Emit { status: 200, .. })),
        1,
        "the response head went down through the actual framer exactly once"
    );
    assert_eq!(
        observed.count(|call| matches!(
            call,
            ObservedCall::Begin {
                side: busbar_contract::abi::transport::SIDE_ACCEPT,
                lines: 1
            }
        )),
        1,
        "the actual framing begins on the accepting side lent the checked anonymous guest line"
    );
    // Successful admission and a complete wire answer exercise the real transport's Begin,
    // host-issued guest authorization, response Head and body Emit through the root dispatcher.
    s.write_all(b"GET /hello HTTP/1.1\r\nhost: t\r\n\r\n")
        .await
        .unwrap();
    let second = answer(&mut s).await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"), "{second:?}");
    assert!(second.ends_with("\r\n\r\nhi"), "{second:?}");
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
    let carrier = actual_transport(busbar_transport_tcp::door);
    assert!(
        !carrier.accepts(),
        "the actual TCP carrier has no accept framer"
    );
    assert!(data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&carrier))
    }))
    .is_none());
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
    let framer = actual_http_framer();
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
    let observed = ObservedDoor::new(actual_transport(busbar_transport_http::door::door));
    let door: Arc<dyn FramerDoor> = observed.clone();
    let framer = data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| door.clone())
    }))
    .unwrap();
    // A one-byte real pipe leaves the actual HTTP head waiting for the peer to read.
    let (mut client, server) = tokio::io::duplex(1);
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
    tokio::time::timeout(Duration::from_secs(10), async {
        while observed.count(|call| matches!(call, ObservedCall::Emit { status: 200, .. })) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual response head reaches the blocked wire");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut served)
            .await
            .is_err(),
        "a blocked response head keeps its following body and connection alive"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got = Vec::new();
        loop {
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            got.push(byte[0]);
            assert!(got.len() <= 16 * 1024, "bounded HTTP response");
            if got.ends_with(b"\r\n\r\nhi") {
                break;
            }
        }
        String::from_utf8(got).unwrap()
    })
    .await
    .expect("reading the real pipe releases the head and body");
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert!(got.contains("content-length: 2\r\n"), "{got:?}");
    assert!(got.ends_with("\r\n\r\nhi"), "{got:?}");
    assert_eq!(
        observed.count(|call| matches!(call, ObservedCall::Emit { status: 200, .. })),
        1,
        "the actual response head is emitted once"
    );
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "drain produces no duplicate response or body"
    );
}

#[tokio::test]
async fn a_final_body_emit_remains_alive_through_graceful_drain() {
    let _publishing = anonymous_policy().await;
    let observed = ObservedDoor::new(actual_transport(busbar_transport_http::door::door));
    let door: Arc<dyn FramerDoor> = observed.clone();
    let framer = data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| door.clone())
    }))
    .unwrap();
    let (mut client, server) = tokio::io::duplex(1);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    // An unknown-length response puts its final HTTP chunk on the wire. The peer can
    // drain the payload while retaining pressure on that distinct terminal Emit.
    let router = Router::new().route(
        "/hello",
        axum::routing::get(|| async {
            axum::response::Response::new(axum::body::Body::from_stream(futures::stream::once(
                async { Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(b"hi")) },
            )))
        }),
    );
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
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !got.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            got.push(byte[0]);
            assert!(got.len() < 16 * 1024, "bounded response head");
        }
        while !got.ends_with(b"\r\n2\r\nhi\r\n") {
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            got.push(byte[0]);
            assert!(got.len() < 16 * 1024, "bounded payload chunk");
        }
        while observed.count(|call| {
            matches!(
                call,
                ObservedCall::Emit {
                    status: 0,
                    end: true,
                    ..
                }
            )
        }) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the real final body reaches the one-byte wire");
    stop.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut served)
            .await
            .is_err(),
        "graceful drain waits for the final body still held by the real pipe"
    );
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
        .await
        .expect("the drained connection closes after the peer reads")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    let got = String::from_utf8(got).unwrap();
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert!(got.contains("transfer-encoding: chunked\r\n"), "{got:?}");
    assert!(got.ends_with("\r\n\r\n2\r\nhi\r\n0\r\n\r\n"), "{got:?}");
    assert_eq!(
        observed.count(|call| matches!(call, ObservedCall::Emit { status: 200, .. })),
        1
    );
    assert_eq!(
        observed.count(|call| matches!(
            call,
            ObservedCall::Emit {
                status: 0,
                end: true,
                ..
            }
        )),
        1,
        "the actual final body is accepted once and survives shutdown custody"
    );
}

#[tokio::test]
async fn a_parked_stream_does_not_hold_an_independent_stream_behind_its_body() {
    let _publishing = anonymous_policy().await;
    let observed = ObservedDoor::new(actual_transport(busbar_transport_http::door::door));
    let door: Arc<dyn FramerDoor> = observed.clone();
    let framer = data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| door.clone())
    }))
    .unwrap();
    let (release, held) = tokio::sync::oneshot::channel();
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let router = Router::new()
        .route(
            "/first",
            axum::routing::get(move || {
                let held = held.lock().unwrap().take().unwrap();
                async move {
                    axum::response::Response::new(axum::body::Body::from_stream(
                        futures::stream::once(async move {
                            held.await.unwrap();
                            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"first"))
                        }),
                    ))
                }
            }),
        )
        .route("/second", axum::routing::get(|| async { "second" }));
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    let connection = tokio::spawn(connection);
    sender = sender.ready().await.unwrap();
    let (first, _) = sender
        .send_request(
            axum::http::Request::builder()
                .uri("http://localhost/first")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.status(), axum::http::StatusCode::OK);
    let mut first = first.into_body();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), first.data())
            .await
            .is_err(),
        "the first stream's actual body producer is still held"
    );
    sender = sender.ready().await.unwrap();
    let (second, _) = sender
        .send_request(
            axum::http::Request::builder()
                .uri("http://localhost/second")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("the real HTTP/2 sibling is independent of the held first body")
        .unwrap();
    assert_eq!(second.status(), axum::http::StatusCode::OK);
    let mut second = second.into_body();
    let mut independent = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = second.data().await {
            let chunk = chunk.unwrap();
            independent.extend_from_slice(&chunk);
            second.flow_control().release_capacity(chunk.len()).unwrap();
        }
    })
    .await
    .expect("the sibling body completes before the first is released");
    assert_eq!(independent, b"second");
    release.send(()).unwrap();
    let mut first_body = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = first.data().await {
            let chunk = chunk.unwrap();
            first_body.extend_from_slice(&chunk);
            first.flow_control().release_capacity(chunk.len()).unwrap();
        }
    })
    .await
    .expect("the released first stream completes once");
    assert_eq!(first_body, b"first");
    assert_eq!(
        observed.count(|call| matches!(call, ObservedCall::Emit { status: 200, .. })),
        2,
        "each actual stream emits one response head"
    );
    drop(sender);
    connection.abort();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]

async fn a_session_waits_for_its_parked_message_before_emitting_the_next() {
    use busbar_kernel::plane_routes::{FramedSession, SessionOut, SessionPipe};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            |axum::Extension(session): axum::Extension<FramedSession>| async move {
                assert!(session.admit().await);
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
    let (mut client, server) = tokio::io::duplex(1);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            assert_eq!(client.read(&mut byte).await.unwrap(), 1);
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024);
        }
        while ws.count(|call| {
            matches!(
                call,
                ObservedCall::Emit {
                    status: 0,
                    len: 5,
                    ..
                }
            )
        }) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual WS message reaches the blocked one-byte pipe");
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut served)
            .await
            .is_err(),
        "wire pressure keeps the queued session alive after its producer closes"
    );
    let mut frames = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        for (opcode, expected) in [(1_u8, b"first".as_slice()), (2_u8, b"second".as_slice())] {
            let mut header = [0; 2];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(
                header[0],
                0x80 | opcode,
                "the actual WS message keeps its frame kind"
            );
            assert_eq!(
                header[1] as usize,
                expected.len(),
                "server frames are complete and unmasked"
            );
            let mut payload = vec![0; expected.len()];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, expected);
            frames.push(payload);
        }
    })
    .await
    .expect("both messages arrive once and in order after reading resumes");
    assert_eq!(frames, [b"first".to_vec(), b"second".to_vec()]);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1,
        "the actual session handshake commits once"
    );
    let _ = stop.send(true);
    // The real producer's closed channel finishes WS with a normal close frame. On a
    // one-byte pipe the peer must drain that wire before the owning server can finish.
    let mut close_wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut close_wire))
        .await
        .expect("the real WS close frame drains before the server retires")
        .unwrap();
    assert_eq!(
        close_wire,
        [0x88, 0x02, 0x03, 0xe8],
        "exact unmasked normal WS close"
    );
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
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

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn an_ended_session_adoption_refuses_before_any_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (_publishing, framer, http, ws) = actual_session_framer().await;
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
    // A real WebSocket handshake missing its mandatory key ends adoption with its own refusal.
    client.write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n").await.unwrap();
    let mut wire = read_reply(&mut client, b"").await;
    let _ = stop.send(true); // A real terminal refusal may already have closed the actor.
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    assert!(
        wire.starts_with(b"HTTP/1.1 400") || wire.starts_with(b"HTTP/1.1 426"),
        "{wire:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1,
        "the actual adoption refusal is preserved without an extractor fallback"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "admission gates every plane effect"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0,
        "no extractor fallback overwrites the stage refusal"
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn a_staged_plane_refusal_keeps_its_head_and_body_without_committing_101() {
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let (router, admitted, release) = held_session_refusal_route();
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
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .expect("the real typed stage reaches the route")
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "adoption's 101 bytes stay held while the route decides"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        0
    );
    release.send(()).unwrap();
    let body = b"the staged plane refused";
    let mut wire = read_reply(&mut client, body).await;
    let _ = stop.send(true); // A real terminal refusal may already have closed the actor.
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    let head_end = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 401"), "{head}");
    assert!(
        head.contains("www-authenticate: bearer realm=\"staged\""),
        "{head}"
    );
    assert_eq!(
        &wire[head_end + 4..],
        body,
        "the full refusal body is unchanged"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1
    );
    assert!(!wire.windows(12).any(|bytes| bytes == b"HTTP/1.1 101"));
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 401, .. })),
        1
    );
    assert_eq!(ws.count(|call| matches!(call, ObservedCall::Emit { status: 0, end: false, len } if *len == body.len())), 1,
        "the refusal payload reaches the actual adopted transport emitter");
    assert_eq!(
        ws.count(|call| matches!(
            call,
            ObservedCall::Emit {
                status: 0,
                end: true,
                len: 0
            }
        )),
        1,
        "the refusal body is terminated through its actual emitter"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
        3,
        "only the refusal head, body and terminal emit occur; no application frame follows"
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test(start_paused = true)]
async fn stopping_eof_and_timeout_abandon_uncommitted_sessions_without_wire() {
    for ending in ["stop", "eof", "timeout"] {
        let (_publishing, framer, _http, ws) = actual_session_framer().await;
        let (router, admitted, mut held) = held_session_refusal_route();
        let (mut client, server) = tokio::io::duplex(4096);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::spawn(super::serve(
            server,
            framer,
            router,
            false,
            Duration::from_secs(60),
            stopped,
        ));
        client.write_all(SESSION_REQUEST).await.unwrap();
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
        drain_reply(&mut client, &mut wire).await;
        assert!(
            wire.is_empty(),
            "{ending}: neither held adoption nor finish wire may leak: {wire:?}"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
            0,
            "{ending}"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Finish)),
            1,
            "{ending}: staged framing finishes exactly once"
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
            0,
            "{ending}"
        );
        tokio::time::timeout(Duration::from_secs(1), held.closed())
            .await
            .expect("the abandoned route receiver is cancelled");
        assert!(held.is_closed(), "{ending}: the pending route is cancelled");
    }
}

#[tokio::test]

async fn a_pending_session_adoption_admits_only_after_its_original_ticket_is_ready() {
    use busbar_kernel::plane_routes::{FramedSession, SessionPipe};
    use std::future::Future as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let effects = Arc::new(AtomicUsize::new(0));
    let (entered, pending) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let (release, held) = tokio::sync::oneshot::channel();
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let route_effects = effects.clone();
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                let effects = route_effects.clone();
                async move {
                    let mut admission = Box::pin(session.admit());
                    std::future::poll_fn(|cx| {
                        assert!(
                            admission.as_mut().poll(cx).is_pending(),
                            "the native admission awaits its actor"
                        );
                        Poll::Ready(())
                    })
                    .await;
                    entered.send(()).unwrap();
                    held.await.unwrap();
                    assert!(
                        admission.await,
                        "the original native admission command acknowledges readiness"
                    );
                    effects.fetch_add(1, Ordering::SeqCst);
                    let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                    let (_outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                    session.put(SessionPipe {
                        from_caller,
                        to_caller,
                    });
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
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
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "the uncommitted admission publishes no handshake wire"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "no route effect precedes native readiness"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    release.send(()).unwrap();
    let head = read_reply(&mut client, b"").await;
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1
    );
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]

async fn a_pending_session_adoption_that_refuses_never_admits_the_route() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
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
    // Withhold the final head delimiter: the actual HTTP decoder needs more peer input.
    client.write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n").await.unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    client.write_all(b"\r\n").await.unwrap();
    let mut wire = read_reply(&mut client, b"").await;
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
    drain_reply(&mut client, &mut wire).await;
    assert!(
        wire.starts_with(b"HTTP/1.1 400") || wire.starts_with(b"HTTP/1.1 426"),
        "{wire:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&wire).matches("HTTP/1.1 ").count(),
        1,
        "the real missing-key refusal is published once"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "refused adoption admits no route effect"
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
}

#[tokio::test]

async fn a_pending_session_commit_holds_wire_and_application_calls_until_ready() {
    use busbar_kernel::plane_routes::{FramedSession, SessionOut, SessionPipe};
    let (_publishing, framer, _http, ws) = actual_session_framer().await;
    let (entered, admitted) = tokio::sync::oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let (release, held) = tokio::sync::oneshot::channel();
    let held = Arc::new(std::sync::Mutex::new(Some(held)));
    let router = Router::new().route(
        "/first",
        axum::routing::get(
            move |axum::Extension(session): axum::Extension<FramedSession>| {
                let entered = entered.lock().unwrap().take().unwrap();
                let held = held.lock().unwrap().take().unwrap();
                async move {
                    assert!(session.admit().await);
                    let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                    let (outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                    outgoing
                        .send(SessionOut {
                            bytes: b"after-commit".to_vec(),
                            text: false,
                        })
                        .await
                        .unwrap();
                    session.put(SessionPipe {
                        from_caller,
                        to_caller,
                    });
                    entered.send(()).unwrap();
                    held.await.unwrap();
                    drop(outgoing);
                    axum::http::StatusCode::SWITCHING_PROTOCOLS
                }
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
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), admitted)
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
            .await
            .is_err(),
        "the actual stage holds handshake and queued message while its route decision is pending"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 0, .. })),
        0
    );
    release.send(()).unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            client.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            assert!(head.len() < 16 * 1024);
        }
        let mut frame = [0; 2];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame, [0x82, 12]);
        let mut body = [0; 12];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"after-commit");
    })
    .await
    .expect("commit publishes one real handshake followed by the queued message");
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        1
    );
    assert_eq!(
        ws.count(|call| matches!(
            call,
            ObservedCall::Emit {
                status: 0,
                len: 12,
                ..
            }
        )),
        1
    );
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]

async fn cancelled_pending_adoption_and_commit_ignore_their_late_wakes() {
    use busbar_kernel::plane_routes::{FramedSession, SessionPipe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for adopting in [true, false] {
        let (_publishing, framer, http, ws) = actual_session_framer().await;
        let effects = Arc::new(AtomicUsize::new(0));
        let route_effects = effects.clone();
        let (entered, mut admitted) = tokio::sync::oneshot::channel();
        let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
        let (release, held) = tokio::sync::oneshot::channel();
        let held = Arc::new(std::sync::Mutex::new(Some(held)));
        let router = Router::new().route(
            "/first",
            axum::routing::get(
                move |axum::Extension(session): axum::Extension<FramedSession>| {
                    let entered = entered.lock().unwrap().take().unwrap();
                    let held = held.lock().unwrap().take().unwrap();
                    let effects = route_effects.clone();
                    async move {
                        assert!(session.admit().await);
                        entered.send(()).unwrap();
                        held.await.unwrap();
                        effects.fetch_add(1, Ordering::SeqCst);
                        let (from_caller, _incoming) = tokio::sync::mpsc::channel(1);
                        let (_outgoing, to_caller) = tokio::sync::mpsc::channel(1);
                        session.put(SessionPipe {
                            from_caller,
                            to_caller,
                        });
                        axum::http::StatusCode::SWITCHING_PROTOCOLS
                    }
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
        if adopting {
            client
                .write_all(&SESSION_REQUEST[..SESSION_REQUEST.len() - 2])
                .await
                .unwrap();
        } else {
            client.write_all(SESSION_REQUEST).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), &mut admitted)
                .await
                .unwrap()
                .unwrap();
        }
        let mut byte = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
            0
        );
        stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("cancellation closes the actual staged actor")
            .unwrap();
        let before = ws.count(|call| matches!(call, ObservedCall::Emit { .. }));
        let _ = release.send(());
        if adopting {
            let _ = client.write_all(b"\r\n").await;
        }
        tokio::task::yield_now().await;
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(
            wire.is_empty(),
            "late peer bytes or route readiness cannot publish canceled handshake wire"
        );
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Emit { .. })),
            before,
            "late readiness cannot emit a message or repeat a commit"
        );
        assert_eq!(
            http.count(|call| matches!(call, ObservedCall::Detach)),
            usize::from(!adopting),
            "only a committed transfer consumes the old HTTP framing"
        );
        assert_eq!(http.count(|call| matches!(call, ObservedCall::Finish)), usize::from(adopting),
            "cancel before transfer finishes HTTP; terminal detach must not finish its consumed token again");
        assert_eq!(
            ws.count(|call| matches!(call, ObservedCall::Finish)),
            usize::from(!adopting),
            "after transfer the adopted WS framing owns exactly one finish"
        );
        if adopting {
            assert!(
                admitted.await.is_err(),
                "a canceled unparsed head never admits its route"
            );
        }
    }
}

#[tokio::test]
async fn a_dropped_pending_admission_ack_cannot_publish_a_late_acceptance() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::future::Future as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
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
                    let mut admission = Box::pin(session.admit());
                    std::future::poll_fn(|cx| {
                        let result = admission.as_mut().poll(cx);
                        if matches!(result, Poll::Ready(true)) {
                            effects.fetch_add(1, Ordering::SeqCst);
                        }
                        assert!(
                            result.is_pending(),
                            "the real admission command waits for its actor acknowledgement"
                        );
                        Poll::Ready(())
                    })
                    .await;
                    drop(admission);
                    let _ = dropped.send(());
                    // Any acceptance after the acknowledgement receiver was dropped must fail closed.
                    axum::http::StatusCode::REQUEST_TIMEOUT
                }
            },
        ),
    );
    let (mut client, server) = tokio::io::duplex(4096);
    let (_stop, stopped) = tokio::sync::watch::channel(false);
    let served = tokio::spawn(super::serve(
        server,
        framer,
        router,
        false,
        Duration::from_secs(30),
        stopped,
    ));
    client.write_all(SESSION_REQUEST).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ack_dropped)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("a dropped native acknowledgement abandons the actual stage")
        .unwrap();
    let mut wire = Vec::new();
    client.read_to_end(&mut wire).await.unwrap();
    assert!(
        wire.is_empty(),
        "a dropped acknowledgement cannot publish held handshake wire"
    );
    assert_eq!(
        effects.load(Ordering::SeqCst),
        0,
        "no admitted application effect"
    );
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
}

#[cfg(feature = "transport-ws")]
#[tokio::test]
async fn a_plain_request_that_declines_detach_keeps_http_400_and_runs_no_plane_effect() {
    use busbar_kernel::plane_routes::FramedSession;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_publishing, framer, http, ws) = actual_session_framer().await;
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
    client
        .write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let wire = read_reply(&mut client, b"").await;
    assert!(wire.starts_with(b"HTTP/1.1 400"), "{wire:?}");
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Detach)),
        1,
        "the actual detach refused"
    );
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Adopt)),
        0,
        "the WS framer is never adopted"
    );
    assert_eq!(
        http.count(|call| matches!(
            call,
            ObservedCall::Refuse {
                stream: 1,
                status: 400,
                head_sent: false
            }
        )),
        1
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        ws.count(|call| matches!(call, ObservedCall::Emit { status: 101, .. })),
        0
    );
    assert!(
        http.count(|call| matches!(call, ObservedCall::Emit { .. })) == 0,
        "the route's fallback 403 is suppressed"
    );
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the retained HTTP actor closes normally")
        .unwrap();
    let mut rest = Vec::new();
    drain_reply(&mut client, &mut rest).await;
    assert!(
        rest.is_empty(),
        "there is no duplicate refusal or 101 handshake"
    );
    assert_eq!(http.count(|call| matches!(call, ObservedCall::Finish)), 1);
    assert_eq!(ws.count(|call| matches!(call, ObservedCall::Finish)), 0);
    assert_eq!(
        http.count(|call| matches!(call, ObservedCall::Cancel))
            + ws.count(|call| matches!(call, ObservedCall::Cancel)),
        0
    );
}

#[cfg(feature = "transport-ws")]
#[path = "listener_real_session_tests.rs"]
mod real_session_tests;

#[tokio::test]
async fn eof_errors_an_unfinished_body_without_invalidating_a_piece_end_body() {
    let _publishing = anonymous_policy().await;
    let (answers, mut received) = tokio::sync::mpsc::unbounded_channel();
    let router = Router::new().route(
        "/capture",
        axum::routing::post(move |body: axum::body::Body| {
            let answers = answers.clone();
            async move {
                let result = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .map_err(|error| error.to_string());
                answers.send(result).unwrap();
                "done"
            }
        }),
    );
    let (mut client, mut conn) = custody_conn(router);
    custody_head(&mut conn, 3, "/capture");
    conn.piece(custody_piece(3, b"cut".to_vec(), false, false));
    custody_head(&mut conn, 5, "/capture");
    conn.piece(custody_piece(5, b"whole".to_vec(), false, true));
    assert!(conn.inflows[&3].body.is_some());
    assert!(conn.inflows[&5].body.is_none());
    client.shutdown().await.unwrap();
    std::future::poll_fn(|cx| {
        assert!(conn.read(cx));
        Poll::Ready(())
    })
    .await;
    let mut answers = Vec::new();
    for _ in 0..2 {
        answers.push(
            tokio::time::timeout(Duration::from_secs(5), received.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(answers.iter().any(|answer| matches!(answer, Err(error) if error.contains("connection closed before the request body ended"))), "unfinished body must fail: {answers:?}");
    assert!(
        answers
            .iter()
            .any(|answer| matches!(answer, Ok(bytes) if bytes.as_ref() == b"whole")),
        "PIECE_END body remains whole: {answers:?}"
    );
}

#[tokio::test]
async fn eof_waits_for_a_parked_ingest_to_deliver_its_valid_piece_end() {
    use base64::Engine as _;
    use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY};
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_CONTAINS};
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
    use ring::signature::KeyPair as _;
    let _publishing = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    for first_body in ["", "hi"] {
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &certificate.signing_key.serialize_der(),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let point = key.public_key().as_ref();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let jwks = serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "kid": "listener-eof", "alg": "ES256", "use": "sig",
            "x": b64.encode(&point[1..33]), "y": b64.encode(&point[33..65]),
        }]})
        .to_string();
        let cert_pem = certificate.cert.pem();
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )),
            )
            .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let jwks_url = format!("https://{}/jwks", listener.local_addr().unwrap());
        let (entered, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer_armed = armed.clone();
        let peer = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let mut entered = Some(entered);
            loop {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let session = rustls::ServerConnection::new(tls.clone()).unwrap();
                let mut socket = rustls::StreamOwned::new(session, socket);
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0; 1];
                    socket.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                    assert!(head.len() <= 8192, "bounded JWKS request");
                }
                assert!(head.starts_with(b"GET /jwks HTTP/1.1\r\n"));
                // READY's best-effort warm-up receives an actual outage. The first VERIFY must
                // fetch its real key document, and this peer withholds that response until EOF.
                let gated = peer_armed.load(std::sync::atomic::Ordering::Acquire);
                let (status, body) = if !gated {
                    ("503 Service Unavailable", "{}")
                } else {
                    entered.take().unwrap().send(()).unwrap();
                    held.recv_timeout(Duration::from_secs(10)).unwrap();
                    ("200 OK", jwks.as_str())
                };
                write!(socket, "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
                socket.flush().unwrap();
                socket.conn.send_close_notify();
                let _ = socket.flush();
                if gated {
                    break;
                }
            }
        });
        let now = busbar_kernel::store::now();
        let header = b64.encode(
            serde_json::to_vec(
                &serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": "listener-eof"}),
            )
            .unwrap(),
        );
        let claims = b64.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": "https://listener-eof.invalid", "aud": "listener-eof", "sub": "listener-client",
            "roles": ["reader"], "exp": now + 3600, "nbf": now.saturating_sub(10),
        }))
        .unwrap(),
    );
        let signed = format!("{header}.{claims}");
        let signature = key
            .sign(&ring::rand::SystemRandom::new(), signed.as_bytes())
            .unwrap();
        let token = format!("{signed}.{}", b64.encode(signature.as_ref()));
        let directory = crate::root::test_plugins::scratch(&format!(
            "listener-real-eof-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let mut store_module = None;
        let mut auth_module = None;
        for (kind, variable) in [
            ("store", "BUSBAR_TEST_SQLITE_CDYLIB"),
            ("auth", "BUSBAR_TEST_OIDC_CDYLIB"),
        ] {
            let path = if kind == "store" {
                crate::root::test_plugins::application_store_library()
            } else {
                std::path::PathBuf::from(
                    std::env::var_os(variable)
                        .unwrap_or_else(|| panic!("{variable} names the actual built product")),
                )
            };
            let statement = crate::root::loader::dispatch::rendering_of_library(&path)
                .unwrap()
                .unwrap();
            let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                .unwrap()
                .name;
            let mut manifest = crate::root::test_plugins::manifest(
                kind,
                &module,
                crate::root::test_plugins::FIXTURE_PUBLISHER,
            );
            manifest.statement = Some(hex::encode(statement));
            let bytes = std::fs::read(path).unwrap();
            let archive = crate::root::test_plugins::signed(
                &crate::dist_root_install::release_key(),
                manifest,
                &bytes,
            );
            std::fs::write(directory.join(format!("{kind}.tar.gz")), archive).unwrap();
            if kind == "auth" {
                auth_module = Some(module);
            } else {
                store_module = Some(module);
            }
        }
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "store": {"module": store_module.unwrap(), "settings": settings},
        "identity-providers": {"held": {"module": auth_module.unwrap(), "settings": {
            "issuer": "https://listener-eof.invalid", "audience": "listener-eof",
            "jwks_url": jwks_url, "ca_cert_pem": cert_pem, "role_claim": "roles",
            "jwks_min_refetch_secs": 1,
        }}},
        "auth": {"chain": ["held"], "admin_auth": [], "role_bindings": {"held": {"reader": {"allowed_pools": []}}}},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    })).unwrap();
        let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
        let plugins = crate::root::test_plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            plugins,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the real root opens the product OIDC verifier and Store");
        drop(limits);
        if let Some(rotate) = rotate {
            rotate();
        }
        let app = Arc::new(app);
        armed.store(true, std::sync::atomic::Ordering::Release);
        // READY's real 503 starts OIDC's mandatory refetch cooldown. Let that configured
        // interval elapse so VERIFY can own the second fetch held below through EOF.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let points = app.auth.position_points("held");
        assert!(points.has(busbar_contract::abi::auth::AuthPoint::Head));
        let guests = GuestList::seal(vec![
            Line {
                route: Route {
                    methods: METHOD_GET,
                    path_form: PATH_CONTAINS,
                    path: "/first".into(),
                    fields: Vec::new(),
                    rung: 0,
                },
                claimant: Claimant::Plane("listener-public-first".into()),
                dialect: 0,
                auth: LineAuth::None,
                upgrade: None,
                offered: AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
            },
            Line {
                route: Route {
                    methods: METHOD_POST,
                    path_form: PATH_CONTAINS,
                    path: "/".into(),
                    fields: Vec::new(),
                    rung: 0,
                },
                claimant: Claimant::Plane("listener-real-eof".into()),
                dialect: 0,
                auth: LineAuth::Chain(vec!["held".into()], points),
                upgrade: None,
                offered: AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
            },
        ])
        .unwrap();
        crate::root::inbound::stage(guests, Vec::new());
        assert!(crate::root::inbound::publish(&app).is_some());
        let (answers, mut received) = tokio::sync::mpsc::unbounded_channel();
        let router = Router::new().route(
            "/capture",
            axum::routing::post(move |body: axum::body::Body| {
                let answers = answers.clone();
                async move {
                    answers
                        .send(
                            axum::body::to_bytes(body, usize::MAX)
                                .await
                                .map_err(|error| error.to_string()),
                        )
                        .unwrap();
                    "done"
                }
            }),
        );
        let router = router.route(
            "/first",
            axum::routing::get(move || async move { first_body }),
        );
        let observed = ObservedDoor::new(actual_transport(busbar_transport_http::door::door));
        let door: Arc<dyn FramerDoor> = observed.clone();
        let framer = data_framer(Arc::new(move |scheme| {
            (scheme == DATA_SCHEME).then(|| door.clone())
        }))
        .unwrap();
        let (mut client, mut conn) = custody_conn_with_framer(router, framer);
        let wire = format!("GET /first HTTP/1.1\r\nhost: t\r\n\r\nPOST /capture HTTP/1.1\r\nhost: t\r\nauthorization: Bearer {token}\r\ncontent-length: 5\r\n\r\nwhole");
        client.write_all(wire.as_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), std::future::poll_fn(|cx| {
        let finished = conn.poll(cx).is_ready();
        let pending_emit = observed.count(|call| matches!(call,
            ObservedCall::EmitResult { outcome: Outcome::Pending, .. }
        )) > 0;
        assert!(!finished, "a real pending Emit retains the connection");
        if pending_emit { Poll::Ready(()) } else { Poll::Pending }
    })).await.expect("the first response Emit drives later queued head admission into real auth.call Pending");
        let (pending_status, pending_ticket) = observed
            .calls
            .lock()
            .unwrap()
            .iter()
            .find_map(|call| match call {
                ObservedCall::EmitResult {
                    status,
                    outcome: Outcome::Pending,
                    ticket,
                    ..
                } => Some((*status, *ticket)),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            pending_status,
            if first_body.is_empty() { 200 } else { 0 },
            "empty responses retain their head; nonempty responses retain their final body Emit"
        );
        assert!(
            pending_ticket.is_some_and(|ticket| !ticket.is_none()),
            "a real callback owns a concrete native ticket"
        );
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the actual OIDC VERIFY reaches its held JWKS peer")
            .unwrap();
        assert!(
            conn.framing.as_ref().unwrap().parked(),
            "the actual auth.call owns a pending decoder ticket"
        );
        assert!(
            received.try_recv().is_err(),
            "no body is published before authentication"
        );
        client.shutdown().await.unwrap();
        std::future::poll_fn(|cx| {
            assert!(conn.read(cx));
            Poll::Ready(())
        })
        .await;
        assert!(conn.read_done);
        assert!(
            conn.framing.as_ref().unwrap().parked(),
            "EOF preserves the genuinely parked ingest"
        );
        release.send(()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| {
                if conn.parked(cx) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .expect("the real JWKS reply wakes and resumes the original decoder ticket");
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = received.recv() => result.unwrap(),
                () = std::future::poll_fn(|cx| conn.poll(cx)) => received.recv().await.unwrap(),
            }
        })
        .await
        .unwrap();
        assert!(observed.count(|call| matches!(call,
        ObservedCall::EmitResult { outcome: Outcome::Ready, ticket, resume: true, .. } if *ticket == pending_ticket
    )) > 0, "the original Emit ticket resumes to READY after the real auth callback");
        tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| conn.poll(cx)),
        )
        .await
        .expect("both actual pipeline requests drain after the callback");
        drop(conn);
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut answer))
            .await
            .unwrap()
            .unwrap();
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer:?}");
        assert_eq!(
            answer.matches("HTTP/1.1 200 OK\r\n").count(),
            2,
            "each pipeline request answers exactly once"
        );
        let first_head = answer.find("\r\n\r\n").unwrap();
        assert_eq!(
            &answer.as_bytes()[first_head + 4..first_head + 4 + first_body.len()],
            first_body.as_bytes()
        );
        if !first_body.is_empty() {
            assert_eq!(
                answer.matches(first_body).count(),
                1,
                "the parked first response body is never duplicated"
            );
        }
        assert_eq!(
            result.unwrap().as_ref(),
            b"whole",
            "the actual decoder's PIECE_END remains whole across pending authentication and EOF"
        );
        peer.join()
            .expect("the real TLS peer completes both requests");
    }
}
