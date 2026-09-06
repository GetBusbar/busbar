// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport battery: byte-exact round trip (a unary-shaped call: one write, then read
//! the answer), multiplexed streams without cross-talk, K writers, honest terminal status, and the
//! transport-meta declarations.

use std::time::Duration;

use futures::StreamExt;

use busbar_contract::{ArenaBytes, StreamId, Transport};
use busbar_contract_transport::wire::{StatusClass, TransportError};

use crate::GrpcTransport;

/// A `grpc` transport standing on `http`, which is what carries an inbound connection.
fn server_transport() -> GrpcTransport {
    GrpcTransport::over(std::sync::Arc::new(
        busbar_transport_http::HttpTransport::new(busbar_transport_http::ClientSettings::default()),
    ))
}

/// A `grpc` transport standing on `tcp`, which is what carries a dialled one.
fn client_transport() -> GrpcTransport {
    GrpcTransport::over(std::sync::Arc::new(
        busbar_transport_tcp::TcpTransport::new(),
    ))
}

/// A bind address, for the layer below.
struct BindTo(String);
impl busbar_contract::ConfigView for BindTo {
    fn get_str(&self, _k: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _k: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _k: &str) -> Option<bool> {
        None
    }
}
impl busbar_contract::TransportConfigView for BindTo {
    fn bind(&self) -> Option<&str> {
        Some(&self.0)
    }
}

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(host: &'static str) -> busbar_contract::VerifiedDestination {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "grpc",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "grpc",
        None,
    )
}

#[tokio::test]
async fn unary_shaped_round_trip() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    // The client opens a fresh call by writing to a `StreamId` it has not used before.
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();

    let mut server_frames = server_t.frames(server_conn.clone());
    let (server_stream, frame) = server_frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"ping", "byte-exact");
    assert_eq!(frame.meta.bytes, 4);
    assert_eq!(frame.meta.transport_units, None);

    // The server answers on the SAME call (its own local stream id for that RPC).
    server_t
        .write(&server_conn, server_stream, ArenaBytes::new(b"pong"))
        .await
        .unwrap();

    let mut client_frames = client_t.frames(client_conn);
    let (_s, frame) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"pong", "byte-exact");
}

/// A raw HTTP/2 peer that answers every call TRAILERS-ONLY: one HEADERS frame carrying
/// `:status: 200`, the gRPC content type and a non-zero `grpc-status`, with END_STREAM set and no
/// DATA at all. This is the standard shape an upstream refuses with — `UNIMPLEMENTED` for a method
/// it does not serve, `UNAUTHENTICATED` for a credential it will not take — and it is not the same
/// wire event as a trailer at the end of a body: the answer is over before any stream exists.
///
/// Hands back the address it is listening on; the task serves calls until the test drops.
async fn trailers_only_peer(code: tonic::Code) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |_req| async move {
                    let mut response =
                        hyper::Response::new(http_body_util::Empty::<bytes::Bytes>::new());
                    response.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    response.headers_mut().insert(
                        "grpc-status",
                        http::HeaderValue::from_str(&(code as i32).to_string()).unwrap(),
                    );
                    response.headers_mut().insert(
                        "grpc-message",
                        http::HeaderValue::from_static("refused by the fixture"),
                    );
                    Ok::<_, std::convert::Infallible>(response)
                });
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(sock), svc)
                        .await;
            });
        }
    });
    addr
}

/// A call the upstream refuses trailers-only still reaches the reader as a TERMINAL FRAME carrying
/// the class the upstream named — the whole point of declaring `STATUS_CLASS` at
/// `StatusAt::Terminal`. Flattening it to a dial error left a call that WAS answered posting no
/// status evidence at all, which is the difference between "the upstream said no" and "nothing
/// answered" on the leg that decides a fee.
#[tokio::test]
async fn terminal_status_is_read_from_the_grpc_status_trailer() {
    let client_t = client_transport();
    let keys = test_key_handle();
    let addr = trailers_only_peer(tonic::Code::PermissionDenied).await;
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();

    let mut client_frames = client_t.frames(client_conn.clone());
    // The write itself still reports the refusal to its caller.
    let wrote = client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"hello"))
        .await;
    assert!(wrote.is_err(), "a refused call is not a delivered write");

    let (_s, terminal) = tokio::time::timeout(Duration::from_secs(5), client_frames.next())
        .await
        .expect("a trailers-only refusal must produce a terminal frame, not silence")
        .unwrap()
        .unwrap();
    assert_eq!(
        terminal.bytes.len(),
        0,
        "the terminal frame carries no body"
    );
    assert_eq!(
        terminal.meta.status,
        Some(StatusClass::ClientError),
        "PERMISSION_DENIED is the upstream blaming the request"
    );
    assert_eq!(
        terminal.meta.status_code,
        Some(tonic::Code::PermissionDenied as i32 as u16),
        "the exact grpc-status number the upstream sent, not just its class"
    );
}

/// The other end of the same rule: a call the upstream answers and ends with an OK `grpc-status`
/// trailer at the end of a real body posts `Success` on its terminal frame.
#[tokio::test]
async fn an_ok_grpc_status_trailer_terminates_the_call_as_success() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"hello"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let (server_stream, _f) = server_frames.next().await.unwrap().unwrap();
    server_t
        .write(&server_conn, server_stream, ArenaBytes::new(b"world"))
        .await
        .unwrap();
    server_t.close(
        server_conn,
        busbar_contract_transport::wire::CloseReason::Normal,
    );

    let mut client_frames = client_t.frames(client_conn);
    let (_s, data_frame) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(data_frame.bytes.as_slice(), b"world");
    // The synthetic terminal frame this crate appends on the reading (client) side once the
    // call's response stream ends — the honest reading of the `grpc-status` trailer.
    let (_s, terminal) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(terminal.bytes.len(), 0);
    assert_eq!(
        terminal.meta.status,
        Some(StatusClass::Success),
        "STATUS_CLASS at Terminal: an OK grpc-status is honestly Success, not merely present"
    );
    assert_eq!(
        terminal.meta.status_code,
        Some(tonic::Code::Ok as i32 as u16),
        "the number the upstream sent, which for an untroubled call is zero"
    );
}

/// [`crate::server::map_status`] directly, EVERY `grpc-status` code the protocol defines, one row
/// each.
///
/// The rows that matter most are the four that used to fall to a catch-all. The two failure classes
/// part company on money — a server-side failure is retried elsewhere and held against the
/// destination, a client-side one is relayed to the caller as its own fault and recorded against
/// nobody — so a code landing in the wrong one is not a labelling question. Every code is listed so
/// the table cannot silently grow a member again.
#[test]
fn map_status_reads_the_grpc_status_trailer_honestly() {
    for (code, expected) in [
        (tonic::Code::Ok, StatusClass::Success),
        // The upstream blamed the request.
        (tonic::Code::InvalidArgument, StatusClass::ClientError),
        (tonic::Code::NotFound, StatusClass::ClientError),
        (tonic::Code::AlreadyExists, StatusClass::ClientError),
        (tonic::Code::PermissionDenied, StatusClass::ClientError),
        (tonic::Code::Unauthenticated, StatusClass::ClientError),
        (tonic::Code::FailedPrecondition, StatusClass::ClientError),
        (tonic::Code::OutOfRange, StatusClass::ClientError),
        (tonic::Code::ResourceExhausted, StatusClass::ClientError),
        // The upstream blamed itself.
        (tonic::Code::Internal, StatusClass::ServerError),
        (tonic::Code::Unavailable, StatusClass::ServerError),
        (tonic::Code::DataLoss, StatusClass::ServerError),
        (tonic::Code::Unimplemented, StatusClass::ServerError),
        // gRPC's own word for a server-side failure it could not attribute — and what an HTTP 5xx
        // with no `grpc-status` at all arrives as.
        (tonic::Code::Unknown, StatusClass::ServerError),
        (tonic::Code::DeadlineExceeded, StatusClass::ServerError),
        (tonic::Code::Aborted, StatusClass::ServerError),
        // The one code where neither side is blamed.
        (tonic::Code::Cancelled, StatusClass::Other),
    ] {
        let status = tonic::Status::new(code, "fixture");
        assert_eq!(
            crate::server::map_status(&status),
            expected,
            "tonic::Code::{code:?} maps to {expected:?}"
        );
    }
}

/// The HTTP/2 driver under a dialled connection FAILING is not the peer finishing.
///
/// The driver holds the socket, and its outcome was thrown away: every way a connection can break —
/// a framing the peer got wrong, a socket that died mid-call — reached the reader as the same clean
/// end-of-stream a finished peer produces, so an aborted answer read as a complete one. The peer
/// here commits a protocol error (a PING on a non-zero stream), which is the deterministic way to
/// make the driver fail rather than finish.
#[tokio::test]
async fn a_dialled_connection_whose_driver_fails_ends_with_an_error_not_a_clean_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut scratch = [0_u8; 4096];
        // The client's preface and SETTINGS.
        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut scratch).await;
        // A well-formed SETTINGS of our own, then a PING carrying a stream id — which RFC 9113
        // makes a connection error, so the peer's driver ends failing rather than finishing.
        let mut out = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
        out.extend_from_slice(&[0, 0, 8, 6, 0, 0, 0, 0, 1]);
        out.extend_from_slice(&[0; 8]);
        let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, &out).await;
        futures::future::pending::<()>().await;
    });

    let client_t = client_transport();
    let keys = test_key_handle();
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();

    let mut frames = client_t.frames(client_conn);
    let item = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("a broken driver must answer, not park")
        .expect("a driver that FAILED is not a clean end of stream");
    assert_eq!(
        item.expect_err("the failure is the stream's last word"),
        TransportError::Reset
    );
}

#[tokio::test]
async fn multiplexed_streams_without_cross_talk() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let host: &'static str = Box::leak(addr.clone().into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    // `accept` must run CONCURRENTLY with the writes below, not after: opening a new gRPC call
    // blocks awaiting the server's response headers, which only arrive once the server has
    // actually started serving this TCP connection.
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    // Two independent calls, opened as two distinct `StreamId`s on the SAME connection.
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"stream-one"))
        .await
        .unwrap();
    client_t
        .write(&client_conn, StreamId(2), ArenaBytes::new(b"stream-two"))
        .await
        .unwrap();

    let server_conn = accept_task.await.unwrap().unwrap();
    let mut server_frames = server_t.frames(server_conn);
    let mut seen = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let (stream, frame) = server_frames.next().await.unwrap().unwrap();
        seen.insert(
            stream,
            String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap(),
        );
    }
    assert_eq!(seen.len(), 2, "two distinct streams, not merged");
    let mut values: Vec<_> = seen.values().cloned().collect();
    values.sort();
    assert_eq!(
        values,
        vec!["stream-one".to_string(), "stream-two".to_string()]
    );
}

#[tokio::test]
async fn k_writers_on_one_call_do_not_corrupt_messages() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = std::sync::Arc::new(client_transport());
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    // `accept` must run CONCURRENTLY with the first write, not after — see the identical note in
    // `multiplexed_streams_without_cross_talk`.
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    // Open the call with a first message, then fan more messages onto the SAME stream from K
    // concurrent tasks — one gRPC call carries an ordered sequence of request messages.
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"open"))
        .await
        .unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();
    let mut server_frames = server_t.frames(server_conn);
    let (_s, first) = server_frames.next().await.unwrap().unwrap();
    assert_eq!(first.bytes.as_slice(), b"open");

    const K: usize = 16;
    let mut handles = Vec::new();
    for i in 0..K {
        let client_t = client_t.clone();
        let client_conn = client_conn.clone();
        handles.push(tokio::spawn(async move {
            let line = format!("msg-{i:02}");
            client_t
                .write(&client_conn, StreamId(1), ArenaBytes::new(line.as_bytes()))
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..K {
        let (_s, frame) = server_frames.next().await.unwrap().unwrap();
        let line = String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap();
        assert!(line.starts_with("msg-"), "no corruption: {line:?}");
        seen.insert(line);
    }
    assert_eq!(seen.len(), K);
}

#[tokio::test]
async fn write_to_unseen_stream_on_an_accepted_connection_is_refused() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"hi"))
        .await
        .unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();
    // The server never originates a call: a `StreamId` it has not seen from the peer is refused,
    // not silently opened.
    let err = server_t
        .write(&server_conn, StreamId(999), ArenaBytes::new(b"nope"))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Framing);
}

/// Refusing request *n* leaves *n±1* completing on the same connection.
///
/// `Unit0Trigger::FirstMessage` opens a session per stream here, so a refusal is one stream's. When
/// the refusal took a whole `Conn` and no stream, the only safe reading was to broadcast onto every
/// open call and close the connection — which refused two units for one unit's fault, on a
/// connection a deployment expected to keep carrying the others.
#[tokio::test]
async fn refusing_one_call_leaves_its_neighbours_completing() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = std::sync::Arc::new(client_transport());
    let keys = test_key_handle();
    let listener = server_t
        .listen(&BindTo("127.0.0.1:0".to_string()), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let client_conn = client_t
        .dial(&verified_upstream(host), &keys)
        .await
        .unwrap();
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    // Three calls on one connection: the middle one is the one that gets refused.
    for (id, body) in [(1_u64, &b"one"[..]), (2, b"two"), (3, b"three")] {
        client_t
            .write(&client_conn, StreamId(id), ArenaBytes::new(body))
            .await
            .unwrap();
    }

    let server_conn = accept_task.await.unwrap().unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let mut server_streams = std::collections::BTreeMap::new();
    for _ in 0..3 {
        let (stream, frame) = tokio::time::timeout(Duration::from_secs(5), server_frames.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_streams.insert(
            String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap(),
            stream,
        );
    }

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::InFlightCap,
        retry_after_secs: None,
        // The refusal names the call it is about, which is the whole of what changed here.
        stream: Some(server_streams["two"]),
        correlates: None,
    };

    // Refuse the middle call by name, then answer its two neighbours normally.
    server_t
        .unit0_refusal(
            server_conn.clone(),
            Some(server_streams["two"]),
            &refusal,
            ArenaBytes::new(b"refused"),
        )
        .await
        .unwrap();
    for name in ["one", "three"] {
        server_t
            .write(
                &server_conn,
                server_streams[name],
                ArenaBytes::new(name.as_bytes()),
            )
            .await
            .expect("a neighbour's call is still open");
    }

    // Every one of the three still gets its own answer, and the refused one gets the refusal.
    let mut client_frames = client_t.frames(client_conn);
    let mut answered = std::collections::BTreeMap::new();
    while answered.len() < 3 {
        let (stream, frame) = tokio::time::timeout(Duration::from_secs(5), client_frames.next())
            .await
            .expect("the connection is still carrying the other calls")
            .unwrap()
            .unwrap();
        if !frame.bytes.as_slice().is_empty() {
            answered.insert(
                stream,
                String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap(),
            );
        }
    }
    let mut bodies: Vec<_> = answered.values().cloned().collect();
    bodies.sort();
    assert_eq!(
        bodies,
        vec![
            "one".to_string(),
            "refused".to_string(),
            "three".to_string()
        ],
        "the refused call got the refusal and its neighbours completed"
    );
}

#[tokio::test]
async fn a_handoff_onto_grpc_is_a_mismatch() {
    // Nothing is adopted ONTO `grpc`: it takes a stream from the layer under it at `accept` and
    // `dial`, and there is no third way in. A handoff offered here is one neither leg declared.
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let keys = test_key_handle();
    let listener = server_t
        .listen(&BindTo("127.0.0.1:0".to_string()), &keys)
        .await
        .unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let conn = client_t
        .dial(&verified_upstream(host), &keys)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(200), accept_task).await;
    let err = client_t.adopt(&client_t, conn, &keys).await.unwrap_err();
    assert_eq!(err, TransportError::HandoffMismatch);
}

/// The method the destination names is the `:path` the call is actually opened against. Before the
/// address shape closed there was nowhere to put a method name, so every call answered to one
/// fixed path and two plane operations could not reach two upstream methods.
#[tokio::test]
async fn the_destinations_method_is_the_path_the_call_opens_against() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let host: &'static str = Box::leak(addr.into_boxed_str());
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    let dest = busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "grpc",
            address: busbar_contract_transport::dest::UpstreamAddress::Grpc {
                authority: host,
                sni: None,
                method: "/vendor.Inference/Chat",
            },
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "grpc",
        None,
    );

    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();

    let mut server_frames = server_t.frames(server_conn.clone());
    let (_, frame) = tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.bytes.as_slice(), b"ping");

    let served: Vec<String> = server_t
        .state_of(server_conn.id())
        .unwrap()
        .served_paths
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect();
    assert_eq!(served, vec!["/vendor.Inference/Chat".to_string()]);

    // And the chain both ends report is the stack they actually stand on.
    assert_eq!(
        server_t.arrival(&server_conn).transport_chain,
        vec!["tcp", "http", "grpc"]
    );
    assert_eq!(
        client_t.arrival(&client_conn).transport_chain,
        vec!["tcp", "grpc"]
    );
}

/// With no layer under it this transport has no socket to reach for.
#[tokio::test]
async fn a_transport_with_no_lower_layer_cannot_listen_or_dial() {
    let t = GrpcTransport::new();
    let keys = test_key_handle();
    assert_eq!(
        t.listen(&BindTo("127.0.0.1:0".to_string()), &keys)
            .await
            .unwrap_err(),
        TransportError::HandoffMismatch
    );
    assert_eq!(
        t.dial(&verified_upstream("127.0.0.1:1"), &keys)
            .await
            .unwrap_err(),
        TransportError::HandoffMismatch
    );
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::TransportMeta;
    use busbar_contract_transport::wire::StatusAt;
    use busbar_contract_transport::wire::Unit0Trigger;
    assert_eq!(<GrpcTransport as TransportMeta>::KEY, "grpc");
    assert!(<GrpcTransport as TransportMeta>::SESSION);
    assert!(<GrpcTransport as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <GrpcTransport as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::FirstMessage)
    );
    assert_eq!(
        <GrpcTransport as TransportMeta>::COMPOSES_OVER,
        &["http", "tcp"]
    );
    assert!(<GrpcTransport as TransportMeta>::UPGRADES_TO.is_empty());
    assert_eq!(
        <GrpcTransport as TransportMeta>::STATUS_CLASS,
        Some(StatusAt::Terminal)
    );
}

/// Two concurrent `write()`s naming the same unseen `StreamId` are one call, not two.
///
/// The "K writers" cell makes concurrent writers on one connection an expected shape. A
/// check-then-open sequence lets both writers miss the map, both open an HTTP/2 call, and the
/// later registration overwrite — and so drop — the earlier sender, ending that call's outbound
/// stream with the first write's bytes accepted but never delivered.
#[tokio::test]
async fn two_writes_racing_on_one_fresh_stream_open_a_single_call() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = std::sync::Arc::new(client_transport());
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = std::sync::Arc::new(client_t.dial(&dest, &keys).await.unwrap());
    let server_conn = accept_task.await.unwrap().unwrap();

    let one = {
        let (t, c) = (client_t.clone(), client_conn.clone());
        tokio::spawn(async move { t.write(&c, StreamId(7), ArenaBytes::new(b"one")).await })
    };
    let two = {
        let (t, c) = (client_t.clone(), client_conn.clone());
        tokio::spawn(async move { t.write(&c, StreamId(7), ArenaBytes::new(b"two")).await })
    };
    one.await.unwrap().unwrap();
    two.await.unwrap().unwrap();

    // Both payloads reach the server, and they reach it on ONE call.
    let mut server_frames = server_t.frames(server_conn.clone());
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for _ in 0..2 {
        let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), server_frames.next())
            .await
            .expect("both writes were accepted, so both messages must arrive")
            .unwrap()
            .unwrap();
        seen.push(frame.bytes.as_slice().to_vec());
    }
    seen.sort();
    assert_eq!(seen, vec![b"one".to_vec(), b"two".to_vec()]);

    let paths = server_t
        .state_of(server_conn.id())
        .unwrap()
        .served_paths
        .lock()
        .unwrap()
        .clone();
    assert_eq!(
        paths.len(),
        1,
        "one fresh StreamId is one gRPC call, however many writers raced for it: {paths:?}"
    );
}

/// The outbound map is per-call, and `next_local_stream` only ever counts up: a long-lived HTTP/2
/// connection serving many short calls must not accumulate one stale sender per call it has
/// already finished. Both registration sites are checked — the dial side's, which registers when a
/// call is opened, and the accept side's, which registers when one arrives.
#[tokio::test]
async fn a_finished_call_leaves_no_entry_behind() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };

    const CALLS: u64 = 20;
    let mut server_frames = server_t.frames(server_conn.clone());
    let mut client_frames = client_t.frames(client_conn.clone());
    for n in 1..=CALLS {
        client_t
            .write(&client_conn, StreamId(n), ArenaBytes::new(b"ping"))
            .await
            .unwrap();
        let (server_stream, _f) =
            tokio::time::timeout(Duration::from_secs(5), server_frames.next())
                .await
                .expect("the call arrives")
                .unwrap()
                .unwrap();
        // The server finishes the call: writing the answer and ending its outbound stream is what
        // emits the `grpc-status` trailer that completes an RPC.
        server_t
            .unit0_refusal(
                server_conn.clone(),
                Some(server_stream),
                &refusal,
                ArenaBytes::new(b"pong"),
            )
            .await
            .unwrap();
        // Drain the client's side of that call through to its terminal status frame, which is what
        // tells the dial side the call is over.
        loop {
            let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), client_frames.next())
                .await
                .expect("the answer arrives")
                .unwrap()
                .unwrap();
            if frame.meta.status.is_some() {
                break;
            }
        }
    }

    let client_state = client_t.state_of(client_conn.id()).unwrap();
    let left = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = client_state.outbound.lock().unwrap().len();
            if n == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        left.is_ok(),
        "the dial side kept a sender per finished call: {} left after {CALLS}",
        client_state.outbound.lock().unwrap().len()
    );
}

/// `served_paths` is a diagnostic record, not a log: a connection open across many RPCs must not
/// grow it forever. Past [`crate::conn::SERVED_PATHS_CAP`] calls it keeps only the most recent.
#[tokio::test]
async fn served_paths_stays_bounded_across_many_calls() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };

    let calls: u64 = crate::conn::SERVED_PATHS_CAP as u64 + 1;
    let mut server_frames = server_t.frames(server_conn.clone());
    let mut client_frames = client_t.frames(client_conn.clone());
    for n in 1..=calls {
        client_t
            .write(&client_conn, StreamId(n), ArenaBytes::new(b"ping"))
            .await
            .unwrap();
        let (server_stream, _f) =
            tokio::time::timeout(Duration::from_secs(5), server_frames.next())
                .await
                .expect("the call arrives")
                .unwrap()
                .unwrap();
        server_t
            .unit0_refusal(
                server_conn.clone(),
                Some(server_stream),
                &refusal,
                ArenaBytes::new(b"pong"),
            )
            .await
            .unwrap();
        loop {
            let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), client_frames.next())
                .await
                .expect("the answer arrives")
                .unwrap()
                .unwrap();
            if frame.meta.status.is_some() {
                break;
            }
        }
    }

    let served = server_t
        .state_of(server_conn.id())
        .unwrap()
        .served_paths
        .lock()
        .unwrap()
        .len();
    assert_eq!(
        served,
        crate::conn::SERVED_PATHS_CAP,
        "{calls} RPCs over one connection fill the record to exactly the cap and no further"
    );
    // And it is the LAST handful, not the first: a record that kept the oldest entries and dropped
    // the newest would be bounded and useless, and `<=` alone could not tell the two apart.
    let oldest = server_t
        .state_of(server_conn.id())
        .unwrap()
        .served_paths
        .lock()
        .unwrap()
        .front()
        .cloned();
    assert_eq!(
        oldest.as_deref(),
        Some(crate::server::RPC_PATH),
        "every call in this fixture is on the same path, so the record's contents are checkable"
    );
}

/// A call `tonic` answers on its own, WITHOUT ever entering this crate's per-RPC handler, must
/// leave nothing behind on the connection.
///
/// `grpc-encoding: gzip` against a server with no compression enabled is exactly that: the answer
/// (UNIMPLEMENTED) is decided while the request headers are being read, so the handler whose drop
/// is what prunes the connection's outbound map never runs. An entry registered before that point
/// is one nothing will ever drain and nothing will ever remove — and a connection-wide refusal
/// walks that map, so it would report a Reset for a call that never existed.
#[tokio::test]
async fn a_call_answered_before_the_handler_runs_leaves_no_entry_behind() {
    use http_body_util::BodyExt;

    let server_t = std::sync::Arc::new(server_transport());
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let sock = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let (mut send, driver) =
        hyper::client::conn::http2::handshake::<_, _, http_body_util::Full<bytes::Bytes>>(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(sock),
        )
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = driver.await;
    });
    let server_conn = accept_task.await.unwrap().unwrap();

    const CALLS: usize = 20;
    for _ in 0..CALLS {
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{addr}{}", crate::server::RPC_PATH))
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers")
            // The compression this server never enabled.
            .header("grpc-encoding", "gzip")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(&[
                0, 0, 0, 0, 1, 7,
            ])))
            .unwrap();
        let response = send.send_request(req).await.unwrap();
        assert_ne!(
            response.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"0".as_slice()),
            "the fixture's whole point is a call tonic refuses outright"
        );
        let _ = response.into_body().collect().await;
    }

    let state = server_t.state_of(server_conn.id()).unwrap();
    let held = state.outbound.lock().unwrap().len();
    assert_eq!(
        held, 0,
        "{CALLS} calls refused before the handler must hold no outbound entries, held {held}"
    );
}

/// The accept side's half of the same rule, at the seam it actually happens on: an RPC's outbound
/// stream being dropped — which is what hyper does when the peer resets the call — is what makes
/// the call over, and the map entry must go with it.
#[tokio::test]
async fn dropping_a_served_calls_outbound_stream_prunes_its_entry() {
    let state = crate::conn::ConnState::new(None, vec!["grpc"]);
    let (tx, rx) = crate::conn::outbound_channel();
    let serial = state.register(3, crate::conn::opened(tx));
    let out = crate::server::OutStream::new(rx, state.clone(), StreamId(3), serial);
    assert_eq!(state.outbound.lock().unwrap().len(), 1);
    drop(out);
    assert_eq!(
        state.outbound.lock().unwrap().len(),
        0,
        "a served call whose outbound stream is gone is a call that is over"
    );
}

/// Bidirectional backpressure, the cell `grpc` is the one in-tree transport that could not pass.
///
/// Every multiplexed call's inbound messages share one channel. A peer writing faster than
/// `frames()` is polled must stall — against the HTTP/2 flow-control window — rather than queue on
/// this process's heap, so filling the per-unit frame buffer with nothing draining it must not
/// complete.
#[tokio::test]
async fn the_inbound_channel_backpressures_a_peer_that_outruns_frames() {
    let state = crate::conn::ConnState::new(None, vec!["grpc"]);
    let one = || {
        Ok((
            StreamId(1),
            busbar_contract::wire::Frame {
                direction: busbar_contract_transport::wire::Direction::Inbound,
                stream: StreamId(1),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b"x"[..])),
                meta: busbar_contract_transport::wire::FrameMeta {
                    bytes: 1,
                    transport_units: None,
                    status: None,
                    status_code: None,
                    retry_after_secs: None,
                },
            },
        ))
    };
    // Nothing polls `frames()`, so nothing drains: well past the buffer's depth, the sender must
    // still be waiting rather than have swallowed every message.
    let flooded = tokio::time::timeout(Duration::from_millis(250), async {
        for _ in 0..crate::conn::INBOUND_FRAME_BUFFER * 4 {
            let _ = state.send_inbound(one()).await;
        }
    })
    .await;
    assert!(
        flooded.is_err(),
        "an undrained inbound channel must backpressure once the per-unit frame buffer is full"
    );
}

/// An arrival names the port it arrived on.
///
/// `Port` is one of the selector forms this transport declares it can claim by, and a claim reads
/// the arrival record. The record said `0` for every connection on every listener, so the one form
/// that tells two bound ports apart could not tell them apart at all: every arrival on this
/// transport looked like every other, whatever it had been accepted on.
#[tokio::test]
async fn an_arrival_names_the_port_it_arrived_on() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let bound: u16 = addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .expect("the listener is bound to a port");
    assert_ne!(bound, 0, "the listener really is bound");

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let _client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    assert_eq!(
        server_t.arrival(&server_conn).port,
        bound,
        "an arrival that names no port cannot be claimed by the Port selector form this transport declares"
    );
}

/// A forwarder parked on a full inbound buffer ends when the connection does.
///
/// Backpressure is a wait, and a wait needs a way out. The wait was on a send with no cancellation
/// leg, and the task doing it holds its own clone of the connection state — which is what keeps the
/// receiving half alive — so nothing could ever end it: not the connection's own completion, not
/// `close`, not a reader that gave up and walked away. One task and one buffer's worth of frames
/// per abandoned call, held for the life of the process.
#[tokio::test]
async fn a_forwarder_parked_on_a_full_inbound_buffer_ends_when_the_connection_does() {
    let state = crate::conn::ConnState::new(None, vec!["grpc"]);
    let one = || {
        Ok((
            StreamId(1),
            busbar_contract::wire::Frame {
                direction: busbar_contract_transport::wire::Direction::Inbound,
                stream: StreamId(1),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b"x"[..])),
                meta: busbar_contract_transport::wire::FrameMeta {
                    bytes: 1,
                    transport_units: None,
                    status: None,
                    status_code: None,
                    retry_after_secs: None,
                },
            },
        ))
    };

    // A forwarder with nothing draining it: it fills the per-unit buffer and parks on the send.
    let forwarder = {
        let state = state.clone();
        tokio::spawn(async move {
            for _ in 0..crate::conn::INBOUND_FRAME_BUFFER * 4 {
                if state.send_inbound(one()).await.is_err() {
                    return;
                }
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !forwarder.is_finished(),
        "the buffer must be full and the forwarder parked on it, or this test proves nothing"
    );

    // The connection ends. Nothing will ever read what is queued, so the forwarder has nothing left
    // to wait for.
    state.end_inbound();
    let ended = tokio::time::timeout(Duration::from_secs(5), forwarder).await;
    assert!(
        ended.is_ok(),
        "a forwarder parked on the inbound buffer outlived the connection it was forwarding for"
    );

    // And with it gone, the last inbound sender is gone: a reader draining what is queued reaches
    // end-of-stream rather than waiting on a connection that has ended.
    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        let mut guard = state.inbound_rx.lock().await;
        let rx = guard
            .as_mut()
            .expect("the receiving half is this connection's");
        while rx.recv().await.is_some() {}
    })
    .await;
    assert!(
        drained.is_ok(),
        "the queued frames of an ended connection never reached end-of-stream"
    );
}

/// A destination is sealed by whatever named the method; nothing validates that string is a legal
/// HTTP/2 `:path` before it gets here. A malformed method must refuse the dial's first write, not
/// panic the process building the request.
#[tokio::test]
async fn a_malformed_sealed_method_refuses_instead_of_panicking() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let host: &'static str = Box::leak(addr.into_boxed_str());
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    let dest = busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "grpc",
            address: busbar_contract_transport::dest::UpstreamAddress::Grpc {
                authority: host,
                sni: None,
                method: "/pkg.Svc/My Method",
            },
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "grpc",
        None,
    );

    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let _server_conn = accept_task.await.unwrap().unwrap();
    let err = client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::AddressRefused);
}

/// A zero-length message is a legal one on this wire: the length-prefix framing spells a body of
/// zero bytes, and a peer that sends the empty message is saying something — it is the shape an
/// empty request or response takes. A codec that answers "not yet, send more" to a body it has
/// already been handed in full does not merely drop that message: the call never leaves the state
/// it was decoding it in, so every message queued behind it is lost too. The empty one and all of
/// its successors must arrive.
#[tokio::test]
async fn an_empty_message_is_delivered_and_does_not_wedge_the_ones_behind_it() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };

    let host: &'static str = Box::leak(addr.into_boxed_str());
    let client_conn = client_t
        .dial(&verified_upstream(host), &keys)
        .await
        .unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"open"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let (server_stream, opened) = server_frames.next().await.unwrap().unwrap();
    assert_eq!(opened.bytes.as_slice(), b"open");

    // The empty message first, then the ones that must not be stuck behind it.
    server_t
        .write(&server_conn, server_stream, ArenaBytes::new(b""))
        .await
        .unwrap();
    for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
        server_t
            .write(&server_conn, server_stream, ArenaBytes::new(payload))
            .await
            .unwrap();
    }

    let mut client_frames = client_t.frames(client_conn);
    let mut got: Vec<Vec<u8>> = Vec::new();
    for _ in 0..4 {
        let next = tokio::time::timeout(Duration::from_secs(5), client_frames.next())
            .await
            .expect("an empty message must not park the call that carries it");
        let (_s, frame) = next.unwrap().unwrap();
        assert_eq!(frame.meta.bytes, frame.bytes.as_slice().len() as u64);
        got.push(frame.bytes.as_slice().to_vec());
    }
    assert_eq!(
        got,
        vec![
            Vec::new(),
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec()
        ],
        "the empty message and every message behind it"
    );
}

/// Closing a connection stops the HTTP/2 server task that serves it.
///
/// `close` is the kernel's only way to be rid of a connection. When the accept side spawned the
/// hyper connection task and dropped its handle, nothing held a way to stop it: a closed connection
/// kept its socket and went on accepting fresh RPCs from the peer, so "closed" meant only that this
/// transport had stopped listing it.
#[tokio::test]
async fn closing_a_connection_stops_serving_new_calls_on_it() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    // The connection is really serving: one call opens and arrives.
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .expect("the first call arrives")
        .unwrap()
        .unwrap();

    server_t.close(
        server_conn,
        busbar_contract_transport::wire::CloseReason::Normal,
    );

    // A closed connection serves nothing further: the peer's next RPC on it must fail rather than
    // be answered by a task the transport can no longer reach. Opening a call is a round trip, so
    // the peer may have one already in flight when the close lands — but only one: past that, every
    // fresh call must be refused, and a connection still serving them never gets there.
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        for n in 2..u64::MAX {
            if client_t
                .write(&client_conn, StreamId(n), ArenaBytes::new(b"ping"))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        refused.is_ok(),
        "a closed connection went on serving fresh calls from the peer"
    );
}

/// `frames()` ends when the connection does, on both sides.
///
/// The connection state owned the inbound sender, so the receiver `frames()` drains could never see
/// end-of-stream: with the peer gone, or after `close`, the stream stayed pending forever instead
/// of finishing. A reader above it cannot tell "the answer is complete" from "the next frame has
/// not arrived yet", so it waits out its whole deadline on a call that already ended whole — and
/// then compensates for a failure that never happened.
#[tokio::test]
async fn frames_end_when_the_connection_does() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let mut client_frames = client_t.frames(client_conn.clone());
    tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .expect("the call arrives")
        .unwrap()
        .unwrap();

    // The peer is finished with this connection and gone.
    server_t.close(
        server_conn,
        busbar_contract_transport::wire::CloseReason::Normal,
    );

    // The closing side's own reader ends: nothing more will ever arrive on a connection this
    // transport has closed.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while server_frames.next().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "the closed side's frames() never ended");

    // And the peer's reader ends once the connection under it is gone — after whatever the calls
    // still in flight have left to say, terminal status included.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while client_frames.next().await.is_some() {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the peer's frames() stayed pending with the connection gone"
    );
}

/// The outbound half backpressures too, which is the other direction of the rule this connection
/// already keeps inbound.
///
/// `write()` handed each message to an unbounded queue, so a peer that never read still let a
/// writer accept messages without limit: every one of them queued on this process's heap, and the
/// `Ok` it returned said "sent" about bytes that had not reached the wire and might never. Bounded,
/// the writer waits on the peer, which is what the HTTP/2 flow-control window is for.
#[tokio::test]
async fn write_backpressures_a_peer_that_never_reads() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    // Accepted, and never read from: nothing polls the server's `frames()`, so the server's own
    // inbound buffer fills, the flow-control window shuts, and the queue behind `write()` is the
    // only place left for the messages to go.
    let _server_conn = accept_task.await.unwrap().unwrap();

    let message = vec![b'x'; 4096];
    let flooded = tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..crate::conn::OUTBOUND_FRAME_BUFFER * 8 {
            client_t
                .write(&client_conn, StreamId(1), ArenaBytes::new(&message))
                .await
                .unwrap();
        }
    })
    .await;
    assert!(
        flooded.is_err(),
        "a writer outran a peer that never read: every message was accepted onto the heap"
    );
}

/// A refusal that could not be delivered says so.
///
/// Refusing names a call, and the refusal's whole point is that the caller is told. When the stream
/// named had no entry — already over, never opened, or the call's channel gone — the refusal was
/// dropped on the floor and `Ok(())` was returned anyway, so the kernel recorded a unit as refused
/// on a connection where nothing had been written.
#[tokio::test]
async fn a_refusal_that_reaches_no_call_is_an_error() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };

    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let (served, _f) = tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .expect("the call arrives")
        .unwrap()
        .unwrap();

    // The first refusal reaches the call and ends it.
    server_t
        .unit0_refusal(
            server_conn.clone(),
            Some(served),
            &refusal,
            ArenaBytes::new(b"no"),
        )
        .await
        .unwrap();

    // The second names a call this connection no longer has: there is nothing left to refuse, and
    // saying so is the difference between a refusal delivered and a refusal imagined.
    let err = server_t
        .unit0_refusal(
            server_conn.clone(),
            Some(served),
            &refusal,
            ArenaBytes::new(b"no"),
        )
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Closed);

    // And a stream this connection never carried at all.
    let err = server_t
        .unit0_refusal(
            server_conn,
            Some(StreamId(9999)),
            &refusal,
            ArenaBytes::new(b"no"),
        )
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Closed);
}

/// A connection-wide refusal on a DIALLED connection reaches the peer before the connection goes.
///
/// A refusal naming no call is about the connection, so it is written and then the connection is
/// closed — and closing a dialled one now takes the stream out from under the HTTP/2 client. The
/// bytes have to be on the wire first: a refusal the caller was told was delivered, cut off inside
/// this process before it left, is exactly the "refusal imagined" the neighbouring cell is about.
#[tokio::test]
async fn a_connection_wide_refusal_is_delivered_before_a_dialled_connection_is_cut() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    let (_served, frame) = tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .expect("the call arrives")
        .unwrap()
        .unwrap();
    assert_eq!(frame.bytes.as_slice(), b"ping");

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    client_t
        .unit0_refusal(client_conn, None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .unwrap();

    // The peer reads the refusal itself, not just the death of the connection that carried it.
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(item) = server_frames.next().await {
            if let Ok((_s, frame)) = item {
                if frame.bytes.as_slice() == b"refused" {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("the peer's reader ends either way");
    assert!(
        refused,
        "the refusal was reported delivered but the connection was cut before it left this process"
    );
}

/// The flush window is a property of CLOSING, not of where `close` happened to be called from.
///
/// Closing writes the connection-wide refusal to every call first and cuts the stream second, and
/// the window between the two is what lets those bytes actually leave this process. Off a thread
/// with no runtime — an operator tool, a shutdown path, a `Drop` — the fallback cut immediately and
/// destroyed exactly the bytes the window exists to protect, with the caller already told they were
/// delivered. Same close, same promise, two different answers depending on the caller's thread.
///
/// A plain `#[test]`, deliberately: no `#[tokio::test]` means no ambient runtime, which IS the
/// condition under test.
#[test]
fn a_close_off_the_runtime_holds_the_cut_for_the_same_flush_window() {
    let (near, far) = tokio::io::duplex(64);
    // Held so the far end is a live peer rather than a closed one.
    let _far = far;
    let (_cuttable, cut) = crate::conn::Cuttable::new(Box::new(near));
    let state = crate::conn::ConnState::new(None, vec!["grpc"]);
    state.arm_cut(cut.clone());
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the fixture is only honest with no runtime on this thread"
    );

    state.stop();

    assert!(
        !cut.is_cut(),
        "a close must not cut the stream out from under bytes it has just accepted"
    );
    std::thread::sleep(crate::conn::CUT_GRACE + Duration::from_millis(500));
    assert!(
        cut.is_cut(),
        "and the window is a window: past it the stream goes, whatever the peer is doing"
    );
}

/// A finished call takes its OWN entry out of the outbound map, not whatever the id holds now.
///
/// Cleanup runs when a call ends — from the dial side's forwarding task, from the served call's
/// outbound stream being dropped, from a failed open. All of them ran by `StreamId` alone, and a
/// `StreamId` is reused: a call ending just as the next one takes its id would remove the live
/// call's sender, ending a second unit's answer for the first one's death.
#[test]
fn a_finished_call_cannot_end_the_one_that_reused_its_id() {
    let state = crate::conn::ConnState::new(None, vec!["grpc"]);
    let (first_tx, _first_rx) = crate::conn::outbound_channel();
    let first = state.register(7, crate::conn::opened(first_tx));
    assert!(
        state.end_call(7, first).is_some(),
        "its own entry is its own"
    );

    // The id comes round again, and the call now holding it is a different call.
    let (second_tx, _second_rx) = crate::conn::outbound_channel();
    let second = state.register(7, crate::conn::opened(second_tx));
    assert_ne!(first, second, "two calls on one id are two calls");

    // The first call's cleanup, arriving late.
    assert!(
        state.end_call(7, first).is_none(),
        "a finished call took the entry of the live one that reused its id"
    );
    assert!(
        state.call(7).is_some(),
        "the live call's sender is gone: nothing will ever drain its answer"
    );

    // And the live one still ends when IT ends.
    assert!(state.end_call(7, second).is_some());
    assert!(state.call(7).is_none());
}

/// Closing a DIALLED connection lets its socket go.
///
/// The stop seam was armed only on the accept side, so `close` on a dialled connection fired
/// nothing, and the task driving its HTTP/2 half could only finish once every request sender had
/// dropped — while the connection state holding those senders was itself kept alive by that same
/// task. The wait was circular: the socket, and the tasks on either end of it, outlived every
/// caller that could have reached them. The peer sees it first — a connection whose dialler has
/// closed must reach end-of-stream, not stay open on a descriptor nothing owns.
#[tokio::test]
async fn closing_a_dialled_connection_releases_its_socket() {
    let server_t = std::sync::Arc::new(server_transport());
    let client_t = client_transport();
    let cfg = BindTo("127.0.0.1:0".to_string());
    let keys = test_key_handle();
    let listener = server_t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();

    let accept_task = {
        let server_t = server_t.clone();
        tokio::spawn(async move { server_t.accept(&listener).await })
    };
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let client_conn = client_t.dial(&dest, &keys).await.unwrap();
    let server_conn = accept_task.await.unwrap().unwrap();

    // The connection is really up: one call opens and arrives.
    client_t
        .write(&client_conn, StreamId(1), ArenaBytes::new(b"ping"))
        .await
        .unwrap();
    let mut server_frames = server_t.frames(server_conn.clone());
    tokio::time::timeout(Duration::from_secs(5), server_frames.next())
        .await
        .expect("the call arrives")
        .unwrap()
        .unwrap();

    // The dialling side is done with it.
    client_t.close(
        client_conn,
        busbar_contract_transport::wire::CloseReason::Normal,
    );

    // The socket goes with it, which is what the accepting side sees: its own reader ends.
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while server_frames.next().await.is_some() {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "a closed dialled connection kept its socket open: the peer never saw end-of-stream"
    );
}
