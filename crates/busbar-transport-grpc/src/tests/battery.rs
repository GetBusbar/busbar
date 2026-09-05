// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport battery: byte-exact round trip (a unary-shaped call: one write, then read
//! the answer), multiplexed streams without cross-talk, K writers, honest terminal status, and the
//! transport-meta declarations.

use std::time::Duration;

use futures::StreamExt;

use busbar_contract::wire::TransportError;
use busbar_contract::{ArenaBytes, StreamId, Transport};

use crate::GrpcTransport;

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    struct Seal;
    impl busbar_contract::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

fn verified_upstream(host: &'static str) -> busbar_contract::VerifiedDestination {
    struct Seal;
    impl busbar_contract::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "grpc",
            host,
            lane: busbar_contract::LaneId::new("test-lane"),
        },
        "grpc",
        None,
    )
}

#[tokio::test]
async fn unary_shaped_round_trip() {
    let server_t = std::sync::Arc::new(GrpcTransport::new());
    let client_t = GrpcTransport::new();
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
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

#[tokio::test]
async fn terminal_status_is_read_from_the_grpc_status_trailer() {
    let server_t = std::sync::Arc::new(GrpcTransport::new());
    let client_t = GrpcTransport::new();
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
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
    server_t.close(server_conn, busbar_contract::wire::CloseReason::Normal);

    let mut client_frames = client_t.frames(client_conn);
    let (_s, data_frame) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(data_frame.bytes.as_slice(), b"world");
    // The synthetic terminal frame this crate appends on the reading (client) side once the
    // call's response stream ends — the honest reading of the `grpc-status` trailer.
    let (_s, terminal) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(terminal.bytes.len(), 0);
    assert!(terminal.meta.status.is_some(), "STATUS_CLASS at Terminal");
}

#[tokio::test]
async fn multiplexed_streams_without_cross_talk() {
    let server_t = std::sync::Arc::new(GrpcTransport::new());
    let client_t = GrpcTransport::new();
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
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
        seen.insert(stream, String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap());
    }
    assert_eq!(seen.len(), 2, "two distinct streams, not merged");
    let mut values: Vec<_> = seen.values().cloned().collect();
    values.sort();
    assert_eq!(values, vec!["stream-one".to_string(), "stream-two".to_string()]);
}

#[tokio::test]
async fn k_writers_on_one_call_do_not_corrupt_messages() {
    let server_t = std::sync::Arc::new(GrpcTransport::new());
    let client_t = std::sync::Arc::new(GrpcTransport::new());
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
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
    let server_t = std::sync::Arc::new(GrpcTransport::new());
    let client_t = GrpcTransport::new();
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
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

#[tokio::test]
async fn upgrade_is_always_refused() {
    let t = GrpcTransport::new();
    let cfg = crate::StaticConfig::bind_to("127.0.0.1:0");
    let keys = test_key_handle();
    let listener = t.listen(&cfg, &keys).await.unwrap();
    let addr = listener.local_addr();
    let host: &'static str = Box::leak(addr.into_boxed_str());
    let dest = verified_upstream(host);
    let accept_task = {
        let t = std::sync::Arc::new(t);
        let t2 = t.clone();
        tokio::spawn(async move { t2.accept(&listener).await })
    };
    let dialer_t = GrpcTransport::new();
    let conn = dialer_t.dial(&dest, &keys).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(200), accept_task).await;
    let err = dialer_t.upgrade(conn, "http", &keys).await.unwrap_err();
    assert_eq!(err, TransportError::Framing);
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::wire::{StatusAt, Unit0Trigger};
    use busbar_contract::TransportMeta;
    assert_eq!(<GrpcTransport as TransportMeta>::KEY, "grpc");
    assert!(<GrpcTransport as TransportMeta>::SESSION);
    assert!(<GrpcTransport as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <GrpcTransport as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::FirstMessage)
    );
    assert_eq!(<GrpcTransport as TransportMeta>::COMPOSES_OVER, &["http"]);
    assert!(<GrpcTransport as TransportMeta>::UPGRADES_TO.is_empty());
    assert_eq!(
        <GrpcTransport as TransportMeta>::STATUS_CLASS,
        Some(StatusAt::Terminal)
    );
}
