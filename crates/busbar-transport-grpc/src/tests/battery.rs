// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The gRPC transport battery: byte-exact round trip (a unary-shaped call: one write, then read
//! the answer), multiplexed streams without cross-talk, K writers, honest terminal status, and the
//! transport-meta declarations.

use std::time::Duration;

use futures::StreamExt;

use busbar_contract::{ArenaBytes, StreamId, Transport};
use busbar_contract_transport::wire::TransportError;

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

#[tokio::test]
async fn terminal_status_is_read_from_the_grpc_status_trailer() {
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
    assert!(terminal.meta.status.is_some(), "STATUS_CLASS at Terminal");
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

    let served = server_t
        .state_of(server_conn.id())
        .unwrap()
        .served_paths
        .lock()
        .unwrap()
        .clone();
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
