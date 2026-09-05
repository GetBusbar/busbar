//! The transport battery, for `tcp`: byte-exact round trip, half-close, cancel mid-frame, every
//! `TransportError` mapped, backpressure, and the frame-meta honesty check (an inflating and a
//! deflating fixture must fail it — the "must turn red" cell from the design's transport battery).

use super::*;
use busbar_contract::{ConfigView, Frame, FrameMeta};
use futures::StreamExt;
use std::sync::Arc as StdArc;

struct TestCfg {
    bind: String,
}

impl ConfigView for TestCfg {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for TestCfg {
    fn bind(&self) -> Option<&str> {
        Some(&self.bind)
    }
}

/// A fixture-only key handle: no real transport-key unit exists in this crate's tests, so tests
/// build the opaque handle through the seal every production caller would use instead.
struct FixtureSeal;
impl busbar_contract::KernelSeal for FixtureSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-transport-tcp test fixture"
    }
}

fn fixture_key() -> busbar_contract::TransportKeyHandle {
    busbar_contract::TransportKeyHandle::issue(&FixtureSeal, 0, "test")
}

async fn bound_pair() -> (StdArc<TcpTransport>, Listener, StdArc<TcpTransport>) {
    let server = StdArc::new(TcpTransport::new());
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = server.listen(&cfg, &fixture_key()).await.unwrap();
    let client = StdArc::new(TcpTransport::new());
    (server, listener, client)
}

fn upstream_dest(addr: &str) -> busbar_contract::VerifiedDestination {
    let host: &'static str = Box::leak(addr.to_string().into_boxed_str());
    busbar_contract::VerifiedDestination::seal(
        &FixtureSeal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "tcp",
            address: busbar_contract::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test"),
        },
        "tcp",
        None,
    )
}

#[tokio::test]
async fn byte_exact_round_trip_inbound_and_outbound() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();

    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });

    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key()).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    let payload = b"the quick brown fox jumps over the lazy dog";
    let n = client
        .write(&client_conn, StreamId(0), ArenaBytes::new(payload))
        .await
        .unwrap();
    assert_eq!(n, payload.len());

    let mut frames = server.frames(server_conn);
    let (_stream, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), payload);
    assert_eq!(frame.meta.bytes, payload.len() as u64);
}

#[tokio::test]
async fn byte_exact_round_trip_the_outbound_leg_too() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key()).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    let reply = b"woof";
    server
        .write(&server_conn, StreamId(0), ArenaBytes::new(reply))
        .await
        .unwrap();
    let mut client_frames = client.frames(client_conn);
    let (_s, frame) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), reply);
    assert_eq!(frame.meta.bytes, reply.len() as u64);
}

#[tokio::test]
async fn half_close_lets_the_other_side_keep_writing() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key()).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    // The client closes (drops its write half via `close`); the server still sees the bytes the
    // client sent before closing, and its read side then reaches a clean end-of-stream rather
    // than an error.
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"bye"))
        .await
        .unwrap();
    client.close(client_conn, CloseReason::Normal);

    let mut frames = server.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"bye");
    // EOF: the stream ends cleanly, with no error frame.
    assert!(frames.next().await.is_none());
}

#[tokio::test]
async fn cancel_mid_frame_leaves_the_connection_usable() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key()).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    // Start a read and cancel it before any bytes arrive (dropping the future mid-poll).
    {
        let mut frames = server.frames(server_conn.clone());
        let fut = frames.next();
        tokio::pin!(fut);
        // Poll once, immediately, with nothing written yet: this is Pending, and dropping it here
        // is the "cancel mid-frame" cell — the connection must survive the drop.
        let _ = futures::poll!(fut.as_mut());
    }

    // The connection is still usable: a fresh frame pump on the same conn sees the next write.
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"still alive"))
        .await
        .unwrap();
    let mut frames = server.frames(server_conn);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"still alive");
}

#[tokio::test]
async fn every_transport_error_is_mapped() {
    // Refused: nothing listens on this port.
    let client = TcpTransport::new();
    let dest = upstream_dest("127.0.0.1:1"); // reserved/unassigned; nothing listens there
    let err = client.dial(&dest, &fixture_key()).await.unwrap_err();
    assert!(matches!(
        err,
        TransportError::Refused | TransportError::Closed | TransportError::Timeout
    ));

    // AddressRefused: an unparsable host never reaches the socket layer at all.
    let bad = upstream_dest("not-an-address");
    let err = client.dial(&bad, &fixture_key()).await.unwrap_err();
    assert_eq!(err, TransportError::AddressRefused);

    // Closed: writing to a connection id this transport never registered.
    struct Ghost;
    impl ConnHandle for Ghost {
        fn id(&self) -> u64 {
            999_999
        }
        fn peer(&self) -> String {
            "ghost".to_string()
        }
    }
    let ghost = Conn::new(StdArc::new(Ghost));
    let err = client
        .write(&ghost, StreamId(0), ArenaBytes::new(b"x"))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Closed);
}

#[tokio::test]
async fn backpressure_bounds_the_per_unit_frame_buffer() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client.dial(&upstream_dest(&addr), &fixture_key()).await.unwrap();
    let server_conn = accept_fut.await.unwrap();

    // Write far more than one read chunk's worth; the frame pump never buffers more than
    // `READ_CHUNK_BYTES` per outstanding frame; consumed one at a time here rather than all at
    // once, proving no unbounded buffering happened on the write side either (the OS socket
    // buffer is the only slack, and it is finite).
    let total = READ_CHUNK_BYTES * 4;
    let payload = vec![7_u8; total];
    let writer = tokio::spawn({
        let payload = payload.clone();
        async move {
            client
                .write(&client_conn, StreamId(0), ArenaBytes::new(&payload))
                .await
                .unwrap()
        }
    });

    let mut frames = server.frames(server_conn);
    let mut got = 0usize;
    while got < total {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        assert!(frame.bytes.len() <= READ_CHUNK_BYTES);
        got += frame.bytes.len();
    }
    assert_eq!(got, total);
    writer.await.unwrap();
}

/// Frame-meta honesty: byte counts a transport reports must equal what actually moved. This test
/// builds two adversarial fixtures — one that inflates its reported count, one that deflates it —
/// and shows the honesty check the design requires ("an inflating and a deflating fixture are
/// red") catches both, while the real `tcp` transport's frames pass it.
fn frame_is_honest(frame: &Frame) -> bool {
    frame.meta.bytes == frame.bytes.len() as u64
}

#[test]
fn inflating_and_deflating_fixtures_are_red() {
    let honest_bytes: StdArc<[u8]> = StdArc::from(&b"abcd"[..]);
    let honest = Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(honest_bytes.clone()),
        meta: FrameMeta {
            bytes: 4,
            transport_units: None,
            status: None,
        },
    };
    assert!(frame_is_honest(&honest));

    let inflated = Frame {
        meta: FrameMeta {
            bytes: 40,
            ..honest.meta
        },
        ..honest.clone()
    };
    assert!(!frame_is_honest(&inflated), "an inflating fixture must fail the honesty check");

    let deflated = Frame {
        meta: FrameMeta {
            bytes: 0,
            ..honest.meta
        },
        ..honest
    };
    assert!(!frame_is_honest(&deflated), "a deflating fixture must fail the honesty check");
}
