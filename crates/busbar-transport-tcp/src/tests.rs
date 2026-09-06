//! The transport battery, for `tcp`: byte-exact round trip, half-close, cancel mid-frame, every
//! `TransportError` mapped, backpressure, and the frame-meta honesty check (an inflating and a
//! deflating fixture must fail it — the "must turn red" cell from the design's transport battery).

use super::*;
use busbar_contract::{ConfigView, Frame};
use busbar_contract_transport::wire::FrameMeta;
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
impl busbar_contract::plugin::KernelSeal for FixtureSeal {
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
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
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

    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
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
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
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
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
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
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
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
async fn close_ends_a_live_frame_stream() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    let mut frames = server.frames(server_conn.clone());
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"first"))
        .await
        .unwrap();
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"first");

    // The kernel finalises the connection. A stream still pumping it must end, and the socket
    // must drop: bytes the peer writes afterwards are never yielded.
    server.close(server_conn, CloseReason::Normal);
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"after close"))
        .await
        .unwrap();
    assert!(
        frames.next().await.is_none(),
        "a closed connection's frame stream must end, not keep yielding inbound frames"
    );
}

/// The close above is seen because a byte arrives after it and the pump wakes to re-check the flag.
/// A pump parked on a silent peer never wakes at all: the flag is set, the registry entry is gone,
/// and the read stays outstanding for as long as the peer stays quiet — which is forever, for a
/// peer that opened a connection and walked away. The socket stays open with it. So the close is a
/// wakeup, not just a flag, and the parked read answers to it.
#[tokio::test]
async fn close_ends_a_read_parked_on_a_silent_peer() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let mut raw = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let server_conn = accept_fut.await.unwrap();
    let _ = client;

    let mut frames = server.frames(server_conn.clone());
    // Park the pump: nothing has been written, so the read is outstanding with no byte to end it.
    let parked = tokio::spawn(async move { frames.next().await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    server.close(server_conn, CloseReason::Normal);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(3), parked)
        .await
        .expect("a closed connection's parked read answers the close, it does not wait for a byte")
        .unwrap();
    assert!(
        ended.is_none(),
        "the stream ends at the close rather than yielding a frame"
    );

    // The last clone of the state is gone with the stream, so the socket really did close.
    let mut sink = [0_u8; 8];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut raw, &mut sink),
    )
    .await
    .expect("the peer sees the close rather than waiting on a socket nothing holds")
    .unwrap();
    assert_eq!(n, 0, "the peer reads end-of-stream");
}

/// A detach that cannot hand the stream up must leave the connection where it found it.
///
/// The removal used to happen first and the unwrap second, so a detach racing a live frame reader
/// returned `None` having ALREADY dropped the registry entry: no stream for the caller, and no
/// connection left for anyone else either — one write away from `Closed` on a socket that was
/// perfectly healthy. `None` has to mean "not yours to take".
#[tokio::test]
async fn a_detach_that_cannot_take_the_stream_leaves_the_connection_alone() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    // A live reader holds its own clone of the state, so the stream is not the detacher's to take.
    let mut frames = server.frames(server_conn.clone());
    assert!(
        server.detach(&server_conn).is_none(),
        "a detach racing a live reader hands nothing up"
    );

    // And the connection is still this transport's: the write goes out and the reader sees it.
    server
        .write(&server_conn, StreamId(0), ArenaBytes::new(b"still here"))
        .await
        .expect("the connection the detach refused to take is still usable");
    let mut client_frames = client.frames(client_conn);
    let (_s, frame) = client_frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"still here");
    drop(frames.next());
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

/// One synthetic `io::Error` per `map_io_err` arm, so swapping two arms is caught here rather than
/// only by whichever live-dial cell happens to provoke that kind. Ported from `busbar-transport-
/// http`'s table cell, which this transport's mapping matches arm for arm; the `tls` sibling's cell
/// carries one arm more, for the handshake this transport does not have.
#[test]
fn every_io_error_kind_maps_through_the_table() {
    for (kind, expected) in [
        (io::ErrorKind::ConnectionRefused, TransportError::Refused),
        (io::ErrorKind::TimedOut, TransportError::Timeout),
        (io::ErrorKind::ConnectionReset, TransportError::Reset),
        (io::ErrorKind::ConnectionAborted, TransportError::Reset),
        (
            io::ErrorKind::AddrNotAvailable,
            TransportError::AddressRefused,
        ),
        (io::ErrorKind::InvalidInput, TransportError::AddressRefused),
        (io::ErrorKind::BrokenPipe, TransportError::Closed),
        (io::ErrorKind::NotFound, TransportError::Closed),
    ] {
        let mapped = TcpTransport::map_io_err(&io::Error::new(kind, "fixture"));
        assert_eq!(
            mapped, expected,
            "io::ErrorKind::{kind:?} maps to {expected:?}"
        );
    }
}

#[tokio::test]
async fn backpressure_bounds_the_per_unit_frame_buffer() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
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

/// Frame meta is honest on frames a REAL `TcpTransport` emitted, and the check that says so is one
/// an inflating or a deflating fixture turns red.
///
/// The old cell built `Frame` literals in the test body, set `meta.bytes` from the same slice it
/// then compared against, and never constructed a transport at all: a tautology that would have
/// shipped green over any count this transport actually reported. The metering path reads
/// `FrameMeta.bytes` as the bytes meter class, so a dishonest one is a billing figure, not a
/// cosmetic slip. This asserts against frames off the wire and proves the predicate discriminates
/// by perturbing them one byte each way.
///
/// `meta.bytes == bytes.len()` is only ever the meter's INTERNAL consistency, though — both come
/// off the same read. The figure the meter owes is the bytes that crossed the wire, so the total is
/// checked against the payloads the fixture wrote, counted here rather than read back off the
/// frames under test.
#[tokio::test]
async fn frame_meta_honesty_catches_inflating_and_deflating_fixtures() {
    fn honest(frame: &Frame) -> bool {
        frame.meta.bytes == frame.bytes.len() as u64
    }
    fn perturbed(frame: &Frame, by: i64) -> Frame {
        Frame {
            meta: FrameMeta {
                bytes: (frame.meta.bytes as i64 + by) as u64,
                ..frame.meta
            },
            ..frame.clone()
        }
    }

    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    // Two payloads, one of them longer than a single read chunk, so the frames under test include
    // ones the transport carved out of a partly filled buffer rather than one write's worth each.
    let payloads: [Vec<u8>; 2] = [
        vec![b'L'; READ_CHUNK_BYTES + 1024],
        b"and a short one".to_vec(),
    ];
    let on_the_wire: u64 = payloads.iter().map(|p| p.len() as u64).sum();
    for payload in &payloads {
        client
            .write(&client_conn, StreamId(0), ArenaBytes::new(payload))
            .await
            .unwrap();
    }

    let mut frames = server.frames(server_conn);
    let mut metered = 0_u64;
    let mut carried = 0_u64;
    while metered < on_the_wire {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        metered += frame.meta.bytes;
        carried += frame.bytes.len() as u64;
        assert!(
            honest(&frame),
            "the transport's own frame reports the bytes it actually carries"
        );
        assert!(
            !honest(&perturbed(&frame, 1)),
            "an inflating fixture is red"
        );
        assert!(
            !honest(&perturbed(&frame, -1)),
            "a deflating fixture is red"
        );
    }

    // Counted from the fixture, not from the frames: every byte the peer wrote is metered exactly
    // once, so a transport that double-counted a reused buffer's tail is caught here even though
    // each frame on its own stayed internally consistent.
    assert_eq!(
        metered, on_the_wire,
        "the meter totals the bytes the peer actually wrote"
    );
    assert_eq!(carried, on_the_wire, "and carries exactly those bytes");
}

/// A writer that accepts every byte and then fails to flush: the exact shape a Unit 0 refusal must
/// not be able to report as delivered. `write_all` succeeds, so only the flush leg can catch it.
struct FlushFailsWriter {
    written: Vec<u8>,
}

impl tokio::io::AsyncWrite for FlushFailsWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.written.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "the peer went away before the refusal reached it",
        )))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn an_undelivered_unit0_refusal_is_an_error() {
    let mut w = FlushFailsWriter {
        written: Vec::new(),
    };
    let err = deliver_refusal(&mut w, b"refused")
        .await
        .expect_err("a refusal whose flush failed was never delivered and must not report Ok");
    assert_eq!(err, TransportError::Reset);
    assert_eq!(w.written.as_slice(), b"refused");
}

/// A refusal that never reached the wire still finalises the connection.
///
/// The error is the caller's to see, but it is not a reason to leave the connection registered: the
/// bytes are gone either way, and a refusal that returned early would leave the entry behind with a
/// pump parked on the socket — the leak the delivered-refusal cell above rules out, reappearing on
/// exactly the path where the peer is already gone. Closing runs on every path out, and the delivery
/// result is reported after it.
#[tokio::test]
async fn a_refusal_that_never_reached_the_wire_still_finalises_the_connection() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();
    let id = server_conn.id();

    // A pump that is live before the refusal, holding its own clone of the state.
    let mut frames = server.frames(server_conn.clone());
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"first"))
        .await
        .unwrap();
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"first");

    // Make the write leg fail for certain: with this side's write half already shut down, the
    // kernel refuses the refusal's bytes locally rather than putting them on the wire. This is the
    // "the peer never sees it" case without a timing race.
    let captured = server.inner(id).expect("the connection is registered");
    {
        let mut guard = captured.write.lock().await;
        tokio::io::AsyncWriteExt::shutdown(&mut *guard).await.ok();
    }

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let err = server
        .unit0_refusal(server_conn, None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .expect_err("a refusal that never left this host is not a delivered refusal");
    assert!(
        matches!(err, TransportError::Closed | TransportError::Reset),
        "the write failure is reported through the same table every other I/O path uses: {err:?}"
    );

    assert!(
        server.inner(id).is_none(),
        "an undelivered refusal still ends the connection: the registry entry must be gone"
    );
    assert!(
        captured.closed.load(Ordering::Acquire),
        "an undelivered refusal still sets the flag a live pump reads, or the pump keeps the socket"
    );

    // The pump ends, which is what the flag exists for.
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"after refusal"))
        .await
        .unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("a refused connection's frame stream must end rather than park on the socket");
    assert!(next.is_none(), "the pump ends on a failed refusal too");
}

/// The read buffer is per-connection and reused across polls, so the byte-exactness cell has a new
/// way to fail: a short frame following a long one must not carry the tail of its predecessor, and
/// the buffer a connection reads through must be the same allocation each time rather than a fresh
/// `READ_CHUNK_BYTES` one per read syscall.
#[tokio::test]
async fn one_read_buffer_per_connection_reused_without_leaking_bytes_between_frames() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    let mut frames = server.frames(server_conn.clone());
    let long = vec![b'L'; 4096];
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(&long))
        .await
        .unwrap();
    let mut got = Vec::new();
    while got.len() < long.len() {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        got.extend_from_slice(frame.bytes.as_slice());
    }
    assert_eq!(got, long);
    let first_buffer = server.scratch_addr(server_conn.id()).await.unwrap();

    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"short"))
        .await
        .unwrap();
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(
        frame.bytes.as_slice(),
        b"short",
        "no residue from the longer frame before it"
    );
    assert_eq!(frame.meta.bytes, 5, "honest frame meta on a reused buffer");
    assert_eq!(
        server.scratch_addr(server_conn.id()).await.unwrap(),
        first_buffer,
        "one buffer per connection, not one per read"
    );
}

/// A refusal finalises the connection, so it must end a frame stream the same way `close` does.
///
/// The registry entry alone is not the connection: a pump started before the refusal holds its own
/// clone of the state, and if the refusal only drops the registry's clone that pump stays parked on
/// the socket forever — one leaked socket per refused connection. The closed flag is what ends it,
/// after which the last clone goes and the peer sees the socket really shut.
#[tokio::test]
async fn a_unit0_refusal_ends_a_live_frame_stream_and_drops_the_socket() {
    let (server, listener, client) = bound_pair().await;
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let server = server.clone();
        async move { server.accept(&listener).await.unwrap() }
    });
    let client_conn = client
        .dial(&upstream_dest(&addr), &fixture_key())
        .await
        .unwrap();
    let server_conn = accept_fut.await.unwrap();

    // A pump that is live before the refusal: it already holds the connection state.
    let mut frames = server.frames(server_conn.clone());
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"first"))
        .await
        .unwrap();
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"first");

    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    server
        .unit0_refusal(server_conn, None, &refusal, ArenaBytes::new(b"refused"))
        .await
        .unwrap();

    // The peer keeps writing, as a peer that has not yet read the refusal will.
    client
        .write(&client_conn, StreamId(0), ArenaBytes::new(b"after refusal"))
        .await
        .unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("a refused connection's frame stream must end rather than park on the socket");
    assert!(
        next.is_none(),
        "a refused connection's frame stream must end, not keep yielding inbound frames"
    );

    // The pump was the last holder: with it finished the socket is really gone, which the peer
    // sees as end-of-stream rather than as a connection still open.
    drop(frames);
    let mut client_frames = client.frames(client_conn);
    let refused = client_frames.next().await.unwrap().unwrap();
    assert_eq!(refused.1.bytes.as_slice(), b"refused");
    let eof = tokio::time::timeout(std::time::Duration::from_secs(5), client_frames.next())
        .await
        .expect("the refused socket must be released, which the peer reads as end-of-stream");
    // Either shape says the socket is gone: a clean end of stream, or the reset the kernel sends
    // when a socket is closed with bytes still unread — and this peer deliberately wrote "after
    // refusal" into a connection that was never going to read it. What must NOT happen is a frame:
    // that would mean the refused connection was still being served.
    assert!(
        eof.is_none() || eof.is_some_and(|next| next.is_err()),
        "the refused connection's socket must close"
    );
}
