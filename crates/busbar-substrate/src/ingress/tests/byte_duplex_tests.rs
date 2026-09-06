// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/ingress/byte_duplex.rs`.

use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// A trivial ECHO plane: no protocol, no wire vocabulary. It echoes an ordinary frame back
/// verbatim, and — to exercise the correlation table — a frame beginning `call` triggers an
/// outbound call whose answer it then re-emits. `classify` recognises a reply solely by the
/// leading marker `reply:<n> `, parsing the bare `CallRef` number the transport minted.
struct EchoPlane;

#[async_trait::async_trait]
impl DuplexPlane for EchoPlane {
    fn classify(&self, frame: &[u8]) -> Option<CallRef> {
        let rest = frame.strip_prefix(b"reply:")?;
        let end = rest.iter().position(|&b| b == b' ')?;
        let n: u64 = std::str::from_utf8(&rest[..end]).ok()?.parse().ok()?;
        Some(CallRef(n))
    }

    async fn handle(self: Arc<Self>, frame: Vec<u8>, out: DuplexHandle) {
        if frame == b"call" {
            let call = out.mint();
            let outbound = format!("call {}", call.0).into_bytes();
            if let Some(reply) = out.issue(call, outbound).await {
                let mut got = b"got ".to_vec();
                got.extend_from_slice(&reply);
                out.emit(got).await.expect("write the answer frame");
            }
        } else {
            // Pure echo. The write is EXPECTED to land: this plane's whole contract in these tests
            // is that what goes in comes back, so a swallowed write error would silently turn a
            // broken transport into a test that merely reads nothing.
            out.emit(frame).await.expect("echo the frame");
        }
    }
}

/// Drive the pump over an in-memory duplex: frames written to the far end come back echoed,
/// both a mid-stream frame and a final unterminated one, and EOF ends the loop.
#[tokio::test]
async fn echo_round_trips_frames_and_stops_on_eof() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"hello\n").await.unwrap();
    far_w.write_all(b"  \n").await.unwrap(); // a blank line is not a frame
    far_w.write_all(b"world\n").await.unwrap();

    let mut line = String::new();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "hello\n");
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "world\n", "the blank line produced no frame");

    // A final UNTERMINATED line is still one frame; closing the writer is EOF.
    far_w.write_all(b"tail").await.unwrap();
    far_w.shutdown().await.unwrap();
    drop(far_w);
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "tail\n");

    // EOF on the reader ends the pump.
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on EOF")
        .unwrap();
}

/// Drive the correlation table: a `call` frame makes the pump ISSUE an outbound call, the far
/// end answers with a `reply:<n> ...` frame, `classify` maps it to the minted `CallRef`, the
/// transport routes it back to the waiting `issue`, and the answer is re-emitted.
#[tokio::test]
async fn correlation_routes_a_reply_to_its_issuer() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"call\n").await.unwrap();

    // The pump issues its outbound call, naming the CallRef it minted.
    let mut asked = String::new();
    far_r.read_line(&mut asked).await.unwrap();
    assert_eq!(asked, "call 1\n", "the transport minted CallRef 1 first");

    // Answer it, tagged with the same ref so classify can pair it.
    far_w.write_all(b"reply:1 pong\n").await.unwrap();

    // The routed answer is re-emitted by the handler.
    let mut got = String::new();
    far_r.read_line(&mut got).await.unwrap();
    assert_eq!(got, "got reply:1 pong\n");

    far_w.shutdown().await.unwrap();
    drop(far_w);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on EOF")
        .unwrap();
}

/// `CallRef::NONE` is reserved and never minted; the mint is monotonic from 1.
#[tokio::test]
async fn mint_is_monotonic_and_never_none() {
    let (_near, far) = tokio::io::duplex(64);
    let (_r, w) = tokio::io::split(far);
    let shared = new_shared(Box::new(NewlineSink { writer: w }));
    let handle = DuplexHandle { shared };
    let a = handle.mint();
    let b = handle.mint();
    assert_eq!(a, CallRef(1));
    assert_eq!(b, CallRef(2));
    assert!(!a.is_none() && !b.is_none());
    assert!(CallRef::NONE.is_none());
}

/// A PEER THAT NEVER TERMINATES A FRAME must not be able to spend this node's memory. One frame is
/// one line, so a stream with no `0x0A` in it is a single frame that grows for as long as the peer
/// keeps writing — the read has to stop somewhere, and the session ends where it stops. Every other
/// read on the inbound path is capped; this one is the byte pipe's own.
#[tokio::test]
async fn an_unterminated_frame_past_the_cap_ends_the_session() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    // Well past the cap, with no terminator anywhere and NO close — the peer is simply still typing.
    let (_far_r, mut far_w) = tokio::io::split(far);
    let flood = tokio::spawn(async move {
        let chunk = vec![b'x'; 64 * 1024];
        let mut written = 0usize;
        while written <= MAX_FRAME_BYTES + chunk.len() {
            if far_w.write_all(&chunk).await.is_err() {
                break;
            }
            written += chunk.len();
        }
        std::future::pending::<()>().await;
    });

    tokio::time::timeout(std::time::Duration::from_secs(20), pump)
        .await
        .expect("the session ends on an unterminated frame instead of buffering it forever")
        .unwrap();
    flood.abort();
}

/// A plane whose handlers all PARK: each one records its arrival and then never finishes, so the
/// number that got in is exactly the number of handler tasks the transport allowed to exist at once.
struct ParkingPlane {
    entered: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl DuplexPlane for ParkingPlane {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, _frame: Vec<u8>, _out: DuplexHandle) {
        self.entered.fetch_add(1, Ordering::Relaxed);
        std::future::pending::<()>().await;
    }
}

/// ONE SESSION'S HANDLERS ARE CAPPED. A peer that floods frames faster than they are handled must not
/// be able to mint an unbounded number of handler tasks: past the cap the reader PARKS, which is what
/// puts the flood back on the peer's own transport instead of on this node's memory. Well past the cap
/// here, so a missing gate shows up as every frame in flight at once.
#[tokio::test]
async fn one_session_holds_no_more_handlers_than_its_cap() {
    use futures::channel::mpsc;

    let entered = Arc::new(AtomicU64::new(0));
    let plane = Arc::new(ParkingPlane {
        entered: entered.clone(),
    });

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, _out_rx) = mpsc::unbounded::<Vec<u8>>();
    let over = MAX_INFLIGHT_HANDLERS + 32;
    for _ in 0..over {
        in_tx.send(b"park".to_vec()).await.unwrap();
    }
    let _pump = tokio::spawn(serve_messages(in_rx, out_tx, plane));

    // Let every handler the transport is willing to admit get in and park.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        if entered.load(Ordering::Relaxed) as usize >= MAX_INFLIGHT_HANDLERS {
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert_eq!(
        entered.load(Ordering::Relaxed) as usize,
        MAX_INFLIGHT_HANDLERS,
        "the session admitted exactly its cap and parked the reader on the rest"
    );
}

/// A plane whose handler finishes the instant it is polled — the ordinary shape of a frame answered
/// from memory, and the one that races the dispatcher's own bookkeeping.
struct InstantPlane;

#[async_trait::async_trait]
impl DuplexPlane for InstantPlane {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, _frame: Vec<u8>, _out: DuplexHandle) {}
}

/// The in-flight registry must be EMPTY once the handlers are done, however fast they were. The
/// dispatcher runs on the reader's thread while the handler runs on the runtime's, so a handler that
/// finishes first clears a key the dispatcher has not written yet — and the dispatcher then writes it
/// anyway. Nothing ever removes such an entry: it blocks the whole EOF drain and grows for the life
/// of the session. Dispatched here from a thread OUTSIDE the runtime driving the handlers, which is
/// exactly the arrangement that produces the overlap.
#[test]
fn a_finished_handler_leaves_the_inflight_registry_empty() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a current-thread runtime for the handlers");
    let handlers = rt.handle().clone();
    // Driven on its OWN thread, so the handlers make progress concurrently with the dispatch below.
    let driver = std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));

    let (_near, far) = tokio::io::duplex(64);
    let (_r, w) = tokio::io::split(far);
    let shared = new_shared(Box::new(NewlineSink { writer: w }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };
    let plane = Arc::new(InstantPlane);

    let _in_runtime = handlers.enter();
    for _ in 0..20_000 {
        // Driven right here, on the dispatching thread: the only await is the handler permit, and the
        // handlers themselves run on the runtime entered above.
        futures::executor::block_on(dispatch_frame(&shared, &handle, &plane, b"frame".to_vec()));
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !shared.inflight.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let stranded = shared.inflight.lock().unwrap().len();
    drop(_in_runtime);
    drop(driver);
    assert_eq!(
        stranded, 0,
        "every finished handler cleared its own in-flight slot"
    );
}

/// An `issue` that is ABANDONED — cancelled at its await, as any caller wrapping it in a
/// `tokio::time::timeout` does — must leave the correlation table exactly as it found it. Its
/// registration goes in before the frame is written, so nothing but the dropped future itself can
/// take it back out, and a channel that outlives many abandoned calls would otherwise carry one dead
/// entry per call for the life of the session.
#[tokio::test]
async fn an_abandoned_issue_leaves_no_registration_behind() {
    let (_near, far) = tokio::io::duplex(64);
    let (_r, w) = tokio::io::split(far);
    let shared = new_shared(Box::new(NewlineSink { writer: w }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };

    let call = handle.mint();
    let abandoned = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        handle.issue(call, b"never answered".to_vec()),
    )
    .await;
    assert!(
        abandoned.is_err(),
        "no answer arrives, so the call times out"
    );
    assert!(
        shared.pending.lock().unwrap().is_empty(),
        "the abandoned call took its registration with it"
    );
}

/// A writer that REFUSES every write — a closed pipe, in one struct. The flush succeeds, so a test
/// using it proves the failure is carried from the write itself and not merely from the drain.
struct BrokenWriter;

impl AsyncWrite for BrokenWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "the far end is gone",
        )))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// A frame that did NOT reach the wire is REPORTED, not swallowed. The transport has no business
/// deciding what a lost line costs — that is the caller's to know — but it must say that one was
/// lost. Before this, a broken pipe and a successful write were indistinguishable to every caller.
#[tokio::test]
async fn a_write_that_fails_is_reported_to_the_caller() {
    let shared = new_shared(Box::new(NewlineSink {
        writer: BrokenWriter,
    }));
    let handle = DuplexHandle { shared };
    let err = handle
        .emit(b"a line nobody will ever read".to_vec())
        .await
        .expect_err("a refused write must not report success");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

/// The FIRST caller policy: a call whose frame never left cannot be answered, so `issue` fails
/// immediately instead of waiting out a deadline for a reply that is not coming — and it withdraws
/// its registration on the way out, so the correlation table does not leak an entry per lost call.
#[tokio::test]
async fn a_call_whose_frame_is_lost_fails_at_once() {
    let shared = new_shared(Box::new(NewlineSink {
        writer: BrokenWriter,
    }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };
    let call = handle.mint();
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        handle.issue(call, b"a call nobody will ever see".to_vec()),
    )
    .await
    .expect("issue must not wait on an answer that can never arrive");
    assert!(answer.is_none(), "the call failed");
    assert!(
        shared.pending.lock().unwrap().is_empty(),
        "the withdrawn call left no entry behind in the correlation table"
    );
}

/// Drive the pump over an in-memory MESSAGE duplex (each channel item is one frame, no newline
/// convention — the shape an already-upgraded WebSocket presents): frames sent to the near end come
/// back echoed verbatim as whole messages, and the stream ending (close) ends the loop. Mirrors
/// `echo_round_trips_frames_and_stops_on_eof` on the byte path.
#[tokio::test]
async fn message_duplex_round_trips_frames_and_stops_on_close() {
    use futures::channel::mpsc;

    // inbound: what the peer sends the pump; outbound: what the pump emits back.
    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    // A whole message is one frame — no terminator on the wire, unlike the byte path.
    in_tx.send(b"hello".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"hello");

    in_tx.send(b"world".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"world");

    // Closing the inbound stream (dropping the sender) is the message-duplex analogue of EOF.
    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}

/// Drive the correlation table over the MESSAGE duplex: a `call` frame makes the pump ISSUE an
/// outbound call as one message, the peer answers with a `reply:<n> ...` message, `classify` maps
/// it to the minted `CallRef`, the transport routes it back to the waiting `issue`, and the answer
/// is re-emitted — the identical machinery `serve` uses, reached through a different framing.
#[tokio::test]
async fn message_duplex_correlation_routes_a_reply_to_its_issuer() {
    use futures::channel::mpsc;

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    in_tx.send(b"call".to_vec()).await.unwrap();

    // The pump issues its outbound call as one whole message, naming the CallRef it minted.
    assert_eq!(out_rx.next().await.unwrap(), b"call 1");

    // Answer it, tagged with the same ref so classify can pair it.
    in_tx.send(b"reply:1 pong".to_vec()).await.unwrap();

    // The routed answer is re-emitted by the handler.
    assert_eq!(out_rx.next().await.unwrap(), b"got reply:1 pong");

    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}
