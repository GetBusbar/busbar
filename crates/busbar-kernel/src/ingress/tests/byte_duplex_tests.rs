// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

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
            out.emit(frame).await.expect("echo the frame");
        }
    }
}

#[tokio::test]
async fn echo_round_trips_frames_and_stops_on_eof() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"hello\n").await.unwrap();
    far_w.write_all(b"  \n").await.unwrap();
    far_w.write_all(b"world\n").await.unwrap();

    let mut line = String::new();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "hello\n");
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "world\n", "the blank line produced no frame");

    far_w.write_all(b"tail").await.unwrap();
    far_w.shutdown().await.unwrap();
    drop(far_w);
    line.clear();
    far_r.read_line(&mut line).await.unwrap();
    assert_eq!(line, "tail\n");

    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on EOF")
        .unwrap();
}

#[tokio::test]
async fn correlation_routes_a_reply_to_its_issuer() {
    let (near, far) = tokio::io::duplex(4096);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

    let (far_r, mut far_w) = tokio::io::split(far);
    let mut far_r = tokio::io::BufReader::new(far_r);

    far_w.write_all(b"call\n").await.unwrap();

    let mut asked = String::new();
    far_r.read_line(&mut asked).await.unwrap();
    assert_eq!(asked, "call 1\n", "the transport minted CallRef 1 first");

    far_w.write_all(b"reply:1 pong\n").await.unwrap();

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

#[tokio::test]
async fn an_unterminated_frame_past_the_cap_ends_the_session() {
    let (near, far) = tokio::io::duplex(64 * 1024);
    let (near_r, near_w) = tokio::io::split(near);
    let pump = tokio::spawn(serve(near_r, near_w, Arc::new(EchoPlane)));

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

struct InstantPlane;

#[async_trait::async_trait]
impl DuplexPlane for InstantPlane {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, _frame: Vec<u8>, _out: DuplexHandle) {}
}

#[test]
fn a_finished_handler_leaves_the_inflight_registry_empty() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a current-thread runtime for the handlers");
    let handlers = rt.handle().clone();

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
        let permit = futures::executor::block_on(shared.handlers.clone().acquire_owned())
            .expect("a handler permit");
        shared
            .queued
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        spawn_handler(&shared, &handle, &plane, b"frame".to_vec(), permit);
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

struct PanickingPlane;

#[async_trait::async_trait]
impl DuplexPlane for PanickingPlane {
    fn classify(&self, _frame: &[u8]) -> Option<CallRef> {
        None
    }
    async fn handle(self: Arc<Self>, _frame: Vec<u8>, _out: DuplexHandle) {
        panic!("a plane callback panicked (deliberate, for the in-flight release test)");
    }
}

#[tokio::test]
async fn a_panicking_handler_releases_its_inflight_slot() {
    let (_near, far) = tokio::io::duplex(64);
    let (_r, w) = tokio::io::split(far);
    let shared = new_shared(Box::new(NewlineSink { writer: w }));
    let handle = DuplexHandle {
        shared: shared.clone(),
    };
    let plane = Arc::new(PanickingPlane);

    let permit = shared
        .handlers
        .clone()
        .acquire_owned()
        .await
        .expect("a handler permit");
    shared
        .queued
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    spawn_handler(&shared, &handle, &plane, b"frame".to_vec(), permit);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while !shared.inflight.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        shared.inflight.lock().unwrap().is_empty(),
        "a handler that panicked must still release its in-flight slot"
    );
    assert_eq!(
        shared.handlers.available_permits(),
        MAX_INFLIGHT_HANDLERS,
        "the panicking handler's permit is returned too"
    );
}

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

#[tokio::test]
async fn message_duplex_round_trips_frames_and_stops_on_close() {
    use futures::channel::mpsc;

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    in_tx.send(b"hello".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"hello");

    in_tx.send(b"world".to_vec()).await.unwrap();
    assert_eq!(out_rx.next().await.unwrap(), b"world");

    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}

#[tokio::test]
async fn message_duplex_correlation_routes_a_reply_to_its_issuer() {
    use futures::channel::mpsc;

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, Arc::new(EchoPlane)));

    in_tx.send(b"call".to_vec()).await.unwrap();

    assert_eq!(out_rx.next().await.unwrap(), b"call 1");

    in_tx.send(b"reply:1 pong".to_vec()).await.unwrap();

    assert_eq!(out_rx.next().await.unwrap(), b"got reply:1 pong");

    drop(in_tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("pump did not stop on stream close")
        .unwrap();
}

struct CallingPlane {
    finished: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl DuplexPlane for CallingPlane {
    fn classify(&self, frame: &[u8]) -> Option<CallRef> {
        let rest = frame.strip_prefix(b"reply:")?;
        let n: u64 = std::str::from_utf8(rest).ok()?.parse().ok()?;
        Some(CallRef(n))
    }
    async fn handle(self: Arc<Self>, _frame: Vec<u8>, out: DuplexHandle) {
        let call = out.mint();
        if out
            .issue(call, format!("call {}", call.0).into_bytes())
            .await
            .is_some()
        {
            self.finished.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[tokio::test]
async fn a_non_reply_frame_ahead_of_the_answers_does_not_wedge_the_session() {
    use futures::channel::mpsc;

    let finished = Arc::new(AtomicU64::new(0));
    let plane = Arc::new(CallingPlane {
        finished: finished.clone(),
    });

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded::<Vec<u8>>();

    for _ in 0..MAX_INFLIGHT_HANDLERS {
        in_tx.send(b"work".to_vec()).await.unwrap();
    }

    in_tx.send(b"work".to_vec()).await.unwrap();

    let _pump = tokio::spawn(serve_messages(in_rx, out_tx, plane));

    let mut refs = Vec::new();
    for _ in 0..MAX_INFLIGHT_HANDLERS {
        let issued = tokio::time::timeout(std::time::Duration::from_secs(10), out_rx.next())
            .await
            .expect("every admitted handler issued its call")
            .expect("the outbound sink stayed open");
        let n: u64 = std::str::from_utf8(&issued[b"call ".len()..])
            .unwrap()
            .parse()
            .unwrap();
        refs.push(n);
    }

    for n in refs {
        in_tx.send(format!("reply:{n}").into_bytes()).await.unwrap();
    }

    for _ in 0..200 {
        if finished.load(Ordering::Relaxed) as usize >= MAX_INFLIGHT_HANDLERS {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert_eq!(
        finished.load(Ordering::Relaxed) as usize,
        MAX_INFLIGHT_HANDLERS,
        "every parked handler was reached by its answer even with a permit-hungry frame in front of it"
    );
}

#[tokio::test]
async fn a_peer_past_both_bounds_ends_the_session_rather_than_buffering() {
    use futures::channel::mpsc;

    let entered = Arc::new(AtomicU64::new(0));
    let plane = Arc::new(ParkingPlane {
        entered: entered.clone(),
    });

    let (mut in_tx, in_rx) = mpsc::unbounded::<Vec<u8>>();
    let (out_tx, _out_rx) = mpsc::unbounded::<Vec<u8>>();

    for _ in 0..(QUEUE_DEPTH + 64) {
        in_tx.send(b"park".to_vec()).await.unwrap();
    }
    let pump = tokio::spawn(serve_messages(in_rx, out_tx, plane));

    tokio::time::timeout(std::time::Duration::from_secs(20), pump)
        .await
        .expect("the session ended on its own rather than buffering the flood")
        .unwrap();

    assert_eq!(
        entered.load(Ordering::Relaxed) as usize,
        MAX_INFLIGHT_HANDLERS,
        "no more handlers than the cap ever existed"
    );
    drop(in_tx);
}
