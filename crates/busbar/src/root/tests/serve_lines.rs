use super::*;
use crate::root::linked::LinkedTransport;

fn row(
    key: crate::root::linked::KeyOf,
    claims: fn() -> Vec<&'static str>,
    lines: fn() -> Vec<&'static str>,
) -> LinkedTransport {
    LinkedTransport {
        key,
        composes_over: || &[],
        build: |_| unreachable!("the carrier is read off the rows, never off a built wire"),
        claims,
        upgrades: Vec::new,
        lines,
        offered: crate::root::doors::offers_unstated,
    }
}

#[test]
fn the_line_carrier_is_the_claim_a_row_declares_opening_on_its_first_line() {
    let rows = [
        row(
            || "framed-wire",
            || vec!["framed-wire", "framed-too"],
            Vec::new,
        ),
        row(|| "pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
    ];
    assert_eq!(line_carrier(&rows), Ok(Some("pipe-wire")));
    assert_eq!(line_carrier(&rows[..1]), Ok(None));
    assert_eq!(line_carrier(&[]), Ok(None));
}

#[test]
fn two_claims_opening_on_their_first_line_are_refused() {
    let rows = [
        row(|| "pipe-wire", || vec!["pipe-wire"], || vec!["pipe-wire"]),
        row(
            || "other-pipe",
            || vec!["other-pipe"],
            || vec!["other-pipe"],
        ),
    ];
    let refusal = line_carrier(&rows).expect_err("two line carriers are ambiguous");
    assert!(refusal.contains("`pipe-wire`"), "{refusal}");
    assert!(refusal.contains("`other-pipe`"), "{refusal}");
}

#[test]
fn the_builds_carrier_is_read_off_its_linked_rows() {
    assert_eq!(refusal(), None, "the build states one line carrier at most");
    assert_eq!(
        carrier(),
        line_carrier(crate::LINKED.transports).expect("one line carrier")
    );
    assert!(carrier().is_some(), "this build links a line carrier");
}

#[test]
fn the_credential_variable_is_spelled_from_the_plane_and_the_carrier() {
    assert_eq!(
        env_credential("tool-door", "pipe"),
        "BUSBAR_TOOL-DOOR_PIPE_CREDENTIAL"
    );
    assert_eq!(env_credential("x", "y"), "BUSBAR_X_Y_CREDENTIAL");
}

#[tokio::test]
async fn a_line_past_the_bound_is_dropped_with_its_tail() {
    let input: &[u8] = b"aaaaaaaaaaaabb\nok\n";
    let mut reader = tokio::io::BufReader::with_capacity(4, input);
    let mut over = Vec::new();
    let read = read_line(&mut reader, &mut over, 8)
        .await
        .expect("the over-long line reads");
    assert_eq!(read, 15, "the whole over-long line is consumed");
    assert!(
        trim(&over).is_empty(),
        "nothing of the over-long line is kept: {:?}",
        String::from_utf8_lossy(&over)
    );
    let mut next = Vec::new();
    read_line(&mut reader, &mut next, 8)
        .await
        .expect("the next line reads");
    assert_eq!(trim(&next), b"ok", "the session goes on at the next line");
}

#[tokio::test]
async fn a_full_payload_has_the_same_bound_with_lf_crlf_or_eof() {
    for input in [&b"abcd\n"[..], &b"abcd\r\n"[..], &b"abcd"[..]] {
        for capacity in 1..=input.len() {
            let mut reader = tokio::io::BufReader::with_capacity(capacity, input);
            let mut bytes = Vec::new();
            assert_eq!(
                read_line(&mut reader, &mut bytes, 4).await.unwrap(),
                input.len()
            );
            assert_eq!(
                trim(&bytes),
                b"abcd",
                "capacity={capacity}, input={input:?}"
            );
        }
    }
    for input in [&b"abcde\nnext\n"[..], &b"abcde\r\nnext\n"[..]] {
        let mut reader = tokio::io::BufReader::with_capacity(1, input);
        let mut bytes = Vec::new();
        read_line(&mut reader, &mut bytes, 4).await.unwrap();
        assert!(bytes.is_empty());
        read_line(&mut reader, &mut bytes, 4).await.unwrap();
        assert_eq!(trim(&bytes), b"next");
    }
}

fn caller_over<R: AsyncRead + Unpin + Send>(reader: R) -> LineCaller<R> {
    LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line: 1024,
        out: mpsc::unbounded_channel().0,
        failure: Arc::new(IoFailure::default()),
    }
}

#[tokio::test]
async fn the_shutdown_signal_ends_the_read_with_no_line() {
    let (_held, reader) = tokio::io::duplex(64);
    let caller = caller_over(reader);
    let stop = std::pin::pin!(std::future::ready(()));
    assert_eq!(next_line(&caller, stop).await, None);
}

#[tokio::test]
async fn with_no_signal_the_next_line_is_read() {
    let caller = caller_over(&b"one\n"[..]);
    let stop = std::pin::pin!(std::future::pending::<()>());
    assert_eq!(next_line(&caller, stop).await, Some(b"one".to_vec()));
}

#[tokio::test(start_paused = true)]
async fn a_unit_in_flight_when_the_serve_stops_finishes_and_answers() {
    let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut units = tokio::task::JoinSet::new();
    let flag = Arc::clone(&answered);
    units.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let deadline = tokio::time::Instant::now() + busbar_kernel::detached::DETACHED_DRAIN_GRACE;
    let ended = drain_units(&mut units, deadline).await;
    assert_eq!(ended, 0, "no unit is ended inside the grace");
    assert!(answered.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_unit_still_running_past_the_drain_grace_is_ended() {
    let mut units = tokio::task::JoinSet::new();
    units.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    });
    let deadline = tokio::time::Instant::now() + busbar_kernel::detached::DETACHED_DRAIN_GRACE;
    let ended = drain_units(&mut units, deadline).await;
    assert_eq!(ended, 1, "the unit past the grace is ended");
    assert!(units.is_empty());
}

const TEST_CARRIER: &str = "test-line-carrier";
const QUEUED_LINE: &[u8] = b"queued";
const OUTPUT_ERROR: &str = "test output failure";

async fn shutdown_result(serve: impl std::future::Future<Output = i32>) -> i32 {
    tokio::time::timeout(busbar_kernel::detached::DETACHED_DRAIN_GRACE * 2, serve)
        .await
        .expect("the line serve must return after its shutdown grace")
}

#[derive(Clone, Copy)]
enum IoOutcome {
    Ready,
    Pending,
    Error,
    Panic,
}

#[derive(Default)]
struct OutputProbe {
    bytes: std::sync::Mutex<Vec<u8>>,
    write_polled: std::sync::atomic::AtomicBool,
    dropped: std::sync::atomic::AtomicBool,
}

struct ProbeWriter {
    probe: Arc<OutputProbe>,
    write: IoOutcome,
    flush: IoOutcome,
    delay: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl ProbeWriter {
    fn new(probe: &Arc<OutputProbe>, write: IoOutcome, flush: IoOutcome) -> Self {
        Self {
            probe: Arc::clone(probe),
            write,
            flush,
            delay: None,
        }
    }
}

impl Drop for ProbeWriter {
    fn drop(&mut self) {
        self.probe
            .dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl AsyncWrite for ProbeWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future as _;
        use std::task::Poll;
        self.probe
            .write_polled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(delay) = self.delay.as_mut() {
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        match self.write {
            IoOutcome::Ready => {
                let count = bytes.len().min(1);
                self.probe
                    .bytes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..count]);
                Poll::Ready(Ok(count))
            }
            IoOutcome::Pending => Poll::Pending,
            IoOutcome::Error => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                OUTPUT_ERROR,
            ))),
            IoOutcome::Panic => panic!("{OUTPUT_ERROR}"),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match self.flush {
            IoOutcome::Ready => Poll::Ready(Ok(())),
            IoOutcome::Pending => Poll::Pending,
            IoOutcome::Error => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                OUTPUT_ERROR,
            ))),
            IoOutcome::Panic => panic!("{OUTPUT_ERROR}"),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn eof_and_stop_retire_a_writer_stuck_in_write_or_flush() {
    for at_eof in [true, false] {
        for (write, flush) in [
            (IoOutcome::Pending, IoOutcome::Ready),
            (IoOutcome::Ready, IoOutcome::Pending),
        ] {
            let probe = Arc::new(OutputProbe::default());
            let writer = ProbeWriter::new(&probe, write, flush);
            let (held, reader) = tokio::io::duplex(1);
            let mut held = Some(held);
            if at_eof {
                drop(held.take());
            }
            let stop = async move {
                if at_eof {
                    std::future::pending::<()>().await;
                }
            };
            let mut closed = false;
            let close_flag = &mut closed;
            let mut failure = None;
            let observed_failure = &mut failure;
            let started = tokio::time::Instant::now();
            let code = shutdown_result(run_io(TEST_CARRIER, reader, writer, stop, move |caller| {
                *observed_failure = Some(Arc::clone(&caller.failure));
                caller.out.send(terminated(QUEUED_LINE)).unwrap();
                (
                    |_| std::future::ready(()),
                    move || {
                        *close_flag = true;
                    },
                )
            }))
            .await;
            assert_ne!(code, 0);
            assert_eq!(
                started.elapsed(),
                busbar_kernel::detached::DETACHED_DRAIN_GRACE
            );
            assert!(closed, "the carrier is closed before returning to the root");
            assert!(probe.write_polled.load(std::sync::atomic::Ordering::SeqCst));
            assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
            let failure = failure.unwrap();
            let recorded = failure.0.lock().unwrap();
            let (direction, error) = recorded.as_ref().unwrap();
            assert_eq!(*direction, "output");
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn queued_lines_and_a_units_answer_drain_whole_and_in_order() {
    let probe = Arc::new(OutputProbe::default());
    let mut writer = ProbeWriter::new(&probe, IoOutcome::Ready, IoOutcome::Ready);
    let delay = busbar_kernel::detached::DETACHED_DRAIN_GRACE / 2;
    writer.delay = Some(Box::pin(tokio::time::sleep(delay)));
    let started = tokio::time::Instant::now();
    let code = shutdown_result(run_io(
        TEST_CARRIER,
        &b"answer\n"[..],
        writer,
        std::future::pending::<()>(),
        |caller| {
            caller.out.send(terminated(b"first")).unwrap();
            caller.out.send(terminated(b"second\n")).unwrap();
            (
                move |line: Vec<u8>| {
                    let caller = Arc::clone(&caller);
                    async move {
                        assert!(caller.write(&line).await);
                    }
                },
                || {},
            )
        },
    ))
    .await;
    assert_eq!(code, 0);
    assert_eq!(started.elapsed(), delay);
    assert_eq!(*probe.bytes.lock().unwrap(), b"first\nsecond\nanswer\n");
    assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn units_and_output_share_one_shutdown_deadline() {
    let probe = Arc::new(OutputProbe::default());
    let writer = ProbeWriter::new(&probe, IoOutcome::Pending, IoOutcome::Ready);
    let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&answered);
    let started = tokio::time::Instant::now();
    let code = shutdown_result(run_io(
        TEST_CARRIER,
        &b"answer\n"[..],
        writer,
        std::future::pending::<()>(),
        |caller| {
            (
                move |line: Vec<u8>| {
                    let caller = Arc::clone(&caller);
                    let flag = Arc::clone(&flag);
                    async move {
                        tokio::time::sleep(busbar_kernel::detached::DETACHED_DRAIN_GRACE / 2).await;
                        assert!(caller.write(&line).await);
                        flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                },
                || {},
            )
        },
    ))
    .await;
    assert_ne!(code, 0);
    assert_eq!(
        started.elapsed(),
        busbar_kernel::detached::DETACHED_DRAIN_GRACE
    );
    assert!(answered.load(std::sync::atomic::Ordering::SeqCst));
    assert!(probe.write_polled.load(std::sync::atomic::Ordering::SeqCst));
    assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn writer_errors_and_panics_end_the_serve_without_repolling_a_finished_join() {
    for at_eof in [true, false] {
        for (write, flush, expected) in [
            (
                IoOutcome::Error,
                IoOutcome::Ready,
                std::io::ErrorKind::BrokenPipe,
            ),
            (
                IoOutcome::Panic,
                IoOutcome::Ready,
                std::io::ErrorKind::Other,
            ),
            (
                IoOutcome::Ready,
                IoOutcome::Error,
                std::io::ErrorKind::BrokenPipe,
            ),
            (
                IoOutcome::Ready,
                IoOutcome::Panic,
                std::io::ErrorKind::Other,
            ),
        ] {
            let probe = Arc::new(OutputProbe::default());
            let writer = ProbeWriter::new(&probe, write, flush);
            let (held, reader) = tokio::io::duplex(1);
            let mut held = Some(held);
            if at_eof {
                drop(held.take());
            }
            let mut failure = None;
            let started = tokio::time::Instant::now();
            let code = shutdown_result(run_io(
                TEST_CARRIER,
                reader,
                writer,
                std::future::pending::<()>(),
                |caller| {
                    failure = Some(Arc::clone(&caller.failure));
                    caller.out.send(terminated(QUEUED_LINE)).unwrap();
                    (|_| std::future::ready(()), || {})
                },
            ))
            .await;
            assert_ne!(code, 0);
            assert_eq!(started.elapsed(), std::time::Duration::ZERO);
            let failure = failure.unwrap();
            let recorded = failure.0.lock().unwrap();
            let (direction, error) = recorded.as_ref().unwrap();
            assert_eq!(*direction, "output");
            assert_eq!(error.kind(), expected);
            assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
        }
    }
}

struct FailedReader;

impl AsyncRead for FailedReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::PermissionDenied.into()))
    }
}

#[tokio::test(start_paused = true)]
async fn an_existing_input_error_survives_the_output_drain_timeout() {
    let probe = Arc::new(OutputProbe::default());
    let writer = ProbeWriter::new(&probe, IoOutcome::Pending, IoOutcome::Ready);
    let mut failure = None;
    let code = shutdown_result(run_io(
        TEST_CARRIER,
        FailedReader,
        writer,
        std::future::pending::<()>(),
        |caller| {
            failure = Some(Arc::clone(&caller.failure));
            caller.out.send(terminated(QUEUED_LINE)).unwrap();
            (|_| std::future::ready(()), || {})
        },
    ))
    .await;
    assert_ne!(code, 0);
    let failure = failure.unwrap();
    let recorded = failure.0.lock().unwrap();
    let (direction, error) = recorded.as_ref().unwrap();
    assert_eq!(*direction, "input");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
}
