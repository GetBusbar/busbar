// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::linked::LinkedTransport;

fn request() -> RequestLease {
    ProcessAdmission::new(0)
        .try_enter(AdmissionClass::Data)
        .unwrap()
}

fn owned_input() -> OwnedInput {
    request().adopt_input(Vec::new()).unwrap()
}

fn row(_claims: fn() -> Vec<&'static str>, lines: fn() -> Vec<&'static str>) -> LinkedTransport {
    LinkedTransport {
        upgrades: Vec::new,
        lines,
    }
}

#[test]
fn the_line_carrier_is_the_claim_a_row_declares_opening_on_its_first_line() {
    let rows = [
        row(|| vec!["framed-wire", "framed-too"], Vec::new),
        row(|| vec!["pipe-wire"], || vec!["pipe-wire"]),
    ];
    assert_eq!(line_carrier(&rows), Ok(Some("pipe-wire")));
    assert_eq!(line_carrier(&rows[..1]), Ok(None));
    assert_eq!(line_carrier(&[]), Ok(None));
}

#[test]
fn two_claims_opening_on_their_first_line_are_refused() {
    let rows = [
        row(|| vec!["pipe-wire"], || vec!["pipe-wire"]),
        row(|| vec!["other-pipe"], || vec!["other-pipe"]),
    ];
    let refusal = line_carrier(&rows).expect_err("two line carriers are ambiguous");
    assert!(refusal.contains("`pipe-wire`"), "{refusal}");
    assert!(refusal.contains("`other-pipe`"), "{refusal}");
}

#[test]
fn the_builds_carrier_is_read_off_its_linked_rows() {
    // The `refusal()` accessor went with the legacy chooser (368dfb336a); it read this same value.
    assert_eq!(
        line_carrier(crate::LINKED.transports).err(),
        None,
        "the build states one line carrier at most"
    );
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
        "BUSBAR_TOOL_DOOR_PIPE_CREDENTIAL"
    );
    assert_eq!(env_credential("x", "y"), "BUSBAR_X_Y_CREDENTIAL");
    // B-N11: an identity-named instance still spells a name a shell can export.
    assert_eq!(
        env_credential("busbar-plane-mcp.v2", "stdio"),
        "BUSBAR_BUSBAR_PLANE_MCP_V2_STDIO_CREDENTIAL"
    );
}

#[tokio::test]
async fn a_line_past_the_bound_is_dropped_with_its_tail() {
    let input: &[u8] = b"aaaaaaaaaaaabb\nok\n";
    let mut reader = tokio::io::BufReader::with_capacity(4, input);
    let mut over = owned_input();
    let read = read_line(&mut reader, &mut over, 8)
        .await
        .expect("the over-long line reads");
    assert_eq!(read, 15, "the whole over-long line is consumed");
    assert!(
        trim(over.as_ref()).is_empty(),
        "nothing of the over-long line is kept: {:?}",
        String::from_utf8_lossy(over.as_ref())
    );
    let mut next = owned_input();
    read_line(&mut reader, &mut next, 8)
        .await
        .expect("the next line reads");
    assert_eq!(
        trim(next.as_ref()),
        b"ok",
        "the session goes on at the next line"
    );
}

#[tokio::test]
async fn a_full_payload_has_the_same_bound_with_lf_crlf_or_eof() {
    for input in [&b"abcd\n"[..], &b"abcd\r\n"[..], &b"abcd"[..]] {
        for capacity in 1..=input.len() {
            let mut reader = tokio::io::BufReader::with_capacity(capacity, input);
            let mut bytes = owned_input();
            assert_eq!(
                read_line(&mut reader, &mut bytes, 4).await.unwrap(),
                input.len()
            );
            assert_eq!(
                trim(bytes.as_ref()),
                b"abcd",
                "capacity={capacity}, input={input:?}"
            );
        }
    }
    for input in [&b"abcde\nnext\n"[..], &b"abcde\r\nnext\n"[..]] {
        let mut reader = tokio::io::BufReader::with_capacity(1, input);
        let mut bytes = owned_input();
        read_line(&mut reader, &mut bytes, 4).await.unwrap();
        assert!(bytes.is_empty());
        read_line(&mut reader, &mut bytes, 4).await.unwrap();
        assert_eq!(trim(bytes.as_ref()), b"next");
    }
}

fn caller_over<R: AsyncRead + Unpin + Send>(reader: R) -> LineCaller<R> {
    LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line: 1024,
        out: mpsc::channel(LINE_OUTPUT_QUEUE_CAPACITY).0,
        spare: Arc::default(),
        failure: Arc::new(IoFailure::default()),
    }
}

#[tokio::test]
async fn the_shutdown_signal_ends_the_read_with_no_line() {
    let (_held, reader) = tokio::io::duplex(64);
    let caller = caller_over(reader);
    let stop = std::pin::pin!(std::future::ready(()));
    assert!(next_line(&caller, request(), stop).await.is_none());
}

#[tokio::test]
async fn with_no_signal_the_next_line_is_read() {
    let caller = caller_over(&b"one\n"[..]);
    let stop = std::pin::pin!(std::future::pending::<()>());
    assert_eq!(
        next_line(&caller, request(), stop).await.unwrap().as_ref(),
        b"one"
    );
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
            let code = shutdown_result(run_io(
                TEST_CARRIER,
                reader,
                writer,
                ProcessAdmission::new(0),
                stop,
                move |caller| {
                    *observed_failure = Some(Arc::clone(&caller.failure));
                    caller.out.try_send(terminated(QUEUED_LINE)).unwrap();
                    (
                        |_| std::future::ready(()),
                        move || {
                            *close_flag = true;
                        },
                    )
                },
            ))
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
        ProcessAdmission::new(0),
        std::future::pending::<()>(),
        |caller| {
            caller.out.try_send(terminated(b"first")).unwrap();
            caller.out.try_send(terminated(b"second\n")).unwrap();
            (
                move |line: OwnedInput| {
                    let caller = Arc::clone(&caller);
                    async move {
                        assert!(caller.write(line.as_ref()).await);
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
        ProcessAdmission::new(0),
        std::future::pending::<()>(),
        |caller| {
            (
                move |line: OwnedInput| {
                    let caller = Arc::clone(&caller);
                    let flag = Arc::clone(&flag);
                    async move {
                        tokio::time::sleep(busbar_kernel::detached::DETACHED_DRAIN_GRACE / 2).await;
                        assert!(caller.write(line.as_ref()).await);
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
                ProcessAdmission::new(0),
                std::future::pending::<()>(),
                |caller| {
                    failure = Some(Arc::clone(&caller.failure));
                    caller.out.try_send(terminated(QUEUED_LINE)).unwrap();
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
        ProcessAdmission::new(0),
        std::future::pending::<()>(),
        |caller| {
            failure = Some(Arc::clone(&caller.failure));
            caller.out.try_send(terminated(QUEUED_LINE)).unwrap();
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

/// IF §12.23 rule 1: the line carrier binds the one ROUTE_LINE route across the served plane instances; none = no
/// line serving, two or more = refused at start naming both configured instance names.
#[test]
fn the_one_line_plane_is_bound_and_two_are_refused_naming_both() {
    assert_eq!(one_line_plane(&[]), Ok(None));
    assert_eq!(
        one_line_plane(&[("llm", false), ("mcp", true)]),
        Ok(Some(1))
    );
    assert_eq!(one_line_plane(&[("llm", false)]), Ok(None));
    let refusal = one_line_plane(&[("mcp", true), ("llm", false), ("mcp-2", true)])
        .expect_err("two line planes are ambiguous");
    assert!(refusal.contains("`mcp`"), "{refusal}");
    assert!(refusal.contains("`mcp-2`"), "{refusal}");
    assert!(refusal.contains("first line"), "{refusal}");
}

#[tokio::test(start_paused = true)]
async fn a_blocked_output_backpressures_answer_futures() {
    let probe = Arc::new(OutputProbe::default());
    let writer = ProbeWriter::new(&probe, IoOutcome::Pending, IoOutcome::Ready);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (completed, mut completions) = mpsc::channel(32);
    let input = b"x\n".repeat(32);
    let service = tokio::spawn(async move {
        run_io(
            TEST_CARRIER,
            std::io::Cursor::new(input),
            writer,
            ProcessAdmission::new(0),
            async {
                let _ = stopped.await;
            },
            |caller| {
                (
                    move |line: OwnedInput| {
                        let caller = Arc::clone(&caller);
                        let completed = completed.clone();
                        async move {
                            if caller.write(line.as_ref()).await {
                                let _ = completed.send(()).await;
                            }
                        }
                    },
                    || {},
                )
            },
        )
        .await
    });
    // One line can sit in the writer and sixteen in the bounded queue. The next
    // answer must remain pending while stdout cannot make progress.
    let overflow = tokio::time::timeout(std::time::Duration::from_millis(1), async {
        for _ in 0..18 {
            completions.recv().await.expect("answer completion");
        }
    })
    .await;
    let _ = stop.send(());
    let code = service.await.unwrap();
    assert_ne!(code, 0, "the blocked writer cannot report a clean drain");
    assert!(
        overflow.is_err(),
        "an unbounded output queue lets every answer complete"
    );
}

#[tokio::test]
async fn synchronous_output_overflow_is_observable_and_wakes_the_reader() {
    let mut caller = caller_over(&b""[..]);
    let (out, _held_receiver) = mpsc::channel(1);
    caller.out = out;
    assert!(caller.emit(b"first"));
    assert!(!caller.emit(b"second"));
    // Failure is recorded before waiting, so this proves the notification persists.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        caller.failure.1.notified(),
    )
    .await
    .unwrap();
    let failure = caller.failure.0.lock().unwrap();
    assert_eq!(
        failure.as_ref().unwrap().1.kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test(start_paused = true)]
async fn inbound_capacity_blocks_the_next_line_until_a_unit_finishes() {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (started, mut starts) = mpsc::channel(3);
    let permits = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::clone(&permits);
    let probe = Arc::new(OutputProbe::default());
    let writer = ProbeWriter::new(&probe, IoOutcome::Ready, IoOutcome::Ready);
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            &b"one\ntwo\nthree\n"[..],
            writer,
            async {
                let _ = stopped.await;
            },
            move |_| {
                (
                    move |line: OwnedInput| {
                        let started = started.clone();
                        let permits = Arc::clone(&permits);
                        async move {
                            started.send(line.as_ref().to_vec()).await.unwrap();
                            permits.acquire().await.unwrap().forget();
                        }
                    },
                    || {},
                )
            },
            1024,
            ProcessAdmission::new(3),
        )
        .await
    });
    assert_eq!(starts.recv().await.unwrap(), b"one");
    assert_eq!(starts.recv().await.unwrap(), b"two");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(1), starts.recv())
            .await
            .is_err()
    );
    release.add_permits(1);
    assert_eq!(starts.recv().await.unwrap(), b"three");
    release.add_permits(2);
    let _ = stop.send(());
    assert_eq!(service.await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn stop_wakes_an_input_loop_waiting_for_capacity() {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (started, mut starts) = mpsc::channel(1);
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let close_flag = Arc::clone(&closed);
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            &b"one\ntwo\n"[..],
            tokio::io::sink(),
            async {
                let _ = stopped.await;
            },
            move |_| {
                (
                    move |_| {
                        let started = started.clone();
                        async move {
                            started.send(()).await.unwrap();
                            std::future::pending::<()>().await;
                        }
                    },
                    move || {
                        close_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    },
                )
            },
            1024,
            ProcessAdmission::new(2),
        )
        .await
    });
    starts.recv().await.unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(busbar_kernel::detached::DETACHED_DRAIN_GRACE * 2, service)
        .await
        .expect("stop must not wait for an inbound permit")
        .unwrap();
    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn callback_overflow_ends_the_line_session_with_failure() {
    let code = run_io_with_limits(
        TEST_CARRIER,
        &b""[..],
        tokio::io::sink(),
        std::future::pending::<()>(),
        |caller| {
            for _ in 0..LINE_OUTPUT_QUEUE_CAPACITY {
                assert!(caller.emit(b"notification"));
            }
            assert!(!caller.emit(b"overflow"));
            (|_| std::future::ready(()), || {})
        },
        1024,
        ProcessAdmission::new(2),
    )
    .await;
    assert_ne!(code, 0);
}

#[tokio::test]
async fn closing_output_wakes_an_async_sender_blocked_on_capacity() {
    let mut caller = caller_over(&b""[..]);
    let (out, receiver) = mpsc::channel(1);
    caller.out = out;
    assert!(caller.write(b"first").await);
    let pending = caller.write(b"second");
    tokio::pin!(pending);
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
            pending.as_mut(),
            cx
        )))
        .await
        .is_pending()
    );
    drop(receiver);
    assert!(!pending.await);
}

#[tokio::test]
async fn an_explicit_zero_inbound_limit_keeps_concurrency_unlimited() {
    let (started, mut starts) = mpsc::channel(2);
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let permits = Arc::clone(&release);
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            &b"one\ntwo\n"[..],
            tokio::io::sink(),
            std::future::pending::<()>(),
            move |_| {
                (
                    move |_| {
                        let started = started.clone();
                        let permits = Arc::clone(&permits);
                        async move {
                            started.send(()).await.unwrap();
                            permits.acquire().await.unwrap().forget();
                        }
                    },
                    || {},
                )
            },
            1024,
            ProcessAdmission::new(0),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        starts.recv().await.unwrap();
        starts.recv().await.unwrap();
    })
    .await
    .expect("both units start before either finishes");
    release.add_permits(2);
    assert_eq!(service.await.unwrap(), 0);
}

#[tokio::test]
async fn network_retirement_wakes_stdio_without_a_local_unit_completion() {
    let budget = ProcessAdmission::new(2);
    let network = budget.try_enter(AdmissionClass::Data).unwrap();
    let operator = budget.try_enter(AdmissionClass::Operator).unwrap();
    let service_budget = Arc::clone(&budget);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (started, mut starts) = mpsc::channel(1);
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            &b"one\n"[..],
            tokio::io::sink(),
            async {
                let _ = stopped.await;
            },
            move |_| {
                (
                    move |line| {
                        let started = started.clone();
                        async move {
                            started.send(line).await.unwrap();
                        }
                    },
                    || {},
                )
            },
            1024,
            service_budget,
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), starts.recv())
            .await
            .is_err()
    );
    drop(network);
    let line = tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.as_ref(), b"one");
    stop.send(()).unwrap();
    assert_eq!(service.await.unwrap(), 0);
    assert!(
        budget.try_enter(AdmissionClass::Data).is_err(),
        "retained input outlives the answer task"
    );
    drop(line);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
    drop(operator);
}

#[tokio::test]
async fn cancelling_a_partial_actual_line_returns_its_payload_credit() {
    let budget = ProcessAdmission::new(2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let (mut input, reader) = tokio::io::duplex(32);
    let caller = caller_over(reader);
    let mut read = Box::pin(caller.read_input(request.clone()));
    input.write_all(b"abc").await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut read)
            .await
            .is_err()
    );
    let remaining = request.try_reserve(224 * 1024 * 1024 - 3).unwrap();
    assert!(
        request.try_reserve(1).is_err(),
        "partial payload is already charged"
    );
    drop(read);
    let returned = request
        .try_reserve(3)
        .expect("cancellation retires the actual partial buffer");
    drop(returned);
    drop(remaining);
}

#[tokio::test]
async fn stopping_stdio_waiting_on_network_capacity_has_no_local_task_dependency() {
    let budget = ProcessAdmission::new(2);
    let network = budget.try_enter(AdmissionClass::Data).unwrap();
    let service_budget = Arc::clone(&budget);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            &b"unread\n"[..],
            tokio::io::sink(),
            async {
                let _ = stopped.await;
            },
            |_| {
                (
                    |_| async {
                        panic!("capacity does not admit a line");
                    },
                    || {},
                )
            },
            1024,
            service_budget,
        )
        .await
    });
    tokio::task::yield_now().await;
    stop.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), service)
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(network);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn one_slot_stdio_refuses_data_without_an_immortal_waiter() {
    let budget = ProcessAdmission::new(1);
    let code = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        run_io_with_limits(
            TEST_CARRIER,
            &b"unread\n"[..],
            tokio::io::sink(),
            std::future::pending::<()>(),
            |_| {
                (
                    |_| async {
                        panic!("one-slot capacity belongs to the operator");
                    },
                    || {},
                )
            },
            1024,
            Arc::clone(&budget),
        ),
    )
    .await
    .unwrap();
    assert_ne!(code, 0);
    assert!(budget.try_enter(AdmissionClass::Operator).is_ok());
}

#[tokio::test]
async fn a_unit_completion_does_not_discard_an_actual_partial_line() {
    let budget = ProcessAdmission::new(3);
    let (mut input, reader) = tokio::io::duplex(64);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (started, mut starts) = mpsc::channel(2);
    let release = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::clone(&release);
    let service = tokio::spawn(async move {
        run_io_with_limits(
            TEST_CARRIER,
            reader,
            tokio::io::sink(),
            async {
                let _ = stopped.await;
            },
            move |_| {
                (
                    move |line: OwnedInput| {
                        let started = started.clone();
                        let release_first = Arc::clone(&release_first);
                        async move {
                            let first = line.as_ref() == b"first";
                            started.send(line.as_ref().to_vec()).await.unwrap();
                            if first {
                                release_first.notified().await;
                            }
                        }
                    },
                    || {},
                )
            },
            1024,
            budget,
        )
        .await
    });
    input.write_all(b"first\npart").await.unwrap();
    assert_eq!(starts.recv().await.unwrap(), b"first");
    // Ensure the second read is pending with a nonempty buffer before the first unit ends.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), starts.recv())
            .await
            .is_err()
    );
    release.notify_one();
    tokio::task::yield_now().await;
    input.write_all(b"ial\n").await.unwrap();
    assert_eq!(starts.recv().await.unwrap(), b"partial");
    stop.send(()).unwrap();
    assert_eq!(service.await.unwrap(), 0);
}

#[tokio::test]
async fn output_failure_cancels_a_global_waiter_without_local_units() {
    let budget = ProcessAdmission::new(2);
    let network = budget.try_enter(AdmissionClass::Data).unwrap();
    let probe = Arc::new(OutputProbe::default());
    let writer = ProbeWriter::new(&probe, IoOutcome::Error, IoOutcome::Ready);
    let code = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        run_io_with_limits(
            TEST_CARRIER,
            &b"unread\n"[..],
            writer,
            std::future::pending::<()>(),
            |caller| {
                caller.out.try_send(terminated(QUEUED_LINE)).unwrap();
                (
                    |_| async {
                        panic!("a network-owned slot does not admit stdio");
                    },
                    || {},
                )
            },
            1024,
            Arc::clone(&budget),
        ),
    )
    .await
    .unwrap();
    assert_ne!(code, 0);
    assert!(probe.dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(network);
    assert!(
        budget.try_enter(AdmissionClass::Data).is_ok(),
        "the cancelled waiter retained no permit"
    );
}
