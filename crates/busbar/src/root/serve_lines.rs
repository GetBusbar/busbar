// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel::channels::frame::{stays_one_message, Framing};
use busbar_kernel::limits::process_admission::{
    AdmissionClass, OwnedInput, ProcessAdmission, RequestLease,
};
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

pub(crate) use crate::root::off_path::serve_lines::env_credential;
#[cfg(test)]
use crate::root::off_path::serve_lines::one_line_plane;
pub(crate) use crate::root::off_path::serve_lines::serve_lines;
pub(crate) use crate::root::off_path::serve_lines::session;

/// The label a MIN-3 line session is bound and logged under: the process's own stdin/stdout (IF §12.23).
pub(crate) const PORT_LINE_CARRIER: &str = "stdio";

pub(crate) struct LineCaller<R> {
    lines: AsyncMutex<tokio::io::BufReader<R>>,
    max_line: usize,
    out: mpsc::Sender<Vec<u8>>,
    failure: Arc<IoFailure>,
}

/// Complete output lines awaiting the writer; individual body sizing is separate.
const LINE_OUTPUT_QUEUE_CAPACITY: usize = 16;

/// `bytes`, already judged [`one_line`], as one newline-terminated output line: allocated here at its final
/// size, moved to the writer, and freed by the writer once it is written.
fn output_line(bytes: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(bytes.len() + 1);
    line.extend_from_slice(bytes);
    terminate(&mut line);
    line
}

#[derive(Default)]
struct IoFailure(
    std::sync::Mutex<Option<(&'static str, std::io::Error)>>,
    tokio::sync::Notify,
);

impl IoFailure {
    fn record(&self, direction: &'static str, error: std::io::Error) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert((direction, error));
        // A permit persists even when the input loop has not started waiting yet.
        self.1.notify_one();
    }

    fn report(&self) -> bool {
        let failure = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((direction, error)) = failure.as_ref() {
            eprintln!("busbar: line {direction} failed: {error}");
            true
        } else {
            false
        }
    }
}

impl<R: AsyncRead + Unpin + Send> CallerEnd for LineCaller<R> {
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, bytes: &[u8]) -> bool {
        one_line(bytes) && self.out.send(output_line(bytes)).await.is_ok()
    }
}

impl<R> LineCaller<R> {
    /// A refused line (not one line) is not written and does not end the session.
    fn emit(&self, bytes: &[u8]) -> bool {
        if !one_line(bytes) {
            return false;
        }
        match self.out.try_send(output_line(bytes)) {
            Ok(()) => true,
            Err(error) => {
                let kind = match error {
                    mpsc::error::TrySendError::Full(_) => std::io::ErrorKind::WouldBlock,
                    mpsc::error::TrySendError::Closed(_) => std::io::ErrorKind::BrokenPipe,
                };
                self.failure.record(
                    "output",
                    std::io::Error::new(kind, "line output queue unavailable"),
                );
                false
            }
        }
    }
}

/// Whether a plane's `bytes` go out as one line of standard output: one trailing `\n` is the line's own end; any
/// other `\n`, or any `\r` (a universal-newline reader ends a line on a lone `\r`), would make the caller read more
/// than one line. A refused line is counted and logged.
fn one_line(bytes: &[u8]) -> bool {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if stays_one_message(Framing::Ndjson, body) {
        return true;
    }
    metrics::counter!(busbar_kernel::snapshot::LINE_BREAK_REFUSED_TOTAL).increment(1);
    tracing::warn!(
        len = bytes.len(),
        "an output line holding a line break was refused"
    );
    false
}

/// Ends a line already judged [`one_line`] with its one `\n`.
fn terminate(line: &mut Vec<u8>) {
    if !line.ends_with(b"\n") {
        line.push(b'\n');
    }
}

impl<R: AsyncRead + Unpin + Send> SessionCaller for LineCaller<R> {
    /// The line loop admits and owns each read explicitly; a bare read cannot bypass admission.
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }
}

impl<R: AsyncRead + Unpin + Send> LineCaller<R> {
    async fn read_input(&self, request: RequestLease) -> Option<OwnedInput> {
        let mut reader = self.lines.lock().await;
        // The line's own buffer: it grows as the line is read and moves to the plane with the line.
        // A blank line reuses it for the next read.
        let mut buf = request.adopt_input(Vec::new()).ok()?;
        loop {
            buf.clear();
            match read_line(&mut *reader, &mut buf, self.max_line).await {
                Ok(0) => return None,
                Err(error) => {
                    self.failure.record("input", error);
                    return None;
                }
                Ok(_) => {}
            }
            let line = trim(buf.as_ref()).len();
            if line != 0 {
                buf.truncate(line);
                return Some(buf);
            }
        }
    }
}

/// IF §12.23 over the plane port: the one `ROUTE_LINE` plane's lines go to `PortSeat::answer_line` with the
/// carrier id in `PlaneReq.carrier`; on EOF, a write failure or shutdown core stops reading, ends the in-flight
/// lines, closes the writer, and then calls `admin(ADMIN_CARRIER_END)` once.
pub(crate) async fn serve_port_lines<R, W, S>(
    seat: busbar_kernel::plane_driver::port::PortSeat,
    app: Arc<busbar_kernel::state::AppHandle>,
    reader: R,
    writer: W,
    admission: Arc<ProcessAdmission>,
    stop: S,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
{
    let instance = seat.instance.as_str();
    // The session's credential, moved at once into its wiping holder and on into the admission,
    // which wipes it when the session is admitted or refused.
    let credential = std::env::var(env_credential(instance, PORT_LINE_CARRIER))
        .ok()
        .filter(|c| !c.is_empty())
        .map(busbar_contract::secure::SecureString::from);
    let gov = match session(
        app.load(),
        instance,
        PORT_LINE_CARRIER,
        seat.audience.as_deref(),
        credential,
    )
    .await
    {
        Ok(gov) => gov,
        Err(sentence) => {
            refuse(instance, PORT_LINE_CARRIER, &sentence);
            return 1;
        }
    };
    tracing::info!(
        governed = gov.is_governed(),
        "{PORT_LINE_CARRIER} serve: session bound; serving on stdin/stdout"
    );
    let driver = Arc::clone(&seat.driver);
    let opened: Arc<std::sync::OnceLock<std::num::NonZeroU64>> = Arc::default();
    let opened_here = Arc::clone(&opened);
    let open_driver = Arc::clone(&driver);
    let answer_seat = seat.clone();
    let code = run_io(
        PORT_LINE_CARRIER,
        reader,
        writer,
        admission,
        stop,
        move |caller| {
            let principal = crate::root::off_path::serve_lines::session_principal(&gov);
            let line_caller = busbar_kernel::plane_driver::port::LineCaller {
                principal: Arc::from(principal.as_str()),
                authenticated: gov.key().is_some(),
            };
            let sink = Arc::clone(&caller);
            // The carrier session shares the line caller's one principal name.
            let carrier = open_driver.open_carrier(
                &line_caller.principal,
                Arc::new(move |bytes: &[u8]| sink.emit(bytes)),
            );
            let _ = opened_here.set(carrier);
            let requests = std::sync::atomic::AtomicU64::new(1);
            let answer = move |line: OwnedInput| {
                let request_id = requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let seat = answer_seat.clone();
                let caller = Arc::clone(&caller);
                let line_caller = line_caller.clone();
                async move {
                    match seat
                        .answer_line(carrier, request_id, line.into_session_input(), &line_caller)
                        .await
                    {
                        Ok(mut body) if !body.is_empty() => {
                            if one_line(&body) {
                                terminate(&mut body);
                                let _ = caller.out.send(body).await;
                            }
                        }
                        Ok(_) => {}
                        Err(refused) => {
                            tracing::warn!(?refused, "a line got no answer from its plane")
                        }
                    }
                }
            };
            (answer, move || open_driver.close_carrier(carrier))
        },
    )
    .await;
    if let Some(carrier) = opened.get() {
        driver.carrier_ended(*carrier).await;
    }
    code
}

async fn run_io<R, W, S, Open, Answer, Unit, Close>(
    carrier: &str,
    reader: R,
    writer: W,
    admission: Arc<ProcessAdmission>,
    stop: S,
    open: Open,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
    Open: FnOnce(Arc<LineCaller<R>>) -> (Answer, Close),
    Answer: Fn(OwnedInput) -> Unit,
    Unit: std::future::Future<Output = ()> + Send + 'static,
    Close: FnOnce(),
{
    let limits = busbar_kernel::config::limits::installed();
    let max_line = limits.as_ref().map_or_else(
        busbar_kernel::config::limits::default_request_body_max_bytes,
        |l| l.request_body_max_bytes,
    );
    run_io_with_limits(carrier, reader, writer, stop, open, max_line, admission).await
}

async fn run_io_with_limits<R, W, S, Open, Answer, Unit, Close>(
    carrier: &str,
    reader: R,
    writer: W,
    stop: S,
    open: Open,
    max_line: usize,
    admission: Arc<ProcessAdmission>,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
    Open: FnOnce(Arc<LineCaller<R>>) -> (Answer, Close),
    Answer: Fn(OwnedInput) -> Unit,
    Unit: std::future::Future<Output = ()> + Send + 'static,
    Close: FnOnce(),
{
    let (out, mut lines_out) = mpsc::channel::<Vec<u8>>(LINE_OUTPUT_QUEUE_CAPACITY);
    let failure = Arc::new(IoFailure::default());
    let write_failure = Arc::clone(&failure);
    let mut written = tokio::spawn(async move {
        let mut writer = writer;
        // Each line is freed here, once it has been written.
        while let Some(line) = lines_out.recv().await {
            if let Err(error) = async {
                writer.write_all(&line).await?;
                writer.flush().await
            }
            .await
            {
                write_failure.record("output", error);
                return;
            }
        }
        if let Err(error) = writer.flush().await {
            write_failure.record("output", error);
        }
    });
    let caller = Arc::new(LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line,
        out,
        failure: Arc::clone(&failure),
    });
    let (answer, close) = open(Arc::clone(&caller));
    let mut units = tokio::task::JoinSet::new();
    let mut stop = std::pin::pin!(stop);
    let mut writer_ended = false;
    loop {
        // Reap only between reads: cancelling caller.read() on a unit completion
        // would discard a partially read line.
        while units.try_join_next().is_some() {}
        let request = tokio::select! {
            biased;
            () = &mut stop => break,
            () = failure.1.notified() => break,
            result = &mut written => {
                writer_ended = true;
                if let Err(error) = result {
                    failure.record("output", std::io::Error::other(error));
                }
                break;
            }
            request = admission.enter(AdmissionClass::Data) => match request {
                Ok(request) => request,
                Err(_) => {
                    failure.record("input", std::io::Error::new(std::io::ErrorKind::WouldBlock, "the gateway is at input capacity"));
                    break;
                }
            },
        };
        let line = tokio::select! {
            biased;
            () = failure.1.notified() => break,
            result = &mut written => {
                writer_ended = true;
                if let Err(error) = result {
                    failure.record("output", std::io::Error::other(error));
                }
                break;
            }
            line = next_line(&*caller, request, stop.as_mut()) => line,
        };
        let Some(line) = line else { break };
        let request = line.request().clone();
        let answer = answer(line);
        units.spawn(async move {
            let _request = request;
            answer.await;
        });

        while units.try_join_next().is_some() {}
    }

    let deadline = crate::root::off_path::serve_lines::drain_deadline();
    let ended = if writer_ended {
        let ended = units.len();
        units.abort_all();
        while units.join_next().await.is_some() {}
        ended
    } else {
        drain_units(&mut units, deadline).await
    };
    if ended > 0 {
        tracing::warn!(
            ended,
            writer_ended,
            "{carrier} serve: remaining units were ended"
        );
    }
    close();
    drop(answer);
    drop(caller);
    if !writer_ended {
        match tokio::time::timeout_at(deadline, &mut written).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failure.record("output", std::io::Error::other(error)),
            Err(_) => {
                written.abort();
                match written.await {
                    Ok(()) => {}
                    Err(error) if error.is_cancelled() => failure.record(
                        "output",
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "output did not drain within the shutdown grace",
                        ),
                    ),
                    Err(error) => failure.record("output", std::io::Error::other(error)),
                }
            }
        }
    }
    i32::from(failure.report())
}

async fn next_line<R, S>(
    caller: &LineCaller<R>,
    request: RequestLease,
    stop: std::pin::Pin<&mut S>,
) -> Option<OwnedInput>
where
    R: AsyncRead + Unpin + Send,
    S: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        () = stop => None,
        line = caller.read_input(request) => line,
    }
}

async fn drain_units(
    units: &mut tokio::task::JoinSet<()>,
    deadline: tokio::time::Instant,
) -> usize {
    let finished = tokio::time::timeout_at(deadline, async {
        while units.join_next().await.is_some() {}
    })
    .await;
    if finished.is_ok() {
        return 0;
    }
    let ended = units.len();
    units.abort_all();
    while units.join_next().await.is_some() {}
    ended
}

async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut OwnedInput,
    max: usize,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    let mut over = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            if over {
                buf.clear();
            }
            return Ok(total);
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if !over && take <= max.saturating_add(2).saturating_sub(buf.len()) {
            buf.try_extend_from_slice(&chunk[..take]).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "the gateway is at input capacity",
                )
            })?;
            let fits = if done {
                trim(buf.as_ref()).len() <= max
            } else {
                buf.len() <= max
                    || (buf.len() == max.saturating_add(1) && buf.as_ref().ends_with(b"\r"))
            };
            if !fits {
                over = true;
                buf.clear();
            }
        } else {
            over = true;
            buf.clear();
        }
        reader.consume(take);
        total += take;
        if done {
            return Ok(total);
        }
    }
}

fn trim(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
#[path = "tests/serve_lines.rs"]
mod tests;
