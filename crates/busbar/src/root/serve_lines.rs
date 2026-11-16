// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use super::{DoorRequest, Served};

pub(crate) use crate::root::off_path::serve_lines::session;
pub(crate) use crate::root::off_path::serve_lines::{env_credential, line_carrier};

fn installed() -> &'static Result<Option<&'static str>, String> {
    static CARRIER: std::sync::OnceLock<Result<Option<&'static str>, String>> =
        std::sync::OnceLock::new();
    CARRIER.get_or_init(|| line_carrier(crate::LINKED.transports))
}

#[must_use]
pub(crate) fn carrier() -> Option<&'static str> {
    installed().as_ref().ok().copied().flatten()
}

#[must_use]
pub(crate) fn refusal() -> Option<&'static str> {
    installed().as_ref().err().map(String::as_str)
}

#[must_use]
pub(crate) fn line_claim(served: &Served) -> Option<(usize, u32)> {
    let carrier = carrier()?;
    served.planes.iter().enumerate().find_map(|(p, plane)| {
        plane
            .snapshot
            .claims
            .iter()
            .position(|c| {
                c.carrier == carrier && c.flags & busbar_contract::abi::plane::CLAIM_RAW_AFFIX == 0
            })
            .and_then(|i| u32::try_from(i).ok())
            .map(|claim| (p, claim))
    })
}

pub(crate) fn refuse(plane: &str, carrier: &str, sentence: &str) {
    eprintln!("busbar: {plane} {carrier} serve refused to start: {sentence}");
}

pub(crate) struct LineCaller<R> {
    lines: AsyncMutex<tokio::io::BufReader<R>>,
    max_line: usize,
    out: mpsc::UnboundedSender<Vec<u8>>,
    /// The output lines the writer hands back once written.
    spare: Arc<LinePool>,
    failure: Arc<IoFailure>,
}

/// Output line buffers the writer hands back once a line is written, so a steady stream of answers
/// reuses a few buffers instead of allocating one per line. Bounded in count and in each buffer's
/// capacity, so one huge answer is not kept for the session's life.
#[derive(Default)]
struct LinePool(std::sync::Mutex<Vec<Vec<u8>>>);

const POOLED_LINES: usize = 16;
const POOLED_LINE_BYTES: usize = 64 * 1024;

impl LinePool {
    fn take(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .unwrap_or_default()
    }

    fn give(&self, mut line: Vec<u8>) {
        if line.capacity() > POOLED_LINE_BYTES {
            return;
        }
        line.clear();
        let mut spare = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if spare.len() < POOLED_LINES {
            spare.push(line);
        }
    }

    /// `bytes` as one newline-terminated output line, in a handed-back buffer.
    fn line(&self, bytes: &[u8]) -> Vec<u8> {
        let mut line = self.take();
        line.extend_from_slice(bytes);
        terminate(&mut line);
        line
    }
}

#[derive(Default)]
struct IoFailure(std::sync::Mutex<Option<(&'static str, std::io::Error)>>);

impl IoFailure {
    fn record(&self, direction: &'static str, error: std::io::Error) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert((direction, error));
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
        self.out.send(self.spare.line(bytes)).is_ok()
    }
}

fn terminate(line: &mut Vec<u8>) {
    if !line.ends_with(b"\n") {
        line.push(b'\n');
    }
}

#[cfg(test)]
fn terminated(bytes: &[u8]) -> Vec<u8> {
    LinePool::default().line(bytes)
}

impl<R: AsyncRead + Unpin + Send> SessionCaller for LineCaller<R> {
    async fn read(&self) -> Option<Vec<u8>> {
        let mut reader = self.lines.lock().await;
        // A handed-back line buffer when one is spare; a blank line reuses it for the next read.
        let mut buf = self.spare.take();
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
            let line = trim(&buf).len();
            if line != 0 {
                buf.truncate(line);
                return Some(buf);
            }
        }
    }
}

pub(crate) async fn serve_lines(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    stop: impl std::future::Future<Output = ()>,
) -> i32 {
    serve_lines_over(
        served,
        app,
        pin,
        tokio::io::stdin(),
        tokio::io::stdout(),
        stop,
    )
    .await
}

pub(crate) async fn serve_lines_over<R, W, S>(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    reader: R,
    writer: W,
    stop: S,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
{
    let serving: Vec<(&str, bool)> = served
        .ports
        .iter()
        .map(|seat| (seat.instance.as_str(), seat.driver.serves_lines()))
        .collect();
    match one_line_plane(&serving) {
        Ok(Some(at)) => {
            let seat = served.ports[at].clone();
            return serve_port_lines(seat, app, reader, writer, stop).await;
        }
        Ok(None) => {}
        Err(refusal) => {
            eprintln!("busbar: {PORT_LINE_CARRIER} serve refused to start: {refusal}");
            return 1;
        }
    }
    let Some(carrier) = carrier() else {
        eprintln!("busbar: no linked transport carries lines: nothing to serve on stdin");
        return 1;
    };
    let Some((plane, claim)) = line_claim(&served) else {
        eprintln!(
            "busbar: no served plane claims the {carrier} transport: nothing to serve on stdin"
        );
        return 1;
    };
    let instance = served.planes[plane].instance.as_str();
    let target = served.planes[plane].snapshot.claims[claim as usize]
        .target
        .clone();
    let audience = served.planes[plane].snapshot.audience.clone();
    let kernel = Arc::clone(&served.planes[plane].kernel);
    let driver = Arc::clone(&served.planes[plane].driver);
    let credential = std::env::var(env_credential(instance, carrier))
        .ok()
        .filter(|c| !c.is_empty());
    let gov = match session(
        app.load(),
        instance,
        carrier,
        audience.as_deref(),
        credential.as_deref(),
    )
    .await
    {
        Ok(gov) => gov,
        Err(sentence) => {
            refuse(instance, carrier, &sentence);
            return 1;
        }
    };
    tracing::info!(
        governed = gov.is_governed(),
        "{carrier} serve: session bound; serving on stdin/stdout"
    );
    let routes = match super::line_routes(served, pin) {
        Ok(routes) => routes,
        Err(e) => {
            eprintln!("busbar: {carrier} serve refused to start: {e}");
            return 1;
        }
    };
    // The session's credential, moved into the one shared zeroising buffer each line's request
    // clones (SP-AU6), never copied per line.
    let credential = credential.map(|c| {
        busbar_kernel::auth::CallerCredential::adopted(busbar_contract::Secret::new(c.into_bytes()))
    });
    run_io(carrier, reader, writer, stop, move |caller| {
        let principal = crate::root::off_path::serve_lines::session_principal(&gov);
        let sink = Arc::clone(&caller);
        let session = std::num::NonZeroU64::new(
            driver
                .open_carrier_session(
                    &principal,
                    Arc::new(move |bytes: &[u8]| sink.out.send(sink.spare.line(bytes)).is_ok()),
                )
                .expect("served plane holds its core caller binding"),
        )
        .expect("kernel carrier sessions are minted above zero");
        let answer = move |line: Vec<u8>| {
            let headers = axum::http::HeaderMap::new();
            let req = DoorRequest {
                method: axum::http::Method::POST,
                uri: axum::http::Uri::try_from(target.as_str())
                    .unwrap_or_else(|_| axum::http::Uri::from_static("/")),
                headers,
                body: axum::body::Bytes::from(line),
                gov: gov.clone(),

                credential: credential.clone(),

                ticket: None,
                host_ticket_admission: None,
                app: app.load(),

                scheme: busbar_contract::abi::host::service::SCHEME_PLAIN,
                consumed_fields: Vec::new(),
            };
            let routes = Arc::clone(&routes);
            let caller = Arc::clone(&caller);
            async move {
                let response = routes.answer_on_line(plane, claim, req, session).await;
                let mut line = caller.spare.take();
                collect(response, &mut line).await;
                if line.is_empty() {
                    caller.spare.give(line);
                } else {
                    terminate(&mut line);
                    let _ = caller.out.send(line);
                }
            }
        };
        (answer, move || kernel.close_carrier_session(session.get()))
    })
    .await
}

/// The label a MIN-3 line session is bound and logged under: the process's own stdin/stdout (IF §12.23).
const PORT_LINE_CARRIER: &str = "stdio";

/// IF §12.23 rule 1: the one served plane instance declaring ROUTE_LINE (`serving` = each instance's configured
/// name and whether it declares one), by its place. None = no line serving; two or more refuse the start, naming both.
pub(crate) fn one_line_plane(serving: &[(&str, bool)]) -> Result<Option<usize>, String> {
    let mut lines = serving.iter().enumerate().filter(|(_, (_, line))| *line);
    match (lines.next(), lines.next()) {
        (Some((_, (one, _))), Some((_, (other, _)))) => Err(format!(
            "the plane instances `{one}` and `{other}` both open a session on their first line, and the \
             process's own stdin/stdout carries one"
        )),
        (one, _) => Ok(one.map(|(at, _)| at)),
    }
}

/// IF §12.23 over the plane port: the one `ROUTE_LINE` plane's lines go to `PortSeat::answer_line` with the
/// carrier id in `PlaneReq.carrier`; on EOF, a write failure or shutdown core stops reading, ends the in-flight
/// lines, closes the writer, and then calls `admin(ADMIN_CARRIER_END)` once.
async fn serve_port_lines<R, W, S>(
    seat: busbar_kernel::plane_driver::port::PortSeat,
    app: Arc<busbar_kernel::state::AppHandle>,
    reader: R,
    writer: W,
    stop: S,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
{
    let instance = seat.instance.as_str();
    let credential = std::env::var(env_credential(instance, PORT_LINE_CARRIER))
        .ok()
        .filter(|c| !c.is_empty());
    let gov = match session(
        app.load(),
        instance,
        PORT_LINE_CARRIER,
        seat.audience.as_deref(),
        credential.as_deref(),
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
    let code = run_io(PORT_LINE_CARRIER, reader, writer, stop, move |caller| {
        let principal = crate::root::off_path::serve_lines::session_principal(&gov);
        let line_caller = busbar_kernel::plane_driver::port::LineCaller {
            principal: Arc::from(principal.as_str()),
            authenticated: gov.key().is_some(),
        };
        let sink = Arc::clone(&caller);
        let carrier = open_driver.open_carrier(
            &principal,
            Arc::new(move |bytes: &[u8]| sink.out.send(sink.spare.line(bytes)).is_ok()),
        );
        let _ = opened_here.set(carrier);
        let requests = std::sync::atomic::AtomicU64::new(1);
        let answer = move |line: Vec<u8>| {
            let request_id = requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let seat = answer_seat.clone();
            let caller = Arc::clone(&caller);
            let line_caller = line_caller.clone();
            async move {
                match seat
                    .answer_line(carrier, request_id, line, &line_caller)
                    .await
                {
                    Ok(mut body) if !body.is_empty() => {
                        terminate(&mut body);
                        let _ = caller.out.send(body);
                    }
                    Ok(_) => {}
                    Err(refused) => tracing::warn!(?refused, "a line got no answer from its plane"),
                }
            }
        };
        (answer, move || open_driver.close_carrier(carrier))
    })
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
    stop: S,
    open: Open,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: std::future::Future<Output = ()>,
    Open: FnOnce(Arc<LineCaller<R>>) -> (Answer, Close),
    Answer: Fn(Vec<u8>) -> Unit,
    Unit: std::future::Future<Output = ()> + Send + 'static,
    Close: FnOnce(),
{
    let (out, mut lines_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let failure = Arc::new(IoFailure::default());
    let write_failure = Arc::clone(&failure);
    let spare = Arc::new(LinePool::default());
    let handed_back = Arc::clone(&spare);
    let mut written = tokio::spawn(async move {
        let mut writer = writer;
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
            handed_back.give(line);
        }
        if let Err(error) = writer.flush().await {
            write_failure.record("output", error);
        }
    });
    let max_line = busbar_kernel::config::limits::installed().map_or_else(
        busbar_kernel::config::limits::default_request_body_max_bytes,
        |l| l.request_body_max_bytes,
    );
    let caller = Arc::new(LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line,
        out,
        spare,
        failure: Arc::clone(&failure),
    });
    let (answer, close) = open(Arc::clone(&caller));
    let mut units = tokio::task::JoinSet::new();
    let mut stop = std::pin::pin!(stop);
    let mut writer_ended = false;
    loop {
        let line = tokio::select! {
            biased;
            result = &mut written => {
                writer_ended = true;
                if let Err(error) = result {
                    failure.record("output", std::io::Error::other(error));
                }
                break;
            }
            line = next_line(&*caller, stop.as_mut()) => line,
        };
        let Some(line) = line else { break };
        units.spawn(answer(line));

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

async fn next_line<R, S>(caller: &LineCaller<R>, stop: std::pin::Pin<&mut S>) -> Option<Vec<u8>>
where
    R: AsyncRead + Unpin + Send,
    S: std::future::Future<Output = ()>,
{
    tokio::select! {
        biased;
        () = stop => None,
        line = caller.read() => line,
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

/// The answer's body, appended to `all`.
async fn collect(response: axum::response::Response, all: &mut Vec<u8>) {
    use http_body::Body as _;
    let mut body = response.into_body();
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            all.extend_from_slice(&data);
        }
    }
}

async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
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
            buf.extend_from_slice(&chunk[..take]);
            let fits = if done {
                trim(buf).len() <= max
            } else {
                buf.len() <= max || (buf.len() == max.saturating_add(1) && buf.ends_with(b"\r"))
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
