// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::host::service::CARRIER_SESSION_FIELD;
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use super::{DoorRequest, Served};

pub fn line_carrier(
    transports: &[crate::root::linked::LinkedTransport],
) -> Result<Option<&'static str>, String> {
    let mut lines = transports.iter().flat_map(|t| (t.lines)());
    let one = lines.next();
    match (one, lines.next()) {
        (Some(one), Some(other)) => Err(format!(
            "the linked transport claims `{one}` and `{other}` both open a session on their first \
             line, and the process's own stdin/stdout carries one"
        )),
        (one, _) => Ok(one),
    }
}

fn installed() -> &'static Result<Option<&'static str>, String> {
    static CARRIER: std::sync::OnceLock<Result<Option<&'static str>, String>> =
        std::sync::OnceLock::new();
    CARRIER.get_or_init(|| line_carrier(crate::LINKED.transports))
}

#[must_use]
pub fn carrier() -> Option<&'static str> {
    installed().as_ref().ok().copied().flatten()
}

#[must_use]
pub fn refusal() -> Option<&'static str> {
    installed().as_ref().err().map(String::as_str)
}

#[must_use]
pub fn env_credential(plane: &str, carrier: &str) -> String {
    format!(
        "BUSBAR_{}_{}_CREDENTIAL",
        plane.to_ascii_uppercase(),
        carrier.to_ascii_uppercase()
    )
}

#[must_use]
pub fn line_claim(served: &Served) -> Option<(usize, u32)> {
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

pub fn refuse(plane: &str, carrier: &str, sentence: &str) {
    eprintln!("busbar: {plane} {carrier} serve refused to start: {sentence}");
}

async fn session(
    app: Arc<busbar_kernel::state::App>,
    plane: &str,
    carrier: &str,
    audience: Option<&str>,
    credential: Option<&str>,
) -> Result<busbar_contract::records::PlaneRequestCtx, String> {
    let env = env_credential(plane, carrier);

    let canonical_uri = format!("{plane}.canonical_uri");
    let Some(resource) = audience else {
        return Err(format!(
            "this deployment's `{plane}:` block states no canonical resource, so a {carrier} session \
             has no audience to be bound to."
        ));
    };

    if let Some(token) = credential {
        use busbar_kernel::auth::audience::Binding;
        match busbar_kernel::auth::audience::inspect_bearer(token, resource) {
            Binding::Deferred | Binding::Bound => {}
            Binding::Mismatch => {
                return Err(format!(
                    "the credential in {env} carries an audience that does not identify this \
                     resource. Request a token whose `resource` (RFC 8707) is this deployment's \
                     `{canonical_uri}`."
                ));
            }
            Binding::Opaque => {
                return Err(format!(
                    "the credential in {env} carries no readable audience, so it cannot be shown \
                     to have been issued for this resource. A busbar-signed key or a JWT access \
                     token bound to `{canonical_uri}` is required."
                ));
            }
        }
    }

    let admitted = busbar_kernel::auth::admit::admit_session(
        app,
        credential.map(str::to_string),
        resource.to_string(),
    )
    .await;
    match admitted {
        Ok((_principal, gov)) => {
            if !gov.is_governed() {
                eprintln!(
                    "[warn] {plane} {carrier} session is UNGOVERNED: no enforcement key is bound, so no \
                     budget applies and audit rows attribute to `anonymous`. Configure \
                     `auth.chain` and set {env} to bind the session to a key."
                );
            }
            Ok(gov)
        }
        Err(busbar_kernel::auth::IdentityRefusal::Denied) => Err(if credential.is_none() {
            format!(
                "this deployment's `auth.chain` is configured, so an unauthenticated {carrier} session \
                 is refused exactly as an unauthenticated POST is. Set {env} to a credential the \
                 chain admits (audience-bound to `{canonical_uri}`)."
            )
        } else {
            format!("the credential in {env} was refused by the auth chain.")
        }),
        Err(busbar_kernel::auth::IdentityRefusal::NoGrant) => Err(format!(
            "the credential in {env} authenticated, but its roles earned no enforcement key under \
             `role_bindings`, and an ungoverned admission would widen its access. The same request \
             over HTTP answers `insufficient_scope`."
        )),
    }
}

pub struct LineCaller<R> {
    lines: AsyncMutex<tokio::io::BufReader<R>>,
    max_line: usize,
    out: mpsc::UnboundedSender<Vec<u8>>,
    failure: Arc<IoFailure>,
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
        self.out.send(terminated(bytes)).is_ok()
    }
}

fn terminated(bytes: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(bytes.len() + 1);
    line.extend_from_slice(bytes);
    if !line.ends_with(b"\n") {
        line.push(b'\n');
    }
    line
}

impl<R: AsyncRead + Unpin + Send> SessionCaller for LineCaller<R> {
    async fn read(&self) -> Option<Vec<u8>> {
        let mut reader = self.lines.lock().await;
        loop {
            let mut buf = Vec::new();
            match read_line(&mut *reader, &mut buf, self.max_line).await {
                Ok(0) => return None,
                Err(error) => {
                    self.failure.record("input", error);
                    return None;
                }
                Ok(_) => {}
            }
            let line = trim(&buf);
            if !line.is_empty() {
                return Some(line.to_vec());
            }
        }
    }
}

pub async fn serve_lines(
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

pub async fn serve_lines_over<R, W, S>(
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
    let instance = served.planes[plane].instance.clone();
    let target = served.planes[plane].snapshot.claims[claim as usize]
        .target
        .clone();
    let audience = served.planes[plane].snapshot.audience.clone();
    let kernel = Arc::clone(&served.planes[plane].kernel);
    let credential = std::env::var(env_credential(&instance, carrier))
        .ok()
        .filter(|c| !c.is_empty());
    let gov = match session(
        app.load(),
        &instance,
        carrier,
        audience.as_deref(),
        credential.as_deref(),
    )
    .await
    {
        Ok(gov) => gov,
        Err(sentence) => {
            refuse(&instance, carrier, &sentence);
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
    run_io(carrier, reader, writer, stop, move |caller| {
        let principal = gov.key().map_or_else(
            || {
                busbar_contract::auth::AuthPrincipal(None)
                    .actor_id()
                    .to_string()
            },
            |k| k.id.clone(),
        );
        let sink_out = caller.out.clone();
        let number = kernel.open_carrier_session(
            &instance,
            &principal,
            Arc::new(move |bytes: &[u8]| sink_out.send(terminated(bytes)).is_ok()),
        );
        let session_field = axum::http::HeaderValue::from(number);
        let answer = move |line: Vec<u8>| {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(CARRIER_SESSION_FIELD, session_field.clone());
            let req = DoorRequest {
                method: axum::http::Method::POST,
                uri: axum::http::Uri::try_from(target.as_str())
                    .unwrap_or_else(|_| axum::http::Uri::from_static("/")),
                headers,
                body: axum::body::Bytes::from(line),
                gov: gov.clone(),

                credential: credential
                    .as_ref()
                    .map(|c| busbar_contract::redacted::Secret::new(c.as_bytes().to_vec())),

                ticket: None,
                app: app.load(),

                scheme: busbar_contract::abi::host::service::SCHEME_PLAIN,
                consumed_fields: Vec::new(),
            };
            let routes = Arc::clone(&routes);
            let caller = Arc::clone(&caller);
            async move {
                let response = routes.answer(plane, claim, req).await;
                let body = collect(response).await;
                if !body.is_empty() {
                    let _ = caller.write(&body).await;
                }
            }
        };
        (answer, move || kernel.close_carrier_session(number))
    })
    .await
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

    let deadline = tokio::time::Instant::now() + busbar_kernel::detached::DETACHED_DRAIN_GRACE;
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

async fn collect(response: axum::response::Response) -> Vec<u8> {
    use http_body::Body as _;
    let mut body = response.into_body();
    let mut all = Vec::new();
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            all.extend_from_slice(&data);
        }
    }
    all
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
