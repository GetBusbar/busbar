// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINE CARRIER (SEAM-S1; ARCHITECT Q1a, consistent with round 4 Q-L3B-STDIO-SHAPE (B)): the
//! process's own stdin/stdout, held open as ONE carrier session for one caller. busbar is somebody's
//! child process here, binds no listener, and serves the door claim a served plane makes over the
//! stdio transport's key.
//!
//! - The session is only the CARRIER ([`LineCaller`], the driver's one `SessionCaller` for a held
//!   carrier): each line it reads is ONE unit, opened exactly as a data-listener arrival is (its own
//!   admission, budget, scope, audit and route walk) through the data routes' one unit path; what a
//!   unit answers is written to stdout as whole lines, never interleaved with another's.
//! - What the plane writes UNSOLICITED (a notification, a request of its own, a keepalive) it writes
//!   with `session.emit` on the session the root opened on the kernel's services for it; every
//!   arrival names that session ([`CARRIER_SESSION_FIELD`]). Nothing else reaches stdout.
//! - THE IDENTITY IS BOUND ONCE, from the boot credential ([`env_credential`]), by the same admission
//!   the data listener runs: the RFC 8707 audience pre-filter against the audience the plane's
//!   snapshot binds, then the configured auth chain and the one verdict resolution. A configured
//!   chain with no credential, or a refused one, refuses to serve: nonzero exit, the sentence on
//!   stderr, not one frame first.
//! - EOF on stdin ends the session: every unit still open ends, and the serve returns `0`.
//!
//! Every meaning a line has is the plane's; this module names no plane.

use std::sync::Arc;

use busbar_contract::abi::host::service::CARRIER_SESSION_FIELD;
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use super::{DoorRequest, Served};

/// The stdio transport's claim key: the claims made over it are the line carrier's.
pub const LINE_CARRIER: &str = "stdio";

/// The environment variable carrying the session credential for the plane keyed `plane` (its
/// instance's key, never a literal here): argv is world-readable, and the launching client's `env`
/// block has exactly this shape.
#[must_use]
pub fn env_credential(plane: &str) -> String {
    format!("BUSBAR_{}_STDIO_CREDENTIAL", plane.to_ascii_uppercase())
}

/// The `(plane, claim)` a served plane claims over the line carrier, the first in binding order.
#[must_use]
pub fn line_claim(served: &Served) -> Option<(usize, u32)> {
    served.planes.iter().enumerate().find_map(|(p, plane)| {
        plane
            .snapshot
            .claims
            .iter()
            .position(|c| c.carrier == LINE_CARRIER)
            .and_then(|i| u32::try_from(i).ok())
            .map(|claim| (p, claim))
    })
}

/// The one line a refused serve writes to stderr before it exits nonzero.
pub fn refuse(plane: &str, sentence: &str) {
    eprintln!("busbar: {plane} stdio serve refused to start: {sentence}");
}

/// RESOLVE THE SESSION IDENTITY from the boot credential, against `audience`: `Err` is a sentence
/// for stderr and a refusal to serve. Every operator sentence names the plane by `plane`.
async fn session(
    app: Arc<busbar_kernel::state::App>,
    plane: &str,
    audience: Option<&str>,
    credential: Option<&str>,
) -> Result<busbar_contract::records::PlaneRequestCtx, String> {
    let env = env_credential(plane);
    let Some(resource) = audience else {
        return Err(format!(
            "this deployment's `{plane}:` block states no canonical resource, so a stdio session \
             has no audience to be bound to."
        ));
    };
    // (1) THE AUDIENCE PRE-FILTER, for a credential busbar did not mint: a token minted for another
    // resource is not made admissible by arriving on a pipe instead of a socket.
    if let Some(token) = credential {
        use busbar_kernel::auth::audience::Binding;
        match busbar_kernel::auth::audience::inspect_bearer(token, resource) {
            Binding::Deferred | Binding::Bound => {}
            Binding::Mismatch => {
                return Err(format!(
                    "the credential in {env} carries an audience that does not identify this \
                     resource. Request a token whose `resource` (RFC 8707) is this deployment's \
                     `{plane}.canonical_uri`."
                ));
            }
            Binding::Opaque => {
                return Err(format!(
                    "the credential in {env} carries no readable audience, so it cannot be shown \
                     to have been issued for this resource. A busbar-signed key or a JWT access \
                     token bound to `{plane}.canonical_uri` is required."
                ));
            }
        }
    }
    // (2)+(3) THE CHAIN AND THE ONE VERDICT RESOLUTION the data listener runs.
    let admitted = busbar_kernel::plane_host::identity_admit_over(
        app,
        credential.map(str::to_string),
        resource.to_string(),
        resource.to_string(),
    )
    .await;
    match admitted {
        Ok((_principal, gov)) => {
            if !gov.is_governed() {
                eprintln!(
                    "[warn] {plane} stdio session is UNGOVERNED: no enforcement key is bound, so no \
                     budget applies and audit rows attribute to `anonymous`. Configure \
                     `auth.chain` and set {env} to bind the session to a key."
                );
            }
            Ok(gov)
        }
        Err(busbar_kernel::auth::IdentityRefusal::Denied) => Err(if credential.is_none() {
            format!(
                "this deployment's `auth.chain` is configured, so an unauthenticated stdio session \
                 is refused exactly as an unauthenticated POST is. Set {env} to a credential the \
                 chain admits (audience-bound to `{plane}.canonical_uri`)."
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

/// THE CARRIER'S CALLER SIDE: the lines read from the reader, and every write — a unit's answer or
/// the plane's unsolicited output — handed to the one writer as whole lines.
pub struct LineCaller<R> {
    lines: AsyncMutex<tokio::io::BufReader<R>>,
    max_line: usize,
    out: mpsc::UnboundedSender<Vec<u8>>,
}

impl<R: AsyncRead + Unpin + Send> CallerEnd for LineCaller<R> {
    /// A pipe has no head.
    fn head(&self, _status: u32, _fields: HeadFields) {}

    async fn write(&self, bytes: &[u8]) -> bool {
        let mut line = bytes.to_vec();
        if !line.ends_with(b"\n") {
            line.push(b'\n');
        }
        self.out.send(line).is_ok()
    }
}

impl<R: AsyncRead + Unpin + Send> SessionCaller for LineCaller<R> {
    /// The next non-empty line, without its terminator; `None` at EOF. A line past the inbound body
    /// bound is read to its end and dropped, so the session goes on.
    async fn read(&self) -> Option<Vec<u8>> {
        let mut reader = self.lines.lock().await;
        loop {
            let mut buf = Vec::new();
            match read_line(&mut *reader, &mut buf, self.max_line).await {
                Ok(0) | Err(_) => return None,
                Ok(_) => {}
            }
            let line = trim(&buf);
            if !line.is_empty() {
                return Some(line.to_vec());
            }
        }
    }
}

/// SERVE the line claim over the process's own stdin/stdout until EOF: the exit code for `main`.
pub async fn serve_lines(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
) -> i32 {
    serve_lines_over(served, app, pin, tokio::io::stdin(), tokio::io::stdout()).await
}

/// SERVE the line claim over any reader/writer pair.
pub async fn serve_lines_over<R, W>(
    served: Served,
    app: Arc<busbar_kernel::state::AppHandle>,
    pin: fn() -> Option<crate::root::kernel::PinnedHistory>,
    reader: R,
    writer: W,
) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let Some((plane, claim)) = line_claim(&served) else {
        eprintln!("busbar: no served plane claims the stdio transport: nothing to serve on stdin");
        return 1;
    };
    let instance = served.planes[plane].instance.clone();
    let target = served.planes[plane].snapshot.claims[claim as usize]
        .target
        .clone();
    let audience = served.planes[plane].snapshot.audience.clone();
    let kernel = Arc::clone(&served.planes[plane].kernel);
    let credential = std::env::var(env_credential(&instance))
        .ok()
        .filter(|c| !c.is_empty());
    let gov = match session(
        app.load(),
        &instance,
        audience.as_deref(),
        credential.as_deref(),
    )
    .await
    {
        Ok(gov) => gov,
        Err(sentence) => {
            refuse(&instance, &sentence);
            return 1;
        }
    };
    tracing::info!(
        governed = gov.is_governed(),
        "stdio serve: session bound; serving on stdin/stdout"
    );
    let routes = match super::line_routes(served, pin) {
        Ok(routes) => routes,
        Err(e) => {
            eprintln!("busbar: stdio serve refused to start: {e}");
            return 1;
        }
    };
    // THE ONE WRITER: whole lines, in the order they were handed over, flushed each.
    let (out, mut lines_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let written = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(line) = lines_out.recv().await {
            if writer.write_all(&line).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
        let _ = writer.flush().await;
    });
    let max_line = busbar_kernel::config::limits::installed().map_or_else(
        busbar_kernel::config::limits::default_request_body_max_bytes,
        |l| l.request_body_max_bytes,
    );
    let caller = Arc::new(LineCaller {
        lines: AsyncMutex::new(tokio::io::BufReader::new(reader)),
        max_line,
        out: out.clone(),
    });
    // THE CARRIER SESSION on the kernel's services: what the plane emits on it goes to the writer.
    let principal = gov.key().map_or_else(
        || {
            busbar_contract::auth::AuthPrincipal(None)
                .actor_id()
                .to_string()
        },
        |k| k.id.clone(),
    );
    let sink_out = out.clone();
    let number = kernel.open_carrier_session(
        &instance,
        &principal,
        Arc::new(move |bytes: &[u8]| {
            let mut line = bytes.to_vec();
            if !line.ends_with(b"\n") {
                line.push(b'\n');
            }
            sink_out.send(line).is_ok()
        }),
    );
    let session_field = axum::http::HeaderValue::from(number);
    let mut units = tokio::task::JoinSet::new();
    while let Some(line) = caller.read().await {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(CARRIER_SESSION_FIELD, session_field.clone());
        let req = DoorRequest {
            method: axum::http::Method::POST,
            uri: axum::http::Uri::try_from(target.as_str())
                .unwrap_or_else(|_| axum::http::Uri::from_static("/")),
            headers,
            body: axum::body::Bytes::from(line),
            gov: gov.clone(),
            // The boot credential is the caller's verified credential, lent for a passthrough
            // member's outbound auth call alone, as the data listener lends the gate's.
            credential: credential
                .as_ref()
                .map(|c| busbar_contract::redacted::Redacted::new(c.as_bytes().to_vec())),
            app: app.load(),
        };
        let routes = Arc::clone(&routes);
        let caller = Arc::clone(&caller);
        units.spawn(async move {
            let response = routes.answer(plane, claim, req).await;
            let body = collect(response).await;
            if !body.is_empty() {
                let _ = caller.write(&body).await;
            }
        });
        // Units that ended are reaped as the session goes, so a long session holds only its open ones.
        while units.try_join_next().is_some() {}
    }
    // EOF: the session closes (an emit on it is refused from now on), and every unit still open
    // ends here.
    kernel.close_carrier_session(number);
    units.abort_all();
    while units.join_next().await.is_some() {}
    drop(caller);
    drop(out);
    let _ = written.await;
    0
}

/// A unit's whole answer.
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

/// One line of at most `max` bytes into `buf`; a longer one is read to its end and dropped (`Ok`
/// with nothing kept but its terminator), so the session goes on. `Ok(0)` at EOF.
async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(total);
        }
        let (take, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        if buf.len() + take <= max {
            buf.extend_from_slice(&chunk[..take]);
        } else {
            buf.clear();
        }
        reader.consume(take);
        total += take;
        if done {
            return Ok(total);
        }
    }
}

/// A line without its terminator.
fn trim(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &line[..end]
}
