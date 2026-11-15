// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER (SDK-SAFE-TEST-HOST §10.2, §12.2): one hyper service adapter. There is no
//! hand-written HTTP codec, no direct `h2` and no `tonic`: hyper-util's `server::conn::auto`
//! serves HTTP/1.1 and h2c prior knowledge on each image's listener, on a current-thread tokio
//! runtime per image, with hyper's own limits (a 64 KiB head, 100 header fields); the client side
//! is hyper's `client::conn::{http1, http2}` over a loopback `TcpStream`.
//!
//! What the carrier adds is the route table both parts mount on ([`Routes`]): a request matching
//! exactly one route is answered by it, on a blocking thread (so it may wait on the image's
//! [`PluginThread`](super::PluginThread)); a request matching none or several, a body over
//! `--max-body`, a route that panics, and a [`Reply::unserved`] answer are each answered
//! `501 not served by the host target: <what>` and recorded, which fails the run. A streamed
//! answer's [`Pieces`] learn when the client has gone.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Body as HttpBody, Bytes, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION};
use hyper::{HeaderMap, Method, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::sync::{mpsc, oneshot};

use super::{Binding, Caller, Callers, Listening, Refused, Report, Subject};

/// The largest request head the carrier takes: hyper's h1 read buffer and the h2 header list.
pub const HEAD_MAX: usize = 64 * 1024;
/// The most header fields an HTTP/1.1 request may carry.
const MAX_HEADERS: usize = 100;
/// The default bound on a request body (`--max-body`).
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Pieces a streamed answer may queue ahead of the client.
const PIECES_QUEUE: usize = 16;
/// How long a stopping image waits for routes still running.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// A route's handler, `Fn(Request) -> Reply`: one request in, one answer out. It runs on a
/// blocking thread, so it may wait on the image's plugin thread.
type RouteFn = dyn Fn(Request) -> Reply + Send + Sync;

/// Stops one image's listener and waits for it.
type Stopper = Box<dyn FnOnce() + Send>;

/// One request, as a route sees it: its head and its whole body (bounded by `--max-body`).
pub struct Request {
    image: &'static str,
    head: hyper::http::request::Parts,
    body: Bytes,
    caller: Option<Arc<Caller>>,
}

impl Request {
    /// The image whose listener took the request (`"linked"` or `"cdylib"`).
    #[must_use]
    pub fn image(&self) -> &'static str {
        self.image
    }

    /// The method.
    #[must_use]
    pub fn verb(&self) -> &Method {
        &self.head.method
    }

    /// The path, without the query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.head.uri.path()
    }

    /// The HTTP version the request arrived on.
    #[must_use]
    pub fn version(&self) -> Version {
        self.head.version
    }

    /// The first value of header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.head.headers.get(name).map(HeaderValue::as_bytes)
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The driver's caller whose bearer token the request presented, if any.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        self.caller.as_deref()
    }
}

/// A route's answer.
pub struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
    unserved: Option<String>,
}

fn status_of(code: u16) -> StatusCode {
    StatusCode::from_u16(code).unwrap_or_else(|_| panic!("{code} is not an HTTP status"))
}

impl Reply {
    /// `200` with `body`.
    #[must_use]
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self::status(200, body)
    }

    /// `code` with `body` (its length stated as `content-length`).
    ///
    /// # Panics
    /// When `code` is not an HTTP status.
    #[must_use]
    pub fn status(code: u16, body: impl Into<Bytes>) -> Self {
        let body: Bytes = body.into();
        Self {
            status: status_of(code),
            headers: HeaderMap::new(),
            body: Body(Inner::Full((!body.is_empty()).then_some(body))),
            unserved: None,
        }
    }

    /// `code` with a streamed body: each [`Pieces::send`] is one data frame (HTTP/1.1: one
    /// chunk), and dropping the [`Pieces`] ends the body.
    ///
    /// # Panics
    /// When `code` is not an HTTP status.
    #[must_use]
    pub fn stream(code: u16) -> (Self, Pieces) {
        let (tx, rx) = mpsc::channel(PIECES_QUEUE);
        let reply = Self {
            status: status_of(code),
            headers: HeaderMap::new(),
            body: Body(Inner::Stream(rx)),
            unserved: None,
        };
        (reply, Pieces(tx))
    }

    /// The request asked for something the target does not serve: `501 not served by the host
    /// target: <what>`, recorded, and the run fails.
    #[must_use]
    pub fn unserved(what: &str) -> Self {
        let mut reply = Self::status(501, format!("not served by the host target: {what}"));
        reply.unserved = Some(what.to_owned());
        reply
    }

    /// Adds header `name: value`.
    ///
    /// # Panics
    /// When `name` is not a header name or `value` not a header value.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes())
            .unwrap_or_else(|_| panic!("`{name}` is not a header name"));
        let value = HeaderValue::from_str(value)
            .unwrap_or_else(|_| panic!("the value for `{name}` is not a header value"));
        self.headers.append(name, value);
        self
    }
}

/// The sending end of a streamed answer ([`Reply::stream`]).
pub struct Pieces(mpsc::Sender<Bytes>);

/// The client has gone: the connection closed or the stream was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gone;

impl Pieces {
    /// Sends one piece, waiting while the client is slow. Call it from a thread, never from
    /// async code.
    ///
    /// # Errors
    /// [`Gone`] once the client has gone.
    pub fn send(&self, piece: impl Into<Bytes>) -> Result<(), Gone> {
        self.0.blocking_send(piece.into()).map_err(|_| Gone)
    }
}

/// A response body: whole, or streamed from [`Pieces`].
struct Body(Inner);

enum Inner {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match &mut self.get_mut().0 {
            Inner::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Inner::Stream(rx) => rx
                .poll_recv(cx)
                .map(|piece| piece.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.0, Inner::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Inner::Full(Some(b)) => {
                SizeHint::with_exact(u64::try_from(b.len()).unwrap_or(u64::MAX))
            }
            Inner::Full(None) => SizeHint::with_exact(0),
            Inner::Stream(_) => SizeHint::default(),
        }
    }
}

#[derive(Clone)]
struct Mount {
    verb: Method,
    path: String,
    route: Arc<RouteFn>,
}

impl Mount {
    /// Exact, or, for a path ending `/*`, any path strictly under that prefix.
    fn matches(&self, path: &str) -> bool {
        match self.path.strip_suffix('*') {
            Some(prefix) if prefix.ends_with('/') => {
                path.len() > prefix.len() && path.starts_with(prefix)
            }
            _ => path == self.path,
        }
    }
}

/// The route table, served on every image's listener: [`Subject::Routes`].
#[derive(Clone)]
pub struct Routes {
    table: Vec<Mount>,
    max_body: usize,
}

impl Default for Routes {
    fn default() -> Self {
        Self::new()
    }
}

impl Routes {
    /// No routes yet; bodies bounded at 64 MiB.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: Vec::new(),
            max_body: MAX_BODY,
        }
    }

    /// Mounts `f` for `verb` on `path`: exact, or every path under it when it ends `/*`. No
    /// precedence is invented: a request two routes match is answered as ambiguous.
    ///
    /// # Panics
    /// When `verb` is not an HTTP method.
    #[must_use]
    pub fn route(
        mut self,
        verb: &str,
        path: &str,
        f: impl Fn(Request) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let verb = Method::from_bytes(verb.as_bytes())
            .unwrap_or_else(|_| panic!("`{verb}` is not an HTTP method"));
        self.table.push(Mount {
            verb,
            path: path.to_owned(),
            route: Arc::new(f),
        });
        self
    }

    fn find(&self, verb: &Method, path: &str) -> Result<Arc<RouteFn>, String> {
        let mut hits = self
            .table
            .iter()
            .filter(|m| m.verb == *verb && m.matches(path));
        match (hits.next(), hits.next()) {
            (Some(m), None) => Ok(Arc::clone(&m.route)),
            (None, _) => Err(format!("unmatched {verb} {path}")),
            (Some(_), Some(_)) => Err(format!("ambiguous {verb} {path}")),
        }
    }
}

impl From<Routes> for Subject {
    fn from(routes: Routes) -> Self {
        Self::Routes(routes)
    }
}

impl Routes {
    /// Binds `image`'s listener at the next address `at` hands out and serves this table on it, h1
    /// and h2c. A datagram or stream target serving beside the carrier calls this for its HTTP
    /// listener and adds its own sockets to the [`Listening`] it returns.
    ///
    /// # Errors
    /// When the listener cannot bind.
    pub fn bind(&self, image: &'static str, at: &Binding<'_>) -> Result<Listening, Refused> {
        let shared = Arc::new(Shared {
            image,
            routes: self.clone(),
            callers: Arc::clone(at.callers()),
            report: at.report().clone(),
        });
        let (addr, stop) = serve_on(at.addr(), shared)?;
        Ok(Listening {
            addr,
            admin: None,
            stop,
        })
    }

    /// The carrier's one flag, `--max-body BYTES`: the largest request body a route takes.
    ///
    /// # Errors
    /// When `flag` is not `--max-body`, or its value is not a byte count.
    pub fn flag(&mut self, flag: &str, value: &str) -> Result<(), Refused> {
        if flag != "--max-body" {
            return Err(Refused::Args(format!("unknown flag {flag} {value}")));
        }
        self.max_body = value
            .parse()
            .map_err(|_| Refused::Args(format!("--max-body {value}: not a byte count")))?;
        Ok(())
    }
}

/// What one image's connections share.
struct Shared {
    image: &'static str,
    routes: Routes,
    callers: Arc<Callers>,
    report: Report,
}

impl Shared {
    fn respond(&self, reply: Reply) -> hyper::Response<Body> {
        if let Some(what) = &reply.unserved {
            self.report
                .record_unserved(format!("{}: {what}", self.image));
        }
        let mut response = hyper::Response::new(reply.body);
        *response.status_mut() = reply.status;
        *response.headers_mut() = reply.headers;
        response
    }
}

/// Binds `at` and serves `shared`'s routes on it, on a current-thread runtime of its own thread.
/// The stopper ends the accept loop, drops every connection and waits for the thread.
fn serve_on(at: SocketAddr, shared: Arc<Shared>) -> Result<(SocketAddr, Stopper), Refused> {
    let image = shared.image;
    let bind = |e: std::io::Error| Refused::Bind(format!("{image} on {at}: {e}"));
    let std_listener = std::net::TcpListener::bind(at).map_err(bind)?;
    std_listener.set_nonblocking(true).map_err(bind)?;
    let addr = std_listener.local_addr().map_err(bind)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(bind)?;
    let listener = {
        let _entered = rt.enter();
        tokio::net::TcpListener::from_std(std_listener).map_err(bind)?
    };
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let thread = std::thread::Builder::new()
        .name(format!("target-{image}"))
        .spawn(move || {
            rt.block_on(async move {
                tokio::spawn(accept(listener, shared));
                let _ = stop_rx.await;
            });
            rt.shutdown_timeout(STOP_GRACE);
        })
        .map_err(bind)?;
    let stop = move || {
        let _ = stop_tx.send(());
        drop(thread.join());
    };
    Ok((addr, Box::new(stop)))
}

async fn accept(listener: tokio::net::TcpListener, shared: Arc<Shared>) {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .max_buf_size(HEAD_MAX)
        .max_headers(MAX_HEADERS);
    builder
        .http2()
        .max_header_list_size(u32::try_from(HEAD_MAX).unwrap_or(u32::MAX));
    let builder = Arc::new(builder);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // Out of descriptors, or a connection reset before it was taken: back off.
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let shared = Arc::clone(&shared);
        let builder = Arc::clone(&builder);
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| answer(Arc::clone(&shared), req));
            drop(
                builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await,
            );
        });
    }
}

/// The bearer token of an `Authorization: Bearer <token>` header.
fn bearer(headers: &HeaderMap) -> Option<&[u8]> {
    let value = headers.get(AUTHORIZATION)?.as_bytes();
    let (scheme, token) = value.split_at_checked(7)?;
    scheme.eq_ignore_ascii_case(b"bearer ").then_some(token)
}

async fn answer(
    shared: Arc<Shared>,
    req: hyper::Request<Incoming>,
) -> Result<hyper::Response<Body>, Infallible> {
    let (head, incoming) = req.into_parts();
    let asked = format!("{} {}", head.method, head.uri.path());
    let route = match shared.routes.find(&head.method, head.uri.path()) {
        Ok(route) => route,
        Err(what) => return Ok(shared.respond(Reply::unserved(&what))),
    };
    let max_body = shared.routes.max_body;
    let body = match Limited::new(incoming, max_body).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            let what = format!("a body over --max-body {max_body} on {asked}");
            return Ok(shared.respond(Reply::unserved(&what)));
        }
        // The client went away mid-body: nobody reads this answer.
        Err(_) => return Ok(shared.respond(Reply::status(400, ""))),
    };
    let caller = bearer(&head.headers).and_then(|token| shared.callers.find(token));
    let request = Request {
        image: shared.image,
        head,
        body,
        caller,
    };
    match tokio::task::spawn_blocking(move || route(request)).await {
        Ok(reply) => Ok(shared.respond(reply)),
        Err(_) => Ok(shared.respond(Reply::unserved(&format!("the route for {asked} panicked")))),
    }
}

/// Why a dial was refused or failed.
#[derive(Debug)]
pub enum Dial {
    /// The address is not loopback once canonical.
    NotLoopback(SocketAddr),
    /// The TCP connect failed.
    Io(std::io::Error),
    /// The HTTP handshake failed.
    Http(hyper::Error),
}

async fn connect(addr: SocketAddr) -> Result<TokioIo<tokio::net::TcpStream>, Dial> {
    if !addr.ip().to_canonical().is_loopback() {
        return Err(Dial::NotLoopback(addr));
    }
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(Dial::Io)?;
    Ok(TokioIo::new(stream))
}

/// Dials `addr` (loopback only) and hands back hyper's own HTTP/1.1 sender; the connection runs
/// on the current tokio runtime until the sender and its responses are dropped.
///
/// # Errors
/// [`Dial`] when `addr` is not loopback, or the connect or handshake fails.
pub async fn dial_h1<B>(addr: SocketAddr) -> Result<http1::SendRequest<B>, Dial>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let io = connect(addr).await?;
    let (send, conn) = http1::handshake(io).await.map_err(Dial::Http)?;
    tokio::spawn(async move { drop(conn.await) });
    Ok(send)
}

/// Dials `addr` (loopback only) with HTTP/2 prior knowledge (h2c) and hands back hyper's own
/// sender; the connection runs on the current tokio runtime.
///
/// # Errors
/// [`Dial`] when `addr` is not loopback, or the connect or handshake fails.
pub async fn dial_h2<B>(addr: SocketAddr) -> Result<http2::SendRequest<B>, Dial>
where
    B: HttpBody + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let io = connect(addr).await?;
    let (send, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .map_err(Dial::Http)?;
    tokio::spawn(async move { drop(conn.await) });
    Ok(send)
}
