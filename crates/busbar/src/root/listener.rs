// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native inbound TLS termination (+ optional mutual-TLS) for the client↔Busbar hop.
//!
//! This module is a thin transport wrapper around the *ingress* listener. It does NOT touch routing,
//! request translation, the breaker, or failover — it only decides, once at startup, whether the
//! accepted stream is handed to axum as-is (plain, the historical default) or first put through a
//! rustls server handshake.
//!
//! ## Why we drive hyper directly here instead of `axum::serve`
//!
//! `axum::serve` in axum 0.7 is hardwired to a concrete `tokio::net::TcpListener` and constructs its
//! per-connection `IncomingStream` from private fields — there is no public `Listener` trait to
//! implement (that arrived in axum 0.8). Rather than bump axum (which would churn the Router/Service
//! types on the routing hot path this feature is contractually forbidden from touching), the TLS
//! branch reproduces axum::serve's accept loop over hyper-util directly:
//!   * accept on the `TcpListener`,
//!   * run the rustls handshake,
//!   * serve the connection with `hyper_util::server::conn::auto::Builder` (http/1.1) and
//!     `TowerToHyperService` bridging the cloned axum `Router`,
//!   * drain in-flight connections on shutdown via `hyper_util`'s `GracefulShutdown`.
//!
//! The plain-HTTP path in `main.rs` is left exactly as it was; only `cfg.tls == Some(_)` reaches
//! this module.
//!
//! ## Connection security is opaque here (DECISIONS #40)
//!
//! [`serve`] does not build a `rustls::ServerConfig` and does not decide TLS vs. plaintext for
//! itself: it is handed an already-built `busbar_contract::transport::wire::ConnectionSecurity`
//! and calls nothing on it but `wrap`. Reading the operator's `tls:` config, resolving the key
//! material through the secret kind, and building the rustls config live in
//! `busbar-core-connector` — this module is the LISTENER half of the seam (the accept loop,
//! hyper serving, graceful shutdown), not the connection-security-prep half.
//!
//! ## Crypto provider
//!
//! The process-wide crypto provider TLS needs is installed by the connector
//! (`busbar_core_connector::tls::install_crypto_provider`), with the `ServerConfig` it builds — TLS
//! stays in the connector, and the composition root names no TLS library.
//!
//! ## Failure model
//!
//! Any cert/key/CA load or parse error is fatal at startup (`die`) with a message naming the file;
//! key bytes are never logged. A handshake failure on a single connection is logged at debug and
//! drops only that connection — it never crashes the server or affects other clients.
//!
//! ## Where the stream comes from
//!
//! The connector accepts: its listening set is the one listener source, and each admitted stream
//! is handed UP to the composition root (BUSBAR-1.6.0.md, inbound listeners). The root serves it
//! here.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use busbar_kernel::diagnostics::{diag_warn, TLS_ACCEPT_PERSISTENT_FAILURE};
use std::time::{Duration, Instant};

fn handshake_timeout() -> Duration {
    Duration::from_secs(busbar_kernel::limits::tls_handshake_timeout_secs())
}

fn body_read_timeout() -> Duration {
    Duration::from_secs(busbar_kernel::limits::request_body_read_timeout_secs())
}

const MIN_BODY_THROUGHPUT_BYTES_PER_SEC: u64 = 1024;

const BODY_THROUGHPUT_GRACE: Duration = Duration::from_secs(10);

fn total_body_deadline() -> Duration {
    let cap_bytes = busbar_kernel_egress::upstream::max_translate_body_bytes() as u64;
    Duration::from_secs(cap_bytes / MIN_BODY_THROUGHPUT_BYTES_PER_SEC)
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use busbar_contract::transport::wire::{ConnectionSecurity, RawIo};
use busbar_core_connector::listen::{Admits, Admitted};
use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// THE ONE ACCEPT-ERROR POLICY, shared by both listener loops below.
///
/// `accept()` errors come in two kinds and the difference matters enormously:
///
///   * PER-CONNECTION transients -- `ECONNABORTED` (the peer reset between SYN and accept),
///     `EINTR`. The next `accept()` will very likely succeed, so retrying immediately is right.
///   * RESOURCE EXHAUSTION -- `EMFILE`/`ENFILE` (fd table full), `ENOBUFS`/`ENOMEM`. These do NOT
///     clear on their own: `accept()` fails instantly, every time, until something else releases an
///     fd. An immediate `continue` therefore spins the loop at 100% CPU on a full core, which is
///     exactly when the process can least afford it -- it starves the very tasks whose completion
///     would free the fds, turning a transient fd shortage into a wedged server.
///
/// So the second kind backs off, exponentially and capped. The cap is deliberately well under a
/// second: it bounds both the CPU burn and how long a shutdown request can sit behind a sleep.
struct AcceptBackoff {
    delay: Option<std::time::Duration>,
}

impl AcceptBackoff {
    const FIRST: std::time::Duration = std::time::Duration::from_millis(5);
    const CAP: std::time::Duration = std::time::Duration::from_millis(250);

    fn new() -> Self {
        Self { delay: None }
    }

    fn reset(&mut self) {
        self.delay = None;
    }

    fn next_delay(&mut self, e: &io::Error) -> Option<std::time::Duration> {
        if matches!(
            e.kind(),
            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
        ) {
            self.delay = None;
            return None;
        }
        let d = match self.delay {
            None => Self::FIRST,
            Some(prev) => (prev * 2).min(Self::CAP),
        };
        self.delay = Some(d);
        Some(d)
    }

    async fn absorb(&mut self, scheme: &'static str, e: &io::Error) {
        match self.next_delay(e) {
            None => tracing::debug!(error = %e, "{scheme}: accept error; continuing"),
            Some(d) => {
                diag_warn!(
                    TLS_ACCEPT_PERSISTENT_FAILURE,
                    error = %e,
                    backoff_ms = d.as_millis() as u64,
                    "{scheme}: accept is failing persistently (fd exhaustion?); backing off",
                );
                tokio::time::sleep(d).await;
            }
        }
    }
}

pub const REQUEST_WIRE: &str = busbar_core_admin::admin_codec::claims::TRANSPORT;

pub struct SocketAdmits {
    listener: TcpListener,
    backoff: AcceptBackoff,
    scheme: &'static str,
}

impl SocketAdmits {
    #[must_use]
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            backoff: AcceptBackoff::new(),
            scheme: REQUEST_WIRE,
        }
    }
}

impl Admits for SocketAdmits {
    async fn admit(&mut self) -> Admitted {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    self.backoff.reset();
                    if let Ok(stream) = stream.into_std() {
                        return Admitted {
                            stream,
                            peer,
                            hold: None,
                        };
                    }
                }
                Err(e) => self.backoff.absorb(self.scheme, &e).await,
            }
        }
    }
}

const REBALANCE_MARGIN: u32 = 2;

const HANDOFF_CHANNEL_DEPTH: usize = 16;

#[repr(align(64))]
struct PaddedCount(std::sync::atomic::AtomicU32);

pub struct ConnBalancer {
    counts: Arc<[PaddedCount]>,
    txs: Arc<[tokio::sync::mpsc::Sender<Admitted>]>,
    me: usize,
    rx: tokio::sync::mpsc::Receiver<Admitted>,
}

impl ConnBalancer {
    pub fn build(n: usize) -> Vec<ConnBalancer> {
        let counts: Arc<[PaddedCount]> = (0..n)
            .map(|_| PaddedCount(std::sync::atomic::AtomicU32::new(0)))
            .collect();
        let mut txs = Vec::with_capacity(n);
        let mut rxs = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, rx) = tokio::sync::mpsc::channel(HANDOFF_CHANNEL_DEPTH);
            txs.push(tx);
            rxs.push(rx);
        }
        let txs: Arc<[_]> = txs.into();
        rxs.into_iter()
            .enumerate()
            .map(|(me, rx)| ConnBalancer {
                counts: counts.clone(),
                txs: txs.clone(),
                me,
                rx,
            })
            .collect()
    }

    fn try_hand_off(&self, admitted: Admitted) -> Option<Admitted> {
        use std::sync::atomic::Ordering;
        let mine = self.counts[self.me].0.load(Ordering::Relaxed);
        let (min_idx, min_val) = self
            .counts
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.0.load(Ordering::Relaxed)))
            .min_by_key(|&(_, v)| v)
            .expect("at least one worker");
        if min_idx == self.me || mine < min_val.saturating_add(REBALANCE_MARGIN) {
            return Some(admitted);
        }

        self.counts[min_idx].0.fetch_add(1, Ordering::Relaxed);
        match self.txs[min_idx].try_send(admitted) {
            Ok(()) => None,
            Err(e) => {
                self.counts[min_idx].0.fetch_sub(1, Ordering::Relaxed);
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(a)
                    | tokio::sync::mpsc::error::TrySendError::Closed(a) => Some(a),
                }
            }
        }
    }

    fn place_local(&self) -> ConnCountGuard {
        use std::sync::atomic::Ordering;
        self.counts[self.me].0.fetch_add(1, Ordering::Relaxed);
        ConnCountGuard {
            counts: self.counts.clone(),
            idx: self.me,
        }
    }

    fn adopt(&self) -> ConnCountGuard {
        ConnCountGuard {
            counts: self.counts.clone(),
            idx: self.me,
        }
    }
}

struct ConnCountGuard {
    counts: Arc<[PaddedCount]>,
    idx: usize,
}

impl Drop for ConnCountGuard {
    fn drop(&mut self) {
        self.counts[self.idx]
            .0
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub async fn serve(
    listener: TcpListener,
    router: Router,
    security: Arc<dyn ConnectionSecurity>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    balancer: Option<ConnBalancer>,
) -> io::Result<()> {
    let served = Served::new(router, Some(security));
    let admits = SocketAdmits {
        listener,
        backoff: AcceptBackoff::new(),
        scheme: served.scheme,
    };
    accept_loop(admits, shutdown, balancer, served).await
}

pub async fn serve_admitted(
    admits: impl Admits,
    router: Router,
    security: Option<Arc<dyn ConnectionSecurity>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    balancer: Option<ConnBalancer>,
) -> io::Result<()> {
    accept_loop(admits, shutdown, balancer, Served::new(router, security)).await
}

pub async fn serve_admitted_framed(
    admits: impl Admits,
    router: Router,
    security: Option<Arc<dyn ConnectionSecurity>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    balancer: Option<ConnBalancer>,
    framer: Option<framed::DataFramer>,
) -> io::Result<()> {
    let framer = framer.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the data listener requires an accepting transport framer",
        )
    })?;
    let mut served = Served::new(router, security);
    served.framer = Some(framer);
    accept_loop(admits, shutdown, balancer, served).await
}

async fn accept_loop(
    mut admits: impl Admits,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    mut balancer: Option<ConnBalancer>,
    served: Served,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();

    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let (live, mut lived) = tokio::sync::mpsc::channel::<()>(1);
    let mut shutdown = std::pin::pin!(shutdown);

    let spawn = |a: Admitted, guard: Option<ConnCountGuard>| {
        let Ok(stream) = tokio::net::TcpStream::from_std(a.stream) else {
            return;
        };
        let drain = Drain {
            stop: stop.clone(),
            _live: live.clone(),
        };
        let conn = served
            .clone()
            .accepted(stream, a.peer, graceful.watcher(), drain);
        let hold = a.hold;
        tokio::spawn(async move {
            conn.await;
            drop(guard);
            drop(hold);
        });
    };

    loop {
        let (admitted, guard) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            handed = async { balancer.as_mut().expect("guarded by if").rx.recv().await },
                if balancer.is_some() =>
            {
                let Some(a) = handed else { continue };
                (a, balancer.as_ref().map(ConnBalancer::adopt))
            }
            a = admits.admit() => match balancer.as_ref() {
                Some(b) => match b.try_hand_off(a) {
                    // Handed to the least-loaded worker — nothing to serve here.
                    None => continue,
                    Some(a) => (a, Some(b.place_local())),
                },
                None => (a, None),
            },
        };
        spawn(admitted, guard);
    }
    drop(admits);

    if let Some(mut b) = balancer.take() {
        while let Ok(a) = b.rx.try_recv() {
            let guard = b.adopt();
            spawn(a, Some(guard));
        }
    }

    let _ = stop_tx.send(true);
    drop(live);
    graceful.shutdown().await;
    let _ = lived.recv().await;
    Ok(())
}

struct Drain {
    stop: tokio::sync::watch::Receiver<bool>,
    _live: tokio::sync::mpsc::Sender<()>,
}

struct TimeoutBody<B> {
    inner: B,
    timeout: Duration,

    sleep: Option<Pin<Box<tokio::time::Sleep>>>,

    started: Option<Instant>,

    bytes: u64,
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: None,
            started: None,
            bytes: 0,
        }
    }
}

/// The error a [`TimeoutBody`] yields when the inter-frame bound elapses. Boxed into the router's
/// body-error type; the message is generic (no client bytes) so it is safe to surface.
#[derive(Debug)]
struct BodyReadTimeout;

impl std::fmt::Display for BodyReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "inbound request body read timed out (slow-loris body bound)"
        )
    }
}
impl std::error::Error for BodyReadTimeout {}

/// The error a [`TimeoutBody`] yields when the TOTAL body deadline or the MINIMUM-THROUGHPUT floor
/// is exceeded - the retention-in-time bound `BodyReadTimeout`'s inter-frame check cannot catch,
/// because a dribbling client that polls at least once per byte keeps resetting that timer forever.
/// Same discipline as `BodyReadTimeout`: generic message, no client bytes.
#[derive(Debug)]
enum BodyBoundExceeded {
    Total,
    Throughput,
}

impl std::fmt::Display for BodyBoundExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Total => write!(f, "inbound request body exceeded its total read deadline"),
            Self::Throughput => write!(
                f,
                "inbound request body fell below the minimum throughput floor"
            ),
        }
    }
}
impl std::error::Error for BodyBoundExceeded {}

fn check_body_bounds(started: Instant, bytes: u64) -> Option<BodyBoundExceeded> {
    let elapsed = started.elapsed();
    if elapsed > total_body_deadline() {
        return Some(BodyBoundExceeded::Total);
    }
    if elapsed > BODY_THROUGHPUT_GRACE
        && bytes < MIN_BODY_THROUGHPUT_BYTES_PER_SEC * elapsed.as_secs()
    {
        return Some(BodyBoundExceeded::Throughput);
    }
    None
}

impl<B> Body for TimeoutBody<B>
where
    B: Body + Unpin,
    B::Data: bytes::Buf,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = B::Data;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        let started = *this.started.get_or_insert_with(Instant::now);

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.sleep = None;
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.remaining() as u64;
                }

                if let Some(e) = check_body_bounds(started, this.bytes) {
                    return Poll::Ready(Some(Err(Box::new(e))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if let Some(e) = check_body_bounds(started, this.bytes) {
                    return Poll::Ready(Some(Err(Box::new(e))));
                }

                let timeout = this.timeout;
                let sleep = this
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(BodyReadTimeout)))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A hyper `Service` that wraps every inbound request's body in a [`TimeoutBody`] before delegating
/// to the axum router (bridged by `TowerToHyperService`). This is the seam that installs the
/// body-read slow-loris bound on BOTH the TLS and plain serve loops, without touching the router or
/// the routing hot path - the router sees an ordinary `http_body::Body`, just one that fails on a
/// stalled inbound stream.
#[derive(Clone)]
struct BodyTimeoutService {
    inner: TowerToHyperService<Router>,
    timeout: Duration,
    /// The listener's scheme, stated on every request it serves.
    scheme: busbar_kernel::plane_routes::ListenerScheme,
}

impl BodyTimeoutService {
    fn new(
        router: Router,
        timeout: Duration,
        scheme: busbar_kernel::plane_routes::ListenerScheme,
    ) -> Self {
        Self {
            inner: TowerToHyperService::new(router),
            timeout,
            scheme,
        }
    }
}

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for BodyTimeoutService {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let timeout = self.timeout;
        let inner = self.inner.clone();
        let scheme = self.scheme;
        if !defers_dispatch(&req) {
            let mut req = req.map(|body| TimeoutBody::new(body, timeout));
            req.extensions_mut().insert(scheme);
            return Box::pin(inner.call(req));
        }
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(scheme);
            let mut body = TimeoutBody::new(body, timeout);
            match read_whole(
                &mut body,
                busbar_kernel_egress::upstream::max_translate_body_bytes(),
            )
            .await
            {
                Ok(bytes) => {
                    let req = hyper::Request::from_parts(parts, axum::body::Body::from(bytes));
                    inner.call(req).await
                }

                Err(status) => Ok(status_response(status)),
            }
        })
    }
}

fn defers_dispatch(req: &hyper::Request<hyper::body::Incoming>) -> bool {
    use hyper::body::Body as _;
    req.version() == hyper::Version::HTTP_2
        && !req.body().is_end_stream()
        && matches!(
            *req.method(),
            hyper::Method::GET
                | hyper::Method::HEAD
                | hyper::Method::OPTIONS
                | hyper::Method::TRACE
        )
}

async fn read_whole(
    body: &mut TimeoutBody<hyper::body::Incoming>,
    cap: usize,
) -> Result<bytes::Bytes, hyper::StatusCode> {
    let mut whole = bytes::BytesMut::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await {
            None => return Ok(whole.freeze()),
            Some(Err(_)) => return Err(hyper::StatusCode::BAD_REQUEST),
            Some(Ok(frame)) => {
                if let Ok(mut data) = frame.into_data() {
                    if whole.len() + data.remaining() > cap {
                        return Err(hyper::StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    whole.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
            }
        }
    }
}

fn status_response(status: hyper::StatusCode) -> axum::response::Response {
    let mut r = axum::response::Response::new(axum::body::Body::empty());
    *r.status_mut() = status;
    r
}

fn hardened_conn_builder() -> ConnBuilder<TokioExecutor> {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30));
    builder
}

pub async fn serve_plain(
    listener: TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    balancer: Option<ConnBalancer>,
) -> io::Result<()> {
    let admits = SocketAdmits {
        listener,
        backoff: AcceptBackoff::new(),
        scheme: REQUEST_WIRE,
    };
    accept_loop(admits, shutdown, balancer, Served::new(router, None)).await
}

/// What one listener serves every connection with: the hardened builder (see
/// `hardened_conn_builder`), the router, and the connection-security wrap (`None` = plain).
#[derive(Clone)]
struct Served {
    builder: Arc<ConnBuilder<TokioExecutor>>,
    router: Router,
    security: Option<Arc<dyn ConnectionSecurity>>,
    /// The scheme a log line names.
    scheme: &'static str,
    /// The framer whose accept side serves each connection; `None` = the hyper loop.
    framer: Option<framed::DataFramer>,
}

fn listener_scheme(secured: bool) -> busbar_kernel::plane_routes::ListenerScheme {
    busbar_kernel::plane_routes::ListenerScheme(if secured {
        busbar_contract::abi::host::service::SCHEME_SECURE
    } else {
        busbar_contract::abi::host::service::SCHEME_PLAIN
    })
}

impl Served {
    fn new(router: Router, security: Option<Arc<dyn ConnectionSecurity>>) -> Self {
        let builder = Arc::new(hardened_conn_builder());
        let scheme = if security.is_some() {
            "tls"
        } else {
            REQUEST_WIRE
        };
        Self {
            builder,
            router,
            security,
            scheme,
            framer: None,
        }
    }

    async fn accepted(
        self,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        watcher: Watcher,
        drain: Drain,
    ) {
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!(error = %e, %peer, "{}: set_nodelay failed; continuing", self.scheme);
        }
        if self.security.is_none() {
            return self.io(stream, peer, watcher, drain).await;
        }
        let raw: Box<dyn RawIo> = Box::new(TokioAsyncReadCompatExt::compat(stream));
        self.raw(raw, peer, watcher, drain).await;
    }

    async fn raw(
        self,
        raw: Box<dyn RawIo>,
        peer: impl std::fmt::Display + Send,
        watcher: Watcher,
        drain: Drain,
    ) {
        let wrapped = match &self.security {
            None => raw,
            Some(security) => {
                match tokio::time::timeout(handshake_timeout(), security.wrap(raw)).await {
                    Ok(Ok(s)) => s,

                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, %peer, "tls: handshake failed; dropping connection");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%peer, "tls: handshake timed out; dropping connection");
                        return;
                    }
                }
            }
        };
        self.io(
            FuturesAsyncReadCompatExt::compat(wrapped),
            peer,
            watcher,
            drain,
        )
        .await;
    }

    async fn io<I>(self, io: I, peer: impl std::fmt::Display, watcher: Watcher, drain: Drain)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        if let Some(framer) = self.framer {
            let secured = self.security.is_some();
            framed::serve(
                io,
                framer,
                self.router,
                secured,
                body_read_timeout(),
                drain.stop,
            )
            .await;
            return;
        }
        let service = BodyTimeoutService::new(
            self.router,
            body_read_timeout(),
            listener_scheme(self.security.is_some()),
        );
        let conn = self
            .builder
            .serve_connection_with_upgrades(TokioIo::new(Lingering(Some(io))), service);
        if let Err(e) = watcher.watch(conn).await {
            tracing::debug!(error = %e, %peer, "{}: connection error", self.scheme);
        }
    }
}

const LINGER_TOTAL: Duration = Duration::from_secs(30);
const LINGER_IDLE: Duration = Duration::from_secs(5);

struct Lingering<I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    Option<I>,
);

impl<I> Lingering<I>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn io(&mut self) -> Pin<&mut I> {
        Pin::new(
            self.0
                .as_mut()
                .expect("the connection's bytes are held until drop"),
        )
    }
}

impl<I> tokio::io::AsyncRead for Lingering<I>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().io().poll_read(cx, buf)
    }
}

impl<I> tokio::io::AsyncWrite for Lingering<I>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().io().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().io().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().io().poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().io().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(tokio::io::AsyncWrite::is_write_vectored)
    }
}

impl<I> Drop for Lingering<I>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn drop(&mut self) {
        let (Some(mut io), Ok(runtime)) = (self.0.take(), tokio::runtime::Handle::try_current())
        else {
            return;
        };
        runtime.spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let _ = io.shutdown().await;
            let mut sink = [0_u8; 16 * 1024];
            let _ = tokio::time::timeout(LINGER_TOTAL, async {
                while let Ok(Ok(n)) = tokio::time::timeout(LINGER_IDLE, io.read(&mut sink)).await {
                    if n == 0 {
                        break;
                    }
                }
            })
            .await;
        });
    }
}

#[path = "listener_framed.rs"]
pub mod framed;

#[cfg(test)]
#[path = "tests/listener_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/listener_h2_tests.rs"]
mod h2_tests;

#[cfg(test)]
#[path = "tests/listener_h2_early_dispatch_tests.rs"]
mod h2_early_dispatch_tests;
