// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native inbound TLS termination (+ optional mutual-TLS) for the client↔Busbar hop.
//!
//! This module is a thin transport wrapper around the *ingress* listener. It does NOT touch routing,
//! request translation, the breaker, or failover — it only decides, once at startup, whether the
//! accepted TCP stream is handed to axum as-is (plain HTTP, the historical default) or first put
//! through a rustls server handshake.
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
//! ## Crypto provider
//!
//! rustls 0.23 requires a process-wide [`rustls::crypto::CryptoProvider`]. busbar already links
//! `ring` (via reqwest/hyper-rustls), so [`install_crypto_provider`] installs ring's provider once
//! at startup and the `ServerConfig` is built on it — exactly one provider in the process, never
//! aws-lc-rs.
//!
//! ## Failure model
//!
//! Any cert/key/CA load or parse error is fatal at startup (`die`) with a message naming the file;
//! key bytes are never logged. A handshake failure on a single connection is logged at debug and
//! drops only that connection — it never crashes the server or affects other clients.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Hard wall-clock bound on the TLS handshake for a single accepted connection. A client that
/// connects then stalls (sends nothing / dribbles handshake bytes) must not park a task + FDs
/// indefinitely — this caps the pre-auth slowloris / handshake-flood surface. The cost is incurred
/// BEFORE mTLS client-cert verification, so this guards the unauthenticated edge.
/// Operator-tunable via `limits.tls_handshake_timeout_secs` (default 10s), read through the
/// process-wide `crate::limits` install. A function (not a `const`) so the configured value is read
/// per accepted connection; falls back to the historical 10s when limits aren't installed.
fn handshake_timeout() -> Duration {
    Duration::from_secs(crate::limits::tls_handshake_timeout_secs())
}

/// Max wall-clock time allowed BETWEEN inbound request-body frames before the connection is dropped.
/// The header-read timeout (`hardened_conn_builder`) covers ONLY the header phase - once headers are
/// complete an unauthenticated slow-loris can dribble the request BODY one byte at a time, holding a
/// connection task, an FD, AND (critically) one of the finite `max_inbound_concurrent` (default 8192)
/// permits indefinitely, starving real traffic. `DefaultBodyLimit` caps total SIZE, not TIME between
/// frames, so it does not help. This wraps every inbound body in a [`TimeoutBody`] that trips when no
/// frame arrives within this bound. Operator-tunable via `limits.request_body_read_timeout_secs`
/// (default 30s), read per connection through the process-wide `crate::limits` install; falls back to
/// the default when limits aren't installed (tests / pre-install).
fn body_read_timeout() -> Duration {
    Duration::from_secs(crate::limits::request_body_read_timeout_secs())
}

/// MINIMUM sustained throughput a body read must maintain once the grace period has elapsed. The
/// inter-frame timer (`body_read_timeout`) resets on ANY progress at all, so a client that dribbles
/// exactly one byte per `body_read_timeout` interval holds a connection, an FD, and an
/// inbound-concurrency permit indefinitely without ever tripping it. This floor catches that: it
/// bounds RETENTION IN TIME, not size (`DefaultBodyLimit`/the per-request buffer cap already bound
/// size) and not concurrency (`GlobalConcurrencyLimitLayer` already bounds that globally). Hardcoded
/// rather than an operator knob (per owner decision): 1 KiB/s is far below any honest client's
/// sustained rate and comfortably above "a client stalling one byte every ~30s".
const MIN_BODY_THROUGHPUT_BYTES_PER_SEC: u64 = 1024;

/// Grace period before the throughput floor is evaluated. Before it, `bytes / elapsed` is unstable
/// (a client that pauses briefly before its first frame, or whose first frame is large relative to
/// elapsed time, would false-positive). Hardcoded alongside the floor for the same reason.
const BODY_THROUGHPUT_GRACE: Duration = Duration::from_secs(10);

/// TOTAL wall-clock deadline for reading one inbound body — the backstop that bounds retention even
/// for a client that stays JUST above the throughput floor forever. DERIVED from the configured body
/// size cap and the throughput floor (`body_cap / floor`), NOT a bare constant: `request_body_max_bytes`
/// is an operator knob with a 1 GiB ceiling, so a fixed total would silently demand an arbitrarily
/// high sustained rate from an honest client uploading near that ceiling. Deriving it means the total
/// always admits exactly "the whole cap, sustained at the floor," regardless of how the operator has
/// configured the cap.
fn total_body_deadline() -> Duration {
    let cap_bytes = crate::limits::translate_body_max_bytes() as u64;
    Duration::from_secs(cap_bytes / MIN_BODY_THROUGHPUT_BYTES_PER_SEC)
}

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::Router;
use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsCfg;

/// Install ring's [`rustls::crypto::CryptoProvider`] as the process default.
///
/// Idempotent and safe to call alongside reqwest/hyper-rustls, which also use ring: a "provider
/// already installed" error is expected and ignored, because all we require is that *a ring provider*
/// is the process default before any `ServerConfig` is built. Must run before [`build_server_config`].
pub(crate) fn install_crypto_provider() {
    // Err(_) => some other code path already installed a provider. Since busbar only ever links ring,
    // that provider is ring too, so there is nothing to fix and nothing to warn about.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
fn read_pem(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
    what: &str,
) -> Result<Vec<u8>, String> {
    resolver
        .resolve(secret)
        .map_err(|e| format!("cannot resolve TLS {what} ({}): {e}", secret.describe()))
}

/// Parse the PEM certificate chain (leaf first). Errors name the secret source; cert bytes are
/// public, but we still avoid echoing them.
fn load_cert_chain(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "cert")?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS cert ({src}): {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "TLS cert ({src}) contains no certificates (expected a PEM chain, leaf first)"
        ));
    }
    Ok(certs)
}

/// Parse the PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) encodings. NEVER logs key
/// material - error messages name only the secret source.
fn load_private_key(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<PrivateKeyDer<'static>, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "key")?;
    // `PrivateKeyDer::from_pem_slice` accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) sections, picking the
    // first private-key section it finds. `NoItemsFound` means none was present; any other variant is a
    // genuine parse error. Neither path echoes key material - error messages name only the source.
    use rustls::pki_types::pem::Error as PemError;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| match e {
        PemError::NoItemsFound => {
            format!("TLS key ({src}) contains no private key (expected PKCS#8 / PKCS#1 / SEC1 PEM)")
        }
        other => format!("cannot parse TLS key ({src}): {other}"),
    })
}

/// Build the client-cert verifier root store from the operator's CA bundle (mTLS).
fn load_client_roots(
    resolver: &crate::config::secret::SecretResolver,
    secret: &crate::config::SecretRef,
) -> Result<RootCertStore, String> {
    let src = secret.describe();
    let bytes = read_pem(resolver, secret, "client_ca")?;
    let cas = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse TLS client_ca ({src}): {e}"))?;
    if cas.is_empty() {
        return Err(format!("TLS client_ca ({src}) contains no CA certificates"));
    }
    let mut roots = RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| format!("invalid CA certificate in TLS client_ca ({src}): {e}"))?;
    }
    Ok(roots)
}

/// Construct the rustls [`ServerConfig`] from the operator's [`TlsCfg`].
///
/// * `client_ca` present ⇒ a [`WebPkiClientVerifier`] is installed: the client MUST present a
///   certificate chaining to that CA or the handshake fails (mTLS required).
/// * `client_ca` absent ⇒ `with_no_client_auth()` (server-only TLS).
///
/// ALPN advertises only `http/1.1` — busbar's axum server speaks http/1.1, so we must not advertise
/// h2. Returns a clear, source-named error on any load/parse problem (the caller turns it into `die`).
pub(crate) fn build_server_config(
    tls: &TlsCfg,
    resolver: &crate::config::secret::SecretResolver,
) -> Result<ServerConfig, String> {
    let certs = load_cert_chain(resolver, &tls.cert)?;
    let key = load_private_key(resolver, &tls.key)?;

    let builder = ServerConfig::builder();

    let builder = match &tls.client_ca {
        Some(ca) => {
            let roots = load_client_roots(resolver, ca)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    format!(
                        "cannot build client-cert verifier from TLS client_ca ({}): {e}",
                        ca.describe()
                    )
                })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder.with_single_cert(certs, key).map_err(|e| {
        format!(
            "TLS cert/key are not a valid pair (cert {}, key {}): {e}",
            tls.cert.describe(),
            tls.key.describe()
        )
    })?;

    // http/1.1 only — busbar's axum 0.7 server does not serve h2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

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

    /// Clear the backoff after a successful accept.
    fn reset(&mut self) {
        self.delay = None;
    }

    /// How long to wait before the next `accept()`, and advance the schedule. `None` = retry now
    /// (a per-connection transient). PURE, so the policy is unit-testable without a listener.
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

    /// Apply the policy: log at the right level and sleep if this error class calls for it.
    async fn absorb(&mut self, scheme: &'static str, e: &io::Error) {
        match self.next_delay(e) {
            None => tracing::debug!(error = %e, "{scheme}: accept error; continuing"),
            Some(d) => {
                tracing::warn!(
                    error = %e,
                    backoff_ms = d.as_millis() as u64,
                    "{scheme}: accept is failing persistently (fd exhaustion?); backing off",
                );
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// Serve `router` over TLS on `listener` until `shutdown` resolves, then drain in-flight connections.
///
/// Mirrors `axum::serve(listener, router).with_graceful_shutdown(shutdown)` for the TLS case:
/// each accepted connection is handshook with rustls and served with hyper's auto builder (http/1.1).
/// A handshake or accept error affects only that one connection — the accept loop continues, so a
/// rejected mTLS client (wrong/missing cert) never takes the server down or blocks other clients.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    server_config: ServerConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let graceful = GracefulShutdown::new();
    let conn_builder = Arc::new(hardened_conn_builder());

    let mut shutdown = std::pin::pin!(shutdown);
    let mut backoff = AcceptBackoff::new();

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => { backoff.reset(); pair }
                // An accept error must not kill the loop; `absorb` decides whether it is a
                // per-connection transient (retry now) or persistent exhaustion (back off).
                Err(e) => { backoff.absorb("tls", &e).await; continue; }
            },
        };

        let acceptor = acceptor.clone();
        let router = router.clone();
        let conn_builder = conn_builder.clone();
        let watcher = graceful.watcher();

        tokio::spawn(async move {
            serve_one(acceptor, conn_builder, watcher, stream, peer, router).await;
        });
    }

    // Stop accepting; drain in-flight connections (the watched futures complete on their own once
    // their requests finish or their clients hang up).
    graceful.shutdown().await;
    Ok(())
}

/// An inbound-body wrapper that bounds the wall-clock time a request body may occupy a connection,
/// on THREE axes. Wraps the hyper `Incoming` body; each `poll_frame` races the inner poll against a
/// `body_read_timeout()` inter-frame timer that is RESET on every delivered frame, AND checks a
/// TOTAL deadline and a MINIMUM-THROUGHPUT floor that are evaluated on every `poll_frame` entry (so
/// no separate timer is needed for either - a dribbling client necessarily polls at least once per
/// byte). The inter-frame timer alone cannot catch a client that dribbles fast enough to keep
/// resetting it forever; the floor closes that gap, and the total deadline backstops a client that
/// stays just above the floor forever. Any of the three failing yields an error, which hyper surfaces
/// as a connection error - dropping the stalled connection and freeing its task, FD, and
/// inbound-concurrency permit. A body that keeps delivering frames promptly and above the floor is
/// passed through unchanged, so a slow-but-progressing large upload is never falsely killed.
/// `SizeHint`/`is_end_stream` delegate to the inner body so framing/content-length behavior is
/// identical to the unwrapped body.
struct TimeoutBody<B> {
    inner: B,
    timeout: Duration,
    // Lazily-armed inter-frame timer. Re-armed after every delivered frame; `None` until the first
    // poll so the timer is driven from the runtime clock inside the connection task.
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Set on the first `poll_frame`, from the runtime clock - the origin for both the total
    /// deadline and the throughput-floor grace period.
    started: Option<Instant>,
    /// Total DATA bytes delivered so far (frame trailers/metadata excluded), for the throughput
    /// floor's `bytes / elapsed` comparison.
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

/// Shared by both the `Ready` and `Pending` arms of `poll_frame`: evaluate the total deadline, then
/// (after the grace period) the throughput floor. `None` means neither tripped.
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
        // Poll the underlying body first: a frame ready right now short-circuits the timer entirely.
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Progress: reset the inter-frame timer for the NEXT frame.
                this.sleep = None;
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.remaining() as u64;
                }
                // Evaluated on EVERY delivered frame too, not just on `Pending`: a dribbling client
                // necessarily polls (and delivers) at least once per byte, so checking only on
                // `Pending` would never see it.
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
                // No frame yet: arm (or poll) the inter-frame timer. On elapse, fail the body so the
                // connection is dropped rather than parked indefinitely on a dribbling client.
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
}

impl BodyTimeoutService {
    fn new(router: Router, timeout: Duration) -> Self {
        Self {
            inner: TowerToHyperService::new(router),
            timeout,
        }
    }
}

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for BodyTimeoutService {
    type Response = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Response;
    type Error = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Error;
    type Future = <TowerToHyperService<Router> as hyper::service::Service<
        hyper::Request<TimeoutBody<hyper::body::Incoming>>,
    >>::Future;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let timeout = self.timeout;
        let req = req.map(|body| TimeoutBody::new(body, timeout));
        self.inner.call(req)
    }
}

/// Build the hyper auto connection builder shared by BOTH the plain-HTTP and TLS serve loops.
///
/// Bounds the HTTP/1 HEADER-read phase (slow-loris defense): a client that opens a connection and
/// then trickles request headers one byte at a time would otherwise hold the connection task + FD
/// indefinitely — `DefaultBodyLimit` only applies AFTER headers are fully received, so it does not
/// help here. `header_read_timeout` bounds ONLY the header phase, so it never truncates a
/// legitimately long response stream (an LLM completion can stream for minutes). 30s is far longer
/// than any real client needs to send its request line + headers, so it cannot false-positive on a
/// healthy connection. `header_read_timeout` requires a `Timer` (hyper panics otherwise), so the
/// Tokio timer is wired to drive it from the runtime clock.
fn hardened_conn_builder() -> ConnBuilder<TokioExecutor> {
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(30));
    builder
}

/// Plain-HTTP serve loop — the no-`tls`-block default path. Mirrors `serve` (and the historical
/// `axum::serve(listener, router).with_graceful_shutdown(shutdown)`) but over the bare TCP stream
/// (no TLS handshake). Routed through the SAME `hardened_conn_builder` so the plain listener gets the
/// identical slow-loris header-read bound the TLS listener has — the previous `axum::serve` path
/// exposed no such timeout, leaving a plain-HTTP edge deployment open to header-trickle clients.
pub(crate) async fn serve_plain(
    listener: TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    let conn_builder = Arc::new(hardened_conn_builder());
    let mut shutdown = std::pin::pin!(shutdown);
    let mut backoff = AcceptBackoff::new();

    loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => { backoff.reset(); pair }
                Err(e) => { backoff.absorb("http", &e).await; continue; }
            },
        };

        let router = router.clone();
        let conn_builder = conn_builder.clone();
        let watcher = graceful.watcher();

        tokio::spawn(async move {
            serve_one_plain(conn_builder, watcher, stream, peer, router).await;
        });
    }

    graceful.shutdown().await;
    Ok(())
}

/// Serve a single accepted plain-TCP connection. Any failure is contained to this connection.
async fn serve_one_plain(
    conn_builder: Arc<ConnBuilder<TokioExecutor>>,
    watcher: hyper_util::server::graceful::Watcher,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
) {
    // TCP_NODELAY parity with axum::serve (which sets it by default on accepted streams).
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, %peer, "http: set_nodelay failed; continuing");
    }
    let service = BodyTimeoutService::new(router, body_read_timeout());
    let io = TokioIo::new(stream);
    let conn = conn_builder.serve_connection_with_upgrades(io, service);
    let conn = watcher.watch(conn);
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, %peer, "http: connection error");
    }
}

/// Handshake + serve a single accepted TCP connection. Any failure is contained to this connection.
async fn serve_one(
    acceptor: TlsAcceptor,
    conn_builder: Arc<ConnBuilder<TokioExecutor>>,
    watcher: hyper_util::server::graceful::Watcher,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
) {
    // TCP_NODELAY parity with axum::serve (which sets it by default on accepted streams).
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, %peer, "tls: set_nodelay failed; continuing");
    }

    // Bound the handshake (see `handshake_timeout()`): on elapse the `accept` future is dropped, which
    // closes the half-open connection and frees the task + FDs. Cancel-safe — no state escapes.
    let tls_stream = match tokio::time::timeout(handshake_timeout(), acceptor.accept(stream)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // Handshake failure (bad/missing client cert under mTLS, protocol mismatch, client gone).
            // Debug-level and dropped — never escalated. NEVER logs key/cert bytes.
            tracing::debug!(error = %e, %peer, "tls: handshake failed; dropping connection");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "tls: handshake timed out; dropping connection");
            return;
        }
    };

    let service = BodyTimeoutService::new(router, body_read_timeout());
    let io = TokioIo::new(tls_stream);
    let conn = conn_builder.serve_connection_with_upgrades(io, service);
    let conn = watcher.watch(conn);

    if let Err(e) = conn.await {
        // Per-connection serving error (client reset, malformed request framing). Contained here.
        tracing::debug!(error = %e, %peer, "tls: connection error");
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end TLS / mTLS transport tests. Each spins a real busbar TLS listener on an ephemeral
    //! port with rcgen-generated certs and drives it with a real reqwest https client over the wire —
    //! exercising the actual rustls handshake (incl. client-cert verification), not a mock.

    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use axum::routing::get;
    use axum::Router;
    use rcgen::{CertificateParams, CertifiedKey, IsCa, Issuer, KeyPair};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use crate::config::TlsCfg;

    /// `crate::limits::install` is a PROCESS-GLOBAL swap, and cargo runs this file's `#[tokio::test]`
    /// fns concurrently by default. Any test that installs a non-default `LimitsResolved` (the
    /// body-read-timeout / throughput-floor / total-deadline tests below) can otherwise stomp a
    /// concurrently-running sibling's installed value mid-test — observed directly: the throughput
    /// floor and total-deadline tests both pass in isolation but fail when run alongside each other.
    /// Every test that calls `crate::limits::install` holds this for its ENTIRE body (not just the
    /// install call), so no two such tests are ever mid-flight at once. An async-aware
    /// `tokio::sync::Mutex`, not `std::sync::Mutex`: every holder awaits (socket I/O) while holding
    /// it, and holding a `std` mutex guard across an await point risks blocking the executor thread
    /// underneath a parked task (clippy's `await_holding_lock`, correctly `-D warnings` here).
    static LIMITS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// THE ACCEPT-ERROR POLICY, asserted directly. Both listener loops route every `accept()` error
    /// through `AcceptBackoff`, so this covers the class rather than one loop.
    ///
    /// The hazard is resource exhaustion, not a peer reset: on `EMFILE`/`ENFILE` `accept()` fails
    /// INSTANTLY and keeps failing until something releases an fd, so a bare `continue` -- which is
    /// what both loops did -- spins a full core rejecting connections, starving the very tasks whose
    /// completion would free the fds.
    #[test]
    fn accept_backoff_spins_only_on_per_connection_transients() {
        use std::io::{Error, ErrorKind};
        let mut b = super::AcceptBackoff::new();

        // A peer that resets between SYN and accept: the next accept will very likely succeed.
        assert_eq!(
            b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
            None,
            "a per-connection transient must retry immediately"
        );
        assert_eq!(b.next_delay(&Error::from(ErrorKind::Interrupted)), None);

        // fd exhaustion: back off, growing, and CAPPED so shutdown is never parked for long.
        let emfile = Error::from_raw_os_error(24); // EMFILE
        let first = b.next_delay(&emfile).expect("exhaustion must back off");
        assert_eq!(first, super::AcceptBackoff::FIRST);
        let second = b.next_delay(&emfile).expect("still failing");
        assert!(
            second > first,
            "the backoff must GROW: {first:?} -> {second:?}"
        );
        for _ in 0..20 {
            let d = b.next_delay(&emfile).expect("still failing");
            assert!(d <= super::AcceptBackoff::CAP, "capped at CAP, got {d:?}");
        }
        assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::CAP));

        // A successful accept clears the schedule, so an isolated blip does not leave the listener
        // permanently slow.
        b.reset();
        assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));

        // And a transient arriving mid-backoff resets it too -- it is not the exhaustion class.
        let _ = b.next_delay(&emfile);
        assert_eq!(
            b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
            None
        );
        assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));
    }

    /// A trivial router standing in for busbar's real one — the TLS transport is protocol-agnostic,
    /// so a `/healthz` that returns 200 is enough to prove a request completed over the secure hop.
    fn test_router() -> Router {
        Router::new().route("/healthz", get(|| async { "ok" }))
    }

    /// Write `contents` to a uniquely-named temp file and return its path. Used to hand the
    /// PEM-on-disk config grammar the same file paths an operator would.
    fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = format!(
            "busbar-tls-test-{tag}-{}-{:?}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(uniq);
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// Generate a self-signed server cert for `localhost`/`127.0.0.1`. Returns (cert_pem, key_pem).
    fn gen_self_signed() -> (String, String) {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    /// Generate a CA + a leaf signed by it (for mTLS). Returns (ca_cert_pem, leaf_cert_pem,
    /// leaf_key_pem). The leaf is the client identity; the CA is what the server verifies against.
    fn gen_ca_and_leaf(cn_sans: Vec<String>) -> (String, String, String) {
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        // rcgen 0.14: leaf signing goes through an `Issuer` (CA params + CA key) rather than
        // passing the CA cert + key positionally. `from_params` borrows the CA params and takes
        // ownership of the CA key pair, which we no longer need after this.
        let issuer = Issuer::from_params(&ca_params, ca_kp);
        let leaf_kp = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(cn_sans).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

        (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
    }

    /// Boot a busbar TLS listener from a `TlsCfg` on an ephemeral port. Returns the bound address and
    /// a shutdown sender (drop or send to stop + drain). Mirrors `main`'s TLS branch exactly:
    /// install provider → build ServerConfig → `tls::serve`.
    async fn spawn_tls_server(tls: &TlsCfg) -> (SocketAddr, oneshot::Sender<()>) {
        super::install_crypto_provider();
        let server_config = super::build_server_config(
            tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect("valid test TLS config");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            super::serve(listener, test_router(), server_config, shutdown)
                .await
                .unwrap();
        });
        // Give the spawned task a tick to begin accepting before the client connects.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (addr, tx)
    }

    /// TEST 1 — TLS happy path: a client trusting the server's self-signed cert completes an https
    /// request and gets 200.
    #[tokio::test]
    async fn tls_happy_path_trusted_client_gets_200() {
        let (cert_pem, key_pem) = gen_self_signed();
        let cert_file = temp_pem("srv-cert", &cert_pem);
        let key_file = temp_pem("srv-key", &key_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: None,
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;

        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://localhost:{}/healthz", addr.port()))
            .send()
            .await
            .expect("https request should succeed over TLS");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    /// TEST 2 — mTLS required + valid client cert: client presents a leaf signed by the configured
    /// CA ⇒ 200.
    #[tokio::test]
    async fn mtls_valid_client_cert_gets_200() {
        let (srv_cert_pem, srv_key_pem) = gen_self_signed();
        let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

        let cert_file = temp_pem("m2-srv-cert", &srv_cert_pem);
        let key_file = temp_pem("m2-srv-key", &srv_key_pem);
        let ca_file = temp_pem("m2-ca", &ca_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: Some(crate::config::SecretRef::file(
                ca_file.to_string_lossy().into_owned(),
            )),
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;

        let identity =
            reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let resp = client
            .get(format!("https://localhost:{}/healthz", addr.port()))
            .send()
            .await
            .expect("mTLS request with valid client cert should succeed");
        assert_eq!(resp.status(), 200);
    }

    /// TEST 3 — mTLS required + no/wrong client cert: the handshake is rejected, the server stays up,
    /// and a subsequent valid client still succeeds.
    #[tokio::test]
    async fn mtls_rejects_bad_client_then_serves_valid() {
        let (srv_cert_pem, srv_key_pem) = gen_self_signed();
        let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

        let cert_file = temp_pem("m3-srv-cert", &srv_cert_pem);
        let key_file = temp_pem("m3-srv-key", &srv_key_pem);
        let ca_file = temp_pem("m3-ca", &ca_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: Some(crate::config::SecretRef::file(
                ca_file.to_string_lossy().into_owned(),
            )),
        };
        let (addr, _stop) = spawn_tls_server(&tls).await;
        let url = format!("https://localhost:{}/healthz", addr.port());

        // (a) Client presenting NO client cert ⇒ rejected (server requires one).
        let no_cert_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .use_rustls_tls()
            .build()
            .unwrap();
        let err = no_cert_client.get(&url).send().await;
        assert!(
            err.is_err(),
            "mTLS server must reject a client with no certificate"
        );

        // (b) Client presenting a cert from a DIFFERENT CA ⇒ also rejected.
        let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(vec!["impostor".into()]);
        let wrong_identity =
            reqwest::Identity::from_pem(format!("{wrong_leaf}{wrong_key}").as_bytes()).unwrap();
        let wrong_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(wrong_identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let wrong = wrong_client.get(&url).send().await;
        assert!(
            wrong.is_err(),
            "mTLS server must reject a client cert from an untrusted CA"
        );

        // (c) Server survived both rejections and still serves a valid client.
        let good_identity =
            reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
        let good_client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
            .identity(good_identity)
            .use_rustls_tls()
            .build()
            .unwrap();
        let resp = good_client
            .get(&url)
            .send()
            .await
            .expect("server must remain up and serve a valid client after rejecting bad ones");
        assert_eq!(resp.status(), 200);
    }

    /// TEST 4a — config regression: with NO `tls` block the plain-HTTP path still works. Drives the
    /// historical `axum::serve` over a plain TcpListener (the exact `None` branch in `main`).
    #[tokio::test]
    async fn plain_http_still_works_without_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            axum::serve(listener, test_router())
                .with_graceful_shutdown(shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", addr.port()))
            .await
            .expect("plain HTTP must still work when tls is absent");
        assert_eq!(resp.status(), 200);
        let _ = tx.send(());
    }

    /// TEST 4b — fail-fast: a bad cert path produces a clear, file-named error from
    /// `build_server_config` (which `main` turns into `die`). No server is started.
    #[test]
    fn bad_cert_path_errors_clearly() {
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-cert.pem"),
            key: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-key.pem"),
            client_ca: None,
        };
        let err = super::build_server_config(
            &tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect_err("missing cert file must error");
        assert!(
            err.contains("cert") && err.contains("does-not-exist-cert.pem"),
            "error must name the offending file: {err}"
        );
    }

    /// TEST 4c — fail-fast: a syntactically invalid PEM cert errors with the file named, not a panic.
    #[test]
    fn malformed_cert_errors_clearly() {
        let cert_file = temp_pem("bad-cert", "-----BEGIN CERTIFICATE-----\nnot base64\n");
        let (_c, key_pem) = gen_self_signed();
        let key_file = temp_pem("ok-key", &key_pem);
        let tls = TlsCfg {
            cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
            key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
            client_ca: None,
        };
        let err = super::build_server_config(
            &tls,
            &crate::config::secret::SecretResolver::builtins_only(),
        )
        .expect_err("malformed cert must error");
        assert!(err.contains("cert"), "error must reference the cert: {err}");
    }

    /// TEST 5 - REGRESSION (P1 slow-loris BODY): the inbound body-read timeout trips on a stalled
    /// request body. Before the fix, only the header-read phase was bounded; a client that finished
    /// its headers then dribbled (here: never sent) the promised body would pin the connection task,
    /// its FD, and one of the finite inbound-concurrency permits INDEFINITELY. This drives the plain
    /// serve loop (same `BodyTimeoutService` seam the TLS loop uses) over a raw socket: send a POST
    /// with a `Content-Length` but NO body, and assert the server closes the connection promptly
    /// (well inside a generous deadline) rather than hanging forever. A short body-read timeout is
    /// installed process-wide for the test; only that one non-default limit is set, so the other
    /// limits-accessor tests (which assert defaults for OTHER fields) are unaffected.
    #[tokio::test]
    async fn body_read_timeout_trips_on_stalled_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = LIMITS_TEST_LOCK.lock().await;
        // Install a SHORT body-read timeout (1s) so the test is fast; leave every other limit at its
        // historical default so no other limits test is perturbed.
        let limits = crate::config::LimitsResolved {
            request_body_read_timeout_secs: 1,
            ..crate::config::LimitsResolved::default()
        };
        crate::limits::install(&limits);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            // A route that WOULD read the body (POST /echo), so the server actually awaits body frames.
            let router = Router::new().route(
                "/echo",
                axum::routing::post(|body: String| async move { body }),
            );
            super::serve_plain(listener, router, shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Headers announce a 100-byte body; we send NONE of it, then stall.
        sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();

        // The server must close the connection (read yields EOF/reset) once the body-read bound (1s)
        // elapses with no body forthcoming. Bound the whole wait generously (5s): pre-fix this would
        // hang until the test's own deadline. `read` returning Ok(0) is a clean EOF; an Err is a
        // reset - either proves the server tore the stalled connection down.
        let mut buf = [0u8; 256];
        let outcome = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
        match outcome {
            Ok(Ok(0)) => {}  // clean EOF: server closed the stalled connection
            Ok(Ok(_n)) => {} // server may first write a 4xx/408-ish response, then close
            Ok(Err(_)) => {} // connection reset: also acceptable
            Err(_) => panic!(
                "body-read timeout did NOT trip: the server kept the stalled-body connection open \
                 past the deadline (slow-loris body regression)"
            ),
        }

        let _ = tx.send(());
    }

    /// TEST — the MINIMUM-THROUGHPUT floor cuts a body that dribbles fast enough that the
    /// inter-frame timer alone (which resets on ANY progress, `poll_frame`'s `this.sleep = None`)
    /// provably CANNOT be what tears the connection down. Copies the shape of
    /// `body_read_timeout_trips_on_stalled_body`: raw socket, `serve_plain`, a route that reads the
    /// body. The inter-frame timeout is set generously (30s, the historical default) and the client
    /// sends one byte every 200ms — far under the 30s inter-frame bound, so that timer never once
    /// arms long enough to fire. Only the hardcoded throughput floor (1 KiB/s after a 10s grace,
    /// `MIN_BODY_THROUGHPUT_BYTES_PER_SEC`/`BODY_THROUGHPUT_GRACE`) can catch this client, since
    /// `bytes/elapsed` at 5 B/s stays far below 1024 B/s for the whole test.
    ///
    /// SLOW BY CONSTRUCTION: the floor/grace are hardcoded consts, not operator knobs (per design),
    /// so this test cannot be sped up by installing a smaller limit — it must actually wait out the
    /// 10s grace period before the floor is even evaluated.
    #[tokio::test]
    async fn throughput_floor_trips_on_a_dribble_the_inter_frame_timer_cannot_catch() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = LIMITS_TEST_LOCK.lock().await;
        // Deliberately generous / left at the historical default: the point of this test is that
        // this timer NEVER fires (the dribble is far faster than 30s per byte).
        crate::limits::install(&crate::config::LimitsResolved::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            let router = Router::new().route(
                "/echo",
                axum::routing::post(|body: String| async move { body }),
            );
            super::serve_plain(listener, router, shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut rd, mut wr) = sock.into_split();
        wr.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\r\n")
            .await
            .unwrap();
        wr.flush().await.unwrap();

        let start = Instant::now();
        let writer = tokio::spawn(async move {
            loop {
                if wr.write_all(b"x").await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // Generous outer bound: must trip once the 10s grace elapses, well before the 30s
        // inter-frame timeout would ever have a chance to (it never stops being reset).
        let mut buf = [0u8; 256];
        let outcome = tokio::time::timeout(Duration::from_secs(20), rd.read(&mut buf)).await;
        let elapsed = start.elapsed();
        writer.abort();

        match outcome {
            Ok(Ok(0)) => {}  // clean EOF: server tore the connection down
            Ok(Ok(_n)) => {} // server may write a response first, then close
            Ok(Err(_)) => {} // reset: also acceptable
            Err(_) => panic!(
                "throughput floor did NOT trip: the server kept a 5 B/s dribble open past the \
                 generous outer bound"
            ),
        }
        // SANITY GATE: elapsed must be well under the 30s inter-frame timeout, or the inter-frame
        // timer (not the floor) is what fired and this test is measuring the wrong thing.
        assert!(
            elapsed < Duration::from_secs(25),
            "elapsed {elapsed:?} is too close to the 30s inter-frame timeout to attribute the \
             teardown to the throughput floor"
        );
        assert!(
            elapsed >= Duration::from_secs(9),
            "elapsed {elapsed:?} tripped before the throughput floor's own 10s grace period \
             elapsed — something else tore the connection down"
        );

        let _ = tx.send(());
    }

    /// TEST — a legitimate fast large upload is NOT killed by the throughput floor or the total
    /// deadline. REGRESSION PROOF (passes before AND after the floor/deadline existed — a body that
    /// arrives promptly and in one shot was never at risk from the inter-frame timer either). Exists
    /// to catch a floor/grace/total value that false-positives on honest traffic.
    #[tokio::test]
    async fn a_fast_large_upload_is_not_killed_by_the_throughput_floor() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = LIMITS_TEST_LOCK.lock().await;
        crate::limits::install(&crate::config::LimitsResolved::default());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            let router = Router::new().route(
                "/echo",
                axum::routing::post(|body: bytes::Bytes| async move { body.len().to_string() }),
            );
            super::serve_plain(listener, router, shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = vec![b'x'; 200_000];
        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(
            format!(
                "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        sock.write_all(&body).await.unwrap();
        sock.flush().await.unwrap();

        // `read_to_end` would block on EOF that never arrives: the connection is a normal HTTP/1.1
        // keep-alive connection, so the server holds it open after responding rather than closing it.
        // Read until the expected echoed length shows up in the response instead — that is the
        // observable "a promptly-delivered body was not killed" signal, not connection closure.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let outcome = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let n = sock.read(&mut chunk).await?;
                if n == 0 {
                    break; // EOF: connection closed (also acceptable if it happens after the body)
                }
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains("200000") {
                    break;
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        assert!(
            outcome.is_ok(),
            "a promptly-delivered large body must not be killed by the throughput floor/total deadline"
        );
        let resp = String::from_utf8_lossy(&buf);
        assert!(
            resp.contains("200000"),
            "the full body must have been echoed back: {resp}"
        );

        let _ = tx.send(());
    }

    /// TEST — the TOTAL deadline trips on a body that stays ABOVE the throughput floor forever (so
    /// the floor itself never fires) — the backstop for a client that paces itself just fast enough
    /// to never trip the floor but never finishes either. `total_body_deadline` is DERIVED from
    /// `request_body_max_bytes / MIN_BODY_THROUGHPUT_BYTES_PER_SEC`, so shrinking the configured cap
    /// to 2048 bytes gives a fast (~2s) deadline without touching either hardcoded const — this is
    /// also, incidentally, the regression proof that the total is derived rather than a bare
    /// constant (a fixed 600s total would make this test take ten minutes).
    #[tokio::test]
    async fn total_deadline_trips_on_a_body_that_stays_above_the_floor_forever() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = LIMITS_TEST_LOCK.lock().await;
        let limits = crate::config::LimitsResolved {
            request_body_max_bytes: 2048, // total_body_deadline() = 2048 / 1024 B/s = 2s
            ..crate::config::LimitsResolved::default()
        };
        crate::limits::install(&limits);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            let router = Router::new().route(
                "/echo",
                axum::routing::post(|body: String| async move { body }),
            );
            super::serve_plain(listener, router, shutdown)
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut rd, mut wr) = sock.into_split();
        // A Content-Length the body never reaches, so the ONLY way this connection ends is a bound
        // tripping.
        wr.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000000\r\n\r\n")
            .await
            .unwrap();
        wr.flush().await.unwrap();

        let start = Instant::now();
        // 200 bytes every 100ms = 2000 B/s, comfortably ABOVE the 1024 B/s floor for the whole test
        // (and well before the 10s grace period even starts mattering, since the 2s total fires
        // first) - this dribble is never what tears the connection down.
        let writer = tokio::spawn(async move {
            let chunk = vec![b'x'; 200];
            loop {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let mut buf = [0u8; 256];
        let outcome = tokio::time::timeout(Duration::from_secs(8), rd.read(&mut buf)).await;
        let elapsed = start.elapsed();
        writer.abort();

        match outcome {
            Ok(Ok(0)) => {}
            Ok(Ok(_n)) => {}
            Ok(Err(_)) => {}
            Err(_) => panic!(
                "total deadline did NOT trip: the server kept an above-floor-forever body open \
                 past the generous outer bound"
            ),
        }
        assert!(
            elapsed < Duration::from_secs(5),
            "elapsed {elapsed:?} is too far past the 2s total deadline to attribute the teardown \
             to it rather than some other bound"
        );

        let _ = tx.send(());
    }
}
