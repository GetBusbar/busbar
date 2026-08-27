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

use crate::diagnostics::{diag_warn, TLS_ACCEPT_PERSISTENT_FAILURE};
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
pub fn install_crypto_provider() {
    // Err(_) => some other code path already installed a provider. Since busbar only ever links ring,
    // that provider is ring too, so there is nothing to fix and nothing to warn about.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Resolve a TLS secret reference to its PEM bytes, mapping any resolve error into a clear,
/// source-named message. Never logs contents.
///
/// `pub(crate)` because the A2A plane's OUTBOUND client identity
/// (`crate::a2a::transport::resolve_client_identities`) loads its cert and key through this one
/// function too. One place in the tree turns a `SecretRef` into TLS PEM; a second would be a second
/// place for the "never echo what you read" rule to be forgotten.
pub(crate) fn read_pem(
    resolver: &dyn busbar_api::SecretResolve,
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
pub fn build_server_config(
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

/// Serve `router` over TLS on `listener` until `shutdown` resolves, then drain in-flight connections.
///
/// Mirrors `axum::serve(listener, router).with_graceful_shutdown(shutdown)` for the TLS case:
/// each accepted connection is handshook with rustls and served with hyper's auto builder (http/1.1).
/// A handshake or accept error affects only that one connection — the accept loop continues, so a
/// rejected mTLS client (wrong/missing cert) never takes the server down or blocks other clients.
pub async fn serve(
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
pub async fn serve_plain(
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
#[path = "tests/tls_tests.rs"]
mod tests;
