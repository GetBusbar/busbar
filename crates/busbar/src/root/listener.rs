// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the composition root keeps of its listener after the native cutover: the accept-error
//! backoff and socket admission (non-unix accept path), the per-worker connection balancer the native
//! supervisor shares, the request body bounds, and the deferred dispatch layer. Serving itself is
//! the native listener (`listener_native`); TLS is the connector's connection security.

#[cfg(any(test, not(unix)))]
use std::io;
use std::sync::Arc;

#[cfg(any(test, not(unix)))]
use busbar_kernel::diagnostics::{diag_warn, TLS_ACCEPT_PERSISTENT_FAILURE};
use std::time::Duration;

const MIN_BODY_THROUGHPUT_BYTES_PER_SEC: u64 = 1024;

const BODY_THROUGHPUT_GRACE: Duration = Duration::from_secs(10);

pub(crate) fn total_body_deadline() -> Duration {
    let cap_bytes = busbar_kernel_egress::upstream::max_translate_body_bytes() as u64;
    Duration::from_secs(cap_bytes / MIN_BODY_THROUGHPUT_BYTES_PER_SEC)
}

use std::pin::Pin;

use axum::Router;
use busbar_core_connector::listen::{Admits, Admitted};
use http_body::Body;
#[cfg(any(test, not(unix)))]
use tokio::net::TcpListener;

/// The admin listener scheme a socket-accepted connection states (non-unix accept path and tests).
#[cfg(any(test, not(unix)))]
pub(crate) const REQUEST_WIRE: &str = busbar_core_admin::admin_codec::claims::TRANSPORT;

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
#[cfg(any(test, not(unix)))]
struct AcceptBackoff {
    delays: busbar_core_connector::listen::AcceptBackoff,
}

#[cfg(any(test, not(unix)))]
impl AcceptBackoff {
    #[cfg(test)]
    const FIRST: std::time::Duration = busbar_core_connector::listen::AcceptBackoff::FIRST;
    #[cfg(test)]
    const CAP: std::time::Duration = busbar_core_connector::listen::AcceptBackoff::CAP;

    fn new() -> Self {
        Self {
            delays: busbar_core_connector::listen::AcceptBackoff::default(),
        }
    }

    fn reset(&mut self) {
        self.delays.reset();
    }

    fn next_delay(&mut self, e: &io::Error) -> Option<std::time::Duration> {
        self.delays.next_delay(e)
    }

    async fn absorb(&mut self, scheme: &'static str, e: &io::Error) {
        match self.next_delay(e) {
            None => tracing::debug!(error = %e, "{scheme}: accept error; continuing"),
            Some(d) => {
                diag_warn!(
                    TLS_ACCEPT_PERSISTENT_FAILURE,
                    error = %e,
                    backoff_ms = d.as_nanos().div_ceil(1_000_000) as u64,
                    "{scheme}: accept is failing persistently (fd exhaustion?); backing off",
                );
                tokio::time::sleep(d).await;
            }
        }
    }
}

#[cfg(any(test, not(unix)))]
pub struct SocketAdmits {
    listener: TcpListener,
    backoff: AcceptBackoff,
    scheme: &'static str,
}

#[cfg(any(test, not(unix)))]
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

#[cfg(any(test, not(unix)))]
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

pub(crate) const HANDOFF_CHANNEL_DEPTH: usize = 16;

#[repr(align(64))]
pub(crate) struct PaddedCount(pub(crate) std::sync::atomic::AtomicU32);

pub struct ConnBalancer {
    pub(crate) counts: Arc<[PaddedCount]>,
    pub(crate) txs: Arc<[tokio::sync::mpsc::Sender<Admitted>]>,
    pub(crate) me: usize,
    pub(crate) rx: tokio::sync::mpsc::Receiver<Admitted>,
}

impl ConnBalancer {
    pub(crate) fn try_hand_off(&self, admitted: Admitted) -> Option<Admitted> {
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

    pub(crate) fn place_local(&self) -> ConnCountGuard {
        use std::sync::atomic::Ordering;
        self.counts[self.me].0.fetch_add(1, Ordering::Relaxed);
        ConnCountGuard {
            counts: self.counts.clone(),
            idx: self.me,
        }
    }

    pub(crate) fn adopt(&self) -> ConnCountGuard {
        ConnCountGuard {
            counts: self.counts.clone(),
            idx: self.me,
        }
    }
}

pub(crate) struct ConnCountGuard {
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

/// Why a request body is refused when the TOTAL body deadline or the MINIMUM-THROUGHPUT floor is
/// exceeded (a dribbling client that keeps an inter-frame timer reset forever). Generic message,
/// no client bytes.
#[derive(Debug)]
pub(crate) enum BodyBoundExceeded {
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

pub(crate) fn check_body_bounds(started: u64, now: u64, bytes: u64) -> Option<BodyBoundExceeded> {
    let elapsed = Duration::from_nanos(now.saturating_sub(started));
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

pub(crate) fn deferred_dispatch_layer<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn(deferred_dispatch))
}

async fn deferred_dispatch(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !defers_dispatch(&req) {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    match read_whole(
        body,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
    )
    .await
    {
        Ok(bytes) => {
            next.run(hyper::Request::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ))
            .await
        }
        Err(status) => status_response(status),
    }
}

fn defers_dispatch<B: Body>(req: &hyper::Request<B>) -> bool {
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
    mut body: axum::body::Body,
    cap: usize,
) -> Result<bytes::Bytes, hyper::StatusCode> {
    let mut whole = bytes::BytesMut::new();
    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
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

#[cfg(test)]
#[path = "tests/listener_tests.rs"]
mod tests;
