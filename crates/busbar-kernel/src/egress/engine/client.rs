// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED ENGINE CLIENT — the request-facing half of the owned pool (`pool.rs` is the
//! checkout/dial machinery). Replaces `hyper_util::client::legacy::Client` behind the SAME
//! surface: `request(http::Request<Full<Bytes>>) -> Future<Result<Response<Incoming>, _>>`,
//! cheap-clone handle over a shared pool.
//!
//! This file owns the two layers the legacy client performed silently and the design re-owns
//! explicitly (they were the audit's blocker findings — silently dropping either malforms the
//! wire or double-sends a billing POST):
//!
//! * REQUEST PREPARATION, applied per attempt: the version gate, the absolute-form
//!   requirement (the URI is also the pool key), h1-only `Host` injection (host:port only when
//!   non-default), and the h1 origin-form rewrite — hyper's low-level `conn::http1` writes the
//!   URI verbatim and only the headers present, so without this layer the first h1 request goes
//!   out absolute-form with no Host and RFC 9112 servers MUST 400 it. h2 sends keep the
//!   absolute-form URI (hyper derives `:authority`/`:path` from it). `CaptureConnectionExtension`
//!   is deliberately NOT replicated: no busbar caller sets it (zero grep hits) — a decision, not
//!   an oversight.
//!
//! * THE RETURN PATH + IDLE-REUSE RETRY: after the response head, the conn returns to the
//!   pool inline when already ready (body drained at head time) or via a spawned watcher that
//!   resolves when hyper's dispatcher finishes the exchange — the same per-undrained-exchange
//!   task legacy pays. The retry trigger is hyper's EXACT signal: `try_send_request` handing the
//!   request back via `take_message()` (the dispatcher never accepted it for writing) AND the
//!   conn being a reused one. Like legacy, the retry LOOPS — each round restores the original
//!   absolute-form URI and re-runs checkout — and terminates structurally because a fresh conn's
//!   failure is never retried. Anything the dispatcher accepted (headers flushed then RST, body
//!   partially written) yields no message back and propagates: the anti-duplicate boundary for
//!   non-idempotent outbound POSTs.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{header::HOST, Method, Request, Response, Uri, Version};
use http_body_util::Full;
use hyper::body::Incoming;

use super::pool::{self, CheckedOut, ClientInner, EngineError, ErrorKind, PoolKey, PoolMap};
use super::{EngineConnector, H2KeepAlive};

/// THE CONNECTION'S RETURN, as a response extension: present on an HTTP/1.1 response whose
/// connection goes back to its pool only once hyper's dispatcher finishes the exchange (the body
/// was not drained at head time). [`ConnReturned::settled`] resolves once that return has happened,
/// or the connection died and is dropped. A caller that reads the body to its end and then reports
/// that end awaits it first, so a hop opened after that end is lent the connection back in the pool
/// instead of racing its return with a fresh dial (a second connection the second hop never rides).
#[derive(Clone, Debug)]
pub struct ConnReturned(tokio::sync::watch::Receiver<bool>);

impl ConnReturned {
    /// The connection is back in its pool, or dropped (it died, or the pool is gone).
    pub async fn settled(mut self) {
        let _ = self.0.wait_for(|returned| *returned).await;
    }
}

/// A delay before a watcher's return, per authority (`host:port`): the window between a body's end
/// and its connection's return, held open so a test meets the order a loaded host gives by chance.
#[cfg(test)]
pub(crate) static RETURN_DELAY_FOR_TESTS: Mutex<Option<(String, Duration)>> = Mutex::new(None);

/// The pooled egress client — the owned struct behind the seam every plane builds from
/// (`build_client`). Cheap to clone: clones share one pool; dropping the last clone releases the
/// pool and closes its idle sockets.
pub struct EngineClient {
    inner: Arc<ClientInner>,
}

impl Clone for EngineClient {
    fn clone(&self) -> Self {
        EngineClient {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for EngineClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineClient").finish()
    }
}

/// The pool knobs `build_client` resolves from an `EngineSpec` (tests assemble directly to pin
/// sub-second timeouts and explicit dial bounds without touching the process-global topology).
pub(crate) struct PoolConfig {
    pub(crate) idle_cap_per_host: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) http1_only: bool,
    pub(crate) h2_prior_knowledge: bool,
    pub(crate) h2_keepalive: Option<H2KeepAlive>,
    pub(crate) dial_bound: usize,
}

impl EngineClient {
    /// Assemble a client over an already-built connector stack. `build_client` is the one
    /// production caller; tests use it to drive fixture connectors through the REAL pool.
    pub(crate) fn assemble(connector: EngineConnector, cfg: PoolConfig) -> Self {
        EngineClient {
            inner: Arc::new(ClientInner {
                connector,
                pool: Mutex::new(PoolMap {
                    map: std::collections::HashMap::new(),
                    reaper_running: false,
                }),
                idle_cap_per_host: cfg.idle_cap_per_host,
                idle_timeout: cfg.idle_timeout,
                http1_only: cfg.http1_only,
                h2_prior_knowledge: cfg.h2_prior_knowledge,
                h2_keepalive: cfg.h2_keepalive,
                dial_bound: cfg.dial_bound,
                #[cfg(test)]
                retry_bounces: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    /// Send one request: checkout (idle hit, or parked waiter under the coalescing invariant),
    /// per-attempt request preparation, send, return-path handling. The returned future is
    /// heap-boxed exactly as legacy's `ResponseFuture` was, so the caller's inline contribution
    /// stays one pointer — the hot-future size tripwire's shape.
    pub fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Incoming>, EngineError>> + Send + 'static>>
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(send_request(inner, req))
    }

    /// The per-client dial bound this client was built with (test-pinned equal to the
    /// gate's permit count — bound == permits is the compose argument).
    #[cfg(test)]
    pub(crate) fn dial_bound_for_tests(&self) -> usize {
        self.inner.dial_bound
    }

    /// Test handle onto the shared pool state.
    #[cfg(test)]
    pub(crate) fn inner_for_tests(&self) -> &Arc<ClientInner> {
        &self.inner
    }

    /// How many take_message bounces the retry loop has taken — the direct pin for the
    /// idle-reuse retry arm.
    #[cfg(test)]
    pub(crate) fn retry_bounces_for_tests(&self) -> usize {
        self.inner
            .retry_bounces
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// (authorities, reaper_running) — the config-off zero-cost probe reads this.
    #[cfg(test)]
    pub(crate) fn pool_stats_for_tests(&self) -> (usize, bool) {
        let pm = super::pool::lock_pool(&self.inner);
        (pm.map.len(), pm.reaper_running)
    }
}

async fn send_request(
    inner: Arc<ClientInner>,
    mut req: Request<Full<Bytes>>,
) -> Result<Response<Incoming>, EngineError> {
    // Preparation, part 1 — the version gate, legacy's exact arms: 1.1/2 pass; 1.0 passes unless the
    // method is CONNECT; anything else (HTTP/0.9) is refused.
    let is_http_connect = req.method() == Method::CONNECT;
    match req.version() {
        Version::HTTP_11 | Version::HTTP_2 => {}
        Version::HTTP_10 => {
            if is_http_connect {
                return Err(EngineError::new(ErrorKind::UserUnsupportedRequestMethod));
            }
        }
        _ => return Err(EngineError::new(ErrorKind::UserUnsupportedVersion)),
    }

    // Preparation, part 2 — absolute-form required: scheme+authority IS the pool key. The CONNECT
    // scheme-inference arm is unreachable for busbar (the tunnel lives below the connector) but
    // kept for surface fidelity.
    let pool_key = extract_domain(req.uri_mut(), is_http_connect)?;
    let original_uri = req.uri().clone();

    // The idle-reuse retry LOOP: a reused conn that hands the request back via
    // `take_message()` sends the request around again through a fresh checkout; the reused-idle
    // population strictly decreases (each bounce destroys the bouncing conn) and a fresh conn's
    // failure exits, so the loop terminates structurally.
    loop {
        let conn = pool::checkout(&inner, &pool_key).await?;
        // Restore the original absolute-form URI: the previous attempt's origin-form rewrite
        // mutated it (legacy does the same restore per retry).
        *req.uri_mut() = original_uri.clone();

        match conn {
            CheckedOut::H1 {
                mut sender,
                extras,
                reused,
            } => {
                // Preparation, part 5 — an HTTP/2 request on an h1 conn is an error, not a downgrade.
                if req.version() == Version::HTTP_2 {
                    return Err(EngineError::new(ErrorKind::UserUnsupportedVersion));
                }
                // Preparation, part 3 — Host injection, h1 only, never overwriting a caller-set Host;
                // port included only when non-default for the scheme.
                set_host_header(&mut req);
                // Preparation, part 4 — request-target form: authority-form for CONNECT (unreachable),
                // origin-form otherwise. `absolute_form` applies only under `is_proxied`, which
                // busbar's CONNECT tunnel never sets (it yields an end-to-end TLS stream, not a
                // plaintext proxy hop) — origin-form-always is correct here, structurally.
                if req.method() == Method::CONNECT {
                    authority_form(req.uri_mut());
                } else {
                    origin_form(req.uri_mut());
                }

                match sender.try_send_request(req).await {
                    Ok(mut resp) => {
                        inject_extras(&mut resp, &extras);
                        // The return path: inline when the exchange already finished (body
                        // drained at head time), else the per-exchange watcher — hyper's h1
                        // `poll_ready` resolves only when the dispatcher finishes the exchange,
                        // which is gated on the caller draining `Incoming`.
                        // A test's lag on this authority's return (see `RETURN_DELAY_FOR_TESTS`)
                        // takes the watcher path even when the exchange already finished.
                        #[cfg(test)]
                        let lag = RETURN_DELAY_FOR_TESTS
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .as_ref()
                            .filter(|(at, _)| *at == pool_key.1.as_str())
                            .map(|(_, d)| *d);
                        #[cfg(not(test))]
                        let lag: Option<Duration> = None;
                        if sender.is_ready() && lag.is_none() {
                            pool::return_h1_conn(&inner, &pool_key, sender, extras);
                        } else {
                            let weak = Arc::downgrade(&inner);
                            let key = pool_key.clone();
                            // The response carries the return's settling, for a caller that
                            // reports the body's end only once its connection is back.
                            let (returned, settled) = tokio::sync::watch::channel(false);
                            resp.extensions_mut().insert(ConnReturned(settled));
                            tokio::spawn(async move {
                                let ready = std::future::poll_fn(|cx| sender.poll_ready(cx)).await;
                                if let Some(lag) = lag {
                                    tokio::time::sleep(lag).await;
                                }
                                // An Err means the conn died during the body read: drop it —
                                // never returned, nothing delivered, no counter touched.
                                if ready.is_ok() {
                                    if let Some(inner) = weak.upgrade() {
                                        pool::return_h1_conn(&inner, &key, sender, extras);
                                    }
                                }
                                let _ = returned.send(true);
                            });
                        }
                        return Ok(resp);
                    }
                    Err(e) => req = inner.retry_or_fail(e, reused)?,
                }
            }
            CheckedOut::H2 {
                mut sender,
                extras,
                reused,
            } => {
                // Preparation, part 6 — no Host injection, no origin-form: hyper's `conn::http2`
                // derives `:authority`/`:path` from the absolute-form URI, exactly as legacy
                // (its whole preparation block runs under `is_http1()`).
                match sender.try_send_request(req).await {
                    Ok(mut resp) => {
                        inject_extras(&mut resp, &extras);
                        // The shared conn never left the pool; dropping this clone is the whole
                        // return path for h2.
                        return Ok(resp);
                    }
                    Err(e) => req = inner.retry_or_fail(e, reused)?,
                }
            }
        }
    }
}

impl ClientInner {
    /// A send the conn refused. A REUSED conn that handed the request back was a stale idle conn:
    /// the request goes round the loop again (`Ok`). A FRESH conn that handed it back failed for
    /// real and terminally — never retried (legacy's Canceled kind, not connect). No request back
    /// means the dispatcher accepted it (headers may have flushed, body may be partially written):
    /// the anti-duplicate boundary — propagate, never retry.
    fn retry_or_fail(
        &self,
        mut e: hyper::client::conn::TrySendError<Request<Full<Bytes>>>,
        reused: bool,
    ) -> Result<Request<Full<Bytes>>, EngineError> {
        let kind = match e.take_message() {
            Some(returned) if reused => {
                #[cfg(test)]
                self.retry_bounces
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Ok(returned);
            }
            Some(_) => ErrorKind::Canceled,
            None => ErrorKind::SendRequest,
        };
        Err(EngineError::with_source(kind, e.into_error()))
    }
}

/// Copy the connection's observed extras onto the response — the contract the observe spike
/// pins: EVERY response served on a connection carries that connection's `PeerKeyPin`.
fn inject_extras(resp: &mut Response<Incoming>, extras: &pool::ConnSnapshot) {
    if let Some(key_pin) = &extras.key_pin {
        resp.extensions_mut().insert(key_pin.clone());
    }
}

/// Preparation, part 3 — insert `Host` (or `host:port` when the port is non-default for the scheme)
/// when the caller set none. Legacy's `set_host` default-true behavior, h1-only by call site.
fn set_host_header(req: &mut Request<Full<Bytes>>) {
    // A caller-set Host wins, checked FIRST so the common already-set case is one map probe and
    // the value is computed BEFORE `headers_mut()` is taken — which is what lets the URI be read
    // in place instead of cloned whole to satisfy the headers_mut/uri borrow split.
    if req.headers().contains_key(HOST) {
        return;
    }
    let uri = req.uri();
    let hostname = uri.host().expect("an absolute-form URI implies a host");
    let value = match get_non_default_port(uri) {
        Some(port) => {
            http::HeaderValue::from_maybe_shared(Bytes::from(format!("{hostname}:{port}")))
        }
        None => http::HeaderValue::from_str(hostname),
    }
    .expect("a URI host is a valid header value");
    req.headers_mut().insert(HOST, value);
}

/// Legacy `get_non_default_port`: 443-on-secure and 80-on-plain are the default ports and stay
/// off the Host header; anything else rides along.
fn get_non_default_port(uri: &Uri) -> Option<u16> {
    match (uri.port_u16(), is_schema_secure(uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        (port, _) => port,
    }
}

fn is_schema_secure(uri: &Uri) -> bool {
    matches!(uri.scheme_str(), Some("wss") | Some("https"))
}

/// Preparation, part 4 — rewrite to origin-form (path + query only; empty or `/` becomes `/`) so hyper's
/// h1 encoder writes `POST /path HTTP/1.1`, never the absolute form.
fn origin_form(uri: &mut Uri) {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            Uri::from_parts(parts).expect("a path is a valid origin-form URI")
        }
        _none_or_just_slash => Uri::default(),
    };
    *uri = path;
}

/// CONNECT sends authority-form. Unreachable for busbar (no caller issues CONNECT through the
/// client — the tunnel lives below the connector) but kept for surface fidelity with legacy.
fn authority_form(uri: &mut Uri) {
    *uri = match uri.authority() {
        Some(auth) => {
            let mut parts = http::uri::Parts::default();
            parts.authority = Some(auth.clone());
            Uri::from_parts(parts).expect("an authority is a valid authority-form URI")
        }
        None => unreachable!("authority_form is only called on an absolute-form URI"),
    };
}

/// Preparation, part 2 — the pool key is the URI's scheme+authority; a relative URI is an immediate
/// error. The CONNECT arm infers a scheme from the port (443 → https), legacy-verbatim.
fn extract_domain(uri: &mut Uri, is_http_connect: bool) -> Result<PoolKey, EngineError> {
    // The common arm reads through an immutable reborrow and returns — no full-Uri clone on the
    // hot path (only the two component clones that build the owned PoolKey). The `&mut` parameter
    // exists solely for the CONNECT scheme-inference arm below.
    if let (Some(scheme), Some(auth)) = (uri.scheme(), uri.authority()) {
        return Ok((scheme.clone(), auth.clone()));
    }
    match uri.authority() {
        Some(auth) if is_http_connect && uri.scheme().is_none() => {
            let auth = auth.clone();
            let scheme = match auth.port_u16() {
                Some(443) => http::uri::Scheme::HTTPS,
                _ => http::uri::Scheme::HTTP,
            };
            set_scheme(uri, scheme.clone());
            Ok((scheme, auth))
        }
        _ => Err(EngineError::new(ErrorKind::UserAbsoluteUriRequired)),
    }
}

/// Test window onto the Host-injection rule (the default-port formatting cannot be pinned
/// through a loopback fixture — nothing can listen on 80/443).
#[cfg(test)]
pub(crate) fn set_host_header_for_tests(req: &mut Request<Full<Bytes>>) {
    set_host_header(req);
}

fn set_scheme(uri: &mut Uri, scheme: http::uri::Scheme) {
    debug_assert!(
        uri.scheme().is_none(),
        "set_scheme expects no existing scheme"
    );
    let old = std::mem::take(uri);
    let mut parts: http::uri::Parts = old.into();
    parts.scheme = Some(scheme);
    parts.path_and_query = Some("/".parse().expect("slash is a valid path"));
    *uri = Uri::from_parts(parts).expect("scheme is valid");
}
