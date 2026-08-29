// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED CONNECTION POOL with dial coalescing — the machinery that replaces
//! `hyper_util::client::legacy::Client`'s shared-mutex pool and its checkout/connect race.
//!
//! One pool per built client (= per worker shard on the LLM lanes). Per authority, ONE invariant
//! governs establishment: `inflight_dials == min(waiters.len(), dial_bound)` whenever waiters
//! exist — dials are started only by [`ensure_dials`], never by a waiter directly, and every dial
//! task is a DETACHED spawn no cancellation can abort. A completed dial's socket is always
//! consumed (next live waiter, the idle list, or the h2 straggler-close), so the legacy client's
//! overshoot regime — every checkout racing its own fresh connect, losers dropped post-SYN — is
//! structurally impossible rather than tuned away.
//!
//! h1 idles LIFO (most-recently-parked reused first: TLS session hot, TCP window open) and
//! expires FIFO (oldest ages out) — hyper_util's own idle order, kept deliberately so the surplus
//! above the working set drains on the idle timer instead of being slammed closed. h2 degenerates
//! to singleflight: one multiplexed conn per authority, dial bound 1 while the authority is known
//! h2, generation-guarded clearing on driver exit, and dial FAILURE for an h2-known authority
//! BROADCASTS to every parked waiter (legacy parity: a failed h2 `Connecting`'s drop removed all
//! waiters for the key) so a dead h2 upstream errors its whole queue inside one connect attempt.

use std::collections::{HashMap, VecDeque};
use std::error::Error as StdError;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::{http1, http2};

use super::{EngineConnector, H2KeepAlive, PeerSpki};

/// The pool key — scheme + authority, exactly legacy's, which is why the userinfo strip in
/// [`super::request`] stays load-bearing (userinfo must never reach this key).
pub(crate) type PoolKey = (http::uri::Scheme, http::uri::Authority);

/// What one client build knows; shared by refcount between the client handle, its in-flight
/// requests, and the transient dial/reaper tasks (the long-lived watcher and driver-exit tasks
/// hold only a `Weak`, so dropping the last client handle releases the pool and its sockets).
pub(crate) struct ClientInner {
    pub(crate) connector: EngineConnector,
    pub(crate) pool: Mutex<PoolMap>,
    pub(crate) idle_cap_per_host: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) http1_only: bool,
    pub(crate) h2_prior_knowledge: bool,
    pub(crate) h2_keepalive: Option<H2KeepAlive>,
    /// The per-client dial bound: the ConnectGate's share of the global establishment budget
    /// (sharded clients) or the undivided budget (pinned single-client postures). Resolved once
    /// at build time by [`super::dial_bound_for`] — the same value the gate's permits use, so
    /// bound == permits and the gate's semaphore is never contended by pool-issued dials.
    pub(crate) dial_bound: usize,
}

impl ClientInner {
    /// `h2_prior_knowledge` pins the protocol by POSTURE (never by evidence): `proto = H2` a
    /// priori and no clear ever reverts it. `http1_only` wins over it, preserving the legacy
    /// builder's apply-order.
    pub(crate) fn h2_pinned(&self) -> bool {
        self.h2_prior_knowledge && !self.http1_only
    }
}

/// The per-client pool: the authority map plus the on-demand reaper's liveness flag, one lock.
/// The lock is held only for O(1) deque/map operations — never across an await, never for an
/// expiry scan on the hot path.
pub(crate) struct PoolMap {
    pub(crate) map: HashMap<PoolKey, AuthorityState>,
    /// Whether the on-demand reaper task is alive. Spawned on the first idle park / h2 install,
    /// exits when the pool holds nothing expirable — config-off planes and idle-empty pools run
    /// ZERO background tasks.
    pub(crate) reaper_running: bool,
}

/// What the pool has learned about an authority's protocol. `H2` is evidence-backed only while
/// [`AuthorityState::h2`] is `Some` — cleared entries revert to `Unknown` (the KnownProto
/// transition rule) unless the posture pins it — so the pool can never be stranded in behaviors
/// (serial bound-1 dialing, whole-queue error broadcasts) against a fleet that rolled back to h1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KnownProto {
    Unknown,
    H1,
    H2,
}

/// What was observed at connect time, captured ONCE from the connector's stream and replayed
/// into every response this connection serves — the extras contract the observe spike pins.
#[derive(Clone)]
pub(crate) struct ConnSnapshot {
    pub(crate) spki: Option<PeerSpki>,
    /// Whether ALPN negotiated h2 on this connection (posture-forced h2c does not set this;
    /// the protocol branch reads posture separately).
    #[allow(dead_code)] // captured for observability parity; the variant carries the protocol
    pub(crate) negotiated_h2: bool,
}

/// One checked-out send handle, as delivered to a request. `reused` feeds the idle-reuse retry
/// boundary: only a REUSED conn's `take_message()` bounce is retried — a fresh dial's
/// failure is real and terminal, which is what makes the retry loop terminate structurally.
pub(crate) enum CheckedOut {
    H1 {
        sender: http1::SendRequest<Full<Bytes>>,
        extras: ConnSnapshot,
        reused: bool,
    },
    H2 {
        sender: http2::SendRequest<Full<Bytes>>,
        extras: ConnSnapshot,
        reused: bool,
    },
}

impl CheckedOut {
    /// Delivered-conn liveness, checked by the WAITER on receipt: a conn that died between the
    /// deliverer's check and the waiter waking is dead-on-arrival — dropped, and the waiter
    /// re-enters checkout (legacy `CheckedOutClosedValue` recovery, a checkout-level retry
    /// exempt from the request-level `take_message()` accounting).
    pub(crate) fn is_live(&self) -> bool {
        match self {
            CheckedOut::H1 { sender, .. } => sender.is_ready() && !sender.is_closed(),
            CheckedOut::H2 { sender, .. } => sender.is_ready() && !sender.is_closed(),
        }
    }
}

/// One parked idle h1 connection. Liveness is checked lazily at pop time (the driver task's exit
/// makes `is_closed()` true); expiry is `idle_since + idle_timeout`, consumed from the deque
/// FRONT (oldest) by the reaper and for free at checkout time.
pub(crate) struct IdleConn {
    pub(crate) sender: http1::SendRequest<Full<Bytes>>,
    pub(crate) extras: ConnSnapshot,
    pub(crate) idle_since: Instant,
}

/// The one multiplexed h2 connection an authority holds. `last_checkout` is the h2 idle clock —
/// legacy reinserts the shared reservation with `idle_at: now` on every checkout, so eviction is
/// idle-timeout-since-last-CHECKOUT, one `Instant` store on the already-locked fast path.
pub(crate) struct H2Entry {
    pub(crate) sender: http2::SendRequest<Full<Bytes>>,
    pub(crate) extras: ConnSnapshot,
    /// Equal to [`AuthorityState::h2_generation`] at install time. A driver-exit handler clears
    /// `st.h2` only when its generation matches, so a STALE conn's late exit can never clear a
    /// newer healthy entry (the generation guard).
    pub(crate) generation: u64,
    pub(crate) last_checkout: Instant,
}

/// A parked checkout. A dropped receiver (caller cancelled, `send_deadline` elapsed) is a CORPSE:
/// deliverers skip it on both the success and the failure walk — it can never kill a dial,
/// because no waiter owns one.
pub(crate) type Waiter = tokio::sync::oneshot::Sender<Result<CheckedOut, DialError>>;

/// A dial failure as delivered to waiters. The cause is `Arc`'d because the h2 failure arm
/// BROADCASTS one cause to N waiters; the `source()` chain stays object-intact end-to-end so
/// core's downcast walk still finds the `ConnectDeadline`'s `io::ErrorKind::TimedOut`.
pub(crate) struct DialError {
    pub(crate) cause: Arc<dyn StdError + Send + Sync>,
}

/// Everything the pool tracks for one (scheme, authority). Entries are created lazily on first
/// request and never evicted — growth is bounded by configured authorities, the same envelope
/// the ConnectGate registry already accepts.
pub(crate) struct AuthorityState {
    pub(crate) proto: KnownProto,
    pub(crate) idle: VecDeque<IdleConn>,
    pub(crate) h2: Option<H2Entry>,
    pub(crate) h2_generation: u64,
    pub(crate) waiters: VecDeque<Waiter>,
    pub(crate) inflight_dials: usize,
}

impl AuthorityState {
    fn new(h2_pinned: bool) -> Self {
        AuthorityState {
            proto: if h2_pinned {
                KnownProto::H2
            } else {
                KnownProto::Unknown
            },
            idle: VecDeque::new(),
            h2: None,
            h2_generation: 0,
            waiters: VecDeque::new(),
            inflight_dials: 0,
        }
    }
}

// ── The owned error type ─────────────────────────────────────────────────────────────────────────

/// The error [`super::EngineClient::request`] yields — the owned replacement for
/// `hyper_util::client::legacy::Error`, same consumer contracts:
/// * [`EngineError::is_connect`] — substrate's `HopError` Connect-vs-Io split (MCP/A2A planes);
/// * [`std::error::Error::source`] — the cause chain carried as ERROR OBJECTS end-to-end (never
///   stringified), so core's `EgressSendError::is_timeout()` downcast walk finds the
///   `ConnectDeadline`'s `io::ErrorKind::TimedOut` and classifies ERR_NET_TIMEOUT;
/// * `Display` + the chain — `with_cause()` renders the same operator-visible causes as legacy
///   (real TLS alert / RST text, not a bare "channel closed").
pub struct EngineError {
    kind: ErrorKind,
    source: Option<Arc<dyn StdError + Send + Sync>>,
}

/// The error classes, mirroring the legacy client's kinds one-for-one where a consumer could
/// observe the difference.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ErrorKind {
    /// The connection could not be established: connector refusal, gate-starved dial hitting the
    /// connect deadline, handshake failure, a fresh conn that could not ready up. The one kind
    /// [`EngineError::is_connect`] reports.
    Connect,
    /// The request was accepted for dispatch and failed after — reset, protocol error, conn died
    /// mid-exchange. Never retried (the anti-duplicate boundary for non-idempotent POSTs).
    SendRequest,
    /// A reused conn handed the request back (`take_message()`) but the retry policy declined —
    /// legacy's `Canceled` kind, kept for classification parity (not connect-class).
    Canceled,
    /// Request version the client cannot speak (HTTP/0.9), or an HTTP/2 request landing on an
    /// h1 connection — an error, not a downgrade.
    UserUnsupportedVersion,
    /// CONNECT over HTTP/1.0 — refused, as legacy refuses it.
    UserUnsupportedRequestMethod,
    /// The request URI is not absolute-form (no scheme+authority): there is no pool key to
    /// checkout against.
    UserAbsoluteUriRequired,
}

impl EngineError {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        EngineError { kind, source: None }
    }

    pub(crate) fn with_source(
        kind: ErrorKind,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        EngineError {
            kind,
            source: Some(Arc::new(source)),
        }
    }

    pub(crate) fn from_dial(err: DialError) -> Self {
        EngineError {
            kind: ErrorKind::Connect,
            source: Some(err.cause),
        }
    }

    /// True when the connection could not be established (TCP, tunnel, TLS, gate-starved dial,
    /// failed handshake/readiness) — the class substrate's `HopError` mapping splits on. Errors
    /// after the request reached a connection return false, exactly as legacy classified.
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }
}

impl fmt::Debug for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut t = f.debug_tuple("busbar_substrate::egress::engine::EngineError");
        t.field(&self.kind);
        if let Some(cause) = &self.source {
            t.field(cause);
        }
        t.finish()
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Legacy's exact rendering shape ("client error (Connect)"), so `with_cause()` output —
        // which operators read in warn lines — keeps its familiar prefix + chain form.
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for EngineError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|e| &**e as &(dyn StdError + 'static))
    }
}

// ── Checkout (the hot path) ──────────────────────────────────────────────────────────────────────

/// Check one send handle out of the pool. The 99% steady-state arm is one uncontended lock and a
/// deque pop; a miss enqueues ONE oneshot waiter and re-establishes the dial invariant, then the
/// caller awaits delivery (its own `send_deadline` bounds the wait — a cancelled waiter is a
/// corpse the deliverers skip).
pub(crate) async fn checkout(
    inner: &Arc<ClientInner>,
    key: &PoolKey,
) -> Result<CheckedOut, EngineError> {
    loop {
        let rx = {
            let mut pm = inner.pool.lock().expect("engine pool lock");
            let h2_pinned = inner.h2_pinned();
            let st = pm
                .map
                .entry(key.clone())
                .or_insert_with(|| AuthorityState::new(h2_pinned));

            // h2 fast path: the shared conn multiplexes — clone the handle, stamp the idle
            // clock, go. No waiter, no dial. (Backpressure past the peer's stream cap lands in
            // hyper's h2 machinery, exactly where legacy's lands.)
            if st.proto == KnownProto::H2 {
                if let Some(entry) = st.h2.as_mut() {
                    if entry.sender.is_ready() && !entry.sender.is_closed() {
                        entry.last_checkout = Instant::now();
                        return Ok(CheckedOut::H2 {
                            sender: entry.sender.clone(),
                            extras: entry.extras.clone(),
                            reused: true,
                        });
                    }
                    // The shared conn died and its driver-exit clear has not landed yet: clear
                    // it here (we hold the lock; the entry IS the current generation) and fall
                    // through to the dial path.
                    st.h2 = None;
                    if !h2_pinned {
                        st.proto = KnownProto::Unknown;
                    }
                }
            }

            // Idle pop — ONLY when no waiters exist (anti-barging: FIFO fairness is structural,
            // not emergent). LIFO reuse; lazy expiry and dead-conn drops for free.
            if st.waiters.is_empty() {
                let now = Instant::now();
                while let Some(conn) = st.idle.pop_back() {
                    if now.saturating_duration_since(conn.idle_since) > inner.idle_timeout {
                        // Expired — and since reuse is LIFO, everything older in the deque is
                        // expired too; keep popping and dropping.
                        continue;
                    }
                    if conn.sender.is_ready() && !conn.sender.is_closed() {
                        return Ok(CheckedOut::H1 {
                            sender: conn.sender,
                            extras: conn.extras,
                            reused: true,
                        });
                    }
                    // Dead conn (driver exited): drop, keep popping.
                }
            }

            // MISS (or waiters exist): park FIFO and re-establish the coalescing invariant.
            let (tx, rx) = tokio::sync::oneshot::channel();
            st.waiters.push_back(tx);
            ensure_dials(inner, key, st);
            rx
        };

        match rx.await {
            Ok(Ok(conn)) => {
                if conn.is_live() {
                    return Ok(conn);
                }
                // Dead on arrival: the conn died between the deliverer's liveness check and this
                // waiter waking. Drop it and re-enter checkout — the checkout-level retry.
            }
            Ok(Err(dial)) => return Err(EngineError::from_dial(dial)),
            // The sender side was dropped without a delivery. Deliverers always send or park, so
            // this is only reachable through pool teardown mid-flight; classify as connect.
            Err(_) => {
                return Err(EngineError::with_source(
                    ErrorKind::Connect,
                    std::io::Error::other("the connection pool was torn down mid-checkout"),
                ))
            }
        }
    }
}

// ── Dial coalescing ──────────────────────────────────────────────────────────────────────────────

/// THE INVARIANT, in one function: while `inflight_dials < min(waiters.len(), bound)`, start a
/// detached dial. Re-run under the lock by every path that consumes a waiter or decrements the
/// counter. For an h2-known authority the effective bound is 1 (singleflight).
pub(crate) fn ensure_dials(inner: &Arc<ClientInner>, key: &PoolKey, st: &mut AuthorityState) {
    let bound = if st.proto == KnownProto::H2 {
        1
    } else {
        inner.dial_bound
    };
    while st.inflight_dials < st.waiters.len().min(bound) {
        st.inflight_dials += 1;
        let inner = Arc::clone(inner);
        let key = key.clone();
        tokio::spawn(dial_task(inner, key));
    }
}

/// What one completed dial hands to the deliverer.
enum DialOutcome {
    H1 {
        sender: http1::SendRequest<Full<Bytes>>,
        extras: ConnSnapshot,
    },
    H2 {
        sender: http2::SendRequest<Full<Bytes>>,
        extras: ConnSnapshot,
        /// The driver-exit task learns its entry's generation through this at install time; a
        /// straggler-closed conn drops it unsent, and the exit task then clears nothing.
        gen_tx: tokio::sync::oneshot::Sender<u64>,
    },
    Failed(Arc<dyn StdError + Send + Sync>),
}

/// The panic containment for [`AuthorityState::inflight_dials`]: a dial task that unwinds (or is
/// aborted at runtime shutdown) before delivering still decrements the counter and re-arms the
/// invariant — a stuck counter would silently halve the dial budget forever.
struct DialGuard {
    inner: Arc<ClientInner>,
    key: PoolKey,
    armed: bool,
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut pm) = self.inner.pool.lock() {
            if let Some(st) = pm.map.get_mut(&self.key) {
                st.inflight_dials = st.inflight_dials.saturating_sub(1);
                ensure_dials(&self.inner, &self.key, st);
            }
        }
    }
}

/// One detached dial: connect through the unchanged connector stack (gate permit → TCP/tunnel →
/// TLS, all under the 10s `ConnectDeadline`), snapshot the connect-time observations once,
/// branch on the negotiated protocol, handshake, spawn the driver, CONFIRM READINESS, then
/// deliver under the pool lock. Entirely off the forward future; no caller owns it.
async fn dial_task(inner: Arc<ClientInner>, key: PoolKey) {
    let mut guard = DialGuard {
        inner: Arc::clone(&inner),
        key: key.clone(),
        armed: true,
    };
    let outcome = perform_dial(&inner, &key).await;
    deliver_dial_outcome(&inner, &key, outcome, &mut guard);
}

async fn perform_dial(inner: &Arc<ClientInner>, key: &PoolKey) -> DialOutcome {
    let dst = domain_as_uri(key);
    let mut connector = inner.connector.clone();
    let connect = async {
        std::future::poll_fn(|cx| tower::Service::poll_ready(&mut connector, cx)).await?;
        tower::Service::call(&mut connector, dst).await
    };
    let io = match connect.await {
        Ok(io) => io,
        Err(e) => return DialOutcome::Failed(Arc::from(e)),
    };
    // The connect-time snapshot, read ONCE: the observed peer SPKI (the extras contract) and the
    // ALPN result (the protocol branch).
    let extras = ConnSnapshot {
        spki: io.peer_spki_snapshot(),
        negotiated_h2: io.negotiated_h2(),
    };
    let is_h2 = extras.negotiated_h2 || inner.h2_pinned();

    if is_h2 {
        let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder.timer(hyper_util::rt::TokioTimer::new());
        if let Some(ka) = inner.h2_keepalive {
            builder
                .keep_alive_interval(ka.interval)
                .keep_alive_timeout(ka.timeout)
                .adaptive_window(ka.adaptive_window);
        }
        let (mut tx, conn) = match builder.handshake::<_, Full<Bytes>>(io).await {
            Ok(pair) => pair,
            Err(e) => return DialOutcome::Failed(Arc::new(e)),
        };
        // The driver task. On exit (GOAWAY drained, error, peer close) it clears the pool entry
        // it was installed as — GENERATION-CHECKED, so a stale exit after a newer install clears
        // nothing. `gen_rx` resolves to the generation sent at install time (buffered in the
        // oneshot), or errs if this conn was straggler-closed and never installed.
        let (gen_tx, gen_rx) = tokio::sync::oneshot::channel::<u64>();
        let weak = Arc::downgrade(inner);
        let exit_key = key.clone();
        tokio::spawn(async move {
            let _ = conn.await;
            if let Ok(generation) = gen_rx.await {
                if let Some(inner) = weak.upgrade() {
                    clear_h2_generation(&inner, &exit_key, generation);
                }
            }
        });
        // Ready up before declaring the conn usable: a conn that cannot ready is a DIAL failure
        // (connect class), not a delivered-then-dead conn.
        match tx.ready().await {
            Ok(()) => DialOutcome::H2 {
                sender: tx,
                extras,
                gen_tx,
            },
            Err(e) => DialOutcome::Failed(Arc::new(e)),
        }
    } else {
        let (mut tx, conn) = match http1::handshake::<_, Full<Bytes>>(io).await {
            Ok(pair) => pair,
            Err(e) => return DialOutcome::Failed(Arc::new(e)),
        };
        // Legacy's err_tx/err_rx correlation: the driver sends its terminal error into a
        // oneshot, so a `ready()` failure with the vague is_closed/ChannelClosed shape can
        // surface the REAL connection error (TLS alert, RST) as the dial cause.
        let (err_tx, err_rx) = tokio::sync::oneshot::channel::<hyper::Error>();
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                let _ = err_tx.send(e);
            }
        });
        match tx.ready().await {
            Ok(()) => DialOutcome::H1 { sender: tx, extras },
            Err(e) if e.is_closed() => match err_rx.await {
                Ok(real) => DialOutcome::Failed(Arc::new(real)),
                Err(_) => DialOutcome::Failed(Arc::new(e)),
            },
            Err(e) => DialOutcome::Failed(Arc::new(e)),
        }
    }
}

/// Deliver one dial's outcome under the pool lock: decrement the in-flight counter (disarming
/// the panic guard in the same lock scope), walk the waiters, then re-establish the invariant.
fn deliver_dial_outcome(
    inner: &Arc<ClientInner>,
    key: &PoolKey,
    outcome: DialOutcome,
    guard: &mut DialGuard,
) {
    let mut pm = inner.pool.lock().expect("engine pool lock");
    guard.armed = false;
    let Some(st) = pm.map.get_mut(key) else {
        return; // unreachable: the authority entry that spawned this dial is never evicted
    };
    st.inflight_dials = st.inflight_dials.saturating_sub(1);
    let mut needs_reaper = false;

    match outcome {
        DialOutcome::H1 { sender, extras } => {
            // Fresh h1 evidence: learn the protocol — but never overwrite live h2 evidence (an
            // Unknown-era h1 dial landing after an h2 install parks beside it and ages out).
            if st.h2.is_none() && !inner.h2_pinned() {
                st.proto = KnownProto::H1;
            }
            needs_reaper = deliver_h1_locked(inner, st, sender, extras, false);
        }
        DialOutcome::H2 {
            sender,
            extras,
            gen_tx,
        } => {
            let existing_live = st
                .h2
                .as_ref()
                .is_some_and(|e| e.sender.is_ready() && !e.sender.is_closed());
            if existing_live {
                // Straggler: the first-completed conn won; a second shared conn is CLOSED, never
                // parked (legacy put-refuse parity) — dropping the sender and the driver task's
                // gen_tx shuts it down gracefully.
                drop(sender);
                drop(gen_tx);
            } else {
                st.h2_generation += 1;
                let generation = st.h2_generation;
                let _ = gen_tx.send(generation);
                st.h2 = Some(H2Entry {
                    sender: sender.clone(),
                    extras: extras.clone(),
                    generation,
                    last_checkout: Instant::now(),
                });
                st.proto = KnownProto::H2;
                // Multiplexing: EVERYONE rides this one conn — drain the whole queue with
                // clones; corpses are simply consumed.
                while let Some(tx) = st.waiters.pop_front() {
                    let _ = tx.send(Ok(CheckedOut::H2 {
                        sender: sender.clone(),
                        extras: extras.clone(),
                        reused: false,
                    }));
                }
                needs_reaper = true;
            }
        }
        DialOutcome::Failed(cause) => {
            if st.proto == KnownProto::H2 {
                // h2-known (learned from ALPN or posture-pinned): BROADCAST — every parked
                // checkout errors within this one connect attempt, exactly as legacy's failed
                // h2 `Connecting` removed all waiters for the key. Without this, a bound-1
                // authority would drain a dead upstream's queue at one error per connect
                // deadline, silently reclassifying Connect into Deadline en masse.
                while let Some(tx) = st.waiters.pop_front() {
                    let _ = tx.send(Err(DialError {
                        cause: Arc::clone(&cause),
                    }));
                }
            } else {
                // h1 / still-Unknown: unicast — but pop corpses until one LIVE waiter accepts
                // the error (symmetric with the success walk; an error sent into a dead oneshot
                // is lost and would burn a full connect round for the live waiter behind it).
                while let Some(tx) = st.waiters.pop_front() {
                    if tx
                        .send(Err(DialError {
                            cause: Arc::clone(&cause),
                        }))
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }
    }

    ensure_dials(inner, key, st);
    if needs_reaper {
        maybe_spawn_reaper(inner, &mut pm);
    }
}

/// The h1 delivery walk, shared verbatim by dial-success delivery and the return path (the
/// second and third lock-serialized mutators): serve waiters front-first skipping corpses, else park idle LIFO, else (at
/// the per-host cap) drop — a completed conn is ALWAYS consumed. Returns whether a conn was
/// parked (the caller spawns the reaper outside the `st` borrow).
fn deliver_h1_locked(
    inner: &Arc<ClientInner>,
    st: &mut AuthorityState,
    sender: http1::SendRequest<Full<Bytes>>,
    extras: ConnSnapshot,
    reused: bool,
) -> bool {
    let mut conn = CheckedOut::H1 {
        sender,
        extras,
        reused,
    };
    while let Some(tx) = st.waiters.pop_front() {
        match tx.send(Ok(conn)) {
            Ok(()) => return false,
            // Corpse: the receiver was dropped; take the conn back and try the next waiter.
            Err(back) => match back {
                Ok(returned) => conn = returned,
                Err(_) => unreachable!("the success walk only ever sends Ok"),
            },
        }
    }
    let CheckedOut::H1 { sender, extras, .. } = conn else {
        unreachable!("the h1 walk only ever carries an h1 conn");
    };
    if st.idle.len() < inner.idle_cap_per_host {
        st.idle.push_back(IdleConn {
            sender,
            extras,
            idle_since: Instant::now(),
        });
        true
    } else {
        // At cap: close (drop). Enforced at park time exactly as legacy — excess is closed,
        // a checkout is never refused.
        false
    }
}

/// The return path's entry (mutator #3): a finished h1 exchange hands its conn back — waiters
/// first (FIFO, no barging), else parked idle, else dropped at cap. `reused` is true by
/// construction: a returned conn has served an exchange.
pub(crate) fn return_h1_conn(
    inner: &Arc<ClientInner>,
    key: &PoolKey,
    sender: http1::SendRequest<Full<Bytes>>,
    extras: ConnSnapshot,
) {
    let mut pm = inner.pool.lock().expect("engine pool lock");
    let Some(st) = pm.map.get_mut(key) else {
        return;
    };
    let parked = deliver_h1_locked(inner, st, sender, extras, true);
    if parked {
        maybe_spawn_reaper(inner, &mut pm);
    }
}

/// Clear the authority's h2 entry iff it is still the given generation — the driver-exit /
/// GOAWAY handler. Reverts `proto` to `Unknown` in the same lock scope unless posture-pinned
/// (the transition rule): a cleared authority redials with the full ALPN offer and no
/// residual assumptions, exactly as legacy would.
pub(crate) fn clear_h2_generation(inner: &Arc<ClientInner>, key: &PoolKey, generation: u64) {
    let mut pm = inner.pool.lock().expect("engine pool lock");
    let Some(st) = pm.map.get_mut(key) else {
        return;
    };
    if st.h2.as_ref().is_some_and(|e| e.generation == generation) {
        st.h2 = None;
        if !inner.h2_pinned() {
            st.proto = KnownProto::Unknown;
        }
        ensure_dials(inner, key, st);
    }
}

fn domain_as_uri(key: &PoolKey) -> http::Uri {
    http::uri::Builder::new()
        .scheme(key.0.clone())
        .authority(key.1.clone())
        .path_and_query("/")
        .build()
        .expect("a pool key is a valid origin URI")
}

// ── Idle expiry: the on-demand reaper ────────────────────────────────────────────────────────────

/// Spawn the per-shard reaper if idle/h2 state now exists and no reaper is alive. It sleeps
/// until the earliest expiry across the shard (front-of-deque entries + h2 idle clocks — O(1)
/// per authority per wakeup, never per request) and EXITS when nothing expirable remains, so a
/// quiescent pool runs zero tasks — strictly cheaper than legacy's always-on interval.
fn maybe_spawn_reaper(inner: &Arc<ClientInner>, pm: &mut PoolMap) {
    if pm.reaper_running {
        return;
    }
    pm.reaper_running = true;
    let weak = Arc::downgrade(inner);
    tokio::spawn(reap_loop(weak));
}

async fn reap_loop(weak: Weak<ClientInner>) {
    loop {
        let next = {
            let Some(inner) = weak.upgrade() else { return };
            let mut pm = inner.pool.lock().expect("engine pool lock");
            let now = Instant::now();
            let timeout = inner.idle_timeout;
            let h2_pinned = inner.h2_pinned();
            let mut earliest: Option<Instant> = None;
            for st in pm.map.values_mut() {
                // Front-of-deque expiry: oldest idles age out first (LIFO reuse guarantees the
                // front is the oldest). Dropping the sender is the FIN the upstream observes.
                while st.idle.front().is_some_and(|c| {
                    now.saturating_duration_since(c.idle_since) > timeout || c.sender.is_closed()
                }) {
                    st.idle.pop_front();
                }
                if let Some(front) = st.idle.front() {
                    let due = front.idle_since + timeout;
                    earliest = Some(earliest.map_or(due, |e| e.min(due)));
                }
                // The h2 idle clock: evict on time-since-last-CHECKOUT. Dropping our handle
                // while streams are still active is graceful — the driver runs until existing
                // streams finish, identical to legacy evicting the shared idle copy.
                if let Some(entry) = &st.h2 {
                    if now.saturating_duration_since(entry.last_checkout) > timeout {
                        st.h2 = None;
                        if !h2_pinned {
                            st.proto = KnownProto::Unknown;
                        }
                    } else {
                        let due = entry.last_checkout + timeout;
                        earliest = Some(earliest.map_or(due, |e| e.min(due)));
                    }
                }
            }
            match earliest {
                Some(instant) => instant,
                None => {
                    pm.reaper_running = false;
                    return;
                }
            }
        };
        // A hair past the deadline: expiry is strict (`>`), so waking exactly AT it would spin.
        tokio::time::sleep_until(tokio::time::Instant::from_std(next + EXPIRY_SLACK)).await;
    }
}

/// How far past the earliest expiry the reaper wakes — covers the strict `>` comparison; the
/// guarantee class is unchanged (closed within one wakeup of expiry, same as legacy's interval).
const EXPIRY_SLACK: Duration = Duration::from_millis(5);

// ── Test instrumentation ─────────────────────────────────────────────────────────────────────────

/// A test-only snapshot of one authority's state, read under the lock.
#[cfg(test)]
pub(crate) struct AuthoritySnapshot {
    pub(crate) proto: KnownProto,
    pub(crate) inflight_dials: usize,
    pub(crate) waiters: usize,
    pub(crate) idle: usize,
    pub(crate) has_h2: bool,
    pub(crate) h2_generation: u64,
}

#[cfg(test)]
pub(crate) fn snapshot_authority(inner: &ClientInner, key: &PoolKey) -> Option<AuthoritySnapshot> {
    let pm = inner.pool.lock().expect("engine pool lock");
    pm.map.get(key).map(|st| AuthoritySnapshot {
        proto: st.proto,
        inflight_dials: st.inflight_dials,
        waiters: st.waiters.len(),
        idle: st.idle.len(),
        has_h2: st.h2.is_some(),
        h2_generation: st.h2_generation,
    })
}
