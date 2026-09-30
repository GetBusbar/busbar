// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE: hyper's `client::conn` (HTTP/1.1 and HTTP/2) run as a sans-IO framer.
//!
//! One [`Framing`] is one connection. Its protocol machine is hyper's own, reading from and writing
//! to an in-memory [`Pipe`] rather than a socket: `ingest` appends what the far side sent to the
//! pipe's read half, and whatever hyper writes collects in its write half until the op hands it to
//! the host as wire bytes. Nothing here blocks, spawns a thread, opens a socket or reads a clock:
//!
//! * THE EXECUTOR hyper's HTTP/2 client needs for its connection task is this framing's own task
//!   list ([`Exec`]), polled inside the op that is running. No runtime, no global state.
//! * THE TIMER hyper's keep-alive, adaptive window and the head wait run on is the host's clock
//!   ([`SinkTimer`]): every op sets it from `FramerSink::now_monotonic_ns` before it drives, and the
//!   earliest sleep still waiting becomes the op's `next_deadline_ns`.
//! * A hyper `Pending` means "more bytes from the far side, or a deadline": the op answers what it
//!   has and returns. The waker every future here sees only records that it was woken, so the op
//!   drives again while something inside hyper still has work, and stops when nothing does.
//!
//! THE ONE REAL-CLOCK READ. `std::time::Instant` has no constructor but `now()`, and hyper's timer
//! speaks `Instant`, so each framing reads the real clock ONCE, at `begin`, as the epoch its host
//! times are laid on: instant(t) = epoch + (t - t_begin). Nothing ever advances from it; every later
//! instant is host time. h2 reads the real clock itself for its reset-stream expiry (a bounded list
//! of recently reset stream ids); that is inside the library and does not move this framing's clock.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::rt::{Executor, ReadBufCursor, Sleep, Timer};

use crate::raw::RawStartLine;
use crate::{complete_message, request_target, retry_after_secs, EgressHead};

/// The most bytes hyper may leave in the pipe's write half before its writes pend: the host has
/// not drained them yet (the sink was full), and a connection does not get to buffer without end.
const WRITE_HIGH_WATER: usize = 256 * 1024;

/// The most drive rounds one op makes. A round repeats only when something inside hyper woke
/// during it, so a settled connection stops after one; the bound is the backstop.
const MAX_ROUNDS: usize = 64;

/// Which HTTP a framing speaks, as connection security (or the operator's cleartext key) agreed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// HTTP/1.1.
    H1,
    /// HTTP/2.
    H2,
}

/// The connection posture 1.5.5's egress client used, carried to every framing.
#[derive(Debug, Clone, Copy)]
pub struct Posture {
    /// HTTP/2 keep-alive ping interval (`None` = no pings).
    pub keep_alive_interval: Option<Duration>,
    /// How long a keep-alive ping may go unanswered.
    pub keep_alive_timeout: Duration,
    /// HTTP/2 adaptive flow-control window.
    pub adaptive_window: bool,
    /// 1.5.5's `limits.upstream_request_timeout_secs`: ONE clock per attempt, from its start to the
    /// response body's end (reqwest's total timeout). Counted from a stream's first `emit` when the
    /// caller stamped no deadline of its own.
    pub request_timeout: Duration,
    /// The largest REQUEST message carried. A response is not capped here: 1.5.5's incremental
    /// body path carried a body for as long as the far end sent one, and its buffered reads are
    /// the plane's.
    pub max_body_bytes: usize,
}

// ── the pipe ─────────────────────────────────────────────────────────────────────────────────────

/// What the far side sent and hyper has not read, whether the far side has ended, and what hyper
/// wrote and the host has not been handed.
#[derive(Default)]
pub struct Pipe {
    rx: VecDeque<u8>,
    eof: bool,
    tx: Vec<u8>,
}

/// hyper's I/O: the framing's pipe.
struct Shim(Arc<Mutex<Pipe>>);

impl hyper::rt::Read for Shim {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut p = self.0.lock().expect("pipe");
        if p.rx.is_empty() {
            // The far side's end reads as a zero-length read; otherwise wait for `ingest`.
            return if p.eof {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        let (a, b) = p.rx.as_slices();
        let src = if a.is_empty() { b } else { a };
        let n = src.len().min(buf.remaining());
        buf.put_slice(&src[..n]);
        p.rx.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for Shim {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut p = self.0.lock().expect("pipe");
        if p.tx.len() >= WRITE_HIGH_WATER {
            return Poll::Pending;
        }
        p.tx.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── the executor ─────────────────────────────────────────────────────────────────────────────────

type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// hyper's executor: this framing's task list, polled inside the op that is running.
#[derive(Clone, Default)]
struct Exec(Arc<Mutex<Vec<Task>>>);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Exec {
    fn execute(&self, fut: F) {
        self.0.lock().expect("exec").push(Box::pin(fut));
    }
}

impl Exec {
    fn run(&self, cx: &mut Context<'_>) {
        let mut tasks = std::mem::take(&mut *self.0.lock().expect("exec"));
        tasks.retain_mut(|t| t.as_mut().poll(cx).is_pending());
        let mut q = self.0.lock().expect("exec");
        // Tasks spawned during the pass run on the next round.
        tasks.append(&mut q);
        *q = tasks;
    }
}

// ── the timer ────────────────────────────────────────────────────────────────────────────────────

/// The host's clock as hyper sees it, and the sleeps waiting on it.
struct Clock {
    epoch: Instant,
    epoch_ns: u64,
    now_ns: u64,
    next_id: u64,
    sleeps: HashMap<u64, (Instant, Option<Waker>)>,
}

impl Clock {
    fn at(&self, ns: u64) -> Instant {
        self.epoch + Duration::from_nanos(ns.saturating_sub(self.epoch_ns))
    }
    fn ns_of(&self, i: Instant) -> u64 {
        let d = i.saturating_duration_since(self.epoch);
        self.epoch_ns
            .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }
}

/// hyper's timer, on the host's clock.
#[derive(Clone)]
struct SinkTimer(Arc<Mutex<Clock>>);

struct SinkSleep {
    clock: Arc<Mutex<Clock>>,
    id: u64,
}

impl Future for SinkSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut c = self.clock.lock().expect("clock");
        let now = c.at(c.now_ns);
        let Some(entry) = c.sleeps.get_mut(&self.id) else {
            return Poll::Ready(());
        };
        if entry.0 <= now {
            Poll::Ready(())
        } else {
            entry.1 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for SinkSleep {
    fn drop(&mut self) {
        if let Ok(mut c) = self.clock.lock() {
            c.sleeps.remove(&self.id);
        }
    }
}

impl Sleep for SinkSleep {}

impl Timer for SinkTimer {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Sleep>> {
        self.sleep_until(self.now() + d)
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        let mut c = self.0.lock().expect("clock");
        let id = c.next_id;
        c.next_id += 1;
        c.sleeps.insert(id, (deadline, None));
        Box::pin(SinkSleep {
            clock: self.0.clone(),
            id,
        })
    }
    fn now(&self) -> Instant {
        let c = self.0.lock().expect("clock");
        c.at(c.now_ns)
    }
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        if let Some(s) = sleep.as_mut().downcast_mut_pin::<SinkSleep>() {
            if let Some(e) = self.0.lock().expect("clock").sleeps.get_mut(&s.id) {
                e.0 = new_deadline;
                return;
            }
        }
        *sleep = self.sleep_until(new_deadline);
    }
}

impl SinkTimer {
    /// The instant a host time is.
    fn at_ns(&self, ns: u64) -> Instant {
        self.0.lock().expect("clock").at(ns)
    }
    /// Set the host's time and wake every sleep it passed.
    fn set(&self, now_ns: u64) {
        let due: Vec<Waker> = {
            let mut c = self.0.lock().expect("clock");
            c.now_ns = c.now_ns.max(now_ns);
            let now = c.at(c.now_ns);
            c.sleeps
                .values_mut()
                .filter(|(d, _)| *d <= now)
                .filter_map(|(_, w)| w.take())
                .collect()
        };
        due.into_iter().for_each(Waker::wake);
    }
    /// The earliest sleep still waiting, as host time.
    fn next_deadline(&self) -> Option<u64> {
        let c = self.0.lock().expect("clock");
        let now = c.at(c.now_ns);
        c.sleeps
            .values()
            .map(|(d, _)| *d)
            .filter(|d| *d > now)
            .min()
            .map(|d| c.ns_of(d))
    }
}

// ── the waker ────────────────────────────────────────────────────────────────────────────────────

/// Every waker hyper sees: it records that something woke, and the op drives again.
#[derive(Default)]
struct Woken(AtomicBool);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

// ── one framing ──────────────────────────────────────────────────────────────────────────────────

/// A frame piece waiting for the host's sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The stream.
    pub stream: u64,
    /// The frame bytes (empty: the stream's response is complete).
    pub bytes: Bytes,
    /// The response status, on the head frame.
    pub status: Option<u16>,
    /// The wait the far side asked for, on the head frame.
    pub retry_after_secs: Option<u64>,
    /// The stream failed; `bytes` are the reason, and this is its last piece.
    pub failed: bool,
    /// `bytes` are a field block: the head.
    pub fields: bool,
}

impl Piece {
    fn failure(stream: u64, why: &Failure) -> Self {
        Self {
            failed: true,
            ..Self::data(stream, Bytes::from(why.0.clone()))
        }
    }
    fn data(stream: u64, bytes: Bytes) -> Self {
        Self {
            stream,
            bytes,
            status: None,
            retry_after_secs: None,
            failed: false,
            fields: false,
        }
    }
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// One exchange's stage. Every stage after `Writing` carries the attempt's ONE deadline sleep, so
/// the wait for the connection, the head and every byte of the body spend the same clock.
enum Stage {
    /// The request message, still arriving, and the attempt's deadline (host ns).
    Writing(Vec<u8>, EgressHead, u64),
    /// A whole request, waiting for the connection to take it.
    Queued(http::Request<Full<Bytes>>, Pin<Box<dyn Sleep>>),
    /// Sent; waiting for the response head.
    Asked(
        BoxFut<hyper::Result<http::Response<Incoming>>>,
        Pin<Box<dyn Sleep>>,
    ),
    /// The response body.
    Body(Incoming, Pin<Box<dyn Sleep>>),
    /// Answered in full.
    Done,
}

/// Why a framing failed; the op that finds it answers FAILED with this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

/// One connection's HTTP machine.
pub struct Framing {
    pipe: Arc<Mutex<Pipe>>,
    exec: Exec,
    timer: SinkTimer,
    woken: Arc<Woken>,
    waker: Waker,
    handshake: Option<BoxFut<hyper::Result<Sender>>>,
    sender: Option<Sender>,
    conn_err: Arc<Mutex<Option<String>>>,
    conn_done: Arc<AtomicBool>,
    dial: http::Uri,
    proto: Proto,
    posture: Posture,
    exchanges: Vec<(u64, Stage)>,
    out: VecDeque<Piece>,
    failed: Option<Failure>,
    now_unix_ns: u64,
    /// Bytes this framing has handed to the host, for the tests' ping count.
    pub wire_out: Arc<AtomicU64>,
}

impl Framing {
    /// Open a dialled framing over `dial`, speaking `proto`, at host time `now_ns`.
    ///
    /// # Errors
    ///
    /// `dial` is not a URI.
    pub fn dial(dial: &str, proto: Proto, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let dial: http::Uri = dial
            .parse()
            .map_err(|_| Failure(format!("not a target: {dial}")))?;
        let pipe = Arc::new(Mutex::new(Pipe::default()));
        let exec = Exec::default();
        // The one real-clock read: this framing's epoch (module docs).
        let timer = SinkTimer(Arc::new(Mutex::new(Clock {
            epoch: Instant::now(),
            epoch_ns: now_ns,
            now_ns,
            next_id: 0,
            sleeps: HashMap::new(),
        })));
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let (ex, err, done) = (exec.clone(), conn_err.clone(), conn_done.clone());
        let shim = Shim(pipe.clone());
        let handshake: BoxFut<hyper::Result<Sender>> = match proto {
            Proto::H2 => {
                let mut b = http2::Builder::new(exec.clone());
                b.timer(timer.clone())
                    .adaptive_window(posture.adaptive_window);
                if let Some(every) = posture.keep_alive_interval {
                    b.keep_alive_interval(every)
                        .keep_alive_timeout(posture.keep_alive_timeout);
                }
                Box::pin(async move {
                    let (s, c) = b.handshake(shim).await?;
                    ex.execute(async move {
                        if let Err(e) = c.await {
                            *err.lock().expect("err") = Some(e.to_string());
                        }
                        done.store(true, Ordering::Release);
                    });
                    Ok(Sender::H2(s))
                })
            }
            Proto::H1 => Box::pin(async move {
                let (s, c) = http1::Builder::new().handshake(shim).await?;
                ex.execute(async move {
                    if let Err(e) = c.await {
                        *err.lock().expect("err") = Some(e.to_string());
                    }
                    done.store(true, Ordering::Release);
                });
                Ok(Sender::H1(s))
            }),
        };
        let woken = Arc::new(Woken::default());
        Ok(Self {
            pipe,
            exec,
            timer,
            waker: Waker::from(woken.clone()),
            woken,
            handshake: Some(handshake),
            sender: None,
            conn_err,
            conn_done,
            dial,
            proto,
            posture,
            exchanges: Vec::new(),
            out: VecDeque::new(),
            failed: None,
            now_unix_ns: 0,
            wire_out: Arc::new(AtomicU64::new(0)),
        })
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        let mut p = self.pipe.lock().expect("pipe");
        p.rx.extend(bytes);
        p.eof |= end;
    }

    /// Bytes for `stream`: part of one HTTP/1.1 request message, rendered by `encode`.
    ///
    /// A message that cannot be sent fails its STREAM on HTTP/2 (a failure piece, its siblings
    /// untouched), and the framing on HTTP/1.1, where the connection carries one exchange.
    ///
    /// # Errors
    ///
    /// HTTP/1.1 only: the message is malformed, over the body cap, or is not a request.
    ///
    /// `deadline_ns` is the attempt's deadline as the caller stamped it at the attempt's start (the
    /// connect spent part of it); `0` counts the configured request timeout from `now_ns`. Only a
    /// stream's first `emit` reads it.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        now_ns: u64,
        deadline_ns: u64,
    ) -> Result<(), Failure> {
        // A re-call after `YIELD_MORE` carries no new bytes: nothing to add to any message.
        if bytes.is_empty() {
            return Ok(());
        }
        let deadline = if deadline_ns != 0 {
            deadline_ns
        } else {
            now_ns.saturating_add(
                u64::try_from(self.posture.request_timeout.as_nanos()).unwrap_or(u64::MAX),
            )
        };
        match self.message(stream, bytes, deadline) {
            Ok(()) => Ok(()),
            Err(f) if self.proto == Proto::H2 => {
                if let Some(slot) = self.exchanges.iter_mut().find(|(s, _)| *s == stream) {
                    slot.1 = Stage::Done;
                }
                self.exchanges.retain(|(_, s)| !matches!(s, Stage::Done));
                self.out.push_back(Piece::failure(stream, &f));
                Ok(())
            }
            Err(f) => Err(f),
        }
    }

    fn message(&mut self, stream: u64, bytes: &[u8], deadline: u64) -> Result<(), Failure> {
        let max = self.posture.max_body_bytes;
        let idx = match self.exchanges.iter().position(|(s, _)| *s == stream) {
            Some(i) => i,
            None => {
                self.exchanges.push((
                    stream,
                    Stage::Writing(Vec::new(), EgressHead::default(), deadline),
                ));
                self.exchanges.len() - 1
            }
        };
        let Stage::Writing(buf, head, deadline) = &mut self.exchanges[idx].1 else {
            return Err(Failure(format!(
                "stream {stream} already carries a request"
            )));
        };
        buf.extend_from_slice(bytes);
        if buf.len() > max {
            return Err(Failure("request message over the body cap".into()));
        }
        let raw = complete_message(buf, head, max)
            .map_err(|e| Failure(format!("request message: {e:?}")))?;
        let Some(raw) = raw else { return Ok(()) };
        let RawStartLine::Request { method, path } = &raw.start else {
            return Err(Failure("a status line is not a request".into()));
        };
        let mut b = http::Request::builder()
            .method(method.as_str())
            .uri(request_target(&self.dial, path).map_err(|e| Failure(format!("{e:?}")))?);
        for (k, v) in &raw.headers {
            // hyper frames the body below; a length or coding the message carried describes the
            // wire it was written for, not the one going out.
            if k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            b = b.header(k, v);
        }
        let mut req = b
            .body(Full::new(Bytes::from(raw.body)))
            .map_err(|e| Failure(format!("request: {e}")))?;
        client_posture(&mut req, self.proto);
        let wait = self.timer.sleep_until(self.timer.at_ns(*deadline));
        self.exchanges[idx].1 = Stage::Queued(req, wait);
        Ok(())
    }

    /// Drive the connection at host time (`now_ns` monotonic, `now_unix_ns` wall) until nothing
    /// inside it has more to do.
    pub fn drive(&mut self, now_ns: u64, now_unix_ns: u64) {
        self.timer.set(now_ns);
        self.now_unix_ns = now_unix_ns;
        if self.failed.is_some() {
            return;
        }
        let waker = self.waker.clone();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..MAX_ROUNDS {
            self.woken.0.store(false, Ordering::Release);
            self.exec.run(&mut cx);
            if let Err(f) = self.step(&mut cx) {
                self.failed = Some(f);
                return;
            }
            if !self.woken.0.load(Ordering::Acquire) {
                break;
            }
        }
        let err = self.conn_err.lock().expect("err").clone();
        if let Some(e) = err {
            if !self.exchanges.is_empty() {
                self.failed = Some(Failure(e));
            }
        }
    }

    /// One round: the handshake, then every stream as far as it goes. A stream's own failure on
    /// HTTP/2 ends THAT stream (dropping its exchange resets it on the wire) with a failure piece;
    /// on HTTP/1.1, or once the connection itself has failed, it fails the framing.
    fn step(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        let k = Knobs {
            now_unix_secs: self.now_unix_ns / 1_000_000_000,
        };
        for (id, stage) in &mut self.exchanges {
            if let Err(f) = advance(*id, stage, &mut self.sender, &mut self.out, &k, cx) {
                let conn_dead = self.conn_err.lock().expect("err").is_some();
                if self.proto == Proto::H1 || conn_dead || f.1 {
                    return Err(f.0);
                }
                *stage = Stage::Done;
                self.out.push_back(Piece::failure(*id, &f.0));
            }
        }
        self.exchanges.retain(|(_, s)| !matches!(s, Stage::Done));
        Ok(())
    }

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }

    /// Whether the connection has ended.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.conn_done.load(Ordering::Acquire)
    }

    /// The earliest host time this framing must be called at.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.timer.next_deadline()
    }

    /// Take up to `cap` wire bytes owed to the far side.
    pub fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        let mut p = self.pipe.lock().expect("pipe");
        let n = p.tx.len().min(cap);
        let out: Vec<u8> = p.tx.drain(..n).collect();
        self.wire_out.fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// Whether wire bytes are still owed after a take.
    #[must_use]
    pub fn wire_pending(&self) -> bool {
        !self.pipe.lock().expect("pipe").tx.is_empty()
    }

    /// The frame pieces waiting for the host.
    pub fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
}

/// What 1.5.5's egress client did to every request after the caller built it, so the bytes on the
/// wire are the bytes 1.5.5 sent: reqwest's default `accept: */*` when the request names none, and,
/// on HTTP/1.1, hyper-util's `host` field (the port only when it is not the scheme's own) with the
/// target rewritten to origin form. On HTTP/2 the target stays absolute: it becomes `:scheme`,
/// `:authority` and `:path`.
fn client_posture(req: &mut http::Request<Full<Bytes>>, proto: Proto) {
    req.headers_mut()
        .entry(http::header::ACCEPT)
        .or_insert(http::HeaderValue::from_static("*/*"));
    if proto == Proto::H2 {
        return;
    }
    let uri = req.uri().clone();
    if let Some(host) = uri.host() {
        let secure = matches!(uri.scheme_str(), Some("https" | "wss"));
        let value = match uri.port_u16() {
            Some(443) if secure => host.to_owned(),
            Some(80) if !secure => host.to_owned(),
            Some(p) => format!("{host}:{p}"),
            None => host.to_owned(),
        };
        if let Ok(v) = http::HeaderValue::from_str(&value) {
            req.headers_mut().entry(http::header::HOST).or_insert(v);
        }
    }
    *req.uri_mut() = match uri.path_and_query() {
        Some(p) if p.as_str() != "/" => p.as_str().parse().unwrap_or_default(),
        _ => http::Uri::default(),
    };
}

/// What every stream's round reads.
struct Knobs {
    now_unix_secs: u64,
}

/// The failure a stream's deadline passing is.
fn timed_out() -> (Failure, bool) {
    (
        Failure("the request timeout passed before the response was whole".into()),
        false,
    )
}

/// Move one stream as far as it goes this round. `Err((why, true))` is the connection's failure
/// (the sender refused), `Err((why, false))` the stream's own.
fn advance(
    id: u64,
    stage: &mut Stage,
    sender: &mut Option<Sender>,
    out: &mut VecDeque<Piece>,
    k: &Knobs,
    cx: &mut Context<'_>,
) -> Result<(), (Failure, bool)> {
    let own = |e: hyper::Error| (Failure(e.to_string()), false);
    loop {
        match stage {
            Stage::Writing(..) | Stage::Done => return Ok(()),
            Stage::Queued(_, wait) => {
                if wait.as_mut().poll(cx).is_ready() {
                    return Err(timed_out());
                }
                let Some(s) = sender.as_mut() else {
                    return Ok(());
                };
                let ready = match s {
                    Sender::H1(s) => s.poll_ready(cx),
                    Sender::H2(s) => s.poll_ready(cx),
                };
                match ready {
                    Poll::Pending => return Ok(()),
                    Poll::Ready(r) => r.map_err(|e| (Failure(e.to_string()), true))?,
                }
                let Stage::Queued(req, wait) = std::mem::replace(stage, Stage::Done) else {
                    unreachable!("matched above")
                };
                let f: BoxFut<_> = match s {
                    Sender::H1(s) => Box::pin(s.send_request(req)),
                    Sender::H2(s) => Box::pin(s.send_request(req)),
                };
                *stage = Stage::Asked(f, wait);
            }
            Stage::Asked(f, wait) => match f.as_mut().poll(cx) {
                Poll::Pending => {
                    if wait.as_mut().poll(cx).is_ready() {
                        return Err(timed_out());
                    }
                    return Ok(());
                }
                Poll::Ready(r) => {
                    let r = r.map_err(own)?;
                    out.push_back(head_piece(id, &r, k.now_unix_secs));
                    let Stage::Asked(_, wait) = std::mem::replace(stage, Stage::Done) else {
                        unreachable!("matched above")
                    };
                    *stage = Stage::Body(r.into_body(), wait);
                }
            },
            Stage::Body(b, wait) => match Pin::new(&mut *b).poll_frame(cx) {
                Poll::Pending => {
                    if wait.as_mut().poll(cx).is_ready() {
                        return Err(timed_out());
                    }
                    return Ok(());
                }
                Poll::Ready(Some(Err(e))) => return Err(own(e)),
                // Data is carried as it arrives. A trailer section is not: 1.5.5's client read a
                // response through reqwest, which yields data frames only, so trailers never
                // reached what the layer above read, and they do not here either.
                Poll::Ready(Some(Ok(fr))) => {
                    if let Ok(d) = fr.into_data() {
                        if !d.is_empty() {
                            out.push_back(Piece::data(id, d));
                        }
                    }
                }
                Poll::Ready(None) => {
                    // The empty piece that says this stream's response is whole.
                    out.push_back(Piece::data(id, Bytes::new()));
                    *stage = Stage::Done;
                    return Ok(());
                }
            },
        }
    }
}

/// The response head as the frame the layer above reads: ONE field block
/// (`busbar_contract::abi::transport::fields`) carrying the status and any `Retry-After`, framed
/// even when no field is left in it, so it always comes before the body.
fn head_piece(stream: u64, r: &http::Response<Incoming>, now_unix_secs: u64) -> Piece {
    Piece {
        stream,
        bytes: Bytes::from(field_block(r.headers())),
        status: Some(r.status().as_u16()),
        retry_after_secs: retry_after_secs(r.headers(), now_unix_secs),
        failed: false,
        fields: true,
    }
}

/// `headers` as the field block: `name: value\r\n` per value, in the map's order (1.5.5's: names
/// as they first arrived, a repeated name's values each on its own line after it), hop-by-hop
/// fields and those `connection` names dropped, and `content-length` too: the pieces carry the body
/// hyper already unframed.
pub(crate) fn field_block(headers: &http::HeaderMap) -> Vec<u8> {
    use busbar_contract::abi::transport::fields::{hop_by_hop, LINE_END, SEPARATOR};
    let nominated = headers.get_all(http::header::CONNECTION);
    let mut block = Vec::new();
    for (name, value) in headers {
        let name = name.as_str();
        if name == "content-length"
            || hop_by_hop(name, nominated.iter().map(http::HeaderValue::as_bytes))
        {
            continue;
        }
        block.extend_from_slice(name.as_bytes());
        block.extend_from_slice(SEPARATOR);
        block.extend_from_slice(value.as_bytes());
        block.extend_from_slice(LINE_END);
    }
    block
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
