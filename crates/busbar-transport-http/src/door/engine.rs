// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE: hyper's `client::conn` (HTTP/1.1 and HTTP/2) run as a sans-IO framer.
//!
//! One [`Framing`] is one connection. Its protocol machine is hyper's own, driven over the host's
//! bytes by the contract's sans-IO drive (`busbar_contract::hyper_io!`, expanded in `door`): an
//! in-memory pipe instead of a socket, the framing's own task list as hyper's executor, and the
//! host's clock as its timer. `ingest` appends what the far side sent to the pipe's read half, and
//! whatever hyper writes collects in its write half until the op hands it to the host as wire
//! bytes. Nothing here blocks, spawns a thread, opens a socket or reads a clock. A hyper `Pending`
//! means "more bytes from the far side, or a deadline": the op answers what it has and returns.
//! The earliest sleep still waiting becomes the op's `next_deadline_ns`.
//!
//! THE ONE REAL-CLOCK READ is the drive's (`HostIo::new`, at `begin`). h2 reads the real clock
//! itself for its reset-stream expiry (a bounded list of recently reset stream ids). That happens
//! inside the library and does not move this framing's clock.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

pub(crate) use super::hyper_io::field_block;
use super::hyper_io::{HeadWords, HostIo, Owed, Piece};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::rt::{Executor, Sleep};

use crate::raw::RawStartLine;
use crate::{complete_message, request_target, retry_after_secs, EgressHead};

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
    io: HostIo,
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
        // The one real-clock read: this framing's epoch (module docs).
        let io = HostIo::new(now_ns);
        let (exec, timer) = (io.exec(), io.timer());
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let (ex, err, done) = (exec.clone(), conn_err.clone(), conn_done.clone());
        let shim = io.stream();
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
        Ok(Self {
            io,
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
        })
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.io.ingest(bytes, end);
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
                self.out.push_back(Piece::failure(stream, &f.0));
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
        let wait = self.io.timer().sleep_until_ns(*deadline);
        self.exchanges[idx].1 = Stage::Queued(req, wait);
        Ok(())
    }

    /// Drive the connection at host time (`now_ns` monotonic, `now_unix_ns` wall) until nothing
    /// inside it has more to do.
    pub fn drive(&mut self, now_ns: u64, now_unix_ns: u64) {
        self.io.set_time(now_ns);
        self.now_unix_ns = now_unix_ns;
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();
        if let Err(f) = io.rounds(|cx| self.step(cx)) {
            self.failed = Some(f);
            return;
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
                self.out.push_back(Piece::failure(*id, &f.0 .0));
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
}

impl Owed for Framing {
    fn take_wire(&mut self, cap: usize) -> Vec<u8> {
        self.io.take_wire(cap)
    }
    fn wire_pending(&self) -> bool {
        self.io.wire_pending()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece> {
        &mut self.out
    }
    fn next_deadline(&self) -> Option<u64> {
        self.io.next_deadline()
    }
    fn ended(&self) -> bool {
        self.conn_done.load(Ordering::Acquire)
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
        status: Some(r.status().as_u16()),
        retry_after_secs: retry_after_secs(r.headers(), now_unix_secs),
        head: reason_phrase(r).map(HeadWords::reason),
        ..Piece::fields(stream, Bytes::from(field_block(r.headers(), &[])))
    }
}

/// An HTTP/1 answer's reason phrase exactly as sent: hyper keeps a phrase that differs from the
/// canonical one, and one it did not keep was the canonical phrase. HTTP/2 has none.
fn reason_phrase(r: &http::Response<Incoming>) -> Option<Bytes> {
    if r.version() >= http::Version::HTTP_2 {
        return None;
    }
    let phrase = r
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map_or_else(
            || Bytes::from_static(r.status().canonical_reason().unwrap_or("").as_bytes()),
            |p| Bytes::copy_from_slice(p.as_bytes()),
        );
    (!phrase.is_empty()).then_some(phrase)
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
