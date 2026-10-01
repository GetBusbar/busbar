// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE: gRPC over `hyper`'s HTTP/2, both sides, run as a sans-IO framer.
//!
//! One [`Conn`] is one connection. Its HTTP/2 machine is `hyper`'s own — `client::conn::http2`
//! on a dialled connection, `server::conn::http2` on an accepted one — driven over the host's
//! bytes by the contract's drive (`busbar_contract::hyper_io!`, expanded at the crate root): no
//! socket, no thread, no runtime, no clock of its own. This file adds the gRPC layer on top: the
//! head block, the length-prefixed messages, the deadline and `grpc-status`.
//!
//! DIALLED. The host `emit`s a stream's head block and its messages; the head's `path` names the
//! method. The request carries `content-type: application/grpc` (or the caller's `+proto`/`+json`
//! form), `te: trailers` and the stream's remaining deadline as `grpc-timeout`, and its body ENDS
//! (END_STREAM) once the head's `content-length` bytes are in, or on an `emit` that ends the frame:
//! a unary server waits for exactly that. The answer comes back as frames (HEAD-FIELDS, GRPC-DOOR
//! rulings): the HEAD, always first, a field block with no status code; one frame per message; the
//! TRAILERS, a field block carrying `grpc-status` as its code; then the terminal piece, empty when
//! the status is `OK`, else a failure whose bytes are the decoded `grpc-message`. A trailers-only
//! answer (status in the head) yields the same three. An answer that is not gRPC fails the stream
//! with its HTTP status mapped the way gRPC maps it. At the deadline the stream is reset and fails
//! `DEADLINE_EXCEEDED`.
//!
//! ACCEPTED. Each call the far end opens is a stream: its head (a field block, with the call's
//! method, target and authority in the stream's head slots, never as fields), one frame per
//! message, and the empty piece when the far end has sent its last. `te` is checked as 1.5.5's
//! server checked it, by HTTP/2 itself: a `te` other than `trailers` resets the stream with
//! `PROTOCOL_ERROR` before it is a call, and a missing one is served; it is then dropped as
//! hop-by-hop. The host answers on the same stream: `emit` a head block (the answer's metadata) and
//! messages; `refuse` with the trailer block (`grpc-status`, `grpc-message`, ...) ends the call —
//! trailers-only when nothing was emitted first. A call that is not gRPC is answered `415` here and
//! never reaches the host.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use crate::hyper_io::{field_block, HeadWords, HostIo, Owed, Piece};
use busbar_contract::abi::transport::fields::hop_by_hop;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client;
use hyper::rt::{Executor, Sleep};
use hyper::server::conn::http2 as server;

use crate::msg::{self, Head, Messages};

/// The connection posture every framing carries.
#[derive(Debug, Clone, Copy)]
pub struct Posture {
    /// HTTP/2 keep-alive ping interval on a dialled connection (`None` = no pings).
    pub keep_alive_interval: Option<Duration>,
    /// How long a keep-alive ping may go unanswered.
    pub keep_alive_timeout: Duration,
    /// HTTP/2 adaptive flow-control window.
    pub adaptive_window: bool,
    /// A dialled call's deadline when the host states none.
    pub timeout: Duration,
    /// The largest message payload carried, either way.
    pub max_message_bytes: usize,
}

/// Why a framing failed; the op that finds it answers FAILED with this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

// ── a body the host feeds ────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct ChanState {
    frames: VecDeque<Frame<Bytes>>,
    ended: bool,
    waker: Option<Waker>,
}

/// The feeding end of a [`ChanBody`].
#[derive(Clone, Default)]
struct Chan(Arc<Mutex<ChanState>>);

impl Chan {
    fn push(&self, f: Frame<Bytes>) {
        let mut s = self.0.lock().expect("chan");
        if s.ended {
            return;
        }
        s.frames.push_back(f);
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn end(&self) {
        let mut s = self.0.lock().expect("chan");
        s.ended = true;
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
    fn ended(&self) -> bool {
        self.0.lock().expect("chan").ended
    }
    fn body(&self) -> ChanBody {
        ChanBody(self.clone())
    }
}

/// A body whose frames the host hands in: data, then (on an answer) the trailers.
struct ChanBody(Chan);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let mut s = self.0 .0.lock().expect("chan");
        if let Some(f) = s.frames.pop_front() {
            return Poll::Ready(Some(Ok(f)));
        }
        if s.ended {
            return Poll::Ready(None);
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
    }
    fn is_end_stream(&self) -> bool {
        let s = self.0 .0.lock().expect("chan");
        s.ended && s.frames.is_empty()
    }
}

// ── the connection ───────────────────────────────────────────────────────────────────────────────

/// One connection's gRPC machine.
pub struct Conn {
    io: HostIo,
    out: VecDeque<Piece>,
    conn_err: Arc<Mutex<Option<String>>>,
    conn_done: Arc<AtomicBool>,
    failed: Option<Failure>,
    posture: Posture,
    side: Side,
}

enum Side {
    Dial(Dial),
    Accept(Accept),
}

impl Owed for Conn {
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

fn watch<F>(
    exec: &impl Executor<BoxFut<()>>,
    conn: F,
    err: &Arc<Mutex<Option<String>>>,
    done: &Arc<AtomicBool>,
) where
    F: Future<Output = hyper::Result<()>> + Send + 'static,
{
    let (err, done) = (err.clone(), done.clone());
    exec.execute(Box::pin(async move {
        if let Err(e) = conn.await {
            *err.lock().expect("err") = Some(e.to_string());
        }
        done.store(true, Ordering::Release);
    }));
}

impl Conn {
    /// Open a dialled connection to `target` (an `http`/`https` URL: its scheme and authority are
    /// every call's), at host time `now_ns`.
    ///
    /// # Errors
    ///
    /// `target` is not a URL with a host.
    pub fn dial(target: &str, posture: Posture, now_ns: u64) -> Result<Self, Failure> {
        let uri: http::Uri = target
            .parse()
            .map_err(|_| Failure(format!("not a target: {target}")))?;
        let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
            return Err(Failure(format!("not a target: {target}")));
        };
        let base = format!("{scheme}://{authority}");
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let mut b = client::Builder::new(io.exec());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        if let Some(every) = posture.keep_alive_interval {
            b.keep_alive_interval(every)
                .keep_alive_timeout(posture.keep_alive_timeout);
        }
        let (exec, err, done, stream) =
            (io.exec(), conn_err.clone(), conn_done.clone(), io.stream());
        let handshake: BoxFut<hyper::Result<client::SendRequest<ChanBody>>> =
            Box::pin(async move {
                let (s, c) = b.handshake(stream).await?;
                watch(&exec, c, &err, &done);
                Ok(s)
            });
        Ok(Self {
            io,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            side: Side::Dial(Dial {
                handshake: Some(handshake),
                sender: None,
                base,
                calls: Vec::new(),
            }),
        })
    }

    /// Open an accepted connection, at host time `now_ns`.
    #[must_use]
    pub fn accept(posture: Posture, now_ns: u64) -> Self {
        let io = HostIo::new(now_ns);
        let conn_err = Arc::new(Mutex::new(None));
        let conn_done = Arc::new(AtomicBool::new(false));
        let arrivals = Arc::new(Mutex::new(Arrivals::default()));
        let svc_arrivals = arrivals.clone();
        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let reply = Reply::default();
            {
                let mut a = svc_arrivals.lock().expect("arrivals");
                a.next += 1;
                let id = a.next;
                a.new.push_back((id, req, reply.clone()));
            }
            ReplyFut(reply)
        });
        let mut b = server::Builder::new(io.exec());
        b.timer(io.timer()).adaptive_window(posture.adaptive_window);
        let conn = b.serve_connection(io.stream(), svc);
        watch(&io.exec(), conn, &conn_err, &conn_done);
        Self {
            io,
            out: VecDeque::new(),
            conn_err,
            conn_done,
            failed: None,
            posture,
            side: Side::Accept(Accept {
                arrivals,
                calls: Vec::new(),
            }),
        }
    }

    /// The far side sent `bytes` (`end` = and then ended).
    pub fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.io.ingest(bytes, end);
    }

    /// Bytes for `stream` (`end` = they end the frame). `deadline_ns` is the attempt's deadline on
    /// a dialled stream's first `emit` (`0` = none stated), `now_ns` the host's time.
    ///
    /// # Errors
    ///
    /// No such accepted stream.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<(), Failure> {
        // A re-call after `YIELD_MORE` carries no new bytes, and the frame's end was taken with
        // the bytes: every step below is idempotent on it.
        let max = self.posture.max_message_bytes.saturating_add(64 * 1024);
        match &mut self.side {
            Side::Dial(d) => {
                let timer = self.io.timer();
                let fallback = now_ns.saturating_add(
                    u64::try_from(self.posture.timeout.as_nanos()).unwrap_or(u64::MAX),
                );
                let idx = match d.calls.iter().position(|(s, _)| *s == stream) {
                    Some(i) => i,
                    None => {
                        let at = if deadline_ns == 0 {
                            fallback
                        } else {
                            deadline_ns
                        };
                        d.calls
                            .push((stream, DialStream::new(at, timer.sleep_until_ns(at))));
                        d.calls.len() - 1
                    }
                };
                let base = d.base.clone();
                let s = &mut d.calls[idx].1;
                if let Err(why) = s.take(&base, bytes, end, now_ns, max) {
                    s.stage = DStage::Done;
                    self.out.push_back(Piece {
                        status: Some(msg::INTERNAL),
                        ..Piece::failure(stream, &why)
                    });
                }
                d.calls.retain(|(_, s)| !s.over());
                Ok(())
            }
            Side::Accept(a) => {
                let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
                    return Err(Failure(format!("no such stream: {stream}")));
                };
                if bytes.is_empty() || s.reply_over {
                    return Ok(());
                }
                if !s.head_sent {
                    s.head_buf.extend_from_slice(bytes);
                    match msg::read_head(&s.head_buf, max) {
                        Ok(None) => return Ok(()),
                        Err(why) => {
                            s.fail_reply(msg::INTERNAL, why.as_bytes());
                            return Ok(());
                        }
                        Ok(Some((head, took))) => {
                            let rest = s.head_buf.split_off(took);
                            s.head_buf.clear();
                            s.send_head(&head, None);
                            if !rest.is_empty() {
                                s.reply.chan.push(Frame::data(Bytes::from(rest)));
                            }
                        }
                    }
                } else {
                    s.reply
                        .chan
                        .push(Frame::data(Bytes::copy_from_slice(bytes)));
                }
                Ok(())
            }
        }
    }

    /// End accepted `stream` with `trailers` (a block of `name: value` lines; `grpc-status` is
    /// `UNKNOWN` with the bytes as its message when the block does not state one).
    ///
    /// # Errors
    ///
    /// This is a dialled connection, or no such stream.
    pub fn end_call(&mut self, stream: u64, trailers: &[u8]) -> Result<(), Failure> {
        let Side::Accept(a) = &mut self.side else {
            return Err(Failure("a dialled call is not answered".into()));
        };
        let Some((_, s)) = a.calls.iter_mut().find(|(s, _)| *s == stream) else {
            return Err(Failure(format!("no such stream: {stream}")));
        };
        if s.reply_over {
            return Ok(());
        }
        let mut block = trailers.to_vec();
        if !block.ends_with(b"\r\n\r\n") {
            if !block.ends_with(b"\r\n") && !block.is_empty() {
                block.extend_from_slice(b"\r\n");
            }
            block.extend_from_slice(b"\r\n");
        }
        let head = match msg::read_head(&block, usize::MAX) {
            Ok(Some((h, _))) if h.get(msg::GRPC_STATUS).is_some() => h,
            _ => Head {
                fields: vec![
                    (msg::GRPC_STATUS.into(), msg::UNKNOWN.to_string().into_bytes()),
                    (
                        msg::GRPC_MESSAGE.into(),
                        msg::encode_message(trailers).into_bytes(),
                    ),
                ],
                content_length: None,
            },
        };
        s.finish(&head);
        Ok(())
    }

    /// Drive the connection at host time `now_ns` until nothing inside it has more to do.
    pub fn drive(&mut self, now_ns: u64) {
        self.io.set_time(now_ns);
        if self.failed.is_some() {
            return;
        }
        let io = self.io.clone();
        let max = self.posture.max_message_bytes;
        let r = io.rounds(|cx| match &mut self.side {
            Side::Dial(d) => d.step(&mut self.out, max, cx),
            Side::Accept(a) => {
                a.step(&mut self.out, max, &io, cx);
                Ok(())
            }
        });
        if let Err(f) = r {
            self.failed = Some(f);
            return;
        }
        let err = self.conn_err.lock().expect("err").clone();
        if let Some(e) = err {
            let busy = match &self.side {
                Side::Dial(d) => !d.calls.is_empty(),
                Side::Accept(_) => false,
            };
            if busy {
                self.failed = Some(Failure(e));
            }
        }
    }

    /// Why this framing failed, once it has.
    #[must_use]
    pub fn failure(&self) -> Option<&Failure> {
        self.failed.as_ref()
    }
}

// ── the dialled side ─────────────────────────────────────────────────────────────────────────────

struct Dial {
    handshake: Option<BoxFut<hyper::Result<client::SendRequest<ChanBody>>>>,
    sender: Option<client::SendRequest<ChanBody>>,
    base: String,
    calls: Vec<(u64, DialStream)>,
}

enum DStage {
    /// The head block, still arriving.
    Head(Vec<u8>),
    /// A request, waiting for the connection to take it.
    Queued(Request<ChanBody>),
    /// Sent; waiting for the answer's head.
    Asked(BoxFut<hyper::Result<Response<Incoming>>>),
    /// The answer's messages.
    Body(Incoming, Messages),
    /// Answered in full, or failed.
    Done,
}

struct DialStream {
    stage: DStage,
    chan: Chan,
    /// Bytes of the message stream still to come, when the head stated its length.
    left: Option<usize>,
    deadline_ns: u64,
    sleep: Pin<Box<dyn Sleep>>,
}

impl DialStream {
    fn new(deadline_ns: u64, sleep: Pin<Box<dyn Sleep>>) -> Self {
        Self {
            stage: DStage::Head(Vec::new()),
            chan: Chan::default(),
            left: None,
            deadline_ns,
            sleep,
        }
    }

    fn over(&self) -> bool {
        matches!(self.stage, DStage::Done)
    }

    /// Take `bytes` the host emitted on this stream.
    fn take(
        &mut self,
        base: &str,
        bytes: &[u8],
        end: bool,
        now_ns: u64,
        max: usize,
    ) -> Result<(), String> {
        let body: Vec<u8> = match &mut self.stage {
            DStage::Head(buf) => {
                buf.extend_from_slice(bytes);
                let Some((head, took)) = msg::read_head(buf, max)? else {
                    if end {
                        return Err("the frame ended inside the head block".into());
                    }
                    return Ok(());
                };
                let rest = buf.split_off(took);
                let req = self.request(base, &head, now_ns)?;
                self.left = head.content_length;
                self.stage = DStage::Queued(req);
                rest
            }
            DStage::Done => return Ok(()),
            _ => bytes.to_vec(),
        };
        if !body.is_empty() {
            if let Some(left) = self.left.as_mut() {
                if body.len() > *left {
                    return Err("more message bytes than the head's content-length".into());
                }
                *left -= body.len();
            }
            self.chan.push(Frame::data(Bytes::from(body)));
        }
        if self.left == Some(0) || (end && self.left.is_none()) {
            // The request's last byte: END_STREAM follows it.
            self.chan.end();
        }
        Ok(())
    }

    fn request(&self, base: &str, head: &Head, now_ns: u64) -> Result<Request<ChanBody>, String> {
        let path = head.get("path").ok_or("the head names no path")?;
        if !path.starts_with(b"/") {
            return Err("the head's path is not absolute".into());
        }
        let uri = format!("{base}{}", String::from_utf8_lossy(path));
        let content_type = match head.get("content-type") {
            Some(ct) if msg::is_grpc_content_type(ct) => {
                HeaderValue::from_bytes(ct).map_err(|_| "content-type is not a field value")?
            }
            Some(_) => return Err("content-type is not a gRPC content type".into()),
            None => HeaderValue::from_static(msg::CONTENT_TYPE),
        };
        let mut b = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .version(http::Version::HTTP_2)
            .header(http::header::CONTENT_TYPE, content_type)
            .header(http::header::TE, "trailers");
        let left = Duration::from_nanos(self.deadline_ns.saturating_sub(now_ns));
        b = b.header(msg::GRPC_TIMEOUT, msg::timeout_value(left));
        for (name, value) in &head.fields {
            if RESERVED_ON_REQUEST.contains(&name.as_str()) || hop_by_hop(name, []) {
                continue;
            }
            let n = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("`{name}` is not a field name"))?;
            let v = HeaderValue::from_bytes(value)
                .map_err(|_| format!("`{name}`'s value is not a field value"))?;
            b = b.header(n, v);
        }
        b.body(self.chan.body())
            .map_err(|e| format!("request: {e}"))
    }
}

/// Fields this layer owns on a request, beside the hop-by-hop ones HTTP/2 forbids: a head block's
/// own are dropped.
const RESERVED_ON_REQUEST: &[&str] = &[
    "path",
    "method",
    "authority",
    "content-type",
    msg::GRPC_TIMEOUT,
    "content-length",
    "host",
];

impl Dial {
    fn step(
        &mut self,
        out: &mut VecDeque<Piece>,
        max: usize,
        cx: &mut Context<'_>,
    ) -> Result<(), Failure> {
        if let Some(h) = self.handshake.as_mut() {
            if let Poll::Ready(r) = h.as_mut().poll(cx) {
                self.handshake = None;
                self.sender = Some(r.map_err(|e| Failure(e.to_string()))?);
            }
        }
        for (id, s) in &mut self.calls {
            if let Err((why, code, conn)) = advance(*id, s, &mut self.sender, out, max, cx) {
                if conn {
                    return Err(Failure(why));
                }
                s.stage = DStage::Done;
                out.push_back(Piece {
                    status: Some(code),
                    ..Piece::failure(*id, &why)
                });
            }
        }
        self.calls.retain(|(_, s)| !s.over());
        Ok(())
    }
}

/// Move one dialled stream as far as it goes this round. `Err((why, code, true))` is the
/// connection's failure (the sender refused), `Err((why, code, false))` the stream's own.
fn advance(
    id: u64,
    s: &mut DialStream,
    sender: &mut Option<client::SendRequest<ChanBody>>,
    out: &mut VecDeque<Piece>,
    max: usize,
    cx: &mut Context<'_>,
) -> Result<(), (String, u16, bool)> {
    if !s.over() && s.sleep.as_mut().poll(cx).is_ready() {
        // Dropping the exchange resets the stream on the wire.
        return Err(("deadline exceeded".into(), msg::DEADLINE_EXCEEDED, false));
    }
    loop {
        match &mut s.stage {
            DStage::Head(_) | DStage::Done => return Ok(()),
            DStage::Queued(_) => {
                let Some(snd) = sender.as_mut() else {
                    return Ok(());
                };
                match snd.poll_ready(cx) {
                    Poll::Pending => return Ok(()),
                    Poll::Ready(r) => r.map_err(|e| (e.to_string(), msg::UNAVAILABLE, true))?,
                }
                let DStage::Queued(req) = std::mem::replace(&mut s.stage, DStage::Done) else {
                    unreachable!("matched above")
                };
                s.stage = DStage::Asked(Box::pin(snd.send_request(req)));
            }
            DStage::Asked(f) => match f.as_mut().poll(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(r) => {
                    let r = r.map_err(|e| (e.to_string(), msg::UNAVAILABLE, false))?;
                    if r.status() != StatusCode::OK {
                        let code = r.status().as_u16();
                        return Err((
                            format!("HTTP status {code}"),
                            msg::status_of_http(code),
                            false,
                        ));
                    }
                    let ct = r.headers().get(http::header::CONTENT_TYPE);
                    if !ct.is_some_and(|v| msg::is_grpc_content_type(v.as_bytes())) {
                        return Err(("the answer is not gRPC".into(), msg::UNKNOWN, false));
                    }
                    out.push_back(Piece::fields(
                        id,
                        Bytes::from(field_block(r.headers(), STATUS_FIELDS)),
                    ));
                    if r.headers().contains_key(msg::GRPC_STATUS) {
                        // Trailers-only: the status is in the head, and the body is empty.
                        out.extend(trailers(id, &HeaderMap::new(), r.headers()));
                        s.stage = DStage::Done;
                        return Ok(());
                    }
                    s.stage = DStage::Body(r.into_body(), Messages::new(max));
                }
            },
            DStage::Body(b, msgs) => match Pin::new(&mut *b).poll_frame(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Some(Err(e))) => return Err((e.to_string(), msg::INTERNAL, false)),
                Poll::Ready(Some(Ok(fr))) => match fr.into_data() {
                    Ok(d) => {
                        let got = msgs
                            .push(&d)
                            .map_err(|e| (e.to_string(), msg::INTERNAL, false))?;
                        out.extend(got.into_iter().map(|m| Piece::data(id, m)));
                    }
                    Err(other) => {
                        if let Ok(t) = other.into_trailers() {
                            msgs.end()
                                .map_err(|e| (e.to_string(), msg::INTERNAL, false))?;
                            out.extend(trailers(id, &t, &t));
                            s.stage = DStage::Done;
                            return Ok(());
                        }
                    }
                },
                Poll::Ready(None) => {
                    return Err((
                        "the answer ended without a grpc-status".into(),
                        msg::UNKNOWN,
                        false,
                    ))
                }
            },
        }
    }
}

/// The fields the trailers' code and the terminal piece carry, never a field block's.
const STATUS_FIELDS: &[&str] = &[msg::GRPC_STATUS, msg::GRPC_MESSAGE];

/// The stream's end, from the fields that carry `grpc-status` (`status`): the trailers (`fields`
/// as a field block, its code the status), then the terminal piece — empty on `OK`, else the
/// failure whose bytes are the decoded `grpc-message`.
fn trailers(id: u64, fields: &HeaderMap, status: &HeaderMap) -> [Piece; 2] {
    let code = status
        .get(msg::GRPC_STATUS)
        .map_or(msg::UNKNOWN, |v| msg::parse_status(v.as_bytes()));
    let block = Piece {
        status: Some(code),
        ..Piece::fields(id, Bytes::from(field_block(fields, STATUS_FIELDS)))
    };
    if code == msg::OK {
        return [block, Piece::data(id, Bytes::new())];
    }
    let text = status
        .get(msg::GRPC_MESSAGE)
        .map(|v| msg::decode_message(v.as_bytes()))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| format!("grpc-status {code}").into_bytes());
    [
        block,
        Piece {
            failed: true,
            ..Piece::data(id, Bytes::from(text))
        },
    ]
}

// ── the accepted side ────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Arrivals {
    next: u64,
    new: VecDeque<(u64, Request<Incoming>, Reply)>,
}

#[derive(Default)]
struct ReplyState {
    head: Option<(StatusCode, HeaderMap)>,
    waker: Option<Waker>,
}

/// The answer to one accepted call: its head once the host states it, and its body.
#[derive(Clone, Default)]
struct Reply {
    state: Arc<Mutex<ReplyState>>,
    chan: Chan,
}

impl Reply {
    fn head(&self, status: StatusCode, fields: HeaderMap) {
        let mut s = self.state.lock().expect("reply");
        s.head = Some((status, fields));
        if let Some(w) = s.waker.take() {
            w.wake();
        }
    }
}

/// The service's answer: ready once the host has stated the head.
struct ReplyFut(Reply);

impl Future for ReplyFut {
    type Output = Result<Response<ChanBody>, Infallible>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut s = self.0.state.lock().expect("reply");
        let Some((status, fields)) = s.head.take() else {
            s.waker = Some(cx.waker().clone());
            return Poll::Pending;
        };
        let mut r = Response::new(self.0.chan.body());
        *r.status_mut() = status;
        *r.headers_mut() = fields;
        Poll::Ready(Ok(r))
    }
}

struct Accept {
    arrivals: Arc<Mutex<Arrivals>>,
    calls: Vec<(u64, AStream)>,
}

struct AStream {
    /// The call's messages; `None` once the far end has sent its last.
    body: Option<(Incoming, Messages)>,
    reply: Reply,
    content_type: HeaderValue,
    head_buf: Vec<u8>,
    head_sent: bool,
    reply_over: bool,
    sleep: Option<Pin<Box<dyn Sleep>>>,
}

impl AStream {
    fn send_head(&mut self, head: &Head, trailers: Option<&Head>) {
        let mut fields = HeaderMap::new();
        fields.insert(http::header::CONTENT_TYPE, self.content_type.clone());
        for h in std::iter::once(head).chain(trailers) {
            for (name, value) in &h.fields {
                if RESERVED_ON_ANSWER.contains(&name.as_str()) || hop_by_hop(name, []) {
                    continue;
                }
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    fields.append(n, v);
                }
            }
        }
        self.head_sent = true;
        self.reply.head(StatusCode::OK, fields);
    }

    fn finish(&mut self, trailers: &Head) {
        if self.head_sent {
            let mut map = HeaderMap::new();
            for (name, value) in &trailers.fields {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    map.append(n, v);
                }
            }
            self.reply.chan.push(Frame::trailers(map));
        } else {
            // Trailers-only: one HEADERS frame carrying the status, and END_STREAM.
            self.send_head(&Head::default(), Some(trailers));
        }
        self.reply.chan.end();
        self.reply_over = true;
    }

    fn fail_reply(&mut self, code: u16, why: &[u8]) {
        self.finish(&Head {
            fields: vec![
                (msg::GRPC_STATUS.into(), code.to_string().into_bytes()),
                (msg::GRPC_MESSAGE.into(), msg::encode_message(why).into_bytes()),
            ],
            content_length: None,
        });
    }
}

/// Fields this layer owns on an answer's head, beside the hop-by-hop ones.
const RESERVED_ON_ANSWER: &[&str] = &["content-type", "content-length"];

impl Accept {
    fn step(&mut self, out: &mut VecDeque<Piece>, max: usize, io: &HostIo, cx: &mut Context<'_>) {
        let new: Vec<_> = self
            .arrivals
            .lock()
            .expect("arrivals")
            .new
            .drain(..)
            .collect();
        for (id, req, reply) in new {
            let ct = req.headers().get(http::header::CONTENT_TYPE).cloned();
            let Some(ct) = ct.filter(|v| msg::is_grpc_content_type(v.as_bytes())) else {
                // Not a gRPC call: answered here, never handed up.
                reply.head(StatusCode::UNSUPPORTED_MEDIA_TYPE, HeaderMap::new());
                reply.chan.end();
                continue;
            };
            let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
            let words = HeadWords {
                method: Bytes::copy_from_slice(req.method().as_str().as_bytes()),
                target: Bytes::copy_from_slice(target.as_bytes()),
                authority: req.uri().authority().map_or_else(Bytes::new, |a| {
                    Bytes::copy_from_slice(a.as_str().as_bytes())
                }),
                reason: Bytes::new(),
            };
            let sleep = req
                .headers()
                .get(msg::GRPC_TIMEOUT)
                .and_then(|v| msg::parse_timeout(v.as_bytes()))
                .map(|d| {
                    let now = io.timer().now_ns();
                    io.timer().sleep_until_ns(
                        now.saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
                    )
                });
            out.push_back(Piece {
                head: Some(words),
                ..Piece::fields(id, Bytes::from(field_block(req.headers(), &[])))
            });
            self.calls.push((
                id,
                AStream {
                    body: Some((req.into_body(), Messages::new(max))),
                    reply,
                    content_type: ct,
                    head_buf: Vec::new(),
                    head_sent: false,
                    reply_over: false,
                    sleep,
                },
            ));
        }
        for (id, s) in &mut self.calls {
            if !s.reply_over {
                if let Some(sl) = s.sleep.as_mut() {
                    if sl.as_mut().poll(cx).is_ready() {
                        s.sleep = None;
                        s.fail_reply(msg::DEADLINE_EXCEEDED, b"deadline exceeded");
                        s.body = None;
                        out.push_back(Piece {
                            status: Some(msg::DEADLINE_EXCEEDED),
                            ..Piece::failure(*id, "deadline exceeded")
                        });
                        continue;
                    }
                }
            }
            while let Some((b, msgs)) = s.body.as_mut() {
                match Pin::new(&mut *b).poll_frame(cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(fr))) => {
                        if let Ok(d) = fr.into_data() {
                            match msgs.push(&d) {
                                Ok(got) => out.extend(got.into_iter().map(|m| Piece::data(*id, m))),
                                Err(e) => {
                                    let why = e.to_string();
                                    s.body = None;
                                    s.fail_reply(msg::INTERNAL, why.as_bytes());
                                    out.push_back(Piece {
                                        status: Some(msg::INTERNAL),
                                        ..Piece::failure(*id, &why)
                                    });
                                }
                            }
                        }
                    }
                    Poll::Ready(None) => {
                        let whole = msgs.end();
                        s.body = None;
                        match whole {
                            // The far end sent its last: the empty piece.
                            Ok(()) => out.push_back(Piece::data(*id, Bytes::new())),
                            Err(e) => {
                                let why = e.to_string();
                                s.fail_reply(msg::INTERNAL, why.as_bytes());
                                out.push_back(Piece {
                                    status: Some(msg::INTERNAL),
                                    ..Piece::failure(*id, &why)
                                });
                            }
                        }
                    }
                    Poll::Ready(Some(Err(e))) => {
                        // The far end reset the call.
                        s.body = None;
                        s.reply_over = true;
                        s.reply.chan.end();
                        out.push_back(Piece {
                            status: Some(msg::CANCELLED),
                            ..Piece::failure(*id, &e.to_string())
                        });
                    }
                }
            }
        }
        self.calls
            .retain(|(_, s)| !(s.reply_over && s.body.is_none() && s.reply.chan.ended()));
    }
}

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod tests;
