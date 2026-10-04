// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE REQUEST, ONE REPLY, over the host connector (THE DESIGN, the connections section; ARCHITECT R2a:
//! `exchange()` is FRAMED). [`exchange`] opens a framed need, sends one [`Request`] through the
//! framer ([`Connector::write_request`]: head, body, end — the framer writes its own wire head, one
//! library per protocol) and reads the reply to its terminal piece into an [`ExchangeResponse`].
//! [`send_and_ack`] is its form for any transport: it writes bytes and answers the transport's
//! [`Ack`] (OWNER ruling: a plugin that sends sees what became of it).
//!
//! Both answer PENDING until they complete. The caller parks the [`Exchange`] on its ticket across
//! PENDING entries (`abi::sdk::safe::Instance::park`) and passes it back each time, making the same
//! services in the same order (the replay rule, `abi::sdk::conn`): no service runs twice.

use std::task::Poll;

use crate::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::{Answer, ConnFailure, Connector, Host, Observed};
use crate::abi::sdk::safe::Instance;
use crate::abi::transport::{fields, FrameSpan};

/// How much one read of a reply asks for.
pub const READ_CHUNK: usize = 16 * 1024;

/// The most a reply's body may reach before the exchange fails (a far end that never ends).
pub const REPLY_MAX: usize = 16 * 1024 * 1024;

/// The failure text of a reply whose body passed [`REPLY_MAX`]: a driver that words that case its
/// own way matches on it.
pub const REPLY_OVER_BOUND: &str = "the reply passed the exchange's bound";

/// ONE REQUEST, as [`exchange`] sends it through a framed need.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Vec<u8>,
    /// The target (the path and query, or what the framer's protocol names a target).
    pub target: Vec<u8>,
    /// The fields, in order; a name never starts with `:` (no pseudo-field) and no name or value
    /// carries a line break.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
    /// How long the request may take, milliseconds; `0` = the op's deadline. Clamped to what is
    /// left of the op's deadline ([`Connector::within`]), and by the host to its deadline class.
    pub timeout_ms: u64,
}

/// The far end's reply to an [`exchange`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeResponse {
    /// The code: the reply's status, or the transport's result code.
    pub status: u16,
    /// The reason exactly as the peer sent it (a non-canonical phrase included); `None` when the
    /// transport carries none.
    pub reason: Option<Vec<u8>>,
    /// The reply's fields, in order, as the field block names them.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

/// What became of what a [`send_and_ack`] sent: the transport's code and the peer's text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ack {
    /// The transport's result code.
    pub code: u32,
    /// The peer's text, exactly as sent; empty when none.
    pub reason: Vec<u8>,
}

/// What is sent: a framed request's head bytes and descriptors, or raw bytes.
#[derive(Debug)]
enum Sending {
    Framed {
        /// The head's method, target and field block, one after another.
        head: Box<[u8]>,
        head_piece: Box<RequestPiece>,
        body: Box<[u8]>,
        body_piece: Box<RequestPiece>,
        end_piece: Box<RequestPiece>,
        timeout_ms: u64,
    },
    Raw(Box<[u8]>),
}

/// An [`exchange`]'s (or a [`send_and_ack`]'s) state across its op's PENDING entries: what it sends
/// (a pending write reads it), the read buffer and the descriptor slot (a pending read writes
/// them) and the reply so far. Parked on the ticket.
#[derive(Debug)]
pub struct Exchange {
    sending: Sending,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
    reply: ExchangeResponse,
    code: u32,
    /// How many of this op's services' results are already applied to `reply`.
    applied: u32,
    /// The handle of the read that answered the terminal piece, once one has.
    ended: Option<u32>,
    /// The address set the dial must land on ([`Exchange::landing_within`]); empty = no pin.
    within: String,
    /// The stream's facts are read before it closes ([`Exchange::observing`]).
    observe: bool,
    /// What they said, once read: kept across replays, which answer without writing them again.
    observed: Option<Observed>,
}

fn piece(kind: u32) -> Box<RequestPiece> {
    Box::new(RequestPiece {
        kind,
        ..RequestPiece::default()
    })
}

const fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
    }
}

impl Exchange {
    fn over(sending: Sending) -> Self {
        Self {
            sending,
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            slot: Box::default(),
            reply: ExchangeResponse::default(),
            code: 0,
            applied: 0,
            ended: None,
            within: String::new(),
            observe: false,
            observed: None,
        }
    }

    /// Read the stream's facts ([`Connector::facts`]) once its reply has ended — or once the reply
    /// failed, a connection the connector refused for its trust anchors included — before it is
    /// closed: [`Exchange::observed`] answers them. One more service on the op's count, made only
    /// by an exchange that asks.
    #[must_use]
    pub fn observing(mut self) -> Self {
        self.observe = true;
        self
    }

    /// What the stream's facts said ([`Exchange::observing`]); `None` before they were read, for
    /// an exchange that did not ask, or a host that offers no facts.
    #[must_use]
    pub fn observed(&self) -> Option<&Observed> {
        self.observed.as_ref()
    }

    /// Land this exchange's dial only on an address of `within`, the set the plugin's
    /// `dest.judge` judged (`Judged::within`): a name that resolves elsewhere at dial time is
    /// refused before the request leaves.
    #[must_use]
    pub fn landing_within(mut self, within: String) -> Self {
        self.within = within;
        self
    }

    /// An exchange sending `request` through a framed need.
    ///
    /// # Errors
    /// A field is a pseudo-field (its name starts with `:`), or a name or value carries a line
    /// break: REFUSED, nothing sent.
    pub fn request(request: Request) -> Result<Self, ConnFailure> {
        let mut head = Vec::new();
        head.extend_from_slice(&request.method);
        head.extend_from_slice(&request.target);
        let block_at = head.len();
        for (name, value) in &request.fields {
            if name.first() == Some(&b':') {
                return Err(ConnFailure::Refused(format!(
                    "a request field `{}` is a pseudo-field; the framer names its own head",
                    String::from_utf8_lossy(name)
                )));
            }
            if name.iter().chain(value).any(|b| *b == b'\r' || *b == b'\n') {
                return Err(ConnFailure::Refused(format!(
                    "the request field `{}` carries a line break",
                    String::from_utf8_lossy(name)
                )));
            }
            head.extend_from_slice(name);
            head.extend_from_slice(fields::SEPARATOR);
            head.extend_from_slice(value);
            head.extend_from_slice(fields::LINE_END);
        }
        let (m, t) = (request.method.len(), request.target.len());
        let head_piece = Box::new(RequestPiece {
            kind: REQUEST_HEAD,
            _reserved: 0,
            method: span(0, m),
            target: span(m, t),
            fields: span(block_at, head.len() - block_at),
            timeout_ms: request.timeout_ms,
        });
        Ok(Self::over(Sending::Framed {
            head: head.into_boxed_slice(),
            head_piece,
            body: request.body.into_boxed_slice(),
            body_piece: piece(REQUEST_BODY),
            end_piece: piece(REQUEST_END),
            timeout_ms: request.timeout_ms,
        }))
    }

    /// An exchange sending `bytes` as they are, over any transport ([`send_and_ack`]).
    #[must_use]
    pub fn send(bytes: Vec<u8>) -> Self {
        Self::over(Sending::Raw(bytes.into_boxed_slice()))
    }
}

/// The bytes `span` names in `buf`, or none past its end.
fn spanned(buf: &[u8], span: FrameSpan) -> &[u8] {
    let (at, len) = (span.offset as usize, span.len as usize);
    buf.get(at..at.saturating_add(len)).unwrap_or(&[])
}

fn failed<T>(text: &str) -> Answer<T> {
    Poll::Ready(Err(ConnFailure::Failed(text.to_string())))
}

/// Ready(Ok(v)) -> v; anything else returns it from the calling function.
macro_rules! ready {
    ($e:expr) => {
        match $e {
            Poll::Ready(Ok(v)) => v,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    };
}

/// Write every byte of `bytes` through `write`, which answers how many it took.
fn write_all(mut write: impl FnMut(&[u8]) -> Answer<usize>, bytes: &[u8]) -> Answer<()> {
    let mut sent = 0;
    while sent < bytes.len() {
        match ready!(write(&bytes[sent..])) {
            0 => return failed("the far end took no bytes"),
            n => sent += n,
        }
    }
    Poll::Ready(Ok(()))
}

/// Send what `state` holds on `stream`.
fn send(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Answer<()> {
    let budget = c.budget_ms();
    match &mut state.sending {
        Sending::Raw(bytes) => write_all(|b| c.write(stream, b), bytes),
        Sending::Framed {
            head,
            head_piece,
            body,
            body_piece,
            end_piece,
            timeout_ms,
        } => {
            // The op's remaining budget bounds the request's own timeout (0 = the budget).
            head_piece.timeout_ms = match (*timeout_ms, budget) {
                (0, Some(b)) => b,
                (t, Some(b)) => t.min(b),
                (t, None) => t,
            };
            let head_piece: &RequestPiece = head_piece;
            let taken = ready!(c.write_request(stream, head_piece, head));
            if taken != head.len() {
                return failed("the framer took part of the request head");
            }
            let body_piece: &RequestPiece = body_piece;
            ready!(write_all(|b| c.write_request(stream, body_piece, b), body));
            ready!(c.write_request(stream, end_piece, &[]));
            Poll::Ready(Ok(()))
        }
    }
}

/// Send, then read the reply to its terminal piece into `state`.
fn send_and_read(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<()> {
    let stream = ready!(c.establish(need, target, &state.within));
    ready!(send(c, state, stream));
    loop {
        let this = c.issued();
        let got = match c.read_reply(stream, &mut state.buf, &mut state.slot) {
            Poll::Ready(Ok(got)) => got,
            Poll::Ready(Err(e)) => {
                // A failed reply: what the stream observed says why, where the caller asks.
                if observe(c, state, stream).is_pending() {
                    return Poll::Pending;
                }
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        };
        // A replayed read answers its stored result; it was applied on the entry that first saw it
        // (its bytes are no longer in the buffer).
        let fresh = this >= state.applied;
        if fresh {
            state.applied = this + 1;
        }
        let p = got.piece;
        match p.kind {
            REPLY_HEAD | REPLY_ACK if fresh => {
                let bytes = &state.buf[..got.len];
                state.code = p.code;
                let reason = spanned(bytes, p.reason);
                state.reply.reason = (!reason.is_empty()).then(|| reason.to_vec());
                state.reply.fields = fields::lines(spanned(bytes, p.fields))
                    .map(|(n, v)| (n.to_vec(), v.to_vec()))
                    .collect();
            }
            REPLY_BODY if fresh => {
                state.reply.body.extend_from_slice(&state.buf[..got.len]);
                if state.reply.body.len() > REPLY_MAX {
                    return failed(REPLY_OVER_BOUND);
                }
            }
            REPLY_HEAD | REPLY_ACK | REPLY_BODY | REPLY_END => {}
            _ => return failed("the transport answered no reply piece: every request is acked"),
        }
        // The terminal piece ends the reads, on the entry that first saw it and on every replay
        // of that read. A replayed earlier read never does: the piece descriptor is the op's one
        // parked slot, so a replay finds the LATEST read's piece there, not its own.
        if fresh && matches!(p.kind, REPLY_ACK | REPLY_END) {
            state.ended = Some(this);
        }
        if state.ended == Some(this) {
            break;
        }
    }
    if observe(c, state, stream).is_pending() {
        return Poll::Pending;
    }
    match c.close(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => Poll::Ready(Ok(())),
    }
}

/// Read `stream`'s facts into `state` where it asks ([`Exchange::observing`]): a facts answer the
/// host replays leaves what the first entry read; a host that offers none leaves none.
fn observe(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Poll<()> {
    if !state.observe {
        return Poll::Ready(());
    }
    match c.facts(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(Some(observed))) => {
            state.observed = Some(observed);
            Poll::Ready(())
        }
        Poll::Ready(_) => Poll::Ready(()),
    }
}

/// ONE REQUEST, ONE REPLY over the declared framed need `need` to `target` (`None` = the need's
/// `target_from`): establish, send the [`Exchange::request`] (head, body, end), read the reply to
/// its terminal piece, close. PENDING until it completes; READY with the reply's code, reason,
/// fields and body, or why it failed. Bounded by the op's deadline and by [`REPLY_MAX`].
pub fn exchange(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<ExchangeResponse> {
    ready!(send_and_read(c, state, need, target));
    let mut reply = std::mem::take(&mut state.reply);
    reply.status = u16::try_from(state.code).unwrap_or(0);
    Poll::Ready(Ok(reply))
}

/// SEND and learn what became of it, over any transport (a pure-send one answers a single ack):
/// establish, write the [`Exchange::send`] bytes, read to the terminal piece, close. READY with the
/// transport's code and the peer's text, verbatim — a failure the transport acked is an [`Ack`]
/// too, never a lost request.
pub fn send_and_ack(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<Ack> {
    ready!(send_and_read(c, state, need, target));
    Poll::Ready(Ok(Ack {
        code: state.code,
        reason: state.reply.reason.take().unwrap_or_default(),
    }))
}

/// What an op parks its exchange on: its instance, whatever the instance state's type.
trait Parks {
    fn ticket(&self) -> Ticket;
    fn park(&self, exchange: Exchange);
    fn resume(&self) -> Option<Box<Exchange>>;
}

impl<T: Send + Sync + 'static> Parks for Instance<'_, T> {
    fn ticket(&self) -> Ticket {
        Instance::ticket(self)
    }
    fn park(&self, exchange: Exchange) {
        Instance::park(self, exchange);
    }
    fn resume(&self) -> Option<Box<Exchange>> {
        Instance::resume(self)
    }
}

/// ONE OP'S EXCHANGE ON ITS TICKET (THE DESIGN, the plugin ABI: every call is Ready or
/// Pending(wake); the replay rule of `abi::sdk::conn`), for a kind SDK whose author answers
/// [`Poll`]: [`Op::exchange`] resumes the exchange the op's last PENDING entry parked, or starts
/// the one its `request` builds, and parks it again while it pends. The op then answers PENDING
/// and is re-entered from the top when its wake fires. One exchange per op.
pub struct Op<'a> {
    on: &'a dyn Parks,
    host: Option<&'a Host>,
}

impl std::fmt::Debug for Op<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Op")
            .field("ticket", &self.on.ticket())
            .field("armed", &self.host.is_some())
            .finish()
    }
}

impl<'a> Op<'a> {
    /// The op `instance` runs, over the host tables `open` handed it (`None`: every exchange
    /// answers [`ConnFailure::Unarmed`]).
    #[must_use]
    pub fn new<'b: 'a, T: Send + Sync + 'static>(
        instance: &'a Instance<'b, T>,
        host: Option<&'a Host>,
    ) -> Self {
        Self { on: instance, host }
    }

    /// [`exchange`] over the declared framed need `need` to `target`: `request` is built only on
    /// the op's first entry (its refusal answers at once, nothing sent). PENDING until it
    /// completes.
    pub fn exchange(
        &self,
        need: u32,
        target: Option<&str>,
        request: impl FnOnce() -> Result<Request, ConnFailure>,
    ) -> Answer<ExchangeResponse> {
        let Some(host) = self.host else {
            return Poll::Ready(Err(ConnFailure::Unarmed));
        };
        let mut state = match self.on.resume() {
            Some(parked) => *parked,
            None => match request().and_then(Exchange::request) {
                Ok(s) => s,
                Err(e) => return Poll::Ready(Err(e)),
            },
        };
        let answer = exchange(
            &mut host.connector(self.on.ticket()),
            &mut state,
            need,
            target,
        );
        if answer.is_pending() {
            self.on.park(state);
        }
        answer
    }
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;
