// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN'S CONNECTIONS, THROUGH THE HOST CONNECTOR (THE DESIGN §5: one connector for every kind;
//! §11.2: every call is Ready or Pending(wake), never a blocking thread). [`Host`] is the instance's
//! host tables as `open` handed them (`OpenIn.host`, kept by the generic lifecycle,
//! `abi::sdk::life::Held::host`); [`Connector`] makes the connector's services for ONE op on ONE
//! ticket, each answering [`Poll::Ready`] or [`Poll::Pending`]; [`exchange`] is the one-shot
//! request/reply every driver needs (establish, write, read the reply to its terminal piece,
//! close), and [`send_and_ack`] its form for a transport whose reply is a single ack.
//!
//! THE REPLAY RULE (the mechanism's completion handles, `abi::mechanism::ticket`). An op that
//! answers PENDING is re-invoked, on the same ticket, when its wake fires; its body runs again from
//! the top. Each service a [`Connector`] makes carries the handle `(ticket, n)`, `n` counting the
//! services this entry made. So a body that makes its services in the same order on every entry
//! re-issues each completed one with its own handle, and the host answers its stored result
//! without running it twice. Memory a pending service writes into (a read buffer) must outlive the
//! entry: [`exchange`] keeps its buffers parked on the ticket (`Held::park`).

use std::task::Poll;

use crate::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, IoIn, ReplyIn, ReplyPiece, StreamIn, UpgradeIn,
    REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD,
};
use crate::abi::host::service::{ServiceFn, ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, HostTables, Ticket};
use crate::abi::transport::{fields, FrameSpan};

/// Why a connector service answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnFailure {
    /// The instance was handed no connector (it declared no need, or its host offers none).
    Unarmed,
    /// The call cannot pend: the op runs on no ticket.
    NoTicket,
    /// The host answered FAILED (the far end, the need or the endpoint said no), with its text
    /// (empty = none), verbatim: a driver may prefix it with its own words.
    Failed(String),
    /// The host refused the call (the egress class, an undeclared need), with its text, verbatim.
    Refused(String),
    /// The host faulted.
    Fault,
}

impl std::fmt::Display for ConnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unarmed => "the instance was handed no connector",
            Self::NoTicket => "the call runs on no ticket and cannot pend",
            Self::Failed(t) if !t.is_empty() => t.as_str(),
            Self::Refused(t) if !t.is_empty() => t.as_str(),
            Self::Failed(_) => "the connector failed the call",
            Self::Refused(_) => "the connector refused the call",
            Self::Fault => "the connector faulted",
        })
    }
}

impl std::error::Error for ConnFailure {}

/// A connector service's answer.
pub type Answer<T> = Poll<Result<T, ConnFailure>>;

/// THE INSTANCE'S HOST TABLES, as `open` handed them: the context every host call is made with,
/// the wake, the connector table and the host services table.
#[derive(Debug, Clone, Copy)]
pub struct Host {
    ctx: HostCtx,
    conns: *const ConnectorSlots,
}

// SAFETY: the context is an opaque handle and the table plain code addresses, both valid for the
// instance's life (the mechanism's host-table rule); every call goes through the host's own
// synchronisation.
unsafe impl Send for Host {}
// SAFETY: as `Send`.
unsafe impl Sync for Host {}

impl Host {
    /// The tables `tables` names.
    #[must_use]
    pub(crate) const fn of(tables: &HostTables) -> Self {
        Self {
            ctx: tables.ctx,
            conns: tables.conns,
        }
    }

    /// The connector for ONE entry of the op running on `ticket`.
    #[must_use]
    pub fn connector(&self, ticket: Ticket) -> Connector<'_> {
        Connector {
            host: self,
            ticket,
            issued: 0,
        }
    }

    fn slots(&self) -> Option<&ConnectorSlots> {
        // SAFETY: NULL, or the host's connector table, valid for the instance's life.
        unsafe { self.conns.as_ref() }
    }
}

/// The connector for one entry of one op: each service it makes carries the next completion
/// handle on its ticket (the replay rule, above).
#[derive(Debug)]
pub struct Connector<'h> {
    host: &'h Host,
    ticket: Ticket,
    issued: u32,
}

/// A service `in`: every one leads with a [`ServiceHead`].
trait ServiceIn {
    fn head(&mut self) -> &mut ServiceHead;
}
macro_rules! service_in {
    ($($t:ty),*) => {$(impl ServiceIn for $t {
        fn head(&mut self) -> &mut ServiceHead { &mut self.head }
    })*};
}
service_in!(EstablishIn, StreamIn, IoIn, UpgradeIn, ReplyIn);

const fn blank_head() -> ServiceHead {
    ServiceHead {
        size: 0,
        op: 0,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

const fn absent() -> AbiStr {
    AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    }
}

/// The host's error text, copied (it is the host's until the next service on the ticket).
fn host_text(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the host's text, `len` bytes, live until its next service on this ticket.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

fn text(s: Option<&str>) -> AbiStr {
    s.map_or(absent(), |s| AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    })
}

impl Connector<'_> {
    /// Make service `op` through `pick`'s slot with `input`: its `out` when READY.
    fn call<I: ServiceIn>(
        &mut self,
        op: u32,
        pick: impl FnOnce(&ConnectorSlots) -> Option<ServiceFn>,
        mut input: I,
    ) -> Answer<ServiceOut> {
        let Some(f) = self.host.slots().and_then(pick) else {
            return Poll::Ready(Err(ConnFailure::Unarmed));
        };
        if self.ticket.is_none() {
            return Poll::Ready(Err(ConnFailure::NoTicket));
        }
        let seq = self.issued;
        self.issued += 1;
        *input.head() = ServiceHead {
            size: std::mem::size_of::<I>() as u32,
            op,
            handle: CompletionHandle {
                ticket: self.ticket,
                seq,
                _reserved: 0,
            },
        };
        let mut out = ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(Outcome::Fault),
            _reserved: [0; 3],
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: absent(),
        };
        let answered = f(self.host.ctx, std::ptr::from_ref(&input).cast(), &mut out).outcome();
        match answered {
            Outcome::Ready => Poll::Ready(Ok(out)),
            Outcome::Pending => Poll::Pending,
            Outcome::Failed => Poll::Ready(Err(ConnFailure::Failed(host_text(out.error)))),
            Outcome::Refused => Poll::Ready(Err(ConnFailure::Refused(host_text(out.error)))),
            Outcome::Fault => Poll::Ready(Err(ConnFailure::Fault)),
        }
    }

    /// Establish a stream for the declared need `need` (its index), to `target` (`None` = the
    /// need's `target_from`): the stream.
    pub fn establish(&mut self, need: u32, target: Option<&str>) -> Answer<u64> {
        let input = EstablishIn {
            head: blank_head(),
            need,
            _reserved: 0,
            target: text(target),
        };
        self.call(service::ESTABLISH, |s| s.establish, input)
            .map(|r| r.map(|o| o.value))
    }

    /// Write `bytes` to `stream`: how many the host took. `bytes` must stay where they are until
    /// the write completes (on a PENDING answer, keep them parked).
    pub fn write(&mut self, stream: u64, bytes: &[u8]) -> Answer<usize> {
        let input = IoIn {
            head: blank_head(),
            stream,
            buf: bytes.as_ptr().cast_mut(),
            len: bytes.len(),
        };
        self.call(service::WRITE, |s| s.write, input)
            .map(|r| r.map(|o| o.len as usize))
    }

    /// Read from `stream` into `buf`: how many bytes; `0` = the end. `buf` must stay where it is
    /// until the read completes (on a PENDING answer, keep it parked).
    pub fn read(&mut self, stream: u64, buf: &mut [u8]) -> Answer<usize> {
        let input = IoIn {
            head: blank_head(),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
        };
        self.call(service::READ, |s| s.read, input)
            .map(|r| r.map(|o| (o.len as usize).min(buf.len())))
    }

    /// Upgrade `stream` to connection security, offering `name` (`None` = the endpoint's) and
    /// trusting `trust` (`None` = the need's anchors).
    pub fn upgrade_secure(
        &mut self,
        stream: u64,
        name: Option<&str>,
        trust: Option<&str>,
    ) -> Answer<()> {
        let input = UpgradeIn {
            head: blank_head(),
            stream,
            offered_name: text(name),
            trust: text(trust),
        };
        self.call(service::UPGRADE_SECURE, |s| s.upgrade_secure, input)
            .map(|r| r.map(|_| ()))
    }

    /// Close `stream`.
    pub fn close(&mut self, stream: u64) -> Answer<()> {
        let input = StreamIn {
            head: blank_head(),
            stream,
        };
        self.call(service::CLOSE, |s| s.close, input)
            .map(|r| r.map(|_| ()))
    }
}

/// One reply piece as [`Connector::read_reply`] reads it: its descriptor, its bytes in the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replied {
    /// The descriptor.
    pub piece: ReplyPiece,
    /// How many bytes the host wrote into the buffer.
    pub len: usize,
}

impl Connector<'_> {
    /// Read the next piece of the reply on `stream` into `buf`, with its descriptor. `buf` (and
    /// the descriptor the SDK keeps beside it in `slot`) must stay where they are until the read
    /// completes (on a PENDING answer, keep them parked).
    pub fn read_reply(
        &mut self,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Answer<Replied> {
        let input = ReplyIn {
            head: blank_head(),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
            piece: std::ptr::from_mut(slot),
        };
        let cap = buf.len();
        self.call(service::READ_REPLY, |s| s.read_reply, input)
            .map(|r| {
                r.map(|o| Replied {
                    piece: *slot,
                    len: (o.len as usize).min(cap),
                })
            })
    }
}

/// How much one read of an [`exchange`] asks for.
pub const EXCHANGE_READ: usize = 16 * 1024;

/// The most an [`exchange`] reads before it fails (a far end that never ends).
pub const EXCHANGE_MAX: usize = 16 * 1024 * 1024;

/// The far end's reply to an [`exchange`], or the ack of a [`send_and_ack`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeResponse {
    /// The code: the reply's status, or the transport's delivery/result code.
    pub status: u16,
    /// The reason exactly as the peer sent it (a non-canonical phrase included); `None` when the
    /// transport carries none (h2, or a transport without one).
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

/// An [`exchange`]'s (or a [`send_and_ack`]'s) state across its op's PENDING entries: the request
/// (a pending write reads it), the read buffer and the descriptor slot (a pending read writes them)
/// and the reply so far. Parked on the ticket.
#[derive(Debug)]
pub struct Exchange {
    request: Box<[u8]>,
    buf: Box<[u8]>,
    slot: Box<ReplyPiece>,
    reply: ExchangeResponse,
    code: u32,
    /// How many of this op's services' results are already applied to `reply`.
    applied: u32,
}

impl Exchange {
    /// An exchange sending `request`.
    #[must_use]
    pub fn new(request: Vec<u8>) -> Self {
        Self {
            request: request.into_boxed_slice(),
            buf: vec![0; EXCHANGE_READ].into_boxed_slice(),
            slot: Box::default(),
            reply: ExchangeResponse::default(),
            code: 0,
            applied: 0,
        }
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

/// Send the request and read the reply to its terminal piece: what it returns is the terminal's
/// kind. The reply accumulates in `state`.
fn send_and_read(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<u32> {
    let stream = match c.establish(need, target) {
        Poll::Ready(Ok(s)) => s,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Pending => return Poll::Pending,
    };
    let mut sent = 0;
    while sent < state.request.len() {
        match c.write(stream, &state.request[sent..]) {
            Poll::Ready(Ok(0)) => return failed("the far end took no bytes"),
            Poll::Ready(Ok(n)) => sent += n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
    let terminal = loop {
        let this = c.issued;
        let got = match c.read_reply(stream, &mut state.buf, &mut state.slot) {
            Poll::Ready(Ok(r)) => r,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        // A replayed read answers its stored result; it was applied on the entry that first saw
        // it (its bytes are no longer in the buffer).
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
                if state.reply.body.len() > EXCHANGE_MAX {
                    return failed("the reply passed the exchange's bound");
                }
            }
            REPLY_HEAD | REPLY_ACK | REPLY_BODY | REPLY_END => {}
            _ => return failed("the transport answered no reply piece: every request is acked"),
        }
        if matches!(p.kind, REPLY_ACK | REPLY_END) {
            break p.kind;
        }
    };
    match c.close(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => Poll::Ready(Ok(terminal)),
    }
}

/// ONE REQUEST, ONE REPLY over the declared need `need` to `target`: establish, write the whole
/// request, read the reply to its terminal piece, close. PENDING until it completes; the caller
/// keeps `state` parked on its ticket across PENDING entries and passes it back each time (the
/// same order of services on every entry: the replay rule). READY with the reply's code, reason,
/// fields and body, or why it failed. Bounded by the op's own deadline and by [`EXCHANGE_MAX`].
pub fn exchange(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<ExchangeResponse> {
    match send_and_read(c, state, need, target) {
        Poll::Ready(Ok(_)) => {
            let mut reply = std::mem::take(&mut state.reply);
            reply.status = u16::try_from(state.code).unwrap_or(0);
            Poll::Ready(Ok(reply))
        }
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => Poll::Pending,
    }
}

/// SEND and learn what became of it, over any transport (a pure-send one answers a single ack):
/// establish, write, read to the terminal piece, close. READY with the transport's code and the
/// peer's text, verbatim — a failure the transport acked is an [`Ack`] too, never a lost request.
pub fn send_and_ack(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<Ack> {
    match send_and_read(c, state, need, target) {
        Poll::Ready(Ok(_)) => Poll::Ready(Ok(Ack {
            code: state.code,
            reason: state.reply.reason.take().unwrap_or_default(),
        })),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => Poll::Pending,
    }
}

#[cfg(test)]
#[path = "tests/conn_tests.rs"]
mod tests;
