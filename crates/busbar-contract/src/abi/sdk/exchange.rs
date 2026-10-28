// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE REQUEST, ONE REPLY, over the host connector (THE DESIGN, the connections section; ARCHITECT R2a:
//! `exchange()` is FRAMED). [`exchange`] opens a framed need, sends one [`Request`] through the
//! framer ([`Connector::write_request`]: head, body, end — the framer writes its own wire head, one
//! library per protocol) and reads the reply to its terminal piece into an [`ExchangeResponse`].
//!
//! It answers PENDING until it completes. The caller parks the [`Exchange`] on its ticket across
//! PENDING entries (`abi::sdk::safe::Instance::park`) and passes it back each time, making the same
//! services in the same order (the replay rule, `abi::sdk::conn`): no service runs twice.
//!
//! WHAT CROSSES IS WIPED. A request's fields carry what a plugin authenticates with (a vault token,
//! an `authorization` value, a client secret) and a reply carries what the far end answered. Every
//! buffer the SDK holds either in is wiped when it goes: the [`Request`] [`Exchange::request`]
//! consumes, the head it frames, the body it sends, the read buffer (after each piece is applied as
//! well), and the reply it gathers (a body that outgrows its allocation wipes the one it leaves).
//! [`Request`] and [`ExchangeResponse`] are [`Zeroize`]: a plugin wipes the ones it holds
//! (`zeroize::Zeroizing::new(reply)`). The bytes on the wire are unchanged.

use std::task::Poll;

use zeroize::{Zeroize, Zeroizing};

use crate::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::{Answer, Closer, ConnFailure, Connector, Host, Observed};
use crate::abi::sdk::safe::Instance;
use crate::abi::transport::{fields, FrameSpan};

/// How much one read of a reply asks for.
pub const READ_CHUNK: usize = 16 * 1024;

/// The most a reply's body may reach before the exchange fails (a far end that never ends).
pub const REPLY_MAX: usize = 16 * 1024 * 1024;

/// The failure text of a reply whose body passed [`REPLY_MAX`]: a driver that words that case its
/// own way matches on it.
pub const REPLY_OVER_BOUND: &str = "the reply passed the exchange's bound";

/// A sealed request field: before which of the request's fields it goes (their count: last), its
/// name, and its sealed value ([`Exchange::request_sealed`]).
pub type SealedField = (usize, Vec<u8>, crate::abi::sdk::cred::Seal);

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

impl Zeroize for Request {
    fn zeroize(&mut self) {
        self.method.zeroize();
        self.target.zeroize();
        self.fields.zeroize();
        self.body.zeroize();
        self.timeout_ms.zeroize();
    }
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

impl Zeroize for ExchangeResponse {
    fn zeroize(&mut self) {
        self.status.zeroize();
        self.reason.zeroize();
        self.fields.zeroize();
        self.body.zeroize();
    }
}

/// What is sent: a framed request's head bytes and descriptors, or raw bytes. The bytes wipe on
/// drop; the descriptors (`repr(C)`) hold spans and a timeout, never a byte of the request.
#[derive(Debug)]
enum Sending {
    Framed {
        /// The head's method, target and field block, one after another.
        head: Zeroizing<Vec<u8>>,
        head_piece: Box<RequestPiece>,
        body: Zeroizing<Vec<u8>>,
        body_piece: Box<RequestPiece>,
        end_piece: Box<RequestPiece>,
        timeout_ms: u64,
    },
    Raw(Zeroizing<Vec<u8>>),
}

/// An [`exchange`]'s state across its op's PENDING entries: what it sends
/// (a pending write reads it), the read buffer and the descriptor slot (a pending read writes
/// them) and the reply so far. Parked on the ticket. Every byte it holds of the request or the
/// reply wipes on drop.
#[derive(Debug)]
pub struct Exchange {
    sending: Sending,
    /// The read buffer: each piece's bytes are wiped once applied, the whole of it on drop.
    buf: Zeroizing<Box<[u8]>>,
    slot: Box<ReplyPiece>,
    reply: Zeroizing<ExchangeResponse>,
    code: u32,
    /// The reply's head (or the transport's ack) was received: `code` is its status
    /// ([`Exchange::head_status`]).
    head_seen: bool,
    /// How many of this op's services' results are already applied to `reply`.
    applied: u32,
    /// The handle of the read that answered the terminal piece, once one has.
    ended: Option<u32>,
    /// The address set the dial must land on ([`Exchange::landing_within`]); empty = no pin.
    within: String,
    /// The registration the exchange reaches ([`Exchange::as_member`]); `None` = none.
    member: Option<String>,
    /// The stream's facts are read before it closes ([`Exchange::observing`]).
    observe: bool,
    /// What they said, once read: kept across replays, which answer without writing them again.
    observed: Option<Observed>,
    /// The reply's head ends the reads; its body is never read ([`Exchange::head_only`]).
    head_only: bool,
    /// The stream the exchange established, once it has: what a caller that gives the exchange up
    /// closes on the host ([`Exchange::stream`]).
    stream: Option<u64>,
    /// The most this exchange's reply body may reach ([`Exchange::reply_limit`]); never above
    /// [`REPLY_MAX`].
    reply_ceiling: usize,
    /// The read whose piece the exchange refused (its handle) and why, once one was: kept across
    /// replays, which do not apply a piece again, so the replayed read fails the exchange again
    /// and its close is issued on the same handle.
    refused_read: Option<(u32, &'static str)>,
    /// The field lines ([`Exchange::framed_fields`]'s indices) whose values are sealed.
    sealed_lines: Vec<usize>,
    /// A sealed value goes out only secured ([`Cred::secure_required`]): the stream is confirmed
    /// secured before the request is written.
    ///
    /// [`Cred::secure_required`]: crate::abi::sdk::cred::Cred::secure_required
    secure_required: bool,
    /// The stream was found in the clear: every re-entry answers the refusal (a replayed `FACTS`
    /// writes nothing, so only this remembers it).
    insecure: bool,
    /// What closes `stream` should the exchange be dropped before it closed it: set when
    /// [`Op::exchange`] parks it, so a parked exchange its op gives up does not leave its host
    /// connection open.
    closer: Option<Closer>,
}

impl Drop for Exchange {
    /// A parked exchange dropped before it closed its stream (its op cancelled, a fresh op on its
    /// ticket, the instance closed) closes it here: the host reclaims a connection only on its
    /// CLOSE. An exchange that answered READY closed its stream already and closes nothing.
    fn drop(&mut self) {
        if let (Some(closer), Some(stream)) = (self.closer, self.stream.take()) {
            closer.close(stream);
        }
    }
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
            buf: Zeroizing::new(vec![0; READ_CHUNK].into_boxed_slice()),
            slot: Box::default(),
            reply: Zeroizing::default(),
            code: 0,
            head_seen: false,
            applied: 0,
            ended: None,
            within: String::new(),
            member: None,
            observe: false,
            observed: None,
            head_only: false,
            stream: None,
            reply_ceiling: REPLY_MAX,
            refused_read: None,
            sealed_lines: Vec::new(),
            secure_required: false,
            insecure: false,
            closer: None,
        }
    }

    /// Lower the most this exchange's reply body may reach to `bytes`. A value above [`REPLY_MAX`]
    /// clamps to it: the ceiling is lowered, never raised. A reply past it is refused as one past
    /// [`REPLY_MAX`] is ([`REPLY_OVER_BOUND`]).
    #[must_use]
    pub fn reply_limit(mut self, bytes: usize) -> Self {
        self.reply_ceiling = bytes.min(REPLY_MAX);
        self
    }

    /// The stream this exchange established, once it has and until the exchange closed it: a
    /// caller that abandons the exchange closes it (`Connector::close`), so the host's connection
    /// does not outlive the attempt. An exchange that answered READY, its reply or its failure,
    /// closed its stream and answers `None`; one [`Op::exchange`] parked closes it when dropped.
    #[must_use]
    pub const fn stream(&self) -> Option<u64> {
        self.stream
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

    /// Judge the reply on its HEAD alone: the first head (or ack) piece ends the reads and the
    /// stream is closed, its facts read first where [`Exchange::observing`] asks. The body is never
    /// read or buffered, so a slow or huge body after the head neither runs the op into its
    /// deadline nor passes [`REPLY_MAX`]; the reply answers an empty body. 1.5.5 judged a webhook
    /// delivery on the response head and dropped the body unread.
    #[must_use]
    pub fn head_only(mut self) -> Self {
        self.head_only = true;
        self
    }

    /// What the stream's facts said ([`Exchange::observing`]); `None` before they were read, for
    /// an exchange that did not ask, or a host that offers no facts.
    #[must_use]
    pub fn observed(&self) -> Option<&Observed> {
        self.observed.as_ref()
    }

    /// WHETHER THE REPLY'S HEAD WAS RECEIVED: `true` once a head (or a pure-send transport's ack)
    /// was read, whatever the exchange answered after it. When a failed exchange answers `true`,
    /// it failed while reading the body (a reset, a stalled body, [`REPLY_OVER_BOUND`]). When it
    /// answers `false`, it failed before any reply arrived (the dial, the send, the far end's
    /// silence).
    #[must_use]
    pub const fn head_seen(&self) -> bool {
        self.head_seen
    }

    /// The status the reply's head carried ([`ExchangeResponse::status`], read as [`exchange`]
    /// reads it), once [`Exchange::head_seen`]; `None` before. Answered on a failed exchange too,
    /// so a driver judges the status before the body as an HTTP client does: a reply past
    /// [`REPLY_OVER_BOUND`] still says what status it came with.
    #[must_use]
    pub fn head_status(&self) -> Option<u16> {
        self.head_seen
            .then(|| u16::try_from(self.code).unwrap_or(0))
    }

    /// Land this exchange's dial only on an address of `within`, the set the plugin's
    /// `dest.judge` judged (`Judged::within`): a name that resolves elsewhere at dial time is
    /// refused before the request leaves.
    #[must_use]
    pub fn landing_within(mut self, within: String) -> Self {
        self.within = within;
        self
    }

    /// This exchange reaches the REGISTRATION `name` (its name in the plugin's declaring section):
    /// what the host sealed for that registration alone (its private reach) applies to its dial;
    /// an exchange that names none dials under its need's class alone (SEAM-4p).
    #[must_use]
    pub fn as_member(mut self, name: impl Into<String>) -> Self {
        self.member = Some(name.into());
        self
    }

    /// An exchange sending `request` through a framed need.
    ///
    /// # Errors
    /// A field is a pseudo-field (its name starts with `:`), or a name or value carries a line
    /// break: REFUSED, nothing sent.
    ///
    /// `request` is the SDK's from here: what it carried is wiped when it goes, framed or refused.
    /// The head is allocated once at its exact length, so no outgrown copy of a field is left.
    pub fn request(request: Request) -> Result<Self, ConnFailure> {
        Self::request_sealed(request, Vec::new())
    }

    /// [`Exchange::request`] with SEALED fields (`abi::sdk::chip`: an `authorization` value, an API
    /// key header): each `(at, name, seal)` goes in before the request's field `at` (its length:
    /// last), so the field order is the caller's. Their values reach only the head the SDK frames
    /// and wipes; [`Exchange::framed_fields`] shows them as `<sealed>`.
    ///
    /// # Errors
    /// As [`Exchange::request`].
    pub fn request_sealed(request: Request, sealed: Vec<SealedField>) -> Result<Self, ConnFailure> {
        Self::request_with(request, sealed, None)
    }

    /// [`Exchange::request_sealed`] whose body is `body` (a form with sealed values,
    /// [`FormBody::encoded`](crate::abi::sdk::cred::FormBody::encoded)) in place of the request's
    /// own.
    ///
    /// # Errors
    /// As [`Exchange::request`].
    pub fn request_with(
        request: Request,
        sealed: Vec<SealedField>,
        body: Option<crate::abi::sdk::cred::SealedWrite>,
    ) -> Result<Self, ConnFailure> {
        let mut request = Zeroizing::new(request);
        let secure_required = sealed.iter().any(|(_, _, s)| s.secure_required())
            || body
                .as_ref()
                .is_some_and(crate::abi::sdk::cred::SealedWrite::secure_required);
        if let Some(mut b) = body {
            request.body.zeroize();
            request.body = std::mem::take(&mut *b.buf);
        }
        for (_, name, _) in &sealed {
            if name.first() == Some(&b':') || name.iter().any(|b| *b == b'\r' || *b == b'\n') {
                return Err(ConnFailure::Refused(format!(
                    "the sealed request field `{}` is a pseudo-field or carries a line break",
                    String::from_utf8_lossy(name)
                )));
            }
        }
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
        }
        let (m, t) = (request.method.len(), request.target.len());
        let line = |name: &[u8], value: &[u8]| {
            name.len() + fields::SEPARATOR.len() + value.len() + fields::LINE_END.len()
        };
        let block: usize = request
            .fields
            .iter()
            .map(|(name, value)| line(name, value))
            .chain(sealed.iter().map(|(_, name, seal)| line(name, seal.wire())))
            .sum();
        let mut head = Zeroizing::new(Vec::with_capacity(m + t + block));
        head.extend_from_slice(&request.method);
        head.extend_from_slice(&request.target);
        let block_at = head.len();
        let mut sealed_lines = Vec::new();
        let put = |head: &mut Vec<u8>, name: &[u8], value: &[u8]| {
            head.extend_from_slice(name);
            head.extend_from_slice(fields::SEPARATOR);
            head.extend_from_slice(value);
            head.extend_from_slice(fields::LINE_END);
        };
        let mut index = 0;
        for at in 0..=request.fields.len() {
            for (_, name, seal) in sealed
                .iter()
                .filter(|(s_at, ..)| (*s_at).min(request.fields.len()) == at)
            {
                put(&mut head, name, seal.wire());
                sealed_lines.push(index);
                index += 1;
            }
            if let Some((name, value)) = request.fields.get(at) {
                put(&mut head, name, value);
                index += 1;
            }
        }
        let head_piece = Box::new(RequestPiece {
            kind: REQUEST_HEAD,
            method: span(0, m),
            target: span(m, t),
            fields: span(block_at, head.len() - block_at),
            timeout_ms: request.timeout_ms,
            ..RequestPiece::ZERO
        });
        let mut ex = Self::over(Sending::Framed {
            head,
            head_piece,
            body: Zeroizing::new(std::mem::take(&mut request.body)),
            body_piece: piece(REQUEST_BODY),
            end_piece: piece(REQUEST_END),
            timeout_ms: request.timeout_ms,
        });
        ex.sealed_lines = sealed_lines;
        ex.secure_required = secure_required;
        Ok(ex)
    }

    /// An exchange sending `bytes` as they are, over any transport.
    #[must_use]
    pub fn send(bytes: Vec<u8>) -> Self {
        Self::over(Sending::Raw(Zeroizing::new(bytes)))
    }

    /// THE FIELDS THIS EXCHANGE FRAMES, read back off the head it sends: `(name, value)`, in
    /// order, exactly what the far end is handed rather than what the caller meant to hand it.
    /// Empty for an exchange that sends raw bytes ([`Exchange::send`]).
    #[must_use]
    pub fn framed_fields(&self) -> Vec<(&[u8], &[u8])> {
        match &self.sending {
            Sending::Framed {
                head, head_piece, ..
            } => fields::lines(spanned(&head[..], head_piece.fields))
                .enumerate()
                .map(|(i, (name, value))| {
                    if self.sealed_lines.contains(&i) {
                        (name, &b"<sealed>"[..])
                    } else {
                        (name, value)
                    }
                })
                .collect(),
            Sending::Raw(_) => Vec::new(),
        }
    }

    /// The whole head this exchange frames, sealed values included (`test_support::chip` alone).
    #[allow(dead_code)]
    pub(crate) fn head_bytes(&self) -> Vec<u8> {
        match &self.sending {
            Sending::Framed { head, .. } => head.to_vec(),
            Sending::Raw(bytes) => bytes.to_vec(),
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

/// Append `bytes` to `body`, growing it as `Vec` grows it (to twice its capacity, at least what
/// it needs, never under 8), but into a fresh allocation, wiping the one it outgrew before that is
/// freed: a reallocation leaves no copy of what the reply carried. The same allocations as
/// `extend_from_slice`, one per growth.
fn extend_wiping(body: &mut Vec<u8>, bytes: &[u8]) {
    let need = body.len().saturating_add(bytes.len());
    if need > body.capacity() {
        let mut grown = Vec::with_capacity(need.max(body.capacity().saturating_mul(2)).max(8));
        grown.extend_from_slice(body);
        body.zeroize();
        *body = grown;
    }
    body.extend_from_slice(bytes);
}

/// Send what `state` holds on `stream`.
fn send(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Answer<()> {
    let budget = c.budget_ms();
    match &mut state.sending {
        Sending::Raw(bytes) => write_all(|b| c.write(stream, b), &bytes[..]),
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
            let taken = ready!(c.write_request(stream, head_piece, &head[..]));
            if taken != head.len() {
                return failed("the framer took part of the request head");
            }
            let body_piece: &RequestPiece = body_piece;
            ready!(write_all(
                |b| c.write_request(stream, body_piece, b),
                &body[..]
            ));
            ready!(c.write_request(stream, end_piece, &[]));
            Poll::Ready(Ok(()))
        }
    }
}

/// Send, then read the reply to its terminal piece into `state`, then close the stream: on a
/// failure after the stream is established as on a reply (the host reclaims a connection only on
/// its CLOSE, so an exchange that failed without one would leave it open for the instance's
/// life). The close's own answer never replaces the exchange's.
fn send_and_read(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<()> {
    // A framed request is made whole when its stream opens, so its security is its target's: a
    // sealed value that must go out secured is refused before the open when the target names a
    // scheme that is not secure. A need's own target (`None`) is the operator's, as written.
    if state.secure_required
        && (state.insecure || target.is_some_and(|t| !crate::abi::sdk::cred::secure_target(t)))
    {
        state.insecure = true;
        return Poll::Ready(Err(ConnFailure::Refused(
            crate::abi::sdk::cred::NOT_SECURE.into(),
        )));
    }
    let stream = ready!(c.establish_as(need, target, &state.within, 0, state.member.as_deref()));
    state.stream = Some(stream);
    let ended = match read_to_end(c, state, stream) {
        Poll::Ready(ended) => ended,
        Poll::Pending => return Poll::Pending,
    };
    match c.close(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => {
            state.stream = None;
            Poll::Ready(ended)
        }
    }
}

/// Send on `stream`, then read the reply to its terminal piece (for a head-only exchange, its head
/// or ack) into `state`; the stream's facts are read where the caller asks, once the reply ended or
/// failed.
fn read_to_end(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Answer<()> {
    ready!(send(c, state, stream));
    loop {
        let this = c.issued();
        let got = match c.read_reply(stream, &mut state.buf[..], &mut state.slot) {
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
        // A replayed read answers its stored result (its piece and bytes written again); it was
        // applied on the entry that first saw it, unless this exchange is that op's fresh re-call.
        let fresh = this >= state.applied;
        if fresh {
            state.applied = this + 1;
        }
        let p = got.piece;
        let applied = apply(state, p, got.len, fresh);
        // A fresh piece's bytes are in the reply now: the read buffer keeps no copy of them into
        // the next read. A replayed read's are not touched: the buffer may still hold the bytes of
        // the read this entry has yet to apply (the one that pended on the last entry).
        if fresh {
            if let Some(used) = state.buf.get_mut(..got.len) {
                used.zeroize();
            }
        }
        if let (true, Err(text)) = (fresh, applied) {
            state.refused_read = Some((this, text));
        }
        // A refused piece fails the exchange on the entry that refused it and on every replay of
        // that read (a replay applies nothing, so only `refused_read` remembers it).
        match (state.refused_read, applied) {
            (Some((at, text)), _) if at == this => return failed(text),
            (_, Err(text)) => return failed(text),
            _ => {}
        }
        // The terminal piece ends the reads, on the entry that first saw it and on every replay
        // of that read. A replayed earlier read never does: the piece descriptor is the op's one
        // parked slot, rewritten by each replayed read: only `ended` marks the terminal one. A
        // head-only exchange's head is its terminal piece, by the same bookkeeping.
        let terminal = match p.kind {
            REPLY_ACK | REPLY_END => true,
            REPLY_HEAD => state.head_only,
            _ => false,
        };
        if fresh && terminal {
            state.ended = Some(this);
        }
        if state.ended == Some(this) {
            break;
        }
    }
    if observe(c, state, stream).is_pending() {
        return Poll::Pending;
    }
    Poll::Ready(Ok(()))
}

/// Apply one reply piece, `p` and its first `len` bytes of the read buffer, to the reply `state`
/// gathers (a `fresh` read only: a replayed one was applied on the entry that first saw it). What a
/// head replaces is wiped first.
fn apply(state: &mut Exchange, p: ReplyPiece, len: usize, fresh: bool) -> Result<(), &'static str> {
    match p.kind {
        REPLY_HEAD | REPLY_ACK if fresh => {
            let bytes = &state.buf[..len];
            state.code = p.code;
            state.head_seen = true;
            let reason = spanned(bytes, p.reason);
            state.reply.reason.zeroize();
            state.reply.reason = (!reason.is_empty()).then(|| reason.to_vec());
            state.reply.fields.zeroize();
            state.reply.fields = fields::lines(spanned(bytes, p.fields))
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect();
        }
        REPLY_BODY if fresh => {
            extend_wiping(&mut state.reply.body, &state.buf[..len]);
            if state.reply.body.len() > state.reply_ceiling {
                return Err(REPLY_OVER_BOUND);
            }
        }
        REPLY_HEAD | REPLY_ACK | REPLY_BODY | REPLY_END => {}
        _ => return Err("the transport answered no reply piece: every request is acked"),
    }
    Ok(())
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
/// fields and body, or why it failed. Bounded by the op's deadline and by [`REPLY_MAX`]. A
/// [`Exchange::head_only`] exchange ends at the head and answers an empty body.
pub fn exchange(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<ExchangeResponse> {
    ready!(send_and_read(c, state, need, target));
    let mut reply = std::mem::take(&mut *state.reply);
    reply.status = u16::try_from(state.code).unwrap_or(0);
    Poll::Ready(Ok(reply))
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

    /// The host tables the op runs over (`None`: the instance was handed none): what an op that
    /// waits on another ticket's work wakes that ticket with ([`Host::wake`]).
    #[must_use]
    pub fn host(&self) -> Option<&'a Host> {
        self.host
    }

    /// The op's ticket ([`Ticket::NONE`] on the spot).
    #[must_use]
    pub fn ticket(&self) -> Ticket {
        self.on.ticket()
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
        self.exchange_sealed(need, target, || request().map(|r| (r, Vec::new())))
    }

    /// [`Op::exchange`] for a request with sealed fields ([`Exchange::request_sealed`]).
    pub fn exchange_sealed(
        &self,
        need: u32,
        target: Option<&str>,
        request: impl FnOnce() -> Result<(Request, Vec<SealedField>), ConnFailure>,
    ) -> Answer<ExchangeResponse> {
        let Some(host) = self.host else {
            return Poll::Ready(Err(ConnFailure::Unarmed));
        };
        let mut state = match self.on.resume() {
            Some(parked) => *parked,
            None => match request().and_then(|(r, sealed)| Exchange::request_sealed(r, sealed)) {
                Ok(s) => s,
                Err(e) => return Poll::Ready(Err(e)),
            },
        };
        let mut c = host.connector(self.on.ticket());
        let answer = exchange(&mut c, &mut state, need, target);
        if answer.is_pending() {
            // Parked, the exchange may be given up (a cancel, a fresh op on the ticket): what it
            // keeps closes its stream then.
            state.closer = Some(c.closer());
            self.on.park(state);
        }
        answer
    }
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;
