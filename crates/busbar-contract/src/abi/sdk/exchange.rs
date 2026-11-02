// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE REQUEST, ONE REPLY, over a framed host connection. [`exchange`]

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::sync::Arc;
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
pub const REPLY_OVER_BOUND: &str = "the reply passed the exchange's bound";

/// A sealed request field: before which of the request's fields it goes (their count: last), its
pub type SealedField = (usize, Vec<u8>, crate::abi::sdk::cred::Seal);

/// ONE REQUEST, as [`exchange`] sends it through a framed need.
/// Its owned bytes wipe on drop, including clones and requests abandoned before framing. Borrow
/// fields when inspecting them; transfer a field with [`std::mem::take`] into another wiping owner.
#[derive(Clone, Default, PartialEq, Eq)]
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

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method_len", &self.method.len())
            .field("target_len", &self.target.len())
            .field("fields_len", &self.fields.len())
            .field("body_len", &self.body.len())
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
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

impl Drop for Request {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The far end's reply to an [`exchange`].
#[derive(Clone, Default, PartialEq, Eq)]
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

impl std::fmt::Debug for ExchangeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeResponse")
            .field("status", &self.status)
            .field("reason_len", &self.reason.as_ref().map(Vec::len))
            .field("fields_len", &self.fields.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Zeroize for ExchangeResponse {
    fn zeroize(&mut self) {
        self.status.zeroize();
        self.reason.zeroize();
        self.fields.zeroize();
        self.body.zeroize();
    }
}

/// What became of what a [`send_and_ack`] sent: the transport's code and the peer's text.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Ack {
    /// The transport's result code.
    pub code: u32,
    /// The peer's text, exactly as sent; empty when none.
    pub reason: Vec<u8>,
}

impl std::fmt::Debug for Ack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ack")
            .field("code", &self.code)
            .field("reason_len", &self.reason.len())
            .finish()
    }
}

impl Zeroize for Ack {
    fn zeroize(&mut self) {
        self.code.zeroize();
        self.reason.zeroize();
    }
}

/// What is sent: a framed request's head bytes and descriptors, or raw bytes. The bytes wipe on
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

impl std::fmt::Debug for Sending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Framed {
                head,
                body,
                timeout_ms,
                ..
            } => f
                .debug_struct("Framed")
                .field("head_len", &head.len())
                .field("body_len", &body.len())
                .field("timeout_ms", timeout_ms)
                .finish(),
            Self::Raw(bytes) => f
                .debug_struct("Raw")
                .field("bytes_len", &bytes.len())
                .finish(),
        }
    }
}

impl std::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exchange")
            .field("sending", &self.sending)
            .field("buffer_len", &self.buf.len())
            .field("reply", &*self.reply)
            .field("code", &self.code)
            .field("head_seen", &self.head_seen)
            .field("applied", &self.applied)
            .field("sealed_fields_len", &self.sealed_lines.len())
            .finish()
    }
}

/// An [`exchange`]'s (or a [`send_and_ack`]'s) state across its op's PENDING entries: what it sends
pub struct Exchange {
    sending: Sending,
    /// The read buffer: each piece's bytes are wiped once applied, the whole of it on drop.
    buf: Zeroizing<Box<[u8]>>,
    slot: Box<ReplyPiece>,
    reply: Zeroizing<ExchangeResponse>,
    code: u32,
    /// The reply's head (or the transport's ack) was received: `code` is its status
    head_seen: bool,
    /// How many of this op's services' results are already applied to `reply`.
    applied: u32,
    /// The handle of the read that answered the terminal piece, once one has.
    ended: Option<u32>,
    /// The handle of the read whose piece the exchange refused, and why: a replay of that read
    refused_at: Option<(u32, &'static str)>,
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
    stream: Option<u64>,
    /// The most this exchange's reply body may reach ([`Exchange::reply_limit`]); never above
    reply_ceiling: usize,
    /// The read whose piece the exchange refused (its handle) and why, once one was: kept across
    refused_read: Option<(u32, &'static str)>,
    /// The field lines ([`Exchange::framed_fields`]'s indices) whose values are sealed.
    sealed_lines: Vec<usize>,
    /// A sealed value goes out only secured ([`Cred::secure_required`]): the stream is confirmed
    secure_required: bool,
    /// The stream was found in the clear: every re-entry answers the refusal (a replayed `FACTS`
    insecure: bool,
    /// What closes `stream` should the exchange be dropped before it closed it: set whenever the
    closer: Option<Closer>,
    /// Opt-in wall-clock bound for the complete exchange, including collection. The absolute
    timeout_ms: Option<u64>,
    deadline_ns: Option<u64>,
    expires_at_ns: Option<u64>,
    begun: bool,
}

impl Drop for Exchange {
    /// A parked exchange dropped before it closed its stream (its op cancelled, a fresh op on its
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
            refused_at: None,
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
            timeout_ms: None,
            deadline_ns: None,
            expires_at_ns: None,
            begun: false,
        }
    }

    /// Bound this complete exchange, from before establishment through its final reply piece.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        if !self.begun {
            self.timeout_ms = (timeout_ms != 0).then_some(timeout_ms);
        }
        self
    }

    /// Clamp the complete exchange to a known absolute caller deadline on the host clock.
    #[must_use]
    pub fn with_deadline_ns(mut self, deadline_ns: u64) -> Self {
        if !self.begun {
            self.deadline_ns = (deadline_ns != 0).then_some(deadline_ns);
        }
        self
    }

    /// The original absolute expiry for a pending exchange. Propagate the earliest nonzero wake
    #[must_use]
    pub const fn wake_at_ns(&self) -> Option<u64> {
        self.expires_at_ns
    }

    fn within_timeout(&mut self, c: &mut Connector<'_>) -> Result<(), ConnFailure> {
        if self.timeout_ms.is_none() && self.deadline_ns.is_none() {
            return Ok(());
        }
        let now = match c.clock_now() {
            Poll::Ready(Ok(now)) => now.mono_ns,
            Poll::Ready(Err(error)) => return self.timeout_failed(c, error),
            Poll::Pending => return self.timeout_failed(c, ConnFailure::Fault),
        };
        let expiry = match self.expires_at_ns {
            Some(expiry) => expiry,
            None => {
                let relative = self.timeout_ms.and_then(|ms| {
                    let ms = c.budget_ms().map_or(ms, |budget| ms.min(budget));
                    ms.checked_mul(1_000_000)
                        .and_then(|span| now.checked_add(span))
                });
                let expiry = match (relative, self.deadline_ns) {
                    (Some(relative), Some(cap)) => relative.min(cap),
                    (Some(relative), None) => relative,
                    (None, Some(cap)) => cap,
                    (None, None) => {
                        return self.timeout_failed(
                            c,
                            ConnFailure::Failed(
                                "whole exchange timeout exceeds the host clock range".into(),
                            ),
                        )
                    }
                };
                self.expires_at_ns = Some(expiry);
                expiry
            }
        };
        if now >= expiry {
            return self.timeout_failed(
                c,
                ConnFailure::Failed(crate::conn::ConnError::Timeout.text().to_owned()),
            );
        }
        Ok(())
    }

    fn timeout_failed(&mut self, c: &Connector<'_>, error: ConnFailure) -> Result<(), ConnFailure> {
        if let Some(stream) = self.stream.take() {
            c.closer().close(stream);
        }
        Err(error)
    }

    /// Lower the most this exchange's reply body may reach to `bytes`. A value above [`REPLY_MAX`]
    #[must_use]
    pub fn reply_limit(mut self, bytes: usize) -> Self {
        self.reply_ceiling = bytes.min(REPLY_MAX);
        self
    }

    /// The stream this exchange established, once it has and until the exchange closed it: a
    #[must_use]
    pub const fn stream(&self) -> Option<u64> {
        self.stream
    }

    /// Read the stream's facts ([`Connector::facts`]) once its reply has ended — or once the reply
    #[must_use]
    pub fn observing(mut self) -> Self {
        self.observe = true;
        self
    }

    /// Judge the reply on its HEAD alone: the first head (or ack) piece ends the reads and the
    #[must_use]
    pub fn head_only(mut self) -> Self {
        self.head_only = true;
        self
    }

    /// What the stream's facts said ([`Exchange::observing`]); `None` before they were read, for
    #[must_use]
    pub fn observed(&self) -> Option<&Observed> {
        self.observed.as_ref()
    }

    /// WHETHER THE REPLY'S HEAD WAS RECEIVED: `true` once a head (or a pure-send transport's ack)
    #[must_use]
    pub const fn head_seen(&self) -> bool {
        self.head_seen
    }

    /// The status the reply's head carried ([`ExchangeResponse::status`], read as [`exchange`]
    #[must_use]
    pub fn head_status(&self) -> Option<u16> {
        self.head_seen
            .then(|| u16::try_from(self.code).unwrap_or(0))
    }

    /// The response fields still owned by this exchange after its reply head was read; `None`
    #[must_use]
    pub fn reply_fields(&self) -> Option<&[(Vec<u8>, Vec<u8>)]> {
        self.head_seen.then_some(self.reply.fields.as_slice())
    }

    /// Land this exchange's dial only on an address of `within`, the set the plugin's
    #[must_use]
    pub fn landing_within(mut self, within: String) -> Self {
        self.within = within;
        self
    }

    /// This exchange reaches the REGISTRATION `name` (its name in the plugin's declaring section):
    #[must_use]
    pub fn as_member(mut self, name: impl Into<String>) -> Self {
        self.member = Some(name.into());
        self
    }

    /// An exchange sending `request` through a framed need.
    pub fn request(request: Request) -> Result<Self, ConnFailure> {
        Self::request_sealed(request, Vec::new())
    }

    /// [`Exchange::request`] with SEALED fields (`abi::sdk::chip`: an `authorization` value, an API
    pub fn request_sealed(request: Request, sealed: Vec<SealedField>) -> Result<Self, ConnFailure> {
        Self::request_with(request, sealed, None)
    }

    /// [`Exchange::request_sealed`] whose body is `body` (a form with sealed values,
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

    /// An exchange sending `bytes` as they are, over any transport ([`send_and_ack`]).
    #[must_use]
    pub fn send(bytes: Vec<u8>) -> Self {
        Self::over(Sending::Raw(Zeroizing::new(bytes)))
    }

    /// THE FIELDS THIS EXCHANGE FRAMES, read back off the head it sends: `(name, value)`, in
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

/// Check an already anchored absolute bound around one service step. Clock reads never draw a
fn bounded_step<T>(
    c: &mut Connector<'_>,
    expires_at_ns: Option<u64>,
    step: impl FnOnce(&mut Connector<'_>) -> Answer<T>,
) -> Answer<T> {
    fn check(c: &mut Connector<'_>, expiry: Option<u64>) -> Result<(), ConnFailure> {
        let Some(expiry) = expiry else {
            return Ok(());
        };
        match c.clock_now() {
            Poll::Ready(Ok(now)) if now.mono_ns < expiry => Ok(()),
            Poll::Ready(Ok(_)) => Err(ConnFailure::Failed(
                crate::conn::ConnError::Timeout.text().to_owned(),
            )),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(ConnFailure::Fault),
        }
    }
    if let Err(error) = check(c, expires_at_ns) {
        return Poll::Ready(Err(error));
    }
    let answer = step(c);
    if let Err(error) = check(c, expires_at_ns) {
        return Poll::Ready(Err(error));
    }
    answer
}

/// Send what `state` holds on `stream`.
fn send(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Answer<()> {
    let budget = c.budget_ms();
    let expiry = state.expires_at_ns;
    match &mut state.sending {
        Sending::Raw(bytes) => write_all(
            |b| bounded_step(c, expiry, |c| c.write(stream, b)),
            &bytes[..],
        ),
        Sending::Framed {
            head,
            head_piece,
            body,
            body_piece,
            end_piece,
            timeout_ms,
        } => {
            head_piece.timeout_ms = match (*timeout_ms, budget) {
                (0, Some(b)) => b,
                (t, Some(b)) => t.min(b),
                (t, None) => t,
            };
            let head_piece: &RequestPiece = head_piece;
            let taken = ready!(bounded_step(c, expiry, |c| c.write_request(
                stream,
                head_piece,
                &head[..]
            )));
            if taken != head.len() {
                return failed("the framer took part of the request head");
            }
            let body_piece: &RequestPiece = body_piece;
            ready!(write_all(
                |b| bounded_step(c, expiry, |c| c.write_request(stream, body_piece, b)),
                &body[..]
            ));
            ready!(bounded_step(c, expiry, |c| c.write_request(
                stream,
                end_piece,
                &[]
            )));
            Poll::Ready(Ok(()))
        }
    }
}

/// Send, then read the reply to its terminal piece into `state`, then close the stream: on a
fn send_and_read(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<()> {
    let answer = match exchange_once(c, state, need, target) {
        Poll::Ready(Err(e)) => match state.stream {
            Some(stream) => match c.close(stream) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => {
                    state.stream = None;
                    Poll::Ready(Err(e))
                }
            },
            None => Poll::Ready(Err(e)),
        },
        Poll::Ready(Ok(())) => {
            state.stream = None;
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
    };
    if answer.is_pending() {
        state.closer = Some(c.closer());
    }
    answer
}

/// One pass of [`send_and_read`]: establish, send, read to the terminal piece, close a whole one.
fn exchange_once(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<()> {
    state.begun = true;
    if let Err(error) = state.within_timeout(c) {
        return Poll::Ready(Err(error));
    }

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

    if let Err(error) = state.within_timeout(c) {
        return Poll::Ready(Err(error));
    }
    if state.expires_at_ns.is_some() && ended.is_err() {
        if let Some(stream) = state.stream.take() {
            c.closer().close(stream);
        }
        return Poll::Ready(ended);
    }
    if state.stream.is_none() {
        return Poll::Ready(ended);
    }
    match c.close(stream) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => {
            state.stream = None;
            Poll::Ready(ended)
        }
    }
}

/// Send on `stream`, then read the reply to its terminal piece (for a head-only exchange, its head
fn read_to_end(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Answer<()> {
    ready!(send(c, state, stream));
    loop {
        if let Err(error) = state.within_timeout(c) {
            return Poll::Ready(Err(error));
        }
        let this = c.issued();
        let got = match bounded_step(c, state.expires_at_ns, |c| {
            c.read_reply(stream, &mut state.buf[..], &mut state.slot)
        }) {
            Poll::Ready(Ok(got)) => got,
            Poll::Ready(Err(e)) => {
                if observe(c, state, stream).is_pending() {
                    return Poll::Pending;
                }
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        };
        if let Err(error) = state.within_timeout(c) {
            return Poll::Ready(Err(error));
        }

        let fresh = this >= state.applied;
        if fresh {
            state.applied = this + 1;
        }
        let p = got.piece;
        let applied = match state.refused_at {
            Some((at, text)) if at == this => Err(text),
            _ => apply(state, p, got.len, fresh),
        };

        if fresh {
            if let Some(used) = state.buf.get_mut(..got.len) {
                used.zeroize();
            }
        }
        if let (true, Err(text)) = (fresh, applied) {
            state.refused_read = Some((this, text));
        }

        match (state.refused_read, applied) {
            (Some((at, text)), _) if at == this => return failed(text),
            (_, Err(text)) => return failed(text),
            _ => {}
        }

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
            if state
                .reply
                .body
                .len()
                .checked_add(len)
                .is_none_or(|total| total > state.reply_ceiling)
            {
                return Err(REPLY_OVER_BOUND);
            }
            extend_wiping(&mut state.reply.body, &state.buf[..len]);
        }
        REPLY_HEAD | REPLY_ACK | REPLY_BODY | REPLY_END => {}
        _ => return Err("the transport answered no reply piece: every request is acked"),
    }
    Ok(())
}

/// Read `stream`'s facts into `state` where it asks ([`Exchange::observing`]): a facts answer the
fn observe(c: &mut Connector<'_>, state: &mut Exchange, stream: u64) -> Poll<()> {
    if !state.observe {
        return Poll::Ready(());
    }
    match bounded_step(c, state.expires_at_ns, |c| c.facts(stream)) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(Some(observed))) => {
            state.observed = Some(observed);
            Poll::Ready(())
        }
        Poll::Ready(_) => Poll::Ready(()),
    }
}

/// ONE REQUEST, ONE REPLY over the declared framed need `need` to `target` (`None` = the need's
pub fn exchange(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<ExchangeResponse> {
    ready!(send_and_read(c, state, need, target));
    if let Err(error) = state.within_timeout(c) {
        return Poll::Ready(Err(error));
    }
    let mut reply = std::mem::take(&mut *state.reply);
    reply.status = u16::try_from(state.code).unwrap_or(0);
    Poll::Ready(Ok(reply))
}

/// SEND and learn what became of it, over any transport (a pure-send one answers a single ack):
pub fn send_and_ack(
    c: &mut Connector<'_>,
    state: &mut Exchange,
    need: u32,
    target: Option<&str>,
) -> Answer<Ack> {
    ready!(send_and_read(c, state, need, target));
    if let Err(error) = state.within_timeout(c) {
        return Poll::Ready(Err(error));
    }
    Poll::Ready(Ok(Ack {
        code: state.code,
        reason: state.reply.reason.take().unwrap_or_default(),
    }))
}

/// A kind's optional typed state, owned by the operation's existing continuation.
pub(crate) type Context = Arc<dyn Any + Send + Sync>;

/// What an op parks its exchange on: its instance, whatever the instance state's type.
pub(crate) trait Parks {
    fn context(&self) -> Option<&RefCell<Option<Context>>> {
        None
    }
    fn resuming(&self) -> bool {
        false
    }
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

/// Why an [`Op::exchange`] answered without a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpFailure {
    /// The op's request builder could not build the request, in its own words: nothing was sent.
    Unbuilt(String),
    /// The exchange failed (or the request it framed was refused), as the connector said.
    Conn(ConnFailure),
}

impl std::fmt::Display for OpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unbuilt(why) => f.write_str(why),
            Self::Conn(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for OpFailure {}

impl From<ConnFailure> for OpFailure {
    fn from(e: ConnFailure) -> Self {
        Self::Conn(e)
    }
}

/// Retained inspection state for one outer operation or kept driver cycle. Keep it across
/// PENDING/RESUME (and TICK-to-DRIVE); dropping it on cancellation discards plugin-side custody.
/// It does not park into the connection exchange's continuation. IDs never wrap within an epoch.
#[derive(Debug, Default)]
pub struct Inspection {
    pending: Option<crate::abi::mechanism::inspection::InspectionRequest>,
    completed: Option<crate::abi::mechanism::inspection::InspectionReceipt>,
    last: Option<(crate::abi::mechanism::ticket::Ticket, u64, u64)>,
}

/// An operation failure with the reply head received before the failure, when one arrived.
pub struct ExchangeFailure {
    cause: OpFailure,
    head: Option<Zeroizing<ExchangeResponse>>,
}

impl ExchangeFailure {
    fn without_head(cause: OpFailure) -> Self {
        Self { cause, head: None }
    }

    /// The builder or connector failure, independently of any earlier reply head.
    #[must_use]
    pub fn cause(&self) -> &OpFailure {
        &self.cause
    }

    /// The earlier status, reason and fields. The body is always empty. A caller can judge this
    #[must_use]
    pub fn head(&self) -> Option<&ExchangeResponse> {
        self.head.as_deref()
    }

    /// Take the underlying failure, wiping and releasing any retained head.
    #[must_use]
    pub fn into_cause(self) -> OpFailure {
        self.cause
    }
}

impl std::fmt::Debug for ExchangeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeFailure")
            .field("status", &self.head().map(|head| head.status))
            .field("head", &self.head().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ExchangeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(f)
    }
}

impl std::error::Error for ExchangeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// ONE OP'S EXCHANGE ON ITS TICKET (THE DESIGN, the plugin ABI: every call is Ready or
pub struct Op<'a> {
    on: &'a dyn Parks,
    host: Option<&'a Host>,
    timeout_ms: Cell<Option<u64>>,
    deadline_ns: Cell<Option<u64>>,
    wake_at_ns: Cell<Option<u64>>,
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
    #[must_use]
    pub fn new<'b: 'a, T: Send + Sync + 'static>(
        instance: &'a Instance<'b, T>,
        host: Option<&'a Host>,
    ) -> Self {
        Self::over(instance, host)
    }

    /// A kind SDK's composite continuation, still owned and cleaned up by its safe instance.
    pub(crate) fn over(on: &'a dyn Parks, host: Option<&'a Host>) -> Self {
        Self {
            on,
            host,
            timeout_ms: Cell::new(None),
            deadline_ns: Cell::new(None),
            wake_at_ns: Cell::new(None),
        }
    }

    /// Opt newly built exchanges into a complete wall-clock bound. A resumed exchange keeps its
    #[must_use]
    pub fn with_timeout_ms(self, timeout_ms: u64) -> Self {
        self.set_timeout_ms(timeout_ms);
        self
    }

    /// [`Op::with_timeout_ms`] for a hook handed a borrowed operation.
    pub fn set_timeout_ms(&self, timeout_ms: u64) {
        self.timeout_ms.set((timeout_ms != 0).then_some(timeout_ms));
    }

    /// Clamp new explicitly timed exchanges to the operation's known absolute deadline on the
    #[must_use]
    pub fn with_deadline_ns(self, deadline_ns: u64) -> Self {
        self.set_deadline_ns(deadline_ns);
        self
    }

    /// [`Op::with_deadline_ns`] for a borrowed operation. Resumed exchanges retain their expiry.
    pub fn set_deadline_ns(&self, deadline_ns: u64) {
        self.deadline_ns
            .set((deadline_ns != 0).then_some(deadline_ns));
    }

    /// The earliest absolute timer requested by this entry's pending exchange. A kind's caller
    #[must_use]
    pub fn wake_at_ns(&self) -> Option<u64> {
        self.wake_at_ns.get()
    }

    /// The host tables the op runs over (`None`: the instance was handed none): what an op that
    #[must_use]
    pub fn host(&self) -> Option<&'a Host> {
        self.host
    }

    /// The op's ticket ([`Ticket::NONE`] on the spot).
    #[must_use]
    pub fn ticket(&self) -> Ticket {
        self.on.ticket()
    }

    /// Whether the kind SDK restored its parked continuation for this entry. This reports actual
    #[must_use]
    pub fn resuming(&self) -> bool {
        self.on.resuming()
    }

    /// Retain this operation's typed state with its continuation. Hook operations support this;
    pub fn context<T: Send + Sync + 'static>(
        &self,
        initialize: impl FnOnce() -> Arc<T>,
    ) -> Result<Arc<T>, &'static str> {
        let slot = self
            .on
            .context()
            .ok_or("operation context is unavailable")?;
        let existing = slot.borrow().as_ref().cloned();
        let value = if let Some(existing) = existing {
            existing
        } else {
            let created: Context = initialize();
            let selected = {
                let mut held = slot.borrow_mut();
                Arc::clone(held.get_or_insert_with(|| Arc::clone(&created)))
            };

            selected
        };
        value
            .downcast::<T>()
            .map_err(|_| "operation context type changed")
    }

    /// Read one negotiated generic host observation. The first supported entry appends a leased
    pub fn inspect<I: super::door::AbiIn, O: super::door::AbiOut>(
        &self,
        input: super::Lent<'_, I>,
        out: &mut super::Out<'_, O>,
        leases: &super::life::Leases,
        state: &mut Inspection,
        id: u64,
        query: &crate::abi::mechanism::inspection::InspectionQuery,
    ) -> Poll<crate::abi::mechanism::inspection::InspectionResult> {
        use crate::abi::mechanism::call::{InHead, FLAG_RESUME};
        use crate::abi::mechanism::inspection::{self, InspectionError, InspectionRequest};
        // SAFETY: AbiIn starts with InHead, and Lent's host-owned pointers live for this entry.
        let head = unsafe { &*std::ptr::from_ref(input.get()).cast::<InHead>() };
        // SAFETY: the extensions are part of the host's lent head, not plugin-provided memory.
        let ext = unsafe { super::Lent::new(&head.extensions) }.bytes();
        let capability = match inspection::read_capability(ext) {
            Ok(Some(capability)) => capability,
            Ok(None) => return Poll::Ready(Err(InspectionError::Unsupported)),
            Err(error) => return Poll::Ready(Err(error)),
        };
        if head.ticket != self.ticket() || head.ticket.is_none() {
            return Poll::Ready(Err(InspectionError::Unticketed));
        }
        if !inspection::query_fits(query, 0) {
            return Poll::Ready(Err(InspectionError::Invalid));
        }
        let request = InspectionRequest {
            ticket: head.ticket,
            epoch: capability.epoch,
            id,
            query: query.clone(),
        };
        if let Err(error) = inspection::encode_request(&request) {
            return Poll::Ready(Err(error));
        }
        if let Some(completed) = state.completed.as_ref().filter(|r| {
            r.request.ticket == request.ticket
                && r.request.epoch == request.epoch
                && r.request.id == id
        }) {
            return if completed.request == request {
                Poll::Ready(completed.result.clone())
            } else {
                Poll::Ready(Err(InspectionError::Correlation))
            };
        }
        if let Some(pending) = state.pending.as_ref() {
            if pending.ticket != request.ticket || pending.epoch != request.epoch {
                state.pending = None;
                return Poll::Ready(Err(InspectionError::Correlation));
            }
            if pending != &request {
                return Poll::Ready(Err(InspectionError::Busy));
            }
            match inspection::read_receipt(ext) {
                Ok(Some(receipt)) if receipt.request == request => {
                    state.pending = None;
                    let result = receipt.result.clone();
                    state.completed = Some(receipt);
                    return Poll::Ready(result);
                }
                Ok(Some(_)) => return Poll::Ready(Err(InspectionError::Correlation)),
                Ok(None) if head.flags & FLAG_RESUME != 0 => {
                    state.pending = None;
                    return Poll::Ready(Err(InspectionError::MissingReceipt));
                }
                Ok(None) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        } else if state.last.is_some_and(|(ticket, epoch, last)| {
            ticket == request.ticket && epoch == request.epoch && id <= last
        }) {
            return Poll::Ready(Err(InspectionError::Invalid));
        }
        let retained = crate::abi::mechanism::extensions::entries(ext)
            .filter(|(key, _)| {
                ![
                    inspection::EXT_CAPABILITY,
                    inspection::EXT_REQUEST,
                    inspection::EXT_REPLY,
                ]
                .iter()
                .any(|known| *key == known.as_bytes())
            })
            .map(|(key, value)| 2 + key.len() + 4 + value.len())
            .sum();
        if !inspection::query_fits(query, retained) {
            return Poll::Ready(Err(InspectionError::Invalid));
        }
        if let Err(error) = out.inspection_request(leases, &request) {
            return Poll::Ready(Err(error));
        }
        state.completed = None;
        state.last = Some((request.ticket, request.epoch, id));
        state.pending = Some(request);
        Poll::Pending
    }

    /// [`exchange`] over the declared framed need `need` to `target`: `request` is built only on
    pub fn exchange(
        &self,
        need: u32,
        target: Option<&str>,
        request: impl FnOnce() -> Result<Request, String>,
    ) -> Poll<Result<ExchangeResponse, OpFailure>> {
        self.exchange_sealed(need, target, || request().map(|r| (r, Vec::new())))
    }

    /// [`Op::exchange`] for a request with sealed fields ([`Exchange::request_sealed`]).
    pub fn exchange_sealed(
        &self,
        need: u32,
        target: Option<&str>,
        request: impl FnOnce() -> Result<(Request, Vec<SealedField>), String>,
    ) -> Poll<Result<ExchangeResponse, OpFailure>> {
        self.exchange_sealed_bounded(need, target, REPLY_MAX, request)
    }

    /// [`Op::exchange`] whose reply body may reach at most `reply_limit` bytes
    pub fn exchange_bounded(
        &self,
        need: u32,
        target: Option<&str>,
        reply_limit: usize,
        request: impl FnOnce() -> Result<Request, String>,
    ) -> Poll<Result<ExchangeResponse, OpFailure>> {
        self.exchange_sealed_bounded(need, target, reply_limit, || {
            request().map(|r| (r, Vec::new()))
        })
    }

    /// [`Op::exchange_bounded`] for a request with sealed fields ([`Exchange::request_sealed`]).
    pub fn exchange_sealed_bounded(
        &self,
        need: u32,
        target: Option<&str>,
        reply_limit: usize,
        request: impl FnOnce() -> Result<(Request, Vec<SealedField>), String>,
    ) -> Poll<Result<ExchangeResponse, OpFailure>> {
        self.exchange_sealed_bounded_with_head(need, target, reply_limit, false, request)
            .map(|answer| answer.map_err(ExchangeFailure::into_cause))
    }

    /// A bounded exchange that retains an earlier reply head when the exchange later fails.
    pub fn exchange_sealed_bounded_with_head(
        &self,
        need: u32,
        target: Option<&str>,
        reply_limit: usize,
        head_only: bool,
        request: impl FnOnce() -> Result<(Request, Vec<SealedField>), String>,
    ) -> Poll<Result<ExchangeResponse, ExchangeFailure>> {
        let Some(host) = self.host else {
            return Poll::Ready(Err(ExchangeFailure::without_head(
                ConnFailure::Unarmed.into(),
            )));
        };
        let mut state = match self.on.resume() {
            Some(parked) => *parked,
            None => match request() {
                Err(why) => {
                    return Poll::Ready(Err(ExchangeFailure::without_head(OpFailure::Unbuilt(why))))
                }
                Ok((r, sealed)) => match Exchange::request_sealed(r, sealed) {
                    Ok(s) => {
                        let s = match self.timeout_ms.get() {
                            Some(ms) => {
                                let s = s.with_timeout_ms(ms);
                                match self.deadline_ns.get() {
                                    Some(deadline) => s.with_deadline_ns(deadline),
                                    None => s,
                                }
                            }

                            None => s,
                        };
                        let s = s.reply_limit(reply_limit);
                        if head_only {
                            s.head_only()
                        } else {
                            s
                        }
                    }
                    Err(e) => return Poll::Ready(Err(ExchangeFailure::without_head(e.into()))),
                },
            },
        };
        let mut c = host.connector(self.on.ticket());
        match exchange(&mut c, &mut state, need, target) {
            Poll::Pending => {
                if let Some(expiry) = state.wake_at_ns() {
                    self.wake_at_ns.set(Some(
                        self.wake_at_ns.get().map_or(expiry, |old| old.min(expiry)),
                    ));
                }
                self.on.park(state);
                Poll::Pending
            }
            Poll::Ready(Ok(reply)) => Poll::Ready(Ok(reply)),
            Poll::Ready(Err(cause)) => {
                let head = state.head_status().map(|status| {
                    Zeroizing::new(ExchangeResponse {
                        status,
                        reason: state.reply.reason.take(),
                        fields: std::mem::take(&mut state.reply.fields),
                        body: Vec::new(),
                    })
                });
                Poll::Ready(Err(ExchangeFailure {
                    cause: cause.into(),
                    head,
                }))
            }
        }
    }
}

#[cfg(test)]
mod bounded_body_tests {
    use super::*;

    #[test]
    fn a_refused_body_piece_is_not_collected_past_the_reply_limit() {
        let mut state = Exchange::request(Request::default())
            .expect("a valid request")
            .reply_limit(100);
        state.buf[..60].fill(b'a');
        let body = ReplyPiece {
            kind: REPLY_BODY,
            ..ReplyPiece::default()
        };
        assert_eq!(apply(&mut state, body, 60, true), Ok(()));
        state.buf[..41].fill(b'b');
        assert_eq!(apply(&mut state, body, 41, true), Err(REPLY_OVER_BOUND));
        assert_eq!(
            state.reply.body.len(),
            60,
            "a rejected piece must not enter the collected body"
        );
        assert!(state.reply.body.iter().all(|byte| *byte == b'a'));
    }
}

#[cfg(test)]
#[path = "tests/exchange_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/inspection_tests.rs"]
mod inspection_tests;
