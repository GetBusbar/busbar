// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The session task core over the plane port (IF §8.6, §11.3, PLANE-DRIVER.md slice 2). One [`Task`] drives one
//! plane session through `request`, `piece`, `rewrite` and `end`; every answer is decoded once into an [`Answer`]
//! whose client side is an ordered list of [`ToClient`] items, applied to the client through the existing
//! [`CallerEnd`] seam ([`deliver`]).
//!
//! The once rules live in [`Once`], the one place that knows whether this session already forwarded or began its
//! client response: FORWARD (with its wants and EXPECTs) is accepted in the `request` answer or in a
//! `piece(FROM_CORE)` answer, once, and never after the response began or beside a to-client item. A second or
//! late FORWARD is handled exactly as an adapter FAULT: the session ends (the handle is dropped, which cancels it)
//! and the caller learns [`Violation`]. The loader has no entry that charges an image for a violation core finds
//! itself; the violation is logged by the caller and counted in `plane_session_violations_total` (a gap recorded
//! in PLANE-DRIVER.md).
//!
//! The calls are synchronous (a port's methods run the plugin on its worker); a driver runs a task inside
//! `spawn_blocking`. The [`Calls`] trait is the seam the tests fake: `PlaneSession` is an ffi handle, so a core
//! test cannot build one.

use busbar_plugin_abi::plane::{
    UsageRec, ATT_DECLINE, ATT_OK, ATT_RELAY, ATT_RETRY, AUDIT_APPLIED, AUDIT_DEGRADED,
    AUDIT_REJECTED, FROM_CORE, FROM_UPSTREAM, MSG_FIN, MSG_TEXT,
};
use busbar_plugin_loader::ports::plane::{PlaneIn, PlaneOut, PlanePort, PlaneSession, TargetIn};
use busbar_plugin_loader::ports::{FactRef, FactVal, PortError};

use super::port_money::AuditRow;
use super::usage::{SessionUsage, UsageInvalid};
use super::{CallerEnd, HeadFields};

/// The plane's calls on one session, as a driver sees them. The port implements it; a test implements it over a
/// script.
pub trait Calls {
    type Session: Send + 'static;

    fn request(
        &self,
        req: &PlaneIn<'_>,
        body: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Self::Session, PortError>;

    fn piece(
        &self,
        s: &mut Self::Session,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;

    fn rewrite(
        &self,
        s: &mut Self::Session,
        conversation: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;

    fn end(&self, s: Self::Session, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError>;

    fn probe(
        &self,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Self::Session, PortError>;

    fn render(
        &self,
        req: &PlaneIn<'_>,
        what: u32,
        arg: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;

    fn upstream(
        &self,
        s: &mut Self::Session,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError>;
}

impl Calls for dyn PlanePort {
    type Session = PlaneSession;

    fn request(
        &self,
        req: &PlaneIn<'_>,
        body: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        PlanePort::request(self, req, body, sink)
    }

    fn piece(
        &self,
        s: &mut PlaneSession,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        PlanePort::piece(self, s, from, exchange, flags, bytes, sink)
    }

    fn rewrite(
        &self,
        s: &mut PlaneSession,
        conversation: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        PlanePort::rewrite(self, s, conversation, sink)
    }

    fn end(&self, s: PlaneSession, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        PlanePort::end(self, s, sink)
    }

    fn probe(
        &self,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        PlanePort::probe(self, t, sink)
    }

    fn render(
        &self,
        req: &PlaneIn<'_>,
        what: u32,
        arg: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        PlanePort::render(self, req, what, arg, sink)
    }

    fn upstream(
        &self,
        s: &mut PlaneSession,
        t: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        PlanePort::upstream(self, s, t, sink)
    }
}

/// Which call produced an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Request,
    Piece(u32),
    Upstream,
    Rewrite,
    Render,
    Probe,
    End,
}

/// What core does not accept from a session, handled as an adapter FAULT (§8.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A second FORWARD.
    SecondForward,
    /// FORWARD after the client response began, or beside a to-client item.
    LateForward,
    /// FORWARD (or a WANT/EXPECT) in an answer that is not a `request` or `piece(FROM_CORE)` answer.
    ForwardOutOfPlace(Origin),
    /// A to-client item after the response's END.
    AfterEnd,
    /// A USAGE the session may not keep (class, scale or source).
    Usage(UsageInvalid),
    /// An ATTEMPT in an answer that is not an `upstream` or `piece(FROM_UPSTREAM)` answer, or an ATT_DECLINE
    /// anywhere but `upstream`.
    AttemptOutOfPlace(Origin),
    /// An ATTEMPT RETRY, HARD or DECLINE beside a to-client record.
    AttemptWithResponse,
    /// An ATTEMPT verdict that is not ATT_OK..=ATT_DECLINE.
    BadAttempt,
    /// An AUDIT with no known verdict or no action.
    BadAudit,
    /// An upstream exchange item (UP_*, EX_MSG) in an answer that is not an `upstream`, `piece` or `probe` answer.
    UpstreamOutOfPlace(Origin),
    /// UP_NEW with exchange 0 (exchange 0 is the session's first, stated by `upstream`).
    BadExchange,
    /// An `upstream` or `probe` answer that is neither ATT_DECLINE nor an exchange 0.
    MissingExchange,
}

/// Why a session call produced no usable answer.
#[derive(Debug)]
pub enum SessionError {
    /// The plane refused, failed or faulted; the port already handled the image.
    Port(PortError),
    /// The plane broke a once rule; the session is cancelled.
    Violation(Violation),
    /// The session is over (`end` ran, or an earlier call failed and dropped it).
    Over,
    /// The answer carries an item a later slice drives.
    NotDriven,
    /// Core could not encode the call's argument.
    Encode,
}

/// One item the client sees, in the order the plane wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToClient {
    Head {
        status: u16,
        fields: HeadFields,
    },
    Body(Vec<u8>),
    Msg {
        flags: u32,
        bytes: Vec<u8>,
    },
    /// The client trailer fields: one `emit(E_TRAILERS)`; trailers-only on HTTP/2 when no `Body` preceded it.
    Trailers(HeadFields),
    End,
}

/// A FORWARD: core now picks candidates and calls `upstream`.
#[derive(Debug, Clone, PartialEq)]
pub struct Forward {
    pub stream: bool,
    pub wants: Vec<(u32, FactVal)>,
}

/// One USAGE the plane stated (IF §12.4): its running total for (class, source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageItem {
    pub class: Box<str>,
    pub amount: u64,
    pub scale: u32,
    pub source: u32,
}

/// One EXPECT: this request's expected usage of a class, for candidate cost recipes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectItem {
    pub class: Box<str>,
    pub amount: u64,
    pub scale: u32,
}

/// One ATTEMPT (IF §8.6): `reason` is operator-only text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptItem {
    pub verdict: u32,
    pub class: u32,
    pub retry_after_s: u64,
    pub reason: Box<str>,
}

/// One upstream exchange an answer asks core to send (IF §8.6): exchange 0 from `upstream`, or one UP_NEW
/// started. `method` and `path` are states the plane gave (the adapter checks the record order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpExchange {
    pub id: u32,
    pub carrier: u32,
    pub outbound: u32,
    pub method: Option<Box<str>>,
    pub path: Option<Box<str>>,
    pub scope: Option<Box<str>>,
    pub headers: HeadFields,
    pub body: Vec<u8>,
    /// UP_MSG items: (flags, bytes).
    pub msgs: Vec<(u32, Vec<u8>)>,
    pub end: bool,
    pub cut: bool,
}

/// One EX_MSG: a message on exchange `exchange`, on `stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExMsgItem {
    pub exchange: u32,
    pub flags: u32,
    pub stream: u64,
    pub bytes: Vec<u8>,
}

/// One answer, decoded. Applied in the order the plane wrote it.
#[derive(Debug, Default)]
pub struct Answer {
    pub client: Vec<ToClient>,
    pub forward: Option<Forward>,
    pub facts: Vec<(u32, FactVal)>,
    pub finish: bool,
    /// An item a later slice drives (intents, accounting, upstream exchanges, records).
    pub later: bool,
    /// USAGE records in answer order (cumulative; the task keeps the last per class and source).
    pub usage: Vec<UsageItem>,
    pub expects: Vec<ExpectItem>,
    /// The outcome of the current attempt, or ATT_DECLINE from `upstream`.
    pub attempt: Option<AttemptItem>,
    /// AUDIT rows in answer order.
    pub audits: Vec<AuditRow>,
    /// The exchanges this answer asks core to send, in the order they began.
    pub exchanges: Vec<UpExchange>,
    pub ex_msgs: Vec<ExMsgItem>,
    pub violation: Option<Violation>,
    /// The exchange the answer is writing now (UP_CARRIER, UP_NEW, UP_METHOD start one), until a client item.
    up_open: Option<usize>,
    /// The exchange a body-only answer belongs to: the one the `piece` named.
    default_exchange: u32,
    head: Option<(u16, HeadFields)>,
    trailers: Option<HeadFields>,
}

/// Effects the plane's answer has outside the client, applied at once, in sink order.
pub trait Effects {
    /// `PlaneOut::Emit`: bytes for a line carrier (§12.23).
    fn emit(&self, carrier: u64, bytes: &[u8]);
}

/// The once rules of one session.
#[derive(Debug, Default)]
pub struct Once {
    forwarded: bool,
    responded: bool,
    ended: bool,
}

impl Once {
    fn forward(&mut self, origin: Origin, here: &Answer) -> Result<(), Violation> {
        if !matches!(origin, Origin::Request | Origin::Piece(FROM_CORE)) {
            return Err(Violation::ForwardOutOfPlace(origin));
        }
        if self.forwarded || here.forward.is_some() {
            return Err(Violation::SecondForward);
        }
        if self.responded || !here.client.is_empty() || here.head.is_some() {
            return Err(Violation::LateForward);
        }
        self.forwarded = true;
        Ok(())
    }

    fn respond(&mut self, here: &Answer) -> Result<(), Violation> {
        if self.ended {
            return Err(Violation::AfterEnd);
        }
        if here.forward.is_some() {
            return Err(Violation::LateForward);
        }
        if here.attempt_fails() {
            return Err(Violation::AttemptWithResponse);
        }
        self.responded = true;
        Ok(())
    }
}

impl Answer {
    /// An answer to a `piece` that named `exchange`: a body-only answer belongs to it.
    pub(crate) fn for_exchange(exchange: u32) -> Self {
        Self {
            default_exchange: exchange,
            ..Self::default()
        }
    }

    fn begin_exchange(&mut self, id: u32) -> usize {
        self.exchanges.push(UpExchange {
            id,
            ..UpExchange::default()
        });
        let at = self.exchanges.len() - 1;
        self.up_open = Some(at);
        at
    }

    fn open_exchange(&mut self) -> usize {
        match self.up_open {
            Some(at) => at,
            None => self.begin_exchange(self.default_exchange),
        }
    }

    fn has_client(&self) -> bool {
        !self.client.is_empty() || self.head.is_some() || self.trailers.is_some()
    }

    /// An ATTEMPT that fails the attempt (RETRY, HARD, DECLINE): no to-client record may accompany it.
    fn attempt_fails(&self) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|a| a.verdict >= ATT_RETRY && a.verdict != ATT_RELAY)
    }

    fn flush_head(&mut self) {
        if let Some((status, fields)) = self.head.take() {
            self.client.push(ToClient::Head { status, fields });
        }
    }

    fn flush_trailers(&mut self) {
        if let Some(fields) = self.trailers.take() {
            self.client.push(ToClient::Trailers(fields));
        }
    }

    /// Decodes one sink item. The first violation is kept and later items are still read, so the sink always
    /// returns normally.
    pub fn take(
        &mut self,
        out: PlaneOut<'_>,
        origin: Origin,
        once: &mut Once,
        effects: &dyn Effects,
    ) {
        if let Err(v) = self.place(out, origin, once, effects) {
            self.violation.get_or_insert(v);
        }
    }

    fn place(
        &mut self,
        out: PlaneOut<'_>,
        origin: Origin,
        once: &mut Once,
        effects: &dyn Effects,
    ) -> Result<(), Violation> {
        match out {
            PlaneOut::Respond { status } => {
                once.respond(self)?;
                self.up_open = None;
                self.flush_head();
                self.head = Some((status, Vec::new()));
            }
            PlaneOut::Header(name, value) => {
                let pair = (name.as_bytes().to_vec(), value.to_vec());
                if let Some(trailers) = self.trailers.as_mut() {
                    trailers.push(pair);
                } else if let Some(open) = self.up_open {
                    self.exchanges[open].headers.push(pair);
                } else if let Some((_, fields)) = self.head.as_mut() {
                    fields.push(pair);
                } else {
                    // A header with no response to carry it: the adapter's order check refuses this; core
                    // keeps what it was told rather than inventing a head.
                    self.later = true;
                }
            }
            PlaneOut::Body(bytes) => {
                once.respond(self)?;
                self.up_open = None;
                self.flush_head();
                self.client.push(ToClient::Body(bytes.to_vec()));
            }
            PlaneOut::Msg { flags, bytes } => {
                once.respond(self)?;
                self.up_open = None;
                self.flush_head();
                self.client.push(ToClient::Msg {
                    flags,
                    bytes: bytes.to_vec(),
                });
            }
            PlaneOut::Trailers => {
                once.respond(self)?;
                self.up_open = None;
                self.flush_head();
                self.trailers = Some(Vec::new());
            }
            PlaneOut::End => {
                once.respond(self)?;
                self.up_open = None;
                self.flush_head();
                self.flush_trailers();
                self.client.push(ToClient::End);
                once.ended = true;
            }
            PlaneOut::Forward { stream } => {
                once.forward(origin, self)?;
                self.forward = Some(Forward {
                    stream,
                    wants: Vec::new(),
                });
            }
            PlaneOut::Want(key, value) => {
                if !matches!(origin, Origin::Request | Origin::Piece(FROM_CORE)) {
                    return Err(Violation::ForwardOutOfPlace(origin));
                }
                let value = fact_val(value);
                match self.forward.as_mut() {
                    Some(forward) => forward.wants.push((key, value)),
                    None => self.facts.push((key, value)),
                }
            }
            PlaneOut::Fact(key, value) => self.facts.push((key, fact_val(value))),
            PlaneOut::Emit { carrier, bytes } => effects.emit(carrier, bytes),
            PlaneOut::Finish => self.finish = true,
            PlaneOut::UpCarrier { carrier, outbound } => {
                upstream_placed(origin)?;
                let at = self.begin_exchange(self.default_exchange);
                self.exchanges[at].carrier = carrier;
                self.exchanges[at].outbound = outbound;
            }
            PlaneOut::UpNew {
                exchange,
                carrier,
                outbound,
            } => {
                upstream_placed(origin)?;
                if exchange == 0 {
                    return Err(Violation::BadExchange);
                }
                let at = self.begin_exchange(exchange);
                self.exchanges[at].carrier = carrier;
                self.exchanges[at].outbound = outbound;
            }
            PlaneOut::UpMethod(method) => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].method = Some(method.into());
            }
            PlaneOut::UpPath(path) => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].path = Some(path.into());
            }
            PlaneOut::UpScope(scope) => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].scope = Some(scope.into());
            }
            PlaneOut::UpBody(bytes) => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].body.extend_from_slice(bytes);
            }
            PlaneOut::UpMsg { flags, bytes } => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].msgs.push((flags, bytes.to_vec()));
            }
            PlaneOut::UpEnd => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].end = true;
            }
            PlaneOut::UpCut => {
                upstream_placed(origin)?;
                let at = self.open_exchange();
                self.exchanges[at].cut = true;
            }
            PlaneOut::ExMsg {
                exchange,
                flags,
                stream,
                bytes,
            } => {
                upstream_placed(origin)?;
                self.ex_msgs.push(ExMsgItem {
                    exchange,
                    flags,
                    stream,
                    bytes: bytes.to_vec(),
                });
            }
            PlaneOut::Usage {
                class,
                amount,
                scale,
                source,
            } => self.usage.push(UsageItem {
                class: class.into(),
                amount,
                scale,
                source,
            }),
            PlaneOut::Expect {
                class,
                amount,
                scale,
            } => {
                if !matches!(origin, Origin::Request | Origin::Piece(FROM_CORE)) {
                    return Err(Violation::ForwardOutOfPlace(origin));
                }
                self.expects.push(ExpectItem {
                    class: class.into(),
                    amount,
                    scale,
                });
            }
            PlaneOut::Attempt {
                verdict,
                class,
                retry_after_s,
                reason,
            } => {
                if !(ATT_OK..=ATT_DECLINE).contains(&verdict) {
                    return Err(Violation::BadAttempt);
                }
                let placed = match origin {
                    Origin::Upstream | Origin::Probe => true,
                    Origin::Piece(FROM_UPSTREAM) => verdict != ATT_DECLINE,
                    _ => false,
                };
                if !placed {
                    return Err(Violation::AttemptOutOfPlace(origin));
                }
                if verdict >= ATT_RETRY && verdict != ATT_RELAY && self.has_client() {
                    return Err(Violation::AttemptWithResponse);
                }
                self.attempt = Some(AttemptItem {
                    verdict,
                    class,
                    retry_after_s,
                    reason: reason.into(),
                });
            }
            PlaneOut::Audit {
                verdict,
                action,
                resource,
            } => {
                if !matches!(verdict, AUDIT_APPLIED | AUDIT_REJECTED | AUDIT_DEGRADED)
                    || action.is_empty()
                {
                    return Err(Violation::BadAudit);
                }
                self.audits.push(AuditRow {
                    verdict,
                    action: action.into(),
                    resource: resource.into(),
                });
            }
            _ => self.later = true,
        }
        Ok(())
    }

    /// Closes the answer: the pending head and trailers are flushed.
    pub fn seal(mut self) -> Self {
        self.flush_head();
        self.flush_trailers();
        self
    }
}

/// Upstream exchange items come in `upstream`, `piece` and `probe` answers only.
fn upstream_placed(origin: Origin) -> Result<(), Violation> {
    match origin {
        Origin::Upstream | Origin::Piece(_) | Origin::Probe => Ok(()),
        _ => Err(Violation::UpstreamOutOfPlace(origin)),
    }
}

fn fact_val(value: FactRef<'_>) -> FactVal {
    match value {
        FactRef::U(n) => FactVal::U(n),
        FactRef::Text(t) => FactVal::Text(t.into()),
    }
}

/// One plane session under core's hand.
pub struct Task<'k, K: Calls + ?Sized> {
    calls: &'k K,
    session: Option<K::Session>,
    once: Once,
    usage: SessionUsage,
}

impl<'k, K: Calls + ?Sized> Task<'k, K> {
    /// `request`: the first answer. A refused or failed request has no session (§10.4).
    pub fn begin(
        calls: &'k K,
        req: &PlaneIn<'_>,
        body: &[u8],
        effects: &dyn Effects,
    ) -> Result<(Self, Answer), SessionError> {
        let mut once = Once::default();
        let mut answer = Answer::default();
        let session = calls
            .request(req, body, &mut |out| {
                answer.take(out, Origin::Request, &mut once, effects);
            })
            .map_err(SessionError::Port)?;
        let mut task = Self {
            calls,
            session: Some(session),
            once,
            usage: SessionUsage::new(),
        };
        let answer = task.checked(answer)?;
        Ok((task, answer))
    }

    /// `probe`: opens a health-probe session on one member; its answer is an `upstream` answer (a minimal request
    /// in the target's dialect, or ATT_DECLINE).
    pub fn probe(
        calls: &'k K,
        target: &TargetIn<'_>,
        effects: &dyn Effects,
    ) -> Result<(Self, Answer), SessionError> {
        let mut once = Once::default();
        let mut answer = Answer::default();
        let session = calls
            .probe(target, &mut |out| {
                answer.take(out, Origin::Probe, &mut once, effects);
            })
            .map_err(SessionError::Port)?;
        let mut task = Self {
            calls,
            session: Some(session),
            once,
            usage: SessionUsage::new(),
        };
        let answer = task.checked(answer)?;
        Ok((task, answer))
    }

    /// One `piece`.
    pub fn piece(
        &mut self,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        effects: &dyn Effects,
    ) -> Result<Answer, SessionError> {
        let origin = Origin::Piece(from);
        let calls = self.calls;
        let once = &mut self.once;
        let session = self.session.as_mut().ok_or(SessionError::Over)?;
        let mut answer = Answer::for_exchange(exchange);
        let called = calls.piece(session, from, exchange, flags, bytes, &mut |out| {
            answer.take(out, origin, once, effects);
        });
        self.settle(called, answer)
    }

    /// `rewrite` (a hook's REWRITE).
    pub fn rewrite(
        &mut self,
        conversation: &[u8],
        effects: &dyn Effects,
    ) -> Result<Answer, SessionError> {
        let calls = self.calls;
        let once = &mut self.once;
        let session = self.session.as_mut().ok_or(SessionError::Over)?;
        let mut answer = Answer::default();
        let called = calls.rewrite(session, conversation, &mut |out| {
            answer.take(out, Origin::Rewrite, once, effects);
        });
        self.settle(called, answer)
    }

    /// `end`: consumes the session. A task whose session is already gone answers `Over`.
    pub fn end(&mut self, effects: &dyn Effects) -> Result<Answer, SessionError> {
        let session = self.session.take().ok_or(SessionError::Over)?;
        let mut answer = Answer::default();
        let once = &mut self.once;
        self.calls
            .end(session, &mut |out| {
                answer.take(out, Origin::End, once, effects);
            })
            .map_err(SessionError::Port)?;
        if let Some(v) = answer.violation {
            return Err(SessionError::Violation(v));
        }
        self.keep_usage(&answer)?;
        Ok(answer.seal())
    }

    /// `upstream`: one attempt's encoding, or its ATT_DECLINE.
    pub fn upstream(
        &mut self,
        target: &TargetIn<'_>,
        effects: &dyn Effects,
    ) -> Result<Answer, SessionError> {
        let calls = self.calls;
        let once = &mut self.once;
        let session = self.session.as_mut().ok_or(SessionError::Over)?;
        let mut answer = Answer::default();
        let called = calls.upstream(session, target, &mut |out| {
            answer.take(out, Origin::Upstream, once, effects);
        });
        self.settle(called, answer)
    }

    /// The last USAGE per (class, source) any answer of this session stated (IF §12.4).
    pub fn usage(&self) -> &SessionUsage {
        &self.usage
    }

    /// Whether the session is still open.
    pub fn open(&self) -> bool {
        self.session.is_some()
    }

    fn settle(
        &mut self,
        called: Result<(), PortError>,
        answer: Answer,
    ) -> Result<Answer, SessionError> {
        if let Err(e) = called {
            self.session = None;
            return Err(SessionError::Port(e));
        }
        self.checked(answer)
    }

    /// A violation drops the session, which cancels it; the plane is told nothing.
    fn checked(&mut self, answer: Answer) -> Result<Answer, SessionError> {
        if let Some(v) = answer.violation {
            self.session = None;
            return Err(SessionError::Violation(v));
        }
        if let Err(error) = self.keep_usage(&answer) {
            self.session = None;
            return Err(error);
        }
        Ok(answer.seal())
    }

    fn keep_usage(&mut self, answer: &Answer) -> Result<(), SessionError> {
        for u in &answer.usage {
            let rec = UsageRec {
                amount: u.amount,
                scale: u.scale,
                source: u.source,
            };
            self.usage
                .answer(&u.class, rec)
                .map_err(|why| SessionError::Violation(Violation::Usage(why)))?;
        }
        Ok(())
    }
}

/// What a local-answer session produced for the client.
#[derive(Debug)]
pub struct Local {
    pub client: Vec<ToClient>,
    /// The AUDIT rows of both answers, in order.
    pub audits: Vec<AuditRow>,
    /// The last USAGE per (class, source) the session stated.
    pub usage: SessionUsage,
}

/// A session the plane answers locally: `request`, then `end`. A FORWARD, or an item a later slice drives, is
/// `NotDriven` here (the session is cancelled by the drop).
pub fn run_local<K: Calls + ?Sized>(
    calls: &K,
    req: &PlaneIn<'_>,
    body: &[u8],
    effects: &dyn Effects,
) -> Result<Local, SessionError> {
    let (mut task, first) = Task::begin(calls, req, body, effects)?;
    if first.forward.is_some() || first.later {
        return Err(SessionError::NotDriven);
    }
    let mut client = first.client;
    let mut audits = first.audits;
    let last = task.end(effects)?;
    if last.forward.is_some() || last.later {
        return Err(SessionError::NotDriven);
    }
    client.extend(last.client);
    audits.extend(last.audits);
    Ok(Local {
        client,
        audits,
        usage: task.usage().clone(),
    })
}

/// `render` (IF §8.8): the plane's rendering of a core decision, `RESPOND PAIR* BODY? (TRAILERS PAIR*)? END`.
/// Anything else in the answer (a forward, an intent, accounting) is a contract break: `NotDriven`.
pub fn render<K: Calls + ?Sized>(
    calls: &K,
    req: &PlaneIn<'_>,
    what: u32,
    arg: &[u8],
    effects: &dyn Effects,
) -> Result<Vec<ToClient>, SessionError> {
    let mut once = Once::default();
    let mut answer = Answer::default();
    calls
        .render(req, what, arg, &mut |out| {
            answer.take(out, Origin::Render, &mut once, effects);
        })
        .map_err(SessionError::Port)?;
    if let Some(v) = answer.violation {
        return Err(SessionError::Violation(v));
    }
    let answer = answer.seal();
    if answer.forward.is_some()
        || answer.later
        || answer.finish
        || !answer.usage.is_empty()
        || !answer.expects.is_empty()
        || answer.attempt.is_some()
    {
        return Err(SessionError::NotDriven);
    }
    Ok(answer.client)
}

/// Applies `items` to the client. False when the client stopped taking bytes.
pub async fn deliver<C: CallerEnd>(caller: &C, items: Vec<ToClient>) -> bool {
    for item in items {
        match item {
            ToClient::Head { status, fields } => caller.head(u32::from(status), fields),
            ToClient::Body(bytes) => {
                if !caller.write_piece(&bytes, false, false).await {
                    return false;
                }
            }
            ToClient::Msg { flags, bytes } => {
                if !caller
                    .write_piece(&bytes, flags & MSG_TEXT != 0, flags & MSG_FIN != 0)
                    .await
                {
                    return false;
                }
            }
            ToClient::Trailers(fields) => caller.trailers(fields),
            ToClient::End => {}
        }
    }
    true
}

#[cfg(test)]
#[path = "tests/port_session_tests.rs"]
mod tests;
